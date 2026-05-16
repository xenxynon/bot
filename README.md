# fileserv

A minimal self-hosted file server with a web UI.

## Features

- Browse, download, copy share links
- Upload via drag & drop (all logged-in users, quota-aware)
- Torrent / magnet download support — via magnet link, `.torrent` URL, or `.torrent` file upload (admin toggle)
- Rename and delete files (role-based)
- Directory navigation & creation
- Inline file preview (`/preview/<path>`) for images, video, audio, text and PDF
- Filter by category (archives, images, video, audio, docs), sort by name / size / date / type
- Dark mode (auto-detected, toggleable)
- Responsive — works on mobile
- Admin panel: user management, flags, stats, audit log

## Setup

```bash
pip install aiohttp python-dotenv
cp .env.example .env   # then edit .env
python web.py
```

> **Note:** Torrent/magnet downloads require `aria2c` to be installed and in your PATH.

## `.env` options

| Key | Description |
|-----|-------------|
| `WEB_PASS` | Access password (required) |
| `WEB_ADMIN_PASS` | Admin password — enables rename, delete, upload, and admin panel |
| `DOWNLOADS_DIR` | Directory to serve (default: `./downloads`) |
| `WEB_PORT` | HTTP port (default: `8080`) |
| `LINK_SECRET` | HMAC secret for share links (auto-generated if unset) |
| `WEB_BASE` | Public base URL shown in startup logs |
| `SUPER_USERS` | Comma-separated Telegram user IDs allowed to delete (bot integration) |
| `MAX_UPLOAD_MB` | Per-file upload size cap in MB (default: 2048) |
| `MAX_FETCH_MB` | Remote URL fetch size cap in MB (default: 4096) |
| `QUOTA_MB` | Per-user upload quota in MB (default: 0 = unlimited) |
| `MAX_SESSIONS_PER_USER` | Simultaneous sessions per account (default: 10) |
| `COOKIE_SECURE` | Set to `true` when running behind an HTTPS reverse proxy |

## Roles

| Role | Browse | Download | Upload | Delete | Rename | Admin panel |
|------|--------|----------|--------|--------|--------|-------------|
| User | ✓ | ✓ | ✓ | own files | own files | — |
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

## API Endpoints

### Public / session

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Explorer UI (or login page) |
| `GET` | `/health` | Health check — disk usage, session count (no auth) |
| `POST` | `/login` | Form login |
| `POST` | `/register` | Self-registration (can be disabled via `registration_open` flag) |
| `POST` | `/logout` | Destroy session |
| `GET` | `/session` | Current session info (role, quota, avatar …) |

### Files

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/files?path=<rel>` | List directory |
| `POST` | `/upload?path=<rel>` | Upload file (multipart) |
| `DELETE` | `/files/<rel>` | Delete file or folder |
| `POST` | `/rename` | Rename file or folder |
| `POST` | `/mkdir` | Create subfolder |
| `GET` | `/zip?path=<rel>` | Download folder as zip |
| `GET` | `/dl/<rel>` | Download file (attachment) |
| `GET` | `/preview/<rel>` | Serve file inline for browser preview |
| `GET` | `/token/<rel>` | Generate a one-time share link |
| `GET` | `/get/<token>/<rel>` | Unauthenticated download via share token |

### Remote fetch & torrents

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/fetch` | Start remote URL download |
| `GET` | `/fetch/progress` | Poll all fetch jobs |
| `POST` | `/fetch/<id>/cancel` | Cancel a fetch job |
| `POST` | `/fetch/<id>/retry` | Retry a failed/cancelled fetch |
| `POST` | `/torrent` | Start torrent/magnet download (admin) |
| `GET` | `/torrent/progress` | Poll torrent jobs (admin) |
| `POST` | `/torrent/<pid>/cancel` | Cancel torrent (admin) |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/users` | List users |
| `DELETE` | `/admin/users/<u>` | Delete user |
| `PATCH` | `/admin/users/<u>` | Update password / role / disabled |
| `POST` | `/admin/users/<u>/reset` | Kill sessions for a user |
| `POST` | `/admin/avatar` | Upload admin avatar |
| `GET` | `/admin/stats` | Disk usage, user counts, job counts |
| `GET` | `/admin/audit?n=200` | Last N audit-log lines |
| `GET` | `/flags` | Read feature flags |
| `POST` | `/flags` | Set feature flags |

## Security notes

- Passwords are stored as **salted SHA-256** (`sha256$<salt>$<digest>`). Legacy
  unsalted hashes are transparently upgraded on first successful login.
- Session tokens are 256-bit random hex; stored server-side only.
- A per-user session cap (default 10) prevents unbounded session growth.
- The remote-fetch handler blocks requests to **private/loopback IP ranges**
  (127.x, 10.x, 172.16–31.x, 192.168.x, 169.254.x, IPv6 loopback/link-local)
  to prevent SSRF attacks.
- All file paths are resolved and checked to be strictly inside `DOWNLOADS_DIR`
  before any operation, preventing path-traversal attacks.
- Uploaded executables (`.exe`, `.sh`, `.dll`, etc.) are rejected.
- All mutating actions are written to `audit.log`.
- Set `COOKIE_SECURE=true` and run behind an HTTPS reverse proxy in production.

## Deployment

Behind a reverse proxy (nginx/caddy) with HTTPS is recommended.
The app itself has no TLS support.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    client_max_body_size 4G;
}
```

---

## New Features (v2)

### A — Expiring / Password-Protected Share Links

Instead of the original HMAC token (valid forever), you can now create links with a TTL, optional password, and optional download cap.

```
POST /share
{
  "rel": "subdir/file.mp4",
  "ttl_hours": 48,        // optional, default 168 (1 week)
  "password": "secret",   // optional
  "max_hits": 5           // optional download cap
}
→ {"token": "abc…", "url": "/s/abc…"}

GET  /share                → list your links
DELETE /share/<token>      → revoke a link
GET  /s/<token>            → download (shows password form if protected)
POST /s/<token>  {password: "…"}  → authenticated download
```

Password-protected links show an inline HTML gate page — no JS required.

---

### B — Move / Copy Files Between Folders

```
POST /move
{
  "src": "folder-a/report.pdf",
  "dst_dir": "folder-b",
  "copy": false           // true = duplicate, false = move (default)
}
```

Works on both files and directories. Admins can move any file; users can only move their own.

---

### C — Bulk Operations

```
POST /bulk
{
  "action": "delete" | "move" | "zip",
  "files": ["a.zip", "subdir/b.mp4"],
  "dst_dir": "archive"    // required for "move"
}
```

- `delete` — removes all listed files, returns per-file errors
- `move` — moves all listed files to `dst_dir`
- `zip` — streams back a `selection.zip` immediately

---

### D — Full Filename Search

```
GET /search?q=report&path=subdir&type=doc
→ {
    "results": [{"name", "rel", "size", "mtime", "owner", "category", "can_modify"}, …],
    "total": 12
  }
```

- `q` — substring match (case-insensitive), required
- `path` — optional subdirectory root (default: entire library)
- `type` — optional category filter: `image` `video` `audio` `archive` `doc` `other`
- Returns up to 200 results

---

### E — Zip Contents Browser

Inspect a zip file without downloading it:

```
GET /zip-inspect?path=subdir/bundle.zip
→ {
    "entries": [{"name", "size", "compressed", "is_dir", "mtime"}, …],
    "count": 42
  }
```

---

### F — Inline Text File Editor

Read and write editable text files directly from the API:

```
GET /edit/<rel>
→ {"content": "…", "name": "notes.md", "size": 1234}

PUT /edit/<rel>
{"content": "updated text here"}
→ {"ok": true, "size": 1240}
```

Editable extensions: `txt md log json yaml toml cfg ini conf py js ts html css xml csv env`
Files over 2 MB are rejected. Only the file owner or admin can save.

---

### G — Webhook Notifications

Configure via the flags API (admin only):

```
POST /flags
{
  "webhook_url": "https://your-server/hook",
  "webhook_events": ["upload", "delete", "fetch_done"]
}
```

Each event fires a JSON POST:
```json
{"event": "upload", "ts": 1716000000.0, "user": "alice", "file": "photo.jpg"}
```

Best-effort, 5-second timeout, no retry. Remove `webhook_url` flag to disable.

---

### H — API Key Authentication

Alternative to cookie sessions, useful for scripted access:

```
POST /apikeys  {"label": "backup-script"}
→ {"key": "raw-key-shown-once", "label": "backup-script"}

GET  /apikeys          → list your keys (hashes + labels only)
DELETE /apikeys/<prefix>  → revoke by 12-char hash prefix
```

Use the key in any request:
```
Authorization: Bearer <key>
# or
GET /files?api_key=<key>
```

API keys inherit the role of the user who created them. Keys are stored as SHA-256 hashes — the raw key is shown only once at creation.

---

### Updated `.env` options

| Key | Description |
|-----|-------------|
| `QUOTA_MB` | Per-user upload quota in MB (0 = unlimited) |
| `MAX_SESSIONS_PER_USER` | Max simultaneous sessions per account (default: 10) |
| `COOKIE_SECURE` | Set `true` when behind HTTPS proxy |

### Flags (set via `POST /flags`, admin only)

| Flag | Type | Description |
|------|------|-------------|
| `webhook_url` | string | URL to POST event payloads to |
| `webhook_events` | list | Which events trigger the webhook |
| `torrent_enabled` | bool | Enable torrent/magnet downloads |
| `registration_open` | bool | Allow new user self-registration |
