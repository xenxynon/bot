# fileserv

A self-hosted file server with a web UI and optional Telegram bot.

---

## Setup

**Requirements:** Python 3.10+, `aiohttp`, `python-dotenv`

```bash
pip install aiohttp python-dotenv
```

Optional (torrent support):
```bash
apt install aria2
```

---

## Configuration

Create a `.env` file:

```env
WEB_PORT=8080
WEB_ADMIN_PASS=changeme

# Path to store uploaded files (default: ./downloads)
DOWNLOADS_DIR=/path/to/downloads

# Optional
MAX_UPLOAD_MB=2048
MAX_FETCH_MB=4096
QUOTA_MB=0                  # 0 = unlimited per user
MAX_SESSIONS_PER_USER=10
COOKIE_SECURE=false         # set true behind HTTPS
LINK_SECRET=                # auto-generated if blank

# Telegram bot (optional)
API_ID=
API_HASH=
BOT_TOKEN=
SUPER_USERS=123456789,987654321   # comma-separated Telegram user IDs
WEB_BASE=https://files.example.com  # used to generate download links in bot replies

# Webhook (optional)
# Set via admin UI or flags API
```

---

## Run

**Requirements (bot only):** `pyrogram`, `httpx`, `asyncssh`

```bash
pip install pyrogram httpx asyncssh
```

```bash
# Web server only
python web.py

# Web + Telegram bot together
python bot.py
```

`bot.py` starts the web server internally, so you only need to run one process.

---

## Usage

Open `http://localhost:8080` in your browser.

### File operations

All actions are accessible by **clicking a file** (preview) or the **⋯ menu** on any row:

| Action | How |
|---|---|
| Preview | Click file row |
| Download | ⋯ → Download |
| Rename | ⋯ → Rename |
| Move / Copy | ⋯ → Move / Copy to… |
| Share link | ⋯ → Create share link |
| Edit text | ⋯ → Edit (text files only) |
| Delete | ⋯ → Delete |

Right-click any row for the same context menu.

### Upload / Fetch / Torrent

Open the **☰ panel** (top right) to:
- Drag-and-drop or browse to upload files
- Fetch a file from a URL (runs in background)
- Start a torrent/magnet link (admin only, requires aria2)

### Share links

Share links can be:
- Time-limited (hours)
- Password-protected
- Download-count-limited

Created via ⋯ → Create share link. Accessible at `/s/<token>` without login.

---

## API

All endpoints accept `Authorization: Bearer <key>` or `?api_key=<key>`.

Generate a key at ⋯ → Account → (coming) or via:

```bash
curl -s -b 'fsid=<session>' http://localhost:8080/apikeys \
  -X POST -H 'Content-Type: application/json' \
  -d '{"label":"my-script"}'
```

| Method | Path | Description |
|---|---|---|
| GET | `/files?path=` | List directory |
| POST | `/upload?path=` | Upload file (multipart) |
| DELETE | `/files/<path>` | Delete file or folder |
| POST | `/rename` | `{old, new}` |
| POST | `/mkdir` | `{path, name}` |
| POST | `/move` | `{src, dst_dir, copy?}` |
| POST | `/bulk` | `{action, files, …}` — delete/move/zip |
| GET | `/search?q=&path=&type=` | Search files |
| GET | `/dl/<path>` | Download |
| GET | `/preview/<path>` | Inline preview |
| POST | `/fetch` | `{url}` — background URL fetch |
| GET | `/fetch/progress` | Fetch job status |
| POST | `/share` | `{rel, ttl_hours, password?, max_hits?}` |
| GET | `/s/<token>` | Public share download |
| GET | `/edit/<path>` | Read text file |
| PUT | `/edit/<path>` | `{content}` — save text file |
| GET | `/zip?path=` | Download folder as ZIP |
| GET | `/zip-inspect?path=` | List ZIP contents |
| POST | `/flags` | Admin: set server flags |
| GET | `/admin/stats` | Admin: disk/file/user stats |
| GET | `/admin/audit?n=200` | Admin: last N audit events |
| PATCH | `/admin/users/<u>` | Admin: `{password?, disabled?, role?}` |

---

## Admin flags

Set via `POST /flags` with JSON body:

| Flag | Default | Description |
|---|---|---|
| `torrent_enabled` | `false` | Enable torrent downloads |
| `registration_open` | `true` | Allow new user sign-ups |
| `webhook_url` | `""` | POST events to this URL |
| `webhook_events` | `["upload","delete","fetch_done"]` | Events to fire |

---

## Security notes

- Executable file types are blocked from upload (`.exe`, `.sh`, `.bat`, etc.)
- Path traversal is prevented on all endpoints
- Passwords are hashed with SHA-256 + random salt
- Sessions are server-side with configurable TTL (24h default)
- Rate limiting: 30 requests/60s per IP on login/register
- URL fetch blocks private/loopback IP addresses
- Audit log written to `audit.log`
