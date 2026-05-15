# fileserv

A minimal self-hosted file server with a web UI.

## Features

- Browse, download, copy share links
- Upload via drag & drop (admin only)
- Torrent / magnet download support — via magnet link, `.torrent` URL, or `.torrent` file upload (admin toggle)
- Rename and delete files (role-based)
- Directory navigation
- Filter by category (archives, images, video, audio, docs), sort by name / size / date / type
- Dark mode (auto-detected, toggleable)
- Responsive — works on mobile

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

## Roles

| Role | Browse | Download | Upload | Delete | Rename | Admin panel |
|------|--------|----------|--------|--------|--------|-------------|
| User | ✓ | ✓ | — | — | — | — |
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

> There is no separate "Guest" role. Everyone who logs in with `WEB_PASS` is a standard user. Logging in with `WEB_ADMIN_PASS` grants admin privileges.

## Deployment

Behind a reverse proxy (nginx/caddy) with HTTPS is recommended. The app itself has no TLS support.
