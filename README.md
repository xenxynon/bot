# fileserv

A minimal self-hosted file server with a web UI.

## Features

- Browse, download, copy share links
- Upload via drag & drop (if enabled)
- Torrent / magnet download support (admin toggle)
- Rename and delete files (role-based)
- Directory navigation
- Filter by extension, sort by name / size / date / type
- Dark mode (auto-detected, toggleable)
- Responsive — works on mobile

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # then edit .env
python web.py
```

## `.env` options

| Key | Description |
|-----|-------------|
| `PASSWORD` | Access password |
| `ADMIN_PASSWORD` | Admin password (rename, delete, torrent toggle) |
| `DOWNLOADS_DIR` | Directory to serve (default: `./downloads`) |
| `PORT` | HTTP port (default: `8080`) |
| `SECRET_KEY` | Flask session secret |
| `CAN_DELETE` | Allow standard users to delete (`true`/`false`) |
| `CAN_WRITE` | Allow standard users to upload (`true`/`false`) |

## Roles

| Role | Browse | Download | Upload | Delete | Rename | Admin panel |
|------|--------|----------|--------|--------|--------|-------------|
| Guest | ✓ | ✓ | — | — | — | — |
| User | ✓ | ✓ | if `CAN_WRITE` | if `CAN_DELETE` | — | — |
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

## Deployment

Behind a reverse proxy (nginx/caddy) with HTTPS is recommended. The app itself has no TLS support.
