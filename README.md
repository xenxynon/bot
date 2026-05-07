# Telegram Transfer Bot

Async Telegram utility bot for remote file transfers, uploads, shell access, and filesystem management.

## Features

- Telegram file uploads/downloads
- URL ↔ Telegram transfer pipeline
- Gofile uploads
- SourceForge uploads via SFTP
- Remote shell execution
- Interactive stdin support
- File management commands
- Live progress bars with speed + ETA
- Transfer cancellation
- User authorization system
- Secret/env protection
- Torrent is currenly blocked

---

## Installation

### Requirements

- Python 3.10+

### Install dependencies

```bash
pip install -U pyrogram tgcrypto asyncssh httpx python-dotenv
```

### Configure `.env`

```env
API_ID=
API_HASH=
BOT_TOKEN=

SF_USER=
SF_PASS=

SUPER_USERS=123456789
```

### Run

```bash
python bot.py
```

---

## Commands

### Transfers

```text
/ul <file>                 Upload file to Telegram
/dl <url>                  Download file
/tr <url|file>             Download + upload
/gf <file>                 Upload to Gofile
/sf <file> [folder]        Upload to SourceForge
```

### Shell

```text
/sh <cmd>                  Run shell command
/stdin <text>              Send stdin to shell
/cancel                    Cancel active task
/status                    Show current task
```

### System

```text
/ps
/top
/free
/uptime
/whoami
/netstat
```

### Filesystem

```text
/ls [path]
/cat <file>
/rm <path>
/mv <src> <dst>
/cp <src> <dst>
```

### Auth

```text
/allow <id>
/revoke <id>
```

---

## Notes

- Files larger than 2GB automatically use Gofile
- Only HTTP/HTTPS downloads are allowed
- Magnet/torrent links are blocked
- Shell processes run in isolated process groups
- Authorized users stored in `allowed_users.json`

---

## Warning

This bot provides remote shell and filesystem access.

Run only on trusted systems.
