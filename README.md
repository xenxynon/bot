# Transfer Bot

A simple, async Telegram bot built with [Pyrogram](https://docs.pyrogram.org/)

## Purpose

Just an alternative to mirror bot with less bells and whistles

## Features

- **Shell** — run commands with live streaming output, stdin injection, process cancellation
- **Transfers** — download from URLs or Telegram media, upload to Telegram / Gofile / SourceForge
- **Filesystem** — ls, cat, cp, mv, rm, find, df, du, env, and more via bot commands
- **Auth** — superuser + allowlist model persisted to JSON

## Requirements

```
python >= 3.11
pyrogram
tgcrypto
asyncssh
httpx
python-dotenv
```

Install:

```bash
pip install pyrogram tgcrypto asyncssh httpx python-dotenv
```

## Configuration

Create a `.env` file:

```env
API_ID=12345678
API_HASH=your_api_hash
BOT_TOKEN=your_bot_token
SF_USER=your_sourceforge_username
SF_PASS=your_sourceforge_password
SUPER_USERS=123456789,987654321
```

`SUPER_USERS` is a comma-separated list of Telegram user IDs with full access.

## Usage

```bash
python bot.py
```

Session file `bot.session` is created on first run.

## Commands

### Transfers

| Command | Description |
|---|---|
| `/ul <path>` | Upload local file to Telegram |
| `/dl <url\|reply> [name]` | Download URL or Telegram file to disk |
| `/tr <url\|path\|reply> [name] [flags]` | Download then upload. `--gf` for Gofile only, `--both` for both |
| `/cancel` | Cancel active transfer or shell |

### Cloud

| Command | Description |
|---|---|
| `/gf <path>` | Upload to Gofile.io |
| `/sf <path> [folder] [--yaap]` | Upload to SourceForge. Default: `bot-uploads/workspace`. `--yaap` targets `xenxynon-roms/yaap` |

### Shell

| Command | Description |
|---|---|
| `/sh <command>` | Run shell command with live output |
| `/stdin <text>` | Send text to running shell's stdin |
| `/ps` | Process list |
| `/top` | CPU/mem snapshot |
| `/free` | Memory usage |
| `/uptime` | System uptime |
| `/whoami` | Current user and groups |
| `/netstat` | Open ports |
| `/tail <file> [n]` | Last N lines (default 50) |
| `/head <file> [n]` | First N lines (default 20) |
| `/grep <pattern> <file>` | Search in file |

### Filesystem

| Command | Description |
|---|---|
| `/ls [path]` | List directory |
| `/cat <file>` | Print file contents (first 8 KB) |
| `/pwd` | Current directory |
| `/echo <text>` | Echo text |
| `/mkdir <path>` | Create directory |
| `/mv <src> <dst>` | Move/rename |
| `/cp <src> <dst>` | Copy file |
| `/rm <path>` | Delete file or directory |
| `/find <path> [glob]` | Find files by glob pattern |
| `/df` | Disk usage for `/` |
| `/du <path>` | Directory size |
| `/env` | Print environment variables |

### Info

| Command | Description |
|---|---|
| `/ping` | Latency check |
| `/status` | Active transfers and shell status |
| `/help` | Command reference |

### Auth _(superusers only)_

| Command | Description |
|---|---|
| `/allow <id>` | Grant access to a user |
| `/revoke <id>` | Remove access from a user |
| `/users` | List allowed users |

## Notes

- Files over 2 GB are automatically routed to Gofile when uploading to Telegram.
- Shell processes run in a new session (`start_new_session=True`). `/cancel` sends `SIGTERM` → `SIGKILL` to the entire process group.
- Shell timeout is 3600 seconds.
- SourceForge folder picker supports inline keyboard or a custom folder name sent as a plain message (5-minute session TTL).
- Allowed users and known chats persist across restarts in `allowed_users.json` and `known_chats.json`.
- On startup the bot sends 🟢 online to all known chats.

## Project Structure

```
bot.py               # single-file bot
allowed_users.json   # persisted allowlist (auto-created)
known_chats.json     # persisted chat list (auto-created)
bot.session          # Pyrogram session (auto-created)
.env                 # credentials
```
