# Transfer Bot

A simple, async Telegram bot built with [Pyrogram](https://docs.pyrogram.org/)

---

## Table of Contents

- [Overview](#overview)
- [Who Made This](#who-made-this)
- [Features](#features)
- [Architecture & How It Works](#architecture--how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Command Reference](#command-reference)
- [Access Control System](#access-control-system)
- [Transfer System Deep Dive](#transfer-system-deep-dive)
- [Shell System Deep Dive](#shell-system-deep-dive)
- [SourceForge Upload System](#sourceforge-upload-system)
- [Persistence & State](#persistence--state)
- [File Structure](#file-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Overview

This bot runs on a Linux server and gives you a Telegram interface to:

- **Upload** local files to Telegram or Gofile.io
- **Download** files from URLs or Telegram directly to the server
- **Transfer** files from URLs or Telegram through to Gofile.io or Telegram (download-then-upload pipeline)
- **Upload releases** to SourceForge FRS via SFTP
- **Run shell commands** with live, streaming output
- **Manage the filesystem** — list, move, copy, delete, find files
- **Monitor the system** — processes, memory, disk, network ports

All operations happen **asynchronously** — long-running tasks don't block the bot, multiple users can operate simultaneously, and you get live progress updates every 3 seconds for transfers and shell output.

---

## Features

### File Transfers
- Upload local server files to Telegram (up to 2 GB natively; auto-routes to Gofile.io for larger files)
- Download files from any HTTP/HTTPS URL to the server, with live progress
- Download Telegram media files (documents, videos, audio, photos) to disk
- Transfer pipeline: download from URL or Telegram → immediately re-upload to Telegram and/or Gofile.io
- Cancel any in-progress transfer at any time with `/cancel`

### Cloud Storage
- **Gofile.io** — anonymous file hosting with automatic server selection and fallback across multiple Gofile servers
- **SourceForge FRS** — authenticated SFTP upload to SourceForge File Release System, with live progress, interactive folder picker via inline keyboard, custom folder input, and hardcoded YAAP ROM project shortcut

### Shell Execution
- Run any shell command with **live streaming output** (updates every 3 seconds)
- Send stdin to running processes with `/stdin`
- Kill running commands with `/cancel` (SIGTERM → SIGKILL with grace period)
- ANSI escape code stripping for clean output
- 1-hour timeout guard on long-running commands
- Process group kill to ensure child processes don't linger

### Filesystem Management
- Full file browsing: `ls`, `cat`, `pwd`, `find`
- File operations: `mkdir`, `mv`, `cp`, `rm` (files and directories)
- Disk info: `df`, `du`
- Environment inspection: `env`
- Text search: `grep`
- File peeking: `head`, `tail`

### System Monitoring
- `ps` — top 30 processes by CPU
- `top` — CPU/memory snapshot
- `free` — memory and vmstat
- `uptime` — system uptime + logged-in users
- `whoami` — current user, groups, kernel info
- `netstat` — open ports via `ss`

### Startup Notification
When the bot starts, it sends `🟢 online` to every chat it has previously been active in, so you always know when it (re)starts.

---

## Architecture & How It Works

### Technology Stack

| Component | Library | Purpose |
|-----------|---------|---------|
| Telegram MTProto | `pyrogram` | Bot framework, message handling, file transfers |
| HTTP client | `httpx` | Async HTTP downloads, Gofile API |
| SSH/SFTP | `asyncssh` | SourceForge file uploads |
| Async runtime | `asyncio` | Concurrent operations, subprocess management |
| Config | `python-dotenv` | Environment variable loading |

### Async Event Loop

The bot runs entirely on Python's `asyncio` event loop. Every command handler is a coroutine (`async def`). Long operations like downloads, uploads, and shell commands are wrapped in `asyncio.Task` objects so they run concurrently without blocking the bot from responding to other messages.

```
Telegram MTProto ──► Pyrogram Client ──► Message Handlers
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                    Transfer Task       Shell Task          Filesystem Op
                    (asyncio.Task)   (subprocess+asyncio)   (sync, instant)
```

### Message Routing

Pyrogram uses a decorator-based filter system. Each command registers a handler function:

```python
@app.on_message(filters.command("dl"))
@require_allowed
async def cmd_download(client, msg): ...
```

Handlers are evaluated in registration order. The special `catch_sf_custom` handler sits last and catches plain-text messages (not starting with `/`) for the SourceForge custom folder input flow.

### Decorator Stack (Auth + Guards)

Three decorators wrap handlers to enforce access control and state checks:

- `@require_allowed` — silently ignores messages from users not in `SUPER_USERS` or `allowed_users`
- `@require_super` — silently ignores messages from non-superusers
- `@require_shell_free` — rejects command if the user already has an active shell running

These are stacked in order, innermost first (Python decorator evaluation order).

### Progress Updates

All long operations update a single status message in-place rather than sending new messages. A `ledge` (last-edit timestamp) prevents edits more often than every 3 seconds (`PROGRESS_INTERVAL`), respecting Telegram's rate limits. `safe_edit()` handles `MessageNotModified` (no-op) and `FloodWait` (sleep + retry) exceptions.

---

## Requirements

- Python 3.11+
- A Linux server (the bot runs shell commands via `asyncio.create_subprocess_shell`)
- A Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- Telegram API credentials (from [my.telegram.org](https://my.telegram.org))
- A SourceForge account with FRS access (for `/sf` commands)

### Python Dependencies

```
pyrogram
tgcrypto        # Pyrogram crypto acceleration (highly recommended)
httpx
asyncssh
python-dotenv
```

Install with:
```bash
pip install pyrogram tgcrypto httpx asyncssh python-dotenv
```

---

## Installation

### 1. Clone / copy the script

```bash
mkdir ~/tgbot && cd ~/tgbot
# place bot.py here
```

### 2. Create the `.env` file

```bash
cp .env.example .env
nano .env
```

### 3. Install dependencies

```bash
pip install pyrogram tgcrypto httpx asyncssh python-dotenv
```

### 4. Run the bot

```bash
python bot.py
```

On first run, Pyrogram will generate a `bot.session` file in the working directory. This file persists the MTProto session — keep it safe and do not share it.

### Running as a systemd service

```ini
[Unit]
Description=Transfer Bot
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/tgbot
ExecStart=/usr/bin/python bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now tgbot
```

---

## Configuration

All configuration is via environment variables, loaded from a `.env` file in the working directory.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `API_ID` | Telegram API ID from my.telegram.org | `12345678` |
| `API_HASH` | Telegram API hash from my.telegram.org | `abcdef1234567890abcdef` |
| `BOT_TOKEN` | Bot token from @BotFather | `123456:ABC-DEF1234ghIkl` |
| `SF_USER` | SourceForge username | `xenxynon` |
| `SF_PASS` | SourceForge password | `mypassword` |
| `SUPER_USERS` | Comma-separated Telegram user IDs with full admin access | `123456789,987654321` |

### Example `.env`

```env
API_ID=12345678
API_HASH=abcdef1234567890abcdef1234567890
BOT_TOKEN=123456789:AAFxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SF_USER=xenxynon
SF_PASS=mysupersecretpassword
SUPER_USERS=123456789
```

### Hardcoded Constants (edit in source)

| Constant | Default | Description |
|----------|---------|-------------|
| `SF_DEFAULT_PROJECT` | `bot-uploads` | Default SourceForge project for `/sf` |
| `SF_DEFAULT_FOLDER` | `workspace` | Default folder within that project |
| `SF_YAAP_PROJECT` | `xenxynon-roms` | Project used with `--yaap` flag |
| `SF_YAAP_FOLDER` | `yaap` | Folder used with `--yaap` flag |
| `SF_FOLDERS` | `[workspace, releases, test, misc]` | Inline keyboard folder choices for `/sf` |
| `TG_MAX_SIZE` | `2 GB` | Files over this size are routed to Gofile |
| `DL_CHUNK_SIZE` | `1 MB` | HTTP download chunk size |
| `PROGRESS_INTERVAL` | `3.0 s` | Minimum seconds between progress message edits |

---

## Command Reference

### Transfer Commands

#### `/ul` or `/upload <path>`
Upload a local file from the server to Telegram.

```
/ul /home/user/myfile.zip
/upload /tmp/build.log
```

- Shows live upload progress (speed, ETA, size)
- Files over 2 GB are automatically rerouted to Gofile.io

---

#### `/dl` or `/download <url> [name]`
Download a file from an HTTP/HTTPS URL to the current working directory. Can also be used as a reply to a Telegram media message to save it to disk.

```
/dl https://example.com/file.zip
/dl https://example.com/file.zip custom-name.zip

# Or reply to a Telegram file:
/dl  (as a reply to a document/video/audio)
```

- Shows live download progress (speed, ETA, percentage bar)
- Partial files are cleaned up on cancel or failure
- Torrent/magnet links are rejected

---

#### `/tr` or `/transfer <url|path> [name] [flags]`
The most powerful transfer command. Downloads from a URL or Telegram file, then immediately uploads to Telegram and/or Gofile.io. Also works with local file paths.

```
/tr https://example.com/rom.zip                # → Telegram
/tr https://example.com/rom.zip --gf           # → Gofile only
/tr https://example.com/rom.zip --both         # → Telegram + Gofile
/tr /local/file.zip                            # local file → Telegram
/tr https://example.com/file.zip myfile.zip    # custom name
```

**Flags:**
- _(no flag)_ — upload to Telegram
- `--gf` — upload to Gofile only
- `--both` — upload to both Telegram and Gofile

Works as a reply to Telegram media files too.

---

#### `/cancel`
Cancel any active transfer or shell command for your user.

```
/cancel
```

Sends SIGTERM (then SIGKILL after 0.5s) to shell processes. Sets a cancellation event for HTTP downloads. Removes the task from the active transfers registry.

---

### Cloud Commands

#### `/gf` or `/gofile <path>`
Upload a local file directly to Gofile.io and return the download link.

```
/gf /home/user/archive.tar.gz
```

- Automatically queries Gofile's API for the best available server
- Falls back to other servers if the first fails
- Returns a direct download page URL

---

#### `/sf <path> [folder] [--yaap]`
Upload a local file to SourceForge FRS via SFTP with real-time progress.

```
/sf /home/user/rom.zip                    # shows folder picker
/sf /home/user/rom.zip releases           # direct to bot-uploads/releases
/sf /home/user/rom.zip --yaap            # direct to xenxynon-roms/yaap
```

**Behavior:**
- With no folder argument → shows an inline keyboard with folder choices: `workspace`, `releases`, `test`, `misc`, and `custom…`
- `custom…` button → prompts you to type a folder name in chat
- With `--yaap` flag → skips picker, uploads directly to `xenxynon-roms/yaap`
- With explicit folder → uploads directly to `bot-uploads/<folder>`

The SourceForge picker session expires after **5 minutes** of inactivity.

---

### Shell Commands

#### `/sh <command>`
Run any shell command on the server with live streaming output.

```
/sh ls -la /builds
/sh df -h
/sh make -j$(nproc) 2>&1
/sh find / -name "*.zip" -newer /tmp/ref
```

- Output streams to the Telegram message, updating every 3 seconds
- ANSI escape codes (colors) are stripped for clean display
- Maximum runtime: 1 hour (then killed automatically)
- Shows exit code or "done" on completion

---

#### `/stdin <text>`
Send input to the currently running shell process's stdin.

```
/stdin yes
/stdin mypassword
```

---

#### `/ps`
Show top 30 processes sorted by CPU usage (`ps aux --sort=-%cpu | head -30`).

#### `/top`
CPU and memory snapshot (`top -bn1 | head -40`).

#### `/free`
Memory usage and vmstat summary.

#### `/uptime`
System uptime and currently logged-in users.

#### `/whoami`
Current user, groups, and kernel/OS info.

#### `/netstat`
Open TCP/UDP ports (`ss -tulnp`).

---

#### `/tail <file> [n]`
Show the last N lines of a file (default: 50).

```
/tail /var/log/syslog
/tail /var/log/nginx/access.log 100
```

#### `/head <file> [n]`
Show the first N lines of a file (default: 20).

```
/head /etc/fstab
/head /proc/cpuinfo 30
```

#### `/grep <pattern> <file>`
Search for a pattern in a file with line numbers.

```
/grep "ERROR" /var/log/app.log
/grep "build" /home/user/Makefile
```

---

### Filesystem Commands

#### `/ls [path]`
List directory contents with permissions, size, and modification time.

```
/ls
/ls /home/user/builds
```

Output format: `rwxrwxrwx  size  date  name`
Directories show `/` suffix, symlinks show `@` suffix.

---

#### `/cat <file>`
Print the contents of a file (up to ~8 KB). Handles both UTF-8 and Latin-1 encoded files.

```
/cat /etc/hosts
/cat /home/user/.env
```

---

#### `/pwd`
Print the current working directory (where the bot process is running).

#### `/echo <text>`
Echo text back. Useful for testing.

#### `/mkdir <path>`
Create a directory (and all intermediate directories).

```
/mkdir /home/user/builds/test-branch
```

#### `/mv <src> <dst>`
Move or rename a file or directory.

```
/mv /tmp/rom.zip /home/user/releases/rom.zip
```

#### `/cp <src> <dst>`
Copy a file, preserving metadata.

#### `/rm <path>`
Delete a file or directory (recursive for directories, safe symlink handling).

```
/rm /tmp/old-build.zip
/rm /home/user/old-branch/
```

#### `/find <path> [glob]`
Find files matching a glob pattern (results capped at 100).

```
/find /home/user *.zip
/find /tmp *.log
```

#### `/df`
Show disk usage for `/` with a visual progress bar.

#### `/du <path>`
Show total disk usage of a path (recursive).

```
/du /home/user/builds
```

#### `/env`
Print all environment variables (truncated at 4000 characters).

---

### Info & Auth Commands

#### `/ping`
Check bot responsiveness. Returns round-trip time in milliseconds.

#### `/status`
Show your currently active transfer and/or shell command with elapsed time and recent output.

#### `/help` or `/start`
Show the full command reference.

#### `/allow <user_id>` _(superusers only)_
Grant a Telegram user access to the bot.

```
/allow 123456789
```

#### `/revoke <user_id>` _(superusers only)_
Remove a user's access.

```
/revoke 123456789
```

#### `/users` _(superusers only)_
List all non-superuser allowed users.

---

## Access Control System

The bot has a two-tier access system:

### Superusers
Defined in the `SUPER_USERS` environment variable as a comma-separated list of Telegram user IDs. Superusers have access to everything, including `/allow`, `/revoke`, and `/users`. They are never stored in files and cannot be removed at runtime.

### Allowed Users
Stored in `allowed_users.json` and managed at runtime via `/allow` and `/revoke`. Allowed users have access to all commands except auth management.

### How Access Is Enforced
The `@require_allowed` and `@require_super` decorators silently drop messages from unauthorized users — no error message is sent. This prevents information leakage about the bot's existence.

The bot also tracks any chat where an allowed user has interacted (`known_chats.json`) for the startup notification feature.

---

## Transfer System Deep Dive

### Active Transfer Tracking
Each user can only have **one active transfer at a time**. Attempting to start a second shows a "busy" message with the current operation name. The `active_transfers` dict maps `user_id → transfer_info`.

### Transfer Info Dict
```python
{
    "type": "download" | "upload",
    "name": "filename.zip",
    "start_time": 1700000000.0,
    "cancel_event": asyncio.Event,  # HTTP downloads only
    "task": asyncio.Task,
}
```

### Cancellation Flow
1. `/cancel` pops the entry from `active_transfers`
2. Sets the `cancel_event` (signals the download loop to stop)
3. Cancels the asyncio Task
4. Partial downloaded files are deleted via the cleanup callback

### Progress Display
```
`filename.zip`
`[########------------] 42.0%`

size:    420.0 MB / 1.0 GB
speed:   35.0 MB/s
eta:     17s
elapsed: 12s
```

### 2 GB Routing
Telegram's Bot API limit is 2 GB per file. Files exceeding `TG_MAX_SIZE` during a Telegram upload are automatically rerouted to Gofile.io, and the final message includes the Gofile download link instead.

---

## Shell System Deep Dive

### Process Management
Shell commands are launched with `asyncio.create_subprocess_shell()` in a new process group (`start_new_session=True`). This allows killing the entire process tree (not just the shell) via `os.killpg()`.

### Output Streaming
A `read_output()` coroutine reads stdout line-by-line from the subprocess. Each line is:
1. Decoded (with error replacement for non-UTF-8 output)
2. ANSI-stripped via regex
3. Truncated to 300 characters
4. Appended to a rolling 200-line buffer

Every 3 seconds, the last 40 lines of the buffer are edited into the status message (capped at 3500 characters to fit Telegram's message limit).

### Kill Sequence
When `/cancel` is issued or a timeout occurs:
1. SIGTERM sent to the process group
2. 0.5 second grace period
3. SIGKILL sent if still alive

### Active Shell Dict
```python
{
    "proc": asyncio.Process,
    "pid": 12345,
    "pgid": 12345,
    "cmd": "make -j8",
    "start_time": 1700000000.0,
    "lines": ["line1", "line2", ...],
    "ledge": [1700000012.0],
}
```

---

## SourceForge Upload System

### SFTP Upload
Uses `asyncssh` to connect to `frs.sourceforge.net` with username/password authentication. The remote path format is:

```
/home/frs/project/<project>/<folder>/<filename>
```

### Progress Callbacks
The SFTP `put()` call uses `asyncssh`'s `progress_handler` parameter to receive byte-count updates, which are formatted into the standard progress display and edited into the status message every 3 seconds.

### Interactive Folder Picker
When `/sf <path>` is called without a folder:
1. An inline keyboard is shown with preset folders + "custom…"
2. Button press → `cb_sf` callback fires via `@app.on_callback_query`
3. "custom…" → bot edits the message to prompt for folder name, sets `awaiting_custom = True`
4. User's next plain-text message → caught by `catch_sf_custom` handler → triggers upload

Sessions expire after 5 minutes. Expired sessions are detected on interaction and cleaned up.

---

## Persistence & State

### `PersistentSet`
A custom `set[int]` class that auto-saves to a JSON file on every mutation. Used for both `allowed_users` and `known_chats`. Reads on startup, writes on `.add()` and `.discard()`. Failures are logged but do not crash the bot.

### Files Created at Runtime

| File | Contents | Purpose |
|------|----------|---------|
| `bot.session` | Pyrogram MTProto session | Telegram authentication |
| `allowed_users.json` | `[123456, 789012]` | Persisted allowed user IDs |
| `known_chats.json` | `[-100123456, 789012]` | Chats for startup notification |

### In-Memory State

| Variable | Type | Description |
|----------|------|-------------|
| `active_transfers` | `dict[int, dict]` | One entry per user with active transfer |
| `active_shells` | `dict[int, dict]` | One entry per user with active shell |
| `pending_sf` | `dict[int, dict]` | SourceForge picker sessions awaiting folder choice |

All in-memory state is lost on bot restart. This is intentional — restarts cleanly reset all locks and pending operations.

---

## File Structure

```
tgbot/
├── bot.py               # The entire bot (single-file)
├── .env                 # Environment variables (never commit this)
├── .env.example         # Template
├── bot.session          # Pyrogram session file (auto-generated)
├── allowed_users.json   # Persisted allowed user list (auto-generated)
└── known_chats.json     # Persisted chat list (auto-generated)
```

---

## Security Considerations

> ⚠️ **This bot runs shell commands as the user it's launched under.** Treat access like SSH access to the server.

- **Keep `SUPER_USERS` to a minimum** — they have unrestricted shell access
- **Keep the `.env` file private** — it contains your SourceForge password and Telegram credentials
- **Keep `bot.session` private** — it authenticates to Telegram as your bot
- **Run the bot as a non-root user** — limit blast radius of shell access
- **Consider sandboxing** — run in a container or with `systemd` resource limits if untrusted users are allowed
- Unauthorized users get **no response at all** — the bot silently drops their messages, so they can't probe for information
- The bot does **not validate file paths** in filesystem commands — allowed users can read/write anywhere the bot process can reach

---

## Troubleshooting

### Bot doesn't respond
- Check the bot token is correct and the bot isn't blocked
- Make sure your Telegram user ID is in `SUPER_USERS`
- Check logs: `journalctl -u tgbot -f`

### `FloodWait` errors in logs
Normal — the bot automatically sleeps and retries. If frequent, increase `PROGRESS_INTERVAL`.

### SourceForge upload fails with auth error
- Verify `SF_USER` and `SF_PASS` in `.env`
- Ensure the SourceForge user has FRS write access to the project
- SourceForge may require you to have uploaded at least once via the web UI first

### Shell commands produce no output
Some commands buffer stdout when not connected to a TTY. Try:
```
/sh stdbuf -oL your-command
/sh script -q -c "your-command" /dev/null
```

### Files appear corrupted after download
Check available disk space with `/df`. Downloads write to the bot's working directory.

### Bot doesn't start, `KeyError` on environment variable
All 6 required environment variables must be set. Check your `.env` file exists in the working directory and is correctly formatted.

### Session file errors
Delete `bot.session` and restart — Pyrogram will re-authenticate.

---

## License

Private/personal use. Not published for distribution.
