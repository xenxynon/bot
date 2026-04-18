import asyncio
import fnmatch
import json
import os
import re
import shutil
import signal
import stat
import time
from datetime import datetime

import asyncssh
import httpx
from dotenv import load_dotenv
from pyrogram import Client, filters, idle
from pyrogram.errors import FloodWait, MessageNotModified
from pyrogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

# ── Config ─────────────────────────────────────────────────────────────────────

load_dotenv()

API_ID      = int(os.environ["API_ID"])
API_HASH    = os.environ["API_HASH"]
BOT_TOKEN   = os.environ["BOT_TOKEN"]
SF_USER     = os.environ["SF_USER"]
SF_PASS     = os.environ["SF_PASS"]
SUPER_USERS = set(int(x) for x in os.environ["SUPER_USERS"].split(","))

SF_DEFAULT_PROJECT = "bot-uploads"
SF_DEFAULT_FOLDER  = "workspace"
SF_YAAP_PROJECT    = "xenxynon-roms"
SF_YAAP_FOLDER     = "yaap"
SF_FOLDERS         = ["workspace", "releases", "test", "misc"]

TG_MAX_SIZE      = 2 * 1024 ** 3  # 2 GB
ALLOWED_FILE     = "allowed_users.json"
KNOWN_CHATS_FILE = "known_chats.json"

ANSI_RE    = re.compile(r"\x1b\[[0-9;]*[mKHJA-Za-z]")
TORRENT_RE = re.compile(r"^magnet:|\.torrent(\?|$)", re.I)

# ── Persistence ────────────────────────────────────────────────────────────────

def _load_int_set(path: str) -> set[int]:
    try:
        with open(path) as f:
            return set(int(x) for x in json.load(f))
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return set()

def _save_int_set(path: str, s: set[int]) -> None:
    try:
        with open(path, "w") as f:
            json.dump(sorted(s), f, indent=2)
    except Exception:
        pass

# ── State ──────────────────────────────────────────────────────────────────────

app = Client("bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

allowed_users:    set[int]        = _load_int_set(ALLOWED_FILE)
known_chats:      set[int]        = _load_int_set(KNOWN_CHATS_FILE)
active_transfers: dict[int, dict] = {}
active_shells:    dict[int, dict] = {}
pending_sf:       dict[int, dict] = {}

def save_allowed() -> None:
    _save_int_set(ALLOWED_FILE, allowed_users)

def track_chat(chat_id: int) -> None:
    """Persist this chat so we can notify it on restart."""
    if chat_id not in known_chats:
        known_chats.add(chat_id)
        _save_int_set(KNOWN_CHATS_FILE, known_chats)

# ── Utilities ──────────────────────────────────────────────────────────────────

def is_allowed(uid: int) -> bool:
    return uid in SUPER_USERS or uid in allowed_users

def is_super(uid: int) -> bool:
    return uid in SUPER_USERS

def get_args(msg: Message, n: int = 1) -> list[str]:
    parts = msg.text.split(maxsplit=n)
    return parts[1:] if len(parts) > 1 else []

def parse_flags(args: list[str]) -> tuple[list[str], set[str]]:
    pos   = [a for a in args if not a.startswith("--")]
    flags = {a.lstrip("-").lower() for a in args if a.startswith("--")}
    return pos, flags

def is_torrent(url: str) -> bool:
    return bool(TORRENT_RE.search(url))

def fmt_size(b: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def fmt_time(s: float) -> str:
    if s < 0 or s > 86400:
        return "--:--"
    m, s = divmod(int(s), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"

def pbar(pct: float, width: int = 20) -> str:
    filled = int(width * pct / 100)
    return f"[{'#' * filled}{'-' * (width - filled)}] {pct:.1f}%"

def fmt_mode(m: int) -> str:
    result = ""
    for who in range(2, -1, -1):
        bits = (m >> (who * 3)) & 7
        result += "r" if bits & 4 else "-"
        result += "w" if bits & 2 else "-"
        result += "x" if bits & 1 else "-"
    return result

async def safe_edit(msg: Message, text: str) -> None:
    try:
        await msg.edit(text)
    except MessageNotModified:
        pass
    except FloodWait as e:
        await asyncio.sleep(e.value)
        try:
            await msg.edit(text)
        except Exception:
            pass
    except Exception:
        pass

def kill_proc(info: dict) -> None:
    for fn, key in ((os.killpg, "pgid"), (os.kill, "pid")):
        target = info.get(key)
        if target:
            try:
                fn(target, signal.SIGKILL)
                return
            except Exception:
                pass
    proc = info.get("proc")
    if proc:
        try:
            proc.kill()
        except Exception:
            pass

# ── Chat tracker (runs alongside all other handlers) ──────────────────────────

@app.on_message(filters.all, group=1)
async def _track_chats(_, msg: Message):
    if msg.from_user and is_allowed(msg.from_user.id):
        track_chat(msg.chat.id)

# ── Progress ───────────────────────────────────────────────────────────────────

def make_progress(label: str, status: Message, t0: float, ledge: list):
    async def cb(current: int, total: int) -> None:
        now = time.time()
        if now - ledge[0] < 3:
            return
        ledge[0] = now
        elapsed = now - t0
        speed   = current / elapsed if elapsed > 0 else 0
        eta     = (total - current) / speed if speed > 0 and total > current else -1
        pct     = current * 100 / total if total > 0 else 0
        await safe_edit(
            status,
            f"`{label}`\n`{pbar(pct)}`\n\n"
            f"size:    {fmt_size(current)} / {fmt_size(total)}\n"
            f"speed:   {fmt_size(speed)}/s\n"
            f"eta:     {fmt_time(eta)}\n"
            f"elapsed: {fmt_time(elapsed)}",
        )
    return cb

# ── Gofile ─────────────────────────────────────────────────────────────────────

async def gofile_upload(path: str, status: Message) -> str:
    name = os.path.basename(path)
    await safe_edit(status, "fetching gofile server…")
    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get("https://api.gofile.io/servers")
        r.raise_for_status()
        server = r.json()["data"]["servers"][0]["name"]
    await safe_edit(status, f"uploading `{name}` to gofile [{server}]…")
    async with httpx.AsyncClient(timeout=None) as http:
        with open(path, "rb") as f:
            r = await http.post(
                f"https://{server}.gofile.io/contents/uploadfile",
                files={"file": (name, f)},
            )
        r.raise_for_status()
        data = r.json()
    if data.get("status") != "ok":
        raise RuntimeError(str(data))
    return data["data"]["downloadPage"]

# ── TG upload ─────────────────────────────────────────────────────────────────

async def tg_upload(client: Client, msg: Message, path: str, status: Message) -> None:
    name  = os.path.basename(path)
    size  = os.path.getsize(path)
    t0    = time.time()
    ledge = [0.0]

    if size > TG_MAX_SIZE:
        await safe_edit(status, f"`{name}` is {fmt_size(size)}, over 2 GB — routing to gofile…")
        link    = await gofile_upload(path, status)
        elapsed = time.time() - t0
        await safe_edit(status, f"gofile done (>2 GB)\nfile: `{name}`\nsize: {fmt_size(size)}\nlink: {link}\ntime: {fmt_time(elapsed)}")
        return

    prog = make_progress(f"uploading {name}", status, t0, ledge)
    await client.send_document(msg.chat.id, path, caption=f"`{name}` — {fmt_size(size)}", progress=prog)
    elapsed = time.time() - t0
    await safe_edit(status, f"upload done\nfile: `{name}`\nsize: {fmt_size(size)}\ntime: {fmt_time(elapsed)}")

# ── HTTP download ──────────────────────────────────────────────────────────────

async def http_download(url: str, dest: str, name: str, status: Message, cancel_ev: asyncio.Event, t0: float) -> int:
    ledge = [0.0]
    async with httpx.AsyncClient(follow_redirects=True, timeout=None) as http:
        async with http.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            done  = 0
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(512 * 1024):
                    if cancel_ev.is_set():
                        raise asyncio.CancelledError
                    f.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - ledge[0] >= 3:
                        ledge[0] = now
                        elapsed = now - t0
                        speed   = done / elapsed if elapsed > 0 else 0
                        eta     = (total - done) / speed if speed > 0 and total > 0 else -1
                        pct     = done * 100 / total if total > 0 else 0
                        szstr   = f"{fmt_size(done)} / {fmt_size(total)}" if total else fmt_size(done)
                        await safe_edit(
                            status,
                            f"`{name}`\n`{pbar(pct)}`\n\n"
                            f"size:    {szstr}\n"
                            f"speed:   {fmt_size(speed)}/s\n"
                            f"eta:     {fmt_time(eta)}\n"
                            f"elapsed: {fmt_time(elapsed)}",
                        )
    return os.path.getsize(dest)

# ── SF upload ──────────────────────────────────────────────────────────────────

async def sf_upload(status: Message, path: str, project: str, folder: str) -> str:
    name   = os.path.basename(path)
    remote = f"/home/frs/project/{project}/{folder}/{name}"
    await safe_edit(status, f"uploading `{name}` to sourceforge [{project}/{folder}]…")
    async with asyncssh.connect("frs.sourceforge.net", username=SF_USER, password=SF_PASS, known_hosts=None) as conn:
        async with conn.start_sftp_client() as sftp:
            await sftp.put(path, remote, block_size=32768)
    return f"https://sourceforge.net/projects/{project}/files/{folder}/{name}"

# ── Auth ───────────────────────────────────────────────────────────────────────

@app.on_message(filters.command("allow"))
async def cmd_allow(_, msg: Message):
    if not is_super(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/allow <user_id>`", quote=True)
        return
    try:
        uid = int(a[0])
        allowed_users.add(uid)
        save_allowed()
        await msg.reply(f"✅ allowed `{uid}`", quote=True)
    except ValueError:
        await msg.reply("invalid user id", quote=True)


@app.on_message(filters.command("revoke"))
async def cmd_revoke(_, msg: Message):
    if not is_super(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/revoke <user_id>`", quote=True)
        return
    try:
        uid = int(a[0])
        allowed_users.discard(uid)
        save_allowed()
        await msg.reply(f"✅ revoked `{uid}`", quote=True)
    except ValueError:
        await msg.reply("invalid user id", quote=True)


@app.on_message(filters.command("users"))
async def cmd_users(_, msg: Message):
    if not is_super(msg.from_user.id):
        return
    if not allowed_users:
        await msg.reply("no extra allowed users", quote=True)
        return
    lines = [f"  `{u}`" for u in sorted(allowed_users)]
    await msg.reply("**allowed users:**\n" + "\n".join(lines), quote=True)

# ── Help / ping / status / cancel ─────────────────────────────────────────────

HELP = """\
**commands**

**transfers**
`/ul /upload <path>` — upload file to telegram
`/dl /download <url|reply> [name]` — download to current dir
`/tr /transfer <url|path|reply> [name] [flags]` — download then upload
  `--gf` — gofile only  |  `--both` — telegram + gofile
`/cancel` — cancel active transfer or shell

**cloud**
`/gf /gofile <path>` — upload to gofile
`/sf <path> [folder] [--yaap]` — upload to sourceforge
  default: bot-uploads/workspace  |  `--yaap`: xenxynon-roms/yaap

**shell**
`/sh <command>` — run command with live output
`/ps` — process list  |  `/top` — cpu/mem snapshot
`/free` — memory  |  `/uptime` — system uptime
`/whoami` — user + groups  |  `/netstat` — open ports
`/tail <file> [n]` — last N lines  |  `/head <file> [n]` — first N lines
`/grep <pattern> <file>` — search in file

**filesystem**
`/ls [path]`  `/cat <file>`  `/pwd`  `/echo <text>`
`/mkdir <path>`  `/mv <src> <dst>`  `/cp <src> <dst>`  `/rm <path>`
`/find <path> [glob]`  `/df`  `/du <path>`  `/env`

**info**
`/ping`  `/status`  `/help`

**auth** _(superusers only)_
`/allow <id>`  `/revoke <id>`  `/users`\
"""


@app.on_message(filters.command(["start", "help"]))
async def cmd_help(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    await msg.reply(HELP, quote=True)


@app.on_message(filters.command("ping"))
async def cmd_ping(_, msg: Message):
    t0    = time.time()
    reply = await msg.reply("…", quote=True)
    ms    = (time.time() - t0) * 1000
    await reply.edit(f"pong — `{ms:.0f}ms`")


@app.on_message(filters.command("status"))
async def cmd_status(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid   = msg.from_user.id
    parts = []

    if uid in active_transfers:
        t       = active_transfers[uid]
        elapsed = time.time() - t["start_time"]
        parts.append(f"**transfer:** `{t['name']}` ({t['type']}) — {fmt_time(elapsed)} elapsed")

    if uid in active_shells:
        s       = active_shells[uid]
        elapsed = time.time() - s["start_time"]
        tail    = "\n".join(s["lines"][-5:]) or "(no output)"
        if len(tail) > 1500:
            tail = tail[-1500:]
        parts.append(f"**shell:** `{s['cmd']}` (pid {s.get('pid', '?')}) — {fmt_time(elapsed)} elapsed\n```\n{tail}\n```")

    await msg.reply("\n\n".join(parts) if parts else "no active tasks", quote=True)


@app.on_message(filters.command("cancel"))
async def cmd_cancel(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid      = msg.from_user.id
    canceled = []

    if uid in active_transfers:
        # Pop immediately so new tasks can start right away
        t  = active_transfers.pop(uid)
        ce = t.get("cancel_event")
        tk = t.get("task")
        if ce:
            ce.set()                          # unblocks http_download loop
        if tk and not tk.done():
            tk.cancel()                       # CancelledError into the coroutine
        canceled.append(f"`{t['name']}` ({t['type']})")

    if uid in active_shells:
        # Pop immediately, then kill the process
        s = active_shells.pop(uid)
        kill_proc(s)                          # SIGKILL to process group
        proc = s.get("proc")
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
        canceled.append(f"`{s['cmd']}` (shell, pid {s.get('pid', '?')})")

    if canceled:
        await msg.reply("cancelled:\n" + "\n".join(f"  • {c}" for c in canceled), quote=True)
    else:
        await msg.reply("nothing active", quote=True)

# ── /ul /upload ────────────────────────────────────────────────────────────────

@app.on_message(filters.command(["ul", "upload"]))
async def cmd_upload(client: Client, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id
    a   = get_args(msg)

    if not a:
        await msg.reply("**usage:** `/ul <path>`\nupload a local file to telegram", quote=True)
        return
    if uid in active_transfers:
        t = active_transfers[uid]
        await msg.reply(f"busy: `{t['name']}` ({t['type']}) — use /cancel first", quote=True)
        return

    path = a[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True)
        return

    name   = os.path.basename(path)
    size   = os.path.getsize(path)
    status = await msg.reply(f"uploading `{name}` ({fmt_size(size)})…", quote=True)
    t0     = time.time()
    active_transfers[uid] = {"type": "upload", "name": name, "start_time": t0}

    async def _run():
        try:
            await tg_upload(client, msg, path, status)
        except asyncio.CancelledError:
            await safe_edit(status, f"cancelled: `{name}`")
        except Exception as e:
            await safe_edit(status, f"upload failed: `{e}`")
        finally:
            active_transfers.pop(uid, None)

    active_transfers[uid]["task"] = asyncio.create_task(_run())

# ── /dl /download ──────────────────────────────────────────────────────────────

@app.on_message(filters.command(["dl", "download"]))
async def cmd_download(client: Client, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id

    if uid in active_transfers:
        t = active_transfers[uid]
        await msg.reply(f"busy: `{t['name']}` ({t['type']}) — use /cancel first", quote=True)
        return

    replied = msg.reply_to_message
    if replied and (replied.document or replied.video or replied.audio or replied.photo):
        media  = replied.document or replied.video or replied.audio or replied.photo
        name   = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        size   = getattr(media, "file_size", 0)
        dest   = os.path.join(os.getcwd(), name)
        status = await msg.reply(f"downloading `{name}` ({fmt_size(size)}) to disk…", quote=True)
        t0     = time.time()
        ledge  = [0.0]
        active_transfers[uid] = {"type": "download", "name": name, "start_time": t0}

        async def _tg_dl():
            try:
                prog = make_progress(f"downloading {name}", status, t0, ledge)
                await client.download_media(replied, file_name=dest, progress=prog)
                fsize   = os.path.getsize(dest) if os.path.exists(dest) else size
                elapsed = time.time() - t0
                await safe_edit(status, f"done\nfile: `{name}`\nsize: {fmt_size(fsize)}\npath: `{dest}`\ntime: {fmt_time(elapsed)}")
            except asyncio.CancelledError:
                await safe_edit(status, f"cancelled: `{name}`")
            except Exception as e:
                await safe_edit(status, f"failed: `{e}`")
            finally:
                active_transfers.pop(uid, None)

        active_transfers[uid]["task"] = asyncio.create_task(_tg_dl())
        return

    a = get_args(msg, n=2)
    if not a:
        await msg.reply(
            "**usage:** `/dl <url> [name]`\n"
            "or reply to a telegram file\n"
            "saves to current directory",
            quote=True,
        )
        return

    url = a[0]
    if is_torrent(url):
        await msg.reply("torrent/magnet links not supported", quote=True)
        return
    if not url.startswith(("http://", "https://")):
        await msg.reply("only http/https urls supported", quote=True)
        return

    name      = a[1] if len(a) > 1 else (os.path.basename(url.split("?")[0]) or "download")
    dest      = os.path.join(os.getcwd(), name)
    status    = await msg.reply(f"downloading `{name}` to `{os.getcwd()}`…", quote=True)
    cancel_ev = asyncio.Event()
    t0        = time.time()
    active_transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": cancel_ev}

    async def _url_dl():
        try:
            fsize   = await http_download(url, dest, name, status, cancel_ev, t0)
            elapsed = time.time() - t0
            await safe_edit(status, f"done\nfile: `{name}`\nsize: {fmt_size(fsize)}\npath: `{dest}`\ntime: {fmt_time(elapsed)}")
        except asyncio.CancelledError:
            await safe_edit(status, f"cancelled: `{name}`")
            _try_remove(dest)
        except Exception as e:
            await safe_edit(status, f"failed: `{e}`")
            _try_remove(dest)
        finally:
            active_transfers.pop(uid, None)

    active_transfers[uid]["task"] = asyncio.create_task(_url_dl())

# ── /tr /transfer ─────────────────────────────────────────────────────────────

@app.on_message(filters.command(["tr", "transfer"]))
async def cmd_transfer(client: Client, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id

    if uid in active_transfers:
        t = active_transfers[uid]
        await msg.reply(f"busy: `{t['name']}` ({t['type']}) — use /cancel first", quote=True)
        return

    raw_args   = get_args(msg, n=10)
    pos, flags = parse_flags(raw_args)
    do_tg      = "gf" not in flags
    do_gf      = "gf" in flags or "both" in flags

    replied = msg.reply_to_message
    if replied and (replied.document or replied.video or replied.audio or replied.photo):
        media  = replied.document or replied.video or replied.audio or replied.photo
        name   = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        size   = getattr(media, "file_size", 0)
        dest   = os.path.join(os.getcwd(), name)
        status = await msg.reply(f"downloading `{name}` ({fmt_size(size)}) then uploading…", quote=True)
        t0     = time.time()
        ledge  = [0.0]
        active_transfers[uid] = {"type": "download", "name": name, "start_time": t0}

        async def _tg_tr():
            try:
                prog = make_progress(f"downloading {name}", status, t0, ledge)
                await client.download_media(replied, file_name=dest, progress=prog)
                active_transfers[uid]["type"] = "upload"
                await _upload_to_targets(client, msg, dest, status, do_tg, do_gf, time.time())
            except asyncio.CancelledError:
                await safe_edit(status, f"cancelled: `{name}`")
            except Exception as e:
                await safe_edit(status, f"failed: `{e}`")
            finally:
                active_transfers.pop(uid, None)
                _try_remove(dest)

        active_transfers[uid]["task"] = asyncio.create_task(_tg_tr())
        return

    if not pos:
        await msg.reply(
            "**usage:** `/tr <url|path> [name] [flags]`\n"
            "  _(no flag)_ — telegram\n"
            "  `--gf` — gofile only\n"
            "  `--both` — telegram + gofile\n"
            "or reply to a telegram file",
            quote=True,
        )
        return

    target = pos[0]

    if not target.startswith(("http://", "https://")):
        if not os.path.isfile(target):
            await msg.reply(f"not found: `{target}`", quote=True)
            return
        name   = os.path.basename(target)
        size   = os.path.getsize(target)
        status = await msg.reply(f"uploading `{name}` ({fmt_size(size)})…", quote=True)
        t0     = time.time()
        active_transfers[uid] = {"type": "upload", "name": name, "start_time": t0}

        async def _local_ul():
            try:
                await _upload_to_targets(client, msg, target, status, do_tg, do_gf, t0)
            except asyncio.CancelledError:
                await safe_edit(status, f"cancelled: `{name}`")
            except Exception as e:
                await safe_edit(status, f"failed: `{e}`")
            finally:
                active_transfers.pop(uid, None)

        active_transfers[uid]["task"] = asyncio.create_task(_local_ul())
        return

    url = target
    if is_torrent(url):
        await msg.reply("torrent/magnet links not supported", quote=True)
        return

    name      = pos[1] if len(pos) > 1 else (os.path.basename(url.split("?")[0]) or "download")
    dest      = os.path.join(os.getcwd(), name)
    status    = await msg.reply(f"downloading `{name}`…", quote=True)
    cancel_ev = asyncio.Event()
    t0        = time.time()
    active_transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": cancel_ev}

    async def _url_tr():
        try:
            await http_download(url, dest, name, status, cancel_ev, t0)
            active_transfers[uid]["type"] = "upload"
            await _upload_to_targets(client, msg, dest, status, do_tg, do_gf, time.time())
        except asyncio.CancelledError:
            await safe_edit(status, f"cancelled: `{name}`")
            _try_remove(dest)
        except Exception as e:
            await safe_edit(status, f"failed: `{e}`")
            _try_remove(dest)
        finally:
            active_transfers.pop(uid, None)
            _try_remove(dest)

    active_transfers[uid]["task"] = asyncio.create_task(_url_tr())


async def _upload_to_targets(client, msg, path, status, do_tg, do_gf, t0):
    name    = os.path.basename(path)
    size    = os.path.getsize(path)
    results = []

    if do_tg:
        await tg_upload(client, msg, path, status)
        results.append("telegram ✓")

    if do_gf:
        if do_tg:
            await safe_edit(status, f"uploading `{name}` to gofile…")
        link = await gofile_upload(path, status)
        results.append(f"gofile: {link}")

    elapsed = time.time() - t0
    await safe_edit(
        status,
        f"done\nfile: `{name}`\nsize: {fmt_size(size)}\ntime: {fmt_time(elapsed)}\n"
        + "\n".join(results),
    )


def _try_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

# ── /gf /gofile ────────────────────────────────────────────────────────────────

@app.on_message(filters.command(["gf", "gofile"]))
async def cmd_gofile(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/gf <path>`\nupload a file to gofile.io", quote=True)
        return
    path = a[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True)
        return
    name   = os.path.basename(path)
    size   = os.path.getsize(path)
    status = await msg.reply(f"uploading `{name}` ({fmt_size(size)}) to gofile…", quote=True)
    try:
        link = await gofile_upload(path, status)
        await safe_edit(status, f"done\nfile: `{name}`\nsize: {fmt_size(size)}\nlink: {link}")
    except Exception as e:
        await safe_edit(status, f"gofile failed: `{e}`")

# ── /sf ────────────────────────────────────────────────────────────────────────

@app.on_message(filters.command("sf"))
async def cmd_sf(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return

    raw = get_args(msg, n=10)
    pos, flags = parse_flags(raw)

    if not pos:
        await msg.reply(
            "**usage:** `/sf <path> [folder] [--yaap]`\n"
            "  default: `bot-uploads/workspace`\n"
            "  `--yaap`: `xenxynon-roms/yaap`\n"
            "  omit folder to get a picker",
            quote=True,
        )
        return

    path = pos[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True)
        return

    if "yaap" in flags:
        status = await msg.reply("uploading to xenxynon-roms/yaap…", quote=True)
        try:
            link = await sf_upload(status, path, SF_YAAP_PROJECT, SF_YAAP_FOLDER)
            await safe_edit(status, f"done\nfile: `{os.path.basename(path)}`\nproject: xenxynon-roms/yaap\nlink: {link}")
        except Exception as e:
            await safe_edit(status, f"sourceforge failed: `{e}`")
        return

    if len(pos) >= 2:
        folder = pos[1]
        status = await msg.reply(f"uploading to bot-uploads/{folder}…", quote=True)
        try:
            link = await sf_upload(status, path, SF_DEFAULT_PROJECT, folder)
            await safe_edit(status, f"done\nfile: `{os.path.basename(path)}`\nfolder: {folder}\nlink: {link}")
        except Exception as e:
            await safe_edit(status, f"sourceforge failed: `{e}`")
        return

    uid = msg.from_user.id
    pending_sf[uid] = {"path": path, "awaiting_custom": False}
    row1 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[:2]]
    row2 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[2:]]
    row3 = [InlineKeyboardButton("custom…", callback_data="sf:__custom__")]
    await msg.reply(
        f"select folder for `{os.path.basename(path)}` (bot-uploads):",
        reply_markup=InlineKeyboardMarkup([row1, row2, row3]),
        quote=True,
    )


@app.on_callback_query(filters.regex(r"^sf:"))
async def cb_sf(_, cq: CallbackQuery):
    uid    = cq.from_user.id
    choice = cq.data.split(":", 1)[1]

    if uid not in pending_sf:
        await cq.answer("session expired — resend /sf", show_alert=True)
        return

    await cq.answer()

    if choice == "__custom__":
        pending_sf[uid]["awaiting_custom"] = True
        await cq.message.edit("send the folder name:")
        return

    info   = pending_sf.pop(uid)
    status = cq.message
    await status.edit(f"uploading to bot-uploads/{choice}…")
    try:
        link = await sf_upload(status, info["path"], SF_DEFAULT_PROJECT, choice)
        await safe_edit(status, f"done\nfile: `{os.path.basename(info['path'])}`\nfolder: {choice}\nlink: {link}")
    except Exception as e:
        await safe_edit(status, f"sourceforge failed: `{e}`")

# ── Shell core ─────────────────────────────────────────────────────────────────

async def _run_shell(msg: Message, cmd: str) -> None:
    """Execute a shell command with live streaming output."""
    uid    = msg.from_user.id
    status = await msg.reply(f"$ `{cmd}`", quote=True)
    lines: list[str] = []
    ledge  = [time.time()]

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
    )
    pid = proc.pid
    try:
        pgid = os.getpgid(pid)
    except Exception:
        pgid = None

    active_shells[uid] = {
        "proc": proc, "pid": pid, "pgid": pgid, "cmd": cmd,
        "start_time": time.time(), "lines": lines, "ledge": ledge,
    }

    killed = False
    try:
        async def read_output():
            async for raw in proc.stdout:
                line = ANSI_RE.sub("", raw.decode(errors="replace").rstrip())
                if len(line) > 300:
                    line = line[:300] + "…"
                lines.append(line)
                if len(lines) > 200:
                    lines.pop(0)
                now = time.time()
                if now - ledge[0] >= 3:
                    ledge[0] = now
                    tail = "\n".join(lines[-40:])
                    if len(tail) > 3500:
                        tail = tail[-3500:]
                    await safe_edit(status, f"$ `{cmd}` (pid {pid})\n```\n{tail}\n```")

        await asyncio.wait_for(read_output(), timeout=3600)
        await proc.wait()
    except (asyncio.TimeoutError, asyncio.CancelledError):
        kill_proc({"pgid": pgid, "pid": pid, "proc": proc})
        killed = True
    except Exception as e:
        lines.append(f"[error: {e}]")
    finally:
        active_shells.pop(uid, None)

    rc   = proc.returncode
    tail = "\n".join(lines[-40:]) or "(no output)"
    if len(tail) > 3500:
        tail = tail[-3500:]
    note = "killed (timeout)" if killed else ("done" if rc == 0 else f"exited {rc}")
    await safe_edit(status, f"$ `{cmd}` — {note}\n```\n{tail}\n```")

# ── /sh ────────────────────────────────────────────────────────────────────────

@app.on_message(filters.command("sh"))
async def cmd_sh(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id
    a   = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/sh <command>`\nrun a shell command with live output", quote=True)
        return
    if uid in active_shells:
        s = active_shells[uid]
        await msg.reply(f"already running: `{s['cmd']}` (pid {s.get('pid', '?')}) — use /cancel", quote=True)
        return
    await _run_shell(msg, a[0])

# ── Shell shortcuts ────────────────────────────────────────────────────────────

def _shell_shortcut(cmd: str):
    """Factory: returns a handler that runs a fixed shell command."""
    async def handler(_, msg: Message):
        if not is_allowed(msg.from_user.id):
            return
        if msg.from_user.id in active_shells:
            s = active_shells[msg.from_user.id]
            await msg.reply(f"shell busy: `{s['cmd']}` — use /cancel", quote=True)
            return
        await _run_shell(msg, cmd)
    return handler

app.on_message(filters.command("ps"))    (_shell_shortcut("ps aux --sort=-%cpu | head -30"))
app.on_message(filters.command("top"))   (_shell_shortcut("top -bn1 | head -40"))
app.on_message(filters.command("free"))  (_shell_shortcut("free -h && echo '' && vmstat -s | head -10"))
app.on_message(filters.command("uptime"))(_shell_shortcut("uptime && echo '' && w"))
app.on_message(filters.command("whoami"))(_shell_shortcut("whoami && id && echo '' && uname -a"))
app.on_message(filters.command("netstat"))(_shell_shortcut("ss -tulnp"))


@app.on_message(filters.command("tail"))
async def cmd_tail(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id
    if uid in active_shells:
        await msg.reply("shell busy — use /cancel", quote=True)
        return
    a = get_args(msg, n=2)
    if not a:
        await msg.reply("**usage:** `/tail <file> [n]`\nshow last N lines (default 50)", quote=True)
        return
    n = int(a[1]) if len(a) > 1 and a[1].isdigit() else 50
    await _run_shell(msg, f"tail -n {n} {a[0]!r}")


@app.on_message(filters.command("head"))
async def cmd_head(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id
    if uid in active_shells:
        await msg.reply("shell busy — use /cancel", quote=True)
        return
    a = get_args(msg, n=2)
    if not a:
        await msg.reply("**usage:** `/head <file> [n]`\nshow first N lines (default 20)", quote=True)
        return
    n = int(a[1]) if len(a) > 1 and a[1].isdigit() else 20
    await _run_shell(msg, f"head -n {n} {a[0]!r}")


@app.on_message(filters.command("grep"))
async def cmd_grep(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    uid = msg.from_user.id
    if uid in active_shells:
        await msg.reply("shell busy — use /cancel", quote=True)
        return
    a = get_args(msg, n=2)
    if len(a) < 2:
        await msg.reply("**usage:** `/grep <pattern> <file>`", quote=True)
        return
    await _run_shell(msg, f"grep -n --color=never {a[0]!r} {a[1]!r}")

# ── Filesystem ─────────────────────────────────────────────────────────────────

@app.on_message(filters.command("ls"))
async def cmd_ls(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a    = get_args(msg)
    path = a[0] if a else "."
    try:
        entries = sorted(
            os.listdir(path),
            key=lambda e: (not os.path.isdir(os.path.join(path, e)), e.lower()),
        )
        if not entries:
            await msg.reply(f"`{os.path.abspath(path)}`: empty", quote=True)
            return

        rows = []
        for e in entries:
            full = os.path.join(path, e)
            try:
                st    = os.stat(full)
                mode  = fmt_mode(stat.S_IMODE(st.st_mode))
                size  = fmt_size(st.st_size) if os.path.isfile(full) else "-"
                mtime = datetime.fromtimestamp(st.st_mtime).strftime("%b %d %H:%M")
                name  = e + "/" if os.path.isdir(full) else e
                rows.append(f"{mode}  {size:>10}  {mtime}  {name}")
            except Exception:
                rows.append(f"?????????  {'?':>10}  ???????????  {e}")

        header = f"{os.path.abspath(path)}  ({len(entries)} items)"
        await msg.reply(f"{header}\n```\n" + "\n".join(rows) + "\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("cat"))
async def cmd_cat(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/cat <file>`", quote=True)
        return
    try:
        with open(a[0]) as f:
            content = f.read(4000)
        await msg.reply(f"```\n{content}\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("echo"))
async def cmd_echo(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    await msg.reply(a[0] if a else "(empty)", quote=True)


@app.on_message(filters.command("pwd"))
async def cmd_pwd(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    await msg.reply(f"`{os.getcwd()}`", quote=True)


@app.on_message(filters.command("mkdir"))
async def cmd_mkdir(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/mkdir <path>`", quote=True)
        return
    try:
        os.makedirs(a[0], exist_ok=True)
        await msg.reply(f"created `{os.path.abspath(a[0])}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("mv"))
async def cmd_mv(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg, n=2)
    if len(a) < 2:
        await msg.reply("**usage:** `/mv <src> <dst>`", quote=True)
        return
    try:
        shutil.move(a[0], a[1])
        await msg.reply(f"`{a[0]}` → `{a[1]}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("cp"))
async def cmd_cp(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg, n=2)
    if len(a) < 2:
        await msg.reply("**usage:** `/cp <src> <dst>`", quote=True)
        return
    try:
        shutil.copy2(a[0], a[1])
        await msg.reply(f"`{a[0]}` → `{a[1]}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("rm"))
async def cmd_rm(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/rm <path>`", quote=True)
        return
    try:
        target = a[0]
        if os.path.isdir(target):
            shutil.rmtree(target)
            await msg.reply(f"removed dir `{target}`", quote=True)
        else:
            os.remove(target)
            await msg.reply(f"deleted `{target}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("find"))
async def cmd_find(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg, n=2)
    if not a:
        await msg.reply("**usage:** `/find <path> [glob]`", quote=True)
        return
    root = a[0]
    pat  = a[1] if len(a) > 1 else "*"
    try:
        results = []
        for dirpath, _, files in os.walk(root):
            for fn in files:
                if fnmatch.fnmatch(fn, pat):
                    results.append(os.path.join(dirpath, fn))
            if len(results) >= 100:
                break
        if not results:
            await msg.reply(f"no matches for `{pat}` in `{root}`", quote=True)
            return
        text = "\n".join(results[:100])
        if len(results) >= 100:
            text += "\n(truncated at 100)"
        await msg.reply(f"{len(results)} result(s):\n```\n{text}\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("df"))
async def cmd_df(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    try:
        total, used, free = shutil.disk_usage("/")
        pct = used * 100 / total
        await msg.reply(
            f"disk /\n`{pbar(pct)}`\nused:  {fmt_size(used)}\nfree:  {fmt_size(free)}\ntotal: {fmt_size(total)}",
            quote=True,
        )
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("du"))
async def cmd_du(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/du <path>`", quote=True)
        return
    try:
        total = 0
        for dirpath, _, files in os.walk(a[0]):
            for fn in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, fn))
                except Exception:
                    pass
        await msg.reply(f"`{a[0]}`: {fmt_size(total)}", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


@app.on_message(filters.command("env"))
async def cmd_env(_, msg: Message):
    if not is_allowed(msg.from_user.id):
        return
    lines = [f"{k}={v}" for k, v in sorted(os.environ.items())]
    text  = "\n".join(lines)
    if len(text) > 4000:
        text = text[:4000] + "\n(truncated)"
    await msg.reply(f"```\n{text}\n```", quote=True)

# ── Custom SF folder (must stay last among message handlers) ───────────────────

@app.on_message(filters.private & filters.text & ~filters.regex(r"^/"))
async def catch_sf_custom(_, msg: Message):
    uid = msg.from_user.id
    if uid not in pending_sf or not pending_sf[uid].get("awaiting_custom"):
        return
    folder = msg.text.strip()
    if not folder:
        return
    info   = pending_sf.pop(uid)
    status = await msg.reply(f"uploading to bot-uploads/{folder}…", quote=True)
    try:
        link = await sf_upload(status, info["path"], SF_DEFAULT_PROJECT, folder)
        await safe_edit(status, f"done\nfile: `{os.path.basename(info['path'])}`\nfolder: {folder}\nlink: {link}")
    except Exception as e:
        await safe_edit(status, f"sourceforge failed: `{e}`")

# ── Startup notification ───────────────────────────────────────────────────────

async def notify_startup() -> None:
    if not known_chats:
        return
    sent = 0
    for cid in list(known_chats):
        try:
            await app.send_message(cid, "🟢 online")
            sent += 1
        except Exception:
            pass
    if sent:
        print(f"[startup] notified {sent} chat(s)")

# ── Run ────────────────────────────────────────────────────────────────────────

async def main():
    await app.start()
    await notify_startup()
    print("[bot] running")
    await idle()
    await app.stop()

if __name__ == "__main__":
    app.run(main())
