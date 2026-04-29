import asyncio
import fnmatch
import json
import logging
import os
import re
import shutil
import signal
import stat
import time
from datetime import datetime
from functools import wraps
from typing import Callable

import asyncssh
import httpx
from dotenv import load_dotenv
from pyrogram import Client, filters, idle
from pyrogram.errors import FloodWait, MessageNotModified
from pyrogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

# ── Config ─────────────────────────────────────────────────────────────────────

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

API_ID      = int(os.environ["API_ID"])
API_HASH    = os.environ["API_HASH"]
BOT_TOKEN   = os.environ["BOT_TOKEN"]
SF_USER     = os.environ["SF_USER"]
SF_PASS     = os.environ["SF_PASS"]
SUPER_USERS = {int(x) for x in os.environ["SUPER_USERS"].split(",")}

SF_DEFAULT_PROJECT = "bot-uploads"
SF_DEFAULT_FOLDER  = "workspace"
SF_YAAP_PROJECT    = "xenxynon-roms"
SF_YAAP_FOLDER     = "yaap"
SF_FOLDERS         = ["workspace", "releases", "test", "misc"]

TG_MAX_SIZE       = 2 * 1024 ** 3
ALLOWED_FILE      = "allowed_users.json"
KNOWN_CHATS_FILE  = "known_chats.json"
DL_CHUNK_SIZE     = 1024 * 1024
PROGRESS_INTERVAL = 3.0
SHELL_TIMEOUT     = 3600
SF_SESSION_TTL    = 300

ANSI_RE    = re.compile(r"\x1b\[[0-9;]*[mKHJA-Za-z]")
TORRENT_RE = re.compile(r"^magnet:|\.torrent(\?|$)", re.I)

# ── Persistence ────────────────────────────────────────────────────────────────

class PersistentSet:
    def __init__(self, path: str) -> None:
        self._path = path
        try:
            with open(path) as f:
                self._data: set[int] = {int(x) for x in json.load(f)}
        except (FileNotFoundError, ValueError, json.JSONDecodeError):
            self._data = set()

    def __contains__(self, item): return item in self._data
    def __iter__(self):           return iter(self._data)
    def __bool__(self):           return bool(self._data)

    def add(self, item: int) -> None:
        self._data.add(item); self._save()

    def discard(self, item: int) -> None:
        self._data.discard(item); self._save()

    def _save(self) -> None:
        try:
            with open(self._path, "w") as f:
                json.dump(sorted(self._data), f, indent=2)
        except Exception as e:
            log.warning("PersistentSet save failed (%s): %s", self._path, e)

# ── State ──────────────────────────────────────────────────────────────────────

app = Client("bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

allowed_users:    PersistentSet   = PersistentSet(ALLOWED_FILE)
known_chats:      PersistentSet   = PersistentSet(KNOWN_CHATS_FILE)
active_transfers: dict[int, dict] = {}
active_shells:    dict[int, dict] = {}
pending_sf:       dict[int, dict] = {}

def track_chat(chat_id: int) -> None:
    if chat_id not in known_chats:
        known_chats.add(chat_id)

# ── Utilities ──────────────────────────────────────────────────────────────────

def is_allowed(uid: int) -> bool: return uid in SUPER_USERS or uid in allowed_users
def is_super(uid: int) -> bool:   return uid in SUPER_USERS

def get_text(msg: Message) -> str:
    return msg.text or msg.caption or ""

def get_args(msg: Message, n: int = 1) -> list[str]:
    parts = get_text(msg).split(maxsplit=n)
    return parts[1:] if len(parts) > 1 else []

def get_shell_arg(msg: Message) -> str:
    text = get_text(msg)
    parts = text.split(maxsplit=1)
    return parts[1] if len(parts) > 1 else ""

def parse_flags(args: list[str]) -> tuple[list[str], set[str]]:
    return (
        [a for a in args if not a.startswith("--")],
        {a.lstrip("-").lower() for a in args if a.startswith("--")},
    )

def is_torrent(url: str) -> bool:
    return bool(TORRENT_RE.search(url))

_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB")
def fmt_size(b: float) -> str:
    for u in _SIZE_UNITS[:-1]:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def fmt_time(s: float) -> str:
    if s < 0 or s > 86400:
        return "--:--"
    m, s = divmod(int(s), 60)
    h, m = divmod(m, 60)
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"

def pbar(pct: float, width: int = 20) -> str:
    filled = int(width * pct / 100)
    return f"[{'#' * filled}{'-' * (width - filled)}] {pct:.1f}%"

def fmt_mode(m: int) -> str:
    result = ""
    for shift in (6, 3, 0):
        bits = (m >> shift) & 7
        result += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    return result

async def safe_edit(msg: Message, text: str) -> None:
    try:
        await msg.edit(text)
    except MessageNotModified:
        pass
    except FloodWait as e:
        await asyncio.sleep(e.value + 1)
        try:
            await msg.edit(text)
        except Exception:
            pass
    except Exception:
        pass

async def kill_proc(info: dict) -> None:
    proc = info.get("proc")
    pgid = info.get("pgid")
    pid  = info.get("pid")

    def _send(fn, target, sig):
        try: fn(target, sig)
        except Exception: pass

    if pgid:       _send(os.killpg, pgid, signal.SIGTERM)
    elif pid:      _send(os.kill,   pid,  signal.SIGTERM)
    elif proc:
        try: proc.terminate()
        except Exception: pass

    await asyncio.sleep(0.5)

    if pgid:       _send(os.killpg, pgid, signal.SIGKILL)
    elif pid:      _send(os.kill,   pid,  signal.SIGKILL)
    elif proc:
        try: proc.kill()
        except Exception: pass

def _try_remove(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

def _tg_media(replied: Message | None):
    if replied:
        return replied.document or replied.video or replied.audio or replied.photo
    return None

# ── Auth decorators ────────────────────────────────────────────────────────────

def require_allowed(fn):
    @wraps(fn)
    async def wrapper(client_or_self, msg: Message, *args, **kwargs):
        if not msg.from_user or not is_allowed(msg.from_user.id):
            return
        return await fn(client_or_self, msg, *args, **kwargs)
    return wrapper

def require_super(fn):
    @wraps(fn)
    async def wrapper(client_or_self, msg: Message, *args, **kwargs):
        if not msg.from_user or not is_super(msg.from_user.id):
            return
        return await fn(client_or_self, msg, *args, **kwargs)
    return wrapper

def require_shell_free(fn):
    @wraps(fn)
    async def wrapper(client_or_self, msg: Message, *args, **kwargs):
        if not msg.from_user:
            return
        uid = msg.from_user.id
        if uid in active_shells:
            await msg.reply(f"shell busy: `{active_shells[uid]['cmd']}` — use /cancel", quote=True)
            return
        active_shells[uid] = {"cmd": "(starting…)", "start_time": time.time(), "lines": []}
        try:
            return await fn(client_or_self, msg, *args, **kwargs)
        except Exception:
            active_shells.pop(uid, None)
            raise
    return wrapper

# ── Chat tracker ───────────────────────────────────────────────────────────────

@app.on_message(filters.all, group=1)
async def _track_chats(_, msg: Message):
    if msg.from_user and is_allowed(msg.from_user.id):
        track_chat(msg.chat.id)

# ── Progress ───────────────────────────────────────────────────────────────────

def _progress_text(label: str, current: int, total: int, elapsed: float) -> str:
    speed = current / elapsed if elapsed > 0 else 0
    eta   = (total - current) / speed if speed > 0 and total > current else -1
    pct   = current * 100 / total if total > 0 else 0
    szstr = f"{fmt_size(current)} / {fmt_size(total)}" if total else fmt_size(current)
    return (
        f"`{label}`\n`{pbar(pct)}`\n\n"
        f"size:    {szstr}\n"
        f"speed:   {fmt_size(speed)}/s\n"
        f"eta:     {fmt_time(eta)}\n"
        f"elapsed: {fmt_time(elapsed)}"
    )

class _Throttle:
    __slots__ = ("ts",)
    def __init__(self): self.ts = 0.0

def make_progress(label: str, status: Message, t0: float, throttle: _Throttle):
    async def cb(current: int, total: int) -> None:
        now = time.time()
        if now - throttle.ts < PROGRESS_INTERVAL:
            return
        throttle.ts = now
        await safe_edit(status, _progress_text(label, current, total, now - t0))
    return cb

# ── Transfer helpers ───────────────────────────────────────────────────────────

def _make_transfer_task(uid: int, coro, cleanup: Callable | None = None) -> asyncio.Task:
    async def _wrapper():
        try:
            await coro
        finally:
            active_transfers.pop(uid, None)
            if cleanup:
                cleanup()
    task = asyncio.create_task(_wrapper())
    active_transfers[uid]["task"] = task
    return task

async def _guard_transfer(msg: Message, uid: int) -> bool:
    if uid in active_transfers:
        t = active_transfers[uid]
        await msg.reply(f"busy: `{t['name']}` ({t['type']}) — use /cancel first", quote=True)
        return True
    return False

# ── Gofile ─────────────────────────────────────────────────────────────────────

async def gofile_upload(path: str, status: Message) -> str:
    name = os.path.basename(path)
    await safe_edit(status, "fetching gofile server…")

    async with httpx.AsyncClient(timeout=30) as http:
        r = await http.get("https://api.gofile.io/servers")
        r.raise_for_status()
        servers = [s["name"] for s in r.json()["data"]["servers"]]

        last_err: Exception | None = None
        for server in servers:
            await safe_edit(status, f"uploading `{name}` to gofile [{server}]…")
            try:
                with open(path, "rb") as f:
                    r = await http.post(
                        f"https://{server}.gofile.io/contents/uploadfile",
                        files={"file": (name, f)},
                        timeout=None,
                    )
                r.raise_for_status()
                data = r.json()
                if data.get("status") != "ok":
                    raise RuntimeError(str(data))
                return data["data"]["downloadPage"]
            except Exception as e:
                last_err = e
                log.warning("gofile server %s failed: %s", server, e)

    raise RuntimeError(f"all gofile servers failed: {last_err}")

# ── TG upload ──────────────────────────────────────────────────────────────────

async def tg_upload(client: Client, msg: Message, path: str, status: Message) -> None:
    name     = os.path.basename(path)
    size     = os.path.getsize(path)
    t0       = time.time()
    throttle = _Throttle()

    if size > TG_MAX_SIZE:
        await safe_edit(status, f"`{name}` is {fmt_size(size)}, over 2 GB — routing to gofile…")
        link = await gofile_upload(path, status)
        await safe_edit(status, f"gofile done (>2 GB)\nfile: `{name}`\nsize: {fmt_size(size)}\nlink: {link}\ntime: {fmt_time(time.time() - t0)}")
        return

    prog = make_progress(f"uploading {name}", status, t0, throttle)
    await client.send_document(msg.chat.id, path, caption=f"`{name}` — {fmt_size(size)}", progress=prog)
    await safe_edit(status, f"upload done\nfile: `{name}`\nsize: {fmt_size(size)}\ntime: {fmt_time(time.time() - t0)}")

# ── HTTP download ──────────────────────────────────────────────────────────────

async def http_download(
    url: str, dest: str, name: str, status: Message, cancel_ev: asyncio.Event, t0: float
) -> int:
    throttle = _Throttle()
    async with httpx.AsyncClient(follow_redirects=True, timeout=None) as http:
        async with http.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            done  = 0
            with open(dest, "wb") as f:
                async for chunk in resp.aiter_bytes(DL_CHUNK_SIZE):
                    if cancel_ev.is_set():
                        raise asyncio.CancelledError
                    f.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - throttle.ts >= PROGRESS_INTERVAL:
                        throttle.ts = now
                        await safe_edit(status, _progress_text(name, done, total, now - t0))
    return os.path.getsize(dest)

# ── SF upload ──────────────────────────────────────────────────────────────────

async def sf_upload(status: Message, path: str, project: str, folder: str) -> str:
    name   = os.path.basename(path)
    remote = f"/home/frs/project/{project}/{folder}/{name}"
    t0     = time.time()
    throttle = _Throttle()
    await safe_edit(status, "connecting to sourceforge…")

    async with asyncssh.connect(
        "frs.sourceforge.net",
        username=SF_USER, password=SF_PASS, known_hosts=None,
    ) as conn:
        async with conn.start_sftp_client() as sftp:
            size = os.path.getsize(path)
            sent = 0

            async def _progress(transferred, _total):
                nonlocal sent
                sent = transferred
                now  = time.time()
                if now - throttle.ts >= PROGRESS_INTERVAL:
                    throttle.ts = now
                    await safe_edit(
                        status,
                        f"uploading `{name}` to sourceforge [{project}/{folder}]…\n"
                        + _progress_text(name, sent, size, now - t0),
                    )

            await sftp.put(path, remote, block_size=65536, progress_handler=_progress)

    return f"https://sourceforge.net/projects/{project}/files/{folder}/{name}"

# ── Download → upload pipeline ─────────────────────────────────────────────────

async def _do_download(
    *,
    client: Client,
    msg: Message,
    status: Message,
    uid: int,
    name: str,
    dest: str,
    t0: float,
    url: str | None = None,
    tg_media=None,
    cancel_ev: asyncio.Event | None = None,
    then_upload: bool = False,
    do_tg: bool = True,
    do_gf: bool = False,
) -> None:
    try:
        if tg_media is not None:
            size     = getattr(tg_media, "file_size", 0)
            throttle = _Throttle()
            prog     = make_progress(f"downloading {name}", status, t0, throttle)
            await client.download_media(msg.reply_to_message, file_name=dest, progress=prog)
        else:
            assert url and cancel_ev
            await http_download(url, dest, name, status, cancel_ev, t0)

        if then_upload:
            active_transfers[uid]["type"] = "upload"
            await _upload_to_targets(client, msg, dest, status, do_tg, do_gf, time.time())
        else:
            fsize = os.path.getsize(dest) if os.path.exists(dest) else 0
            await safe_edit(
                status,
                f"done\nfile: `{name}`\nsize: {fmt_size(fsize)}\npath: `{dest}`\ntime: {fmt_time(time.time() - t0)}",
            )
    except asyncio.CancelledError:
        await safe_edit(status, f"cancelled: `{name}`")
        if not tg_media:
            _try_remove(dest)
    except Exception as e:
        await safe_edit(status, f"failed: `{e}`")
        if not tg_media:
            _try_remove(dest)

async def _upload_to_targets(
    client: Client, msg: Message, path: str, status: Message,
    do_tg: bool, do_gf: bool, t0: float,
) -> None:
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

    await safe_edit(
        status,
        f"done\nfile: `{name}`\nsize: {fmt_size(size)}\ntime: {fmt_time(time.time() - t0)}\n"
        + "\n".join(results),
    )

# ── /allow /revoke /users ──────────────────────────────────────────────────────

@app.on_message(filters.command("allow"))
@require_super
async def cmd_allow(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/allow <user_id>`", quote=True); return
    try:
        uid = int(a[0])
        allowed_users.add(uid)
        await msg.reply(f"✅ allowed `{uid}`", quote=True)
    except ValueError:
        await msg.reply("invalid user id", quote=True)

@app.on_message(filters.command("revoke"))
@require_super
async def cmd_revoke(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/revoke <user_id>`", quote=True); return
    try:
        uid = int(a[0])
        allowed_users.discard(uid)
        await msg.reply(f"✅ revoked `{uid}`", quote=True)
    except ValueError:
        await msg.reply("invalid user id", quote=True)

@app.on_message(filters.command("users"))
@require_super
async def cmd_users(_, msg: Message):
    if not allowed_users:
        await msg.reply("no extra allowed users", quote=True); return
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
`/gf /gofile <path>` — upload to gofile.io
`/sf <path> [folder] [--yaap]` — upload to sourceforge
  default: bot-uploads/workspace  |  `--yaap`: xenxynon-roms/yaap

**shell**
`/sh <command>` — run command with live output
`/stdin <text>` — send input to running shell process
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
@require_allowed
async def cmd_help(_, msg: Message):
    await msg.reply(HELP, quote=True)

@app.on_message(filters.command("ping"))
async def cmd_ping(_, msg: Message):
    t0    = time.time()
    reply = await msg.reply("…", quote=True)
    await reply.edit(f"pong — `{(time.time() - t0) * 1000:.0f}ms`")

@app.on_message(filters.command("status"))
@require_allowed
async def cmd_status(_, msg: Message):
    uid   = msg.from_user.id
    parts = []

    if uid in active_transfers:
        t = active_transfers[uid]
        parts.append(f"**transfer:** `{t['name']}` ({t['type']}) — {fmt_time(time.time() - t['start_time'])} elapsed")

    if uid in active_shells:
        s    = active_shells[uid]
        tail = "\n".join(s["lines"][-5:]) or "(no output)"
        if len(tail) > 1500:
            tail = tail[-1500:]
        parts.append(f"**shell:** `{s['cmd']}` (pid {s.get('pid', '?')}) — {fmt_time(time.time() - s['start_time'])} elapsed\n```\n{tail}\n```")

    await msg.reply("\n\n".join(parts) if parts else "no active tasks", quote=True)

@app.on_message(filters.command("cancel"))
@require_allowed
async def cmd_cancel(_, msg: Message):
    uid      = msg.from_user.id
    canceled = []

    if uid in active_transfers:
        t = active_transfers.pop(uid)
        if ce := t.get("cancel_event"):
            ce.set()
        if (tk := t.get("task")) and not tk.done():
            tk.cancel()
        canceled.append(f"`{t['name']}` ({t['type']})")

    if uid in active_shells:
        s = active_shells.pop(uid)
        await kill_proc(s)
        canceled.append(f"`{s['cmd']}` (shell, pid {s.get('pid', '?')})")

    await msg.reply(
        "cancelled:\n" + "\n".join(f"  • {c}" for c in canceled) if canceled else "nothing active",
        quote=True,
    )

# ── /ul /upload ────────────────────────────────────────────────────────────────

@app.on_message(filters.command(["ul", "upload"]))
@require_allowed
async def cmd_upload(client: Client, msg: Message):
    uid = msg.from_user.id
    a   = get_args(msg)

    if not a:
        await msg.reply("**usage:** `/ul <path>`\nupload a local file to telegram", quote=True); return
    if await _guard_transfer(msg, uid):
        return

    path = a[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True); return

    name   = os.path.basename(path)
    status = await msg.reply(f"uploading `{name}` ({fmt_size(os.path.getsize(path))})…", quote=True)
    t0     = time.time()
    active_transfers[uid] = {"type": "upload", "name": name, "start_time": t0}

    async def _run():
        try:
            await tg_upload(client, msg, path, status)
        except asyncio.CancelledError:
            await safe_edit(status, f"cancelled: `{name}`")
        except Exception as e:
            await safe_edit(status, f"upload failed: `{e}`")

    _make_transfer_task(uid, _run())

# ── /dl /download ──────────────────────────────────────────────────────────────

@app.on_message(filters.command(["dl", "download"]))
@require_allowed
async def cmd_download(client: Client, msg: Message):
    uid = msg.from_user.id
    if await _guard_transfer(msg, uid):
        return

    media = _tg_media(msg.reply_to_message)
    if media:
        name   = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        size   = getattr(media, "file_size", 0)
        dest   = os.path.join(os.getcwd(), name)
        t0     = time.time()
        status = await msg.reply(f"downloading `{name}` ({fmt_size(size)}) to disk…", quote=True)
        active_transfers[uid] = {"type": "download", "name": name, "start_time": t0}
        _make_transfer_task(uid, _do_download(
            client=client, msg=msg, status=status, uid=uid,
            name=name, dest=dest, t0=t0, tg_media=media,
        ))
        return

    a = get_args(msg, n=2)
    if not a:
        await msg.reply(
            "**usage:** `/dl <url> [name]`\nor reply to a telegram file\nsaves to current directory",
            quote=True,
        ); return

    url = a[0]
    if is_torrent(url):
        await msg.reply("torrent/magnet links not supported", quote=True); return
    if not url.startswith(("http://", "https://")):
        await msg.reply("only http/https urls supported", quote=True); return

    name      = a[1] if len(a) > 1 else (os.path.basename(url.split("?")[0]) or "download")
    dest      = os.path.join(os.getcwd(), name)
    cancel_ev = asyncio.Event()
    t0        = time.time()
    status    = await msg.reply(f"downloading `{name}` to `{os.getcwd()}`…", quote=True)
    active_transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": cancel_ev}
    _make_transfer_task(uid, _do_download(
        client=client, msg=msg, status=status, uid=uid,
        name=name, dest=dest, t0=t0, url=url, cancel_ev=cancel_ev,
    ))

# ── /tr /transfer ─────────────────────────────────────────────────────────────

@app.on_message(filters.command(["tr", "transfer"]))
@require_allowed
async def cmd_transfer(client: Client, msg: Message):
    uid = msg.from_user.id
    if await _guard_transfer(msg, uid):
        return

    raw_args   = get_args(msg, n=10)
    pos, flags = parse_flags(raw_args)
    do_tg      = "gf" not in flags
    do_gf      = "gf" in flags or "both" in flags

    media = _tg_media(msg.reply_to_message)
    if media:
        name   = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        size   = getattr(media, "file_size", 0)
        dest   = os.path.join(os.getcwd(), name)
        t0     = time.time()
        status = await msg.reply(f"downloading `{name}` ({fmt_size(size)}) then uploading…", quote=True)
        active_transfers[uid] = {"type": "download", "name": name, "start_time": t0}
        _make_transfer_task(uid, _do_download(
            client=client, msg=msg, status=status, uid=uid,
            name=name, dest=dest, t0=t0, tg_media=media,
            then_upload=True, do_tg=do_tg, do_gf=do_gf,
        ), cleanup=lambda: _try_remove(dest))
        return

    if not pos:
        await msg.reply(
            "**usage:** `/tr <url|path> [name] [flags]`\n"
            "  _(no flag)_ — telegram\n  `--gf` — gofile only\n  `--both` — telegram + gofile\n"
            "or reply to a telegram file",
            quote=True,
        ); return

    target = pos[0]

    if not target.startswith(("http://", "https://")):
        if not os.path.isfile(target):
            await msg.reply(f"not found: `{target}`", quote=True); return
        name   = os.path.basename(target)
        t0     = time.time()
        status = await msg.reply(f"uploading `{name}` ({fmt_size(os.path.getsize(target))})…", quote=True)
        active_transfers[uid] = {"type": "upload", "name": name, "start_time": t0}

        async def _local_ul():
            try:
                await _upload_to_targets(client, msg, target, status, do_tg, do_gf, t0)
            except asyncio.CancelledError:
                await safe_edit(status, f"cancelled: `{name}`")
            except Exception as e:
                await safe_edit(status, f"failed: `{e}`")

        _make_transfer_task(uid, _local_ul())
        return

    url = target
    if is_torrent(url):
        await msg.reply("torrent/magnet links not supported", quote=True); return

    name      = pos[1] if len(pos) > 1 else (os.path.basename(url.split("?")[0]) or "download")
    dest      = os.path.join(os.getcwd(), name)
    cancel_ev = asyncio.Event()
    t0        = time.time()
    status    = await msg.reply(f"downloading `{name}`…", quote=True)
    active_transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": cancel_ev}
    _make_transfer_task(uid, _do_download(
        client=client, msg=msg, status=status, uid=uid,
        name=name, dest=dest, t0=t0, url=url, cancel_ev=cancel_ev,
        then_upload=True, do_tg=do_tg, do_gf=do_gf,
    ), cleanup=lambda: _try_remove(dest))

# ── /gf /gofile ────────────────────────────────────────────────────────────────

@app.on_message(filters.command(["gf", "gofile"]))
@require_allowed
async def cmd_gofile(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/gf <path>`\nupload a file to gofile.io", quote=True); return
    path = a[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True); return
    name   = os.path.basename(path)
    size   = os.path.getsize(path)
    status = await msg.reply(f"uploading `{name}` ({fmt_size(size)}) to gofile…", quote=True)
    try:
        link = await gofile_upload(path, status)
        await safe_edit(status, f"done\nfile: `{name}`\nsize: {fmt_size(size)}\nlink: {link}")
    except Exception as e:
        await safe_edit(status, f"gofile failed: `{e}`")

# ── /sf ────────────────────────────────────────────────────────────────────────

async def _sf_do(status: Message, path: str, project: str, folder: str) -> None:
    try:
        link = await sf_upload(status, path, project, folder)
        await safe_edit(
            status,
            f"done\nfile: `{os.path.basename(path)}`\nproject: {project}/{folder}\nlink: {link}",
        )
    except Exception as e:
        await safe_edit(status, f"sourceforge failed: `{e}`")

@app.on_message(filters.command("sf"))
@require_allowed
async def cmd_sf(_, msg: Message):
    raw = get_args(msg, n=10)
    pos, flags = parse_flags(raw)

    if not pos:
        await msg.reply(
            "**usage:** `/sf <path> [folder] [--yaap]`\n"
            "  default: `bot-uploads/workspace`\n  `--yaap`: `xenxynon-roms/yaap`\n"
            "  omit folder to get a picker",
            quote=True,
        ); return

    path = pos[0]
    if not os.path.isfile(path):
        await msg.reply(f"not found: `{path}`", quote=True); return

    if "yaap" in flags:
        status = await msg.reply("uploading to xenxynon-roms/yaap…", quote=True)
        await _sf_do(status, path, SF_YAAP_PROJECT, SF_YAAP_FOLDER)
        return

    if len(pos) >= 2:
        folder = pos[1]
        status = await msg.reply(f"uploading to bot-uploads/{folder}…", quote=True)
        await _sf_do(status, path, SF_DEFAULT_PROJECT, folder)
        return

    uid = msg.from_user.id
    pending_sf[uid] = {"path": path, "awaiting_custom": False, "ts": time.time()}
    row1 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[:2]]
    row2 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[2:]]
    row3 = [InlineKeyboardButton("custom…", callback_data="sf:__custom__")]
    await msg.reply(
        f"select folder for `{os.path.basename(path)}` (bot-uploads):",
        reply_markup=InlineKeyboardMarkup([row1, row2, row3]),
        quote=True,
    )

def _sf_check_session(uid: int) -> dict | None:
    now = time.time()
    for k in [k for k, v in list(pending_sf.items()) if now - v["ts"] > SF_SESSION_TTL]:
        pending_sf.pop(k, None)
    info = pending_sf.get(uid)
    if not info:
        return None
    return info

@app.on_callback_query(filters.regex(r"^sf:"))
async def cb_sf(_, cq: CallbackQuery):
    uid    = cq.from_user.id
    choice = cq.data.split(":", 1)[1]
    info   = _sf_check_session(uid)

    if info is None:
        await cq.answer("session expired — resend /sf", show_alert=True); return

    await cq.answer()

    if choice == "__custom__":
        info["awaiting_custom"] = True
        info["ts"] = time.time()
        await cq.message.edit("send the folder name:")
        return

    pending_sf.pop(uid)
    status = cq.message
    await status.edit(f"uploading to bot-uploads/{choice}…")
    await _sf_do(status, info["path"], SF_DEFAULT_PROJECT, choice)

# ── Shell core ─────────────────────────────────────────────────────────────────

async def _run_shell(msg: Message, cmd: str) -> None:
    uid = msg.from_user.id

    if uid in active_shells:
        active_shells[uid]["cmd"] = cmd

    status = await msg.reply(f"$ `{cmd}`", quote=True)
    lines: list[str] = []
    throttle = _Throttle()

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    pid = proc.pid
    try:    pgid = os.getpgid(pid)
    except Exception: pgid = None

    # update slot with full process info
    active_shells[uid].update({
        "proc": proc, "pid": pid, "pgid": pgid,
        "start_time": active_shells[uid].get("start_time", time.time()),
        "lines": lines,
    })

    killed = False
    try:
        async def read_output():
            assert proc.stdout
            async for raw in proc.stdout:
                line = ANSI_RE.sub("", raw.decode(errors="replace").rstrip())
                if len(line) > 300:
                    line = line[:300] + "…"
                lines.append(line)
                if len(lines) > 200:
                    lines.pop(0)
                now = time.time()
                if now - throttle.ts >= PROGRESS_INTERVAL:
                    throttle.ts = now
                    tail = "\n".join(lines[-40:])
                    if len(tail) > 3500:
                        tail = "…" + tail[-3499:]
                    await safe_edit(status, f"$ `{cmd}` (pid {pid})\n```\n{tail}\n```")

        await asyncio.wait_for(read_output(), timeout=SHELL_TIMEOUT)
        await proc.wait()
    except asyncio.TimeoutError:
        await kill_proc({"pgid": pgid, "pid": pid, "proc": proc})
        killed = True
    except asyncio.CancelledError:
        await kill_proc({"pgid": pgid, "pid": pid, "proc": proc})
        killed = True
    except Exception as e:
        lines.append(f"[error: {e}]")
    finally:
        active_shells.pop(uid, None)

    tail = "\n".join(lines[-40:]) or "(no output)"
    if len(tail) > 3500:
        tail = "…" + tail[-3499:]
    rc   = proc.returncode
    note = "killed (timeout/cancelled)" if killed else ("done" if rc == 0 else f"exited {rc}")
    await safe_edit(status, f"$ `{cmd}` — {note}\n```\n{tail}\n```")

# ── /sh ────────────────────────────────────────────────────────────────────────

@app.on_message(filters.command("sh"))
@require_allowed
@require_shell_free
async def cmd_sh(_, msg: Message):
    cmd = get_shell_arg(msg)
    if not cmd:
        active_shells.pop(msg.from_user.id, None)
        await msg.reply("**usage:** `/sh <command>`\nrun a shell command with live output", quote=True)
        return
    asyncio.create_task(_run_shell(msg, cmd))

# ── /stdin ─────────────────────────────────────────────────────────────────────

@app.on_message(filters.command("stdin"))
@require_allowed
async def cmd_stdin(_, msg: Message):
    uid = msg.from_user.id
    if uid not in active_shells:
        await msg.reply("no active shell", quote=True); return
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/stdin <text>`", quote=True); return
    proc = active_shells[uid].get("proc")
    if proc and proc.stdin:
        try:
            proc.stdin.write((a[0] + "\n").encode())
            await proc.stdin.drain()
            await msg.reply("sent", quote=True)
        except Exception as e:
            await msg.reply(f"error: `{e}`", quote=True)
    else:
        await msg.reply("process stdin not available", quote=True)

# ── Shell shortcuts ────────────────────────────────────────────────────────────

_SHELL_SHORTCUTS: dict[str, str] = {
    "ps":      "ps aux --sort=-%cpu | head -30",
    "top":     "top -bn1 | head -40",
    "free":    "free -h && echo '' && vmstat -s | head -10",
    "uptime":  "uptime && echo '' && w",
    "whoami":  "whoami && id && echo '' && uname -a",
    "netstat": "ss -tulnp",
}

for _cmd, _shell in _SHELL_SHORTCUTS.items():
    def _make(shell_cmd: str):
        @require_allowed
        @require_shell_free
        async def _handler(_, msg: Message):
            asyncio.create_task(_run_shell(msg, shell_cmd))
        return _handler
    app.on_message(filters.command(_cmd))(_make(_shell))

@app.on_message(filters.command("tail"))
@require_allowed
@require_shell_free
async def cmd_tail(_, msg: Message):
    a = get_args(msg, n=2)
    if not a:
        active_shells.pop(msg.from_user.id, None)
        await msg.reply("**usage:** `/tail <file> [n]`\nshow last N lines (default 50)", quote=True); return
    n = int(a[1]) if len(a) > 1 and a[1].isdigit() else 50
    asyncio.create_task(_run_shell(msg, f"tail -n {n} {a[0]!r}"))

@app.on_message(filters.command("head"))
@require_allowed
@require_shell_free
async def cmd_head(_, msg: Message):
    a = get_args(msg, n=2)
    if not a:
        active_shells.pop(msg.from_user.id, None)
        await msg.reply("**usage:** `/head <file> [n]`\nshow first N lines (default 20)", quote=True); return
    n = int(a[1]) if len(a) > 1 and a[1].isdigit() else 20
    asyncio.create_task(_run_shell(msg, f"head -n {n} {a[0]!r}"))

@app.on_message(filters.command("grep"))
@require_allowed
@require_shell_free
async def cmd_grep(_, msg: Message):
    a = get_args(msg, n=2)
    if len(a) < 2:
        active_shells.pop(msg.from_user.id, None)
        await msg.reply("**usage:** `/grep <pattern> <file>`", quote=True); return
    asyncio.create_task(_run_shell(msg, f"grep -n --color=never {a[0]!r} {a[1]!r}"))

# ── Filesystem ─────────────────────────────────────────────────────────────────

@app.on_message(filters.command("ls"))
@require_allowed
async def cmd_ls(_, msg: Message):
    a    = get_args(msg)
    path = a[0] if a else "."
    try:
        entries = sorted(
            os.listdir(path),
            key=lambda e: (not os.path.isdir(os.path.join(path, e)), e.lower()),
        )
        if not entries:
            await msg.reply(f"`{os.path.abspath(path)}`: empty", quote=True); return

        rows = []
        for e in entries:
            full = os.path.join(path, e)
            try:
                st     = os.lstat(full)
                mode   = fmt_mode(stat.S_IMODE(st.st_mode))
                is_lnk = stat.S_ISLNK(st.st_mode)
                is_dir = os.path.isdir(full)
                size   = fmt_size(st.st_size) if not is_dir else "-"
                mtime  = datetime.fromtimestamp(st.st_mtime).strftime("%b %d %H:%M")
                name   = e + ("/" if is_dir else ("@" if is_lnk else ""))
                rows.append(f"{mode}  {size:>10}  {mtime}  {name}")
            except Exception:
                rows.append(f"?????????  {'?':>10}  ???????????  {e}")

        await msg.reply(
            f"`{os.path.abspath(path)}`  ({len(entries)} items)\n```\n" + "\n".join(rows) + "\n```",
            quote=True,
        )
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("cat"))
@require_allowed
async def cmd_cat(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/cat <file>`", quote=True); return
    try:
        with open(a[0], "rb") as f:
            raw = f.read(8192)
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("latin-1")
        if len(content) > 4000:
            content = content[:4000] + "\n…(truncated)"
        content = content.replace("`", "\`")
        await msg.reply(f"```\n{content}\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("echo"))
@require_allowed
async def cmd_echo(_, msg: Message):
    a = get_args(msg)
    await msg.reply(a[0] if a else "(empty)", quote=True)

@app.on_message(filters.command("pwd"))
@require_allowed
async def cmd_pwd(_, msg: Message):
    await msg.reply(f"`{os.getcwd()}`", quote=True)

@app.on_message(filters.command("mkdir"))
@require_allowed
async def cmd_mkdir(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/mkdir <path>`", quote=True); return
    try:
        os.makedirs(a[0], exist_ok=True)
        await msg.reply(f"created `{os.path.abspath(a[0])}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("mv"))
@require_allowed
async def cmd_mv(_, msg: Message):
    a = get_args(msg, n=2)
    if len(a) < 2:
        await msg.reply("**usage:** `/mv <src> <dst>`", quote=True); return
    try:
        shutil.move(a[0], a[1])
        await msg.reply(f"`{a[0]}` → `{a[1]}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("cp"))
@require_allowed
async def cmd_cp(_, msg: Message):
    a = get_args(msg, n=2)
    if len(a) < 2:
        await msg.reply("**usage:** `/cp <src> <dst>`", quote=True); return
    try:
        shutil.copy2(a[0], a[1])
        await msg.reply(f"`{a[0]}` → `{a[1]}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("rm"))
@require_allowed
async def cmd_rm(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/rm <path>`", quote=True); return
    try:
        target = a[0]
        if os.path.isdir(target) and not os.path.islink(target):
            shutil.rmtree(target)
            await msg.reply(f"removed dir `{target}`", quote=True)
        else:
            os.remove(target)
            await msg.reply(f"deleted `{target}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("find"))
@require_allowed
async def cmd_find(_, msg: Message):
    a = get_args(msg, n=2)
    if not a:
        await msg.reply("**usage:** `/find <path> [glob]`", quote=True); return
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
            await msg.reply(f"no matches for `{pat}` in `{root}`", quote=True); return
        text = "\n".join(results[:100])
        if len(results) >= 100:
            text += "\n(truncated at 100)"
        await msg.reply(f"{len(results)} result(s):\n```\n{text}\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("df"))
@require_allowed
async def cmd_df(_, msg: Message):
    try:
        total, used, free = shutil.disk_usage("/")
        await msg.reply(
            f"disk /\n`{pbar(used * 100 / total)}`\nused:  {fmt_size(used)}\nfree:  {fmt_size(free)}\ntotal: {fmt_size(total)}",
            quote=True,
        )
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("du"))
@require_allowed
async def cmd_du(_, msg: Message):
    a = get_args(msg)
    if not a:
        await msg.reply("**usage:** `/du <path>`", quote=True); return
    try:
        total = 0
        for dp, _, files in os.walk(a[0]):
            for fn in files:
                try:
                    total += os.path.getsize(os.path.join(dp, fn))
                except OSError:
                    pass
        await msg.reply(f"`{a[0]}`: {fmt_size(total)}", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("env"))
@require_allowed
async def cmd_env(_, msg: Message):
    text = "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))
    if len(text) > 4000:
        text = text[:4000] + "\n…(truncated)"
    await msg.reply(f"```\n{text}\n```", quote=True)

# ── Custom SF folder ───────────────────────────────────────────────────────────

@app.on_message(filters.text & ~filters.regex(r"^/"))
async def catch_sf_custom(_, msg: Message):
    if not msg.from_user:
        return
    uid  = msg.from_user.id
    info = _sf_check_session(uid)
    if not info or not info.get("awaiting_custom"):
        return
    folder = msg.text.strip()
    if not folder:
        return
    pending_sf.pop(uid)
    status = await msg.reply(f"uploading to bot-uploads/{folder}…", quote=True)
    await _sf_do(status, info["path"], SF_DEFAULT_PROJECT, folder)

# ── Startup notification ───────────────────────────────────────────────────────

async def notify_startup() -> None:
    if not known_chats:
        return
    sent = 0
    for cid in list(known_chats):
        if cid not in SUPER_USERS and cid not in allowed_users:
            continue
        try:
            await app.send_message(cid, "🟢 online")
            sent += 1
            await asyncio.sleep(0.05)
        except FloodWait as e:
            await asyncio.sleep(e.value + 1)
            try:
                await app.send_message(cid, "🟢 online")
                sent += 1
            except Exception:
                pass
        except Exception:
            pass
    if sent:
        log.info("startup: notified %d chat(s)", sent)

# ── Run ────────────────────────────────────────────────────────────────────────

async def main():
    await app.start()
    await notify_startup()
    log.info("bot running")
    await idle()
    await app.stop()

if __name__ == "__main__":
    app.run(main())
