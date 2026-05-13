import asyncio
import json
import os
import re
import shutil
import signal
import tempfile
import time
from collections import deque
from functools import wraps
from pathlib import Path

import asyncssh
import httpx
from dotenv import load_dotenv
from pyrogram import Client, filters, idle
from pyrogram.errors import FloodWait, MessageNotModified
from pyrogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

load_dotenv()

API_ID      = int(os.environ["API_ID"])
API_HASH    = os.environ["API_HASH"]
BOT_TOKEN   = os.environ["BOT_TOKEN"]
SF_USER     = os.environ["SF_USER"]
SF_PASS     = os.environ["SF_PASS"]
SUPER_USERS = {int(x) for x in os.environ["SUPER_USERS"].split(",")}
WEB_BASE    = os.environ.get("WEB_BASE", "").rstrip("/")   # e.g. https://files.example.com

_SECRET_VARS = frozenset({"api_id","api_hash","bot_token","sf_pass","sf_user","super_users"})
_SECRET_KEYS = frozenset({"API_HASH","API_ID","BOT_TOKEN","SF_PASS","SF_USER","SUPER_USERS"})

SF_PROJECT  = "bot-uploads"
SF_YAAP_PRJ = "xenxynon-roms"
SF_YAAP_DIR = "yaap"
SF_FOLDERS  = ["workspace","releases","test","misc"]

# All downloads land here; web.py serves from the same dir
DOWNLOADS_DIR = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

TG_MAX_SIZE       = 2 * 1024**3
ALLOWED_FILE      = "allowed_users.json"
DL_CHUNK_SIZE     = 1024 * 1024
PROGRESS_INTERVAL = 3.0
SHELL_TIMEOUT     = 3600
SF_SESSION_TTL    = 300
BUSY_MSG          = "busy — /cancel first"

ANSI_RE    = re.compile(r"\x1b\[[0-9;]*[mKHJA-Za-z]")
TORRENT_RE = re.compile(r"^magnet:|\.torrent(\?|$)", re.I)

SHELL_CMDS = {
    "ps":      "ps aux --sort=-%cpu | head -30",
    "top":     "top -bn1 | head -40",
    "free":    "free -h",
    "uptime":  "uptime",
    "whoami":  "id",
    "netstat": "ss -tulnp",
}

_ENV_FILE      = os.path.abspath(os.environ.get("DOTENV_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")))
_ENV_FILE_NAME = os.path.basename(_ENV_FILE)

def _sensitive(p):
    try:    return os.path.abspath(p) == _ENV_FILE
    except: return True

def _shell_safe(cmd):
    if _ENV_FILE_NAME in cmd or _ENV_FILE in cmd: return False
    lo = cmd.lower()
    if any(v in lo for v in _SECRET_VARS): return False
    return not ("/proc/" in cmd and "environ" in cmd)

def _web_link(name: str) -> str | None:
    """Return a web UI download link for a file if WEB_BASE is configured."""
    if not WEB_BASE: return None
    return f"{WEB_BASE}/dl/{name}"

def _dl_dest(name: str) -> str:
    """Canonical download destination inside DOWNLOADS_DIR."""
    return str(DOWNLOADS_DIR / name)


# ── Persistent user set ────────────────────────────────────────────────────────

class PSet:
    def __init__(self, path):
        self._p = path
        try:
            with open(path) as f: self._d = {int(x) for x in json.load(f)}
        except: self._d = set()
    def __contains__(self, x): return x in self._d
    def __bool__(self):        return bool(self._d)
    def add(self, x):     self._d.add(x);     self._save()
    def discard(self, x): self._d.discard(x); self._save()
    def _save(self):
        t = self._p + ".tmp"
        try:
            with open(t, "w") as f: json.dump(sorted(self._d), f)
            os.replace(t, self._p)
        except Exception as e:
            print(f"[warn] PSet save: {e}")
            try: os.remove(t)
            except: pass


app           = Client("bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)
allowed_users = PSet(ALLOWED_FILE)
transfers: dict[int, dict] = {}
shells:    dict[int, dict] = {}
psf:       dict[int, dict] = {}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ok(uid):  return uid in SUPER_USERS or uid in allowed_users
def _su(uid):  return uid in SUPER_USERS
def _uid(msg): return msg.from_user.id if msg.from_user else None

def _txt(msg):  return msg.text or msg.caption or ""
def _args(msg, n=1):
    p = _txt(msg).split(maxsplit=n + 1)
    return p[1:] if len(p) > 1 else []
def _sharg(msg):
    p = _txt(msg).split(maxsplit=1)
    return re.sub(r"^@\S+\s*", "", p[1]).strip() if len(p) > 1 else ""
def _flags(args):
    return ([a for a in args if not a.startswith("--")],
            {a.lstrip("-").lower() for a in args if a.startswith("--")})

def fsize(b):
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def ftime(s):
    if s < 0 or s > 86400: return "--:--"
    m, s = divmod(int(s), 60); h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s" if h else f"{m}m {s}s" if m else f"{s}s"

def _ptext(label, cur, tot, elapsed):
    spd = cur / elapsed if elapsed else 0
    eta = (tot - cur) / spd if spd and tot > cur else -1
    pct = cur * 100 / tot if tot else 0
    bar = f"[{'#' * int(20 * pct / 100)}{'-' * (20 - int(20 * pct / 100))}] {pct:.1f}%"
    return (f"`{label}`\n`{bar}`\n\n"
            f"size:    {fsize(cur)}/{fsize(tot) if tot else '?'}\n"
            f"speed:   {fsize(spd)}/s\neta:     {ftime(eta)}\nelapsed: {ftime(elapsed)}")

def _prog(label, status, t0, ts):
    async def cb(cur, tot):
        now = time.time()
        if now - ts[0] < PROGRESS_INTERVAL: return
        ts[0] = now
        await _edit(status, _ptext(label, cur, tot, now - t0))
    return cb

async def _edit(msg, text):
    try: await msg.edit(text)
    except MessageNotModified: pass
    except FloodWait as e:
        await asyncio.sleep(e.value + 1)
        try: await msg.edit(text)
        except: pass
    except: pass

def _sig(fn, t, s):
    try: fn(t, s)
    except: pass

async def _kill(info):
    g, p, proc = info.get("pgid"), info.get("pid"), info.get("proc")
    if g:     _sig(os.killpg, g, signal.SIGTERM)
    elif p:   _sig(os.kill, p, signal.SIGTERM)
    elif proc:
        try: proc.terminate()
        except: pass
    await asyncio.sleep(0.5)
    if g:     _sig(os.killpg, g, signal.SIGKILL)
    elif p:   _sig(os.kill, p, signal.SIGKILL)
    elif proc:
        try: proc.kill()
        except: pass

def _rm(path):
    try: os.remove(path)
    except: pass

def _mktask(uid, coro, cleanup=None):
    e = transfers[uid]
    async def _w():
        try: await coro
        finally:
            transfers.pop(uid, None)
            if cleanup: cleanup()
    e["task"] = t = asyncio.create_task(_w())
    return t


# ── Auth decorators ────────────────────────────────────────────────────────────

def auth(fn):
    @wraps(fn)
    async def wrapper(c, msg, *a, **kw):
        if msg.from_user and _ok(msg.from_user.id):
            return await fn(c, msg, *a, **kw)
    return wrapper

def superauth(fn):
    @wraps(fn)
    async def wrapper(c, msg, *a, **kw):
        if msg.from_user and _su(msg.from_user.id):
            return await fn(c, msg, *a, **kw)
    return wrapper


# ── Gofile ─────────────────────────────────────────────────────────────────────

async def _gofile(path, status):
    name = os.path.basename(path)
    await _edit(status, "fetching gofile server…")
    async with httpx.AsyncClient(timeout=30) as h:
        r = await h.get("https://api.gofile.io/servers"); r.raise_for_status()
        servers = [s["name"] for s in r.json()["data"]["servers"]]
    last = None
    for sv in servers:
        await _edit(status, f"↑ `{name}` → gofile [{sv}]…")
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30, read=None)) as h:
                with open(path, "rb") as f:
                    r = await h.post(f"https://{sv}.gofile.io/contents/uploadfile",
                                     files={"file": (name, f)})
                r.raise_for_status()
                d = r.json()
                if d.get("status") != "ok": raise RuntimeError(str(d))
                return d["data"]["downloadPage"]
        except Exception as e: last = e
    raise RuntimeError(f"gofile failed: {last}")


# ── TG upload ──────────────────────────────────────────────────────────────────

async def _tgup(client, msg, path, status, *, silent=False):
    name, size, t0, ts = os.path.basename(path), os.path.getsize(path), time.time(), [0.0]
    if size > TG_MAX_SIZE:
        await _edit(status, f"`{name}` >2 GB → gofile…")
        link = await _gofile(path, status)
        if not silent:
            await _edit(status, f"done\nfile: `{name}`\nsize: {fsize(size)}\nlink: {link}\ntime: {ftime(time.time()-t0)}")
        return
    await client.send_document(msg.chat.id, path,
                               caption=f"`{name}` — {fsize(size)}",
                               progress=_prog(f"↑ {name}", status, t0, ts))
    if not silent:
        await _edit(status, f"done\nfile: `{name}`\nsize: {fsize(size)}\ntime: {ftime(time.time()-t0)}")


# ── HTTP download ──────────────────────────────────────────────────────────────

async def _httpdl(url, dest, name, status, ev, t0):
    ts, tmp = [0.0], None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(dest)))
        with os.fdopen(fd, "wb") as f:
            async with httpx.AsyncClient(follow_redirects=True, timeout=None) as h:
                async with h.stream("GET", url) as r:
                    r.raise_for_status()
                    tot, done = int(r.headers.get("content-length", 0)), 0
                    async for chunk in r.aiter_bytes(DL_CHUNK_SIZE):
                        if ev.is_set(): raise asyncio.CancelledError
                        f.write(chunk); done += len(chunk)
                        now = time.time()
                        if now - ts[0] >= PROGRESS_INTERVAL:
                            ts[0] = now
                            await _edit(status, _ptext(name, done, tot, now - t0))
        os.replace(tmp, dest); tmp = None
    finally:
        if tmp: _rm(tmp)


# ── SF upload ──────────────────────────────────────────────────────────────────

async def _sfup(status, path, project, folder):
    name, t0, ts = os.path.basename(path), time.time(), [0.0]
    await _edit(status, "connecting to sourceforge…")
    async with asyncssh.connect("frs.sourceforge.net",
                                username=SF_USER, password=SF_PASS,
                                known_hosts=None) as conn:
        async with conn.start_sftp_client() as sftp:
            size, sent = os.path.getsize(path), 0
            async def _p(xfr, _):
                nonlocal sent; sent = xfr; now = time.time()
                if now - ts[0] >= PROGRESS_INTERVAL:
                    ts[0] = now
                    await _edit(status, f"↑ sf [{project}/{folder}]\n" +
                                _ptext(name, sent, size, now - t0))
            await sftp.put(path, f"/home/frs/project/{project}/{folder}/{name}",
                           block_size=65536, progress_handler=_p)
    return f"https://sourceforge.net/projects/{project}/files/{folder}/{name}"


# ── Combined upload (TG + optional gofile) ────────────────────────────────────

async def _upload(client, msg, path, status, do_tg, do_gf, t0):
    name, size, res = os.path.basename(path), os.path.getsize(path), []
    if do_tg:
        await _tgup(client, msg, path, status, silent=True)
        res.append("tg ✓")
    if do_gf:
        if do_tg: await _edit(status, f"↑ `{name}` → gofile…")
        res.append(f"gofile: {await _gofile(path, status)}")
    web = _web_link(name)
    if web: res.append(f"web: {web}")
    await _edit(status,
                f"done\nfile: `{name}`\nsize: {fsize(size)}\n"
                f"time: {ftime(time.time()-t0)}\n" + "\n".join(res))


# ── Download + optional re-upload ─────────────────────────────────────────────

async def _dl(*, client, msg, status, uid, name, dest, t0,
              url=None, tg_media=None, ev=None,
              then_upload=False, do_tg=True, do_gf=False):
    try:
        if tg_media is not None:
            ts = [0.0]
            await client.download_media(msg.reply_to_message, file_name=dest,
                                        progress=_prog(f"↓ {name}", status, t0, ts))
        else:
            await _httpdl(url, dest, name, status, ev, t0)
        if then_upload:
            transfers[uid]["type"] = "upload"
            await _upload(client, msg, dest, status, do_tg, do_gf, time.time())
        else:
            sz = os.path.getsize(dest) if os.path.exists(dest) else 0
            web = _web_link(name)
            summary = (f"done\nfile: `{name}`\nsize: {fsize(sz)}\n"
                       f"path: `{dest}`\ntime: {ftime(time.time()-t0)}")
            if web: summary += f"\nweb:  {web}"
            await _edit(status, summary)
    except asyncio.CancelledError:
        await _edit(status, f"cancelled: `{name}`"); _rm(dest)
    except Exception as e:
        await _edit(status, f"failed: `{e}`"); _rm(dest)


# ── SF session helpers ─────────────────────────────────────────────────────────

def _sfses(uid):
    now = time.time()
    expired = [k for k, v in psf.items() if now - v["ts"] > SF_SESSION_TTL]
    for k in expired: del psf[k]
    return psf.get(uid)

async def _sfexec(uid, status, path, project, folder):
    transfers[uid] = {"type": "sf", "name": os.path.basename(path), "start_time": time.time()}
    async def _run():
        try:
            link = await _sfup(status, path, project, folder)
            await _edit(status,
                        f"done\nfile: `{os.path.basename(path)}`\n"
                        f"{project}/{folder}\nlink: {link}")
        except asyncio.CancelledError:
            await _edit(status, f"cancelled: `{os.path.basename(path)}`")
        except Exception as e:
            await _edit(status, f"sf failed: `{e}`")
    _mktask(uid, _run())


# ── Shell ──────────────────────────────────────────────────────────────────────

async def _runsh(msg, cmd):
    uid = msg.from_user.id
    lines = deque(maxlen=200)
    shells[uid] = {"cmd": cmd, "start_time": time.time(), "lines": lines}
    status, ts = await msg.reply(f"$ `{cmd}`", quote=True), [0.0]
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        start_new_session=True)
    pid = proc.pid
    try:    pgid = os.getpgid(pid)
    except: pgid = None
    shells[uid].update({"proc": proc, "pid": pid, "pgid": pgid})
    killed = False
    try:
        async def _read():
            async for raw in proc.stdout:
                line = ANSI_RE.sub("", raw.decode(errors="replace").rstrip())
                lines.append(line[:300] + "…" if len(line) > 300 else line)
                now = time.time()
                if now - ts[0] >= PROGRESS_INTERVAL:
                    ts[0] = now
                    tail = "\n".join(lines)
                    if len(tail) > 3500: tail = "…" + tail[-3499:]
                    await _edit(status, f"$ `{cmd}` (pid {pid})\n```\n{tail}\n```")
        await asyncio.wait_for(_read(), timeout=SHELL_TIMEOUT)
        await proc.wait()
    except (asyncio.TimeoutError, asyncio.CancelledError):
        await _kill({"pgid": pgid, "pid": pid, "proc": proc}); killed = True
    except Exception as e:
        lines.append(f"[error: {e}]")
    finally:
        shells.pop(uid, None)
    tail = "\n".join(lines) or "(no output)"
    if len(tail) > 3500: tail = "…" + tail[-3499:]
    note = "killed" if killed else ("done" if proc.returncode == 0 else f"exited {proc.returncode}")
    await _edit(status, f"$ `{cmd}` — {note}\n```\n{tail}\n```")


# ── Commands ───────────────────────────────────────────────────────────────────

@app.on_message(filters.command("allow"))
@superauth
async def cmd_allow(_, msg):
    a = _args(msg)
    if not a: await msg.reply("usage: /allow <id>", quote=True); return
    try: allowed_users.add(int(a[0])); await msg.reply(f"✅ `{a[0]}`", quote=True)
    except: await msg.reply("bad id", quote=True)

@app.on_message(filters.command("revoke"))
@superauth
async def cmd_revoke(_, msg):
    a = _args(msg)
    if not a: await msg.reply("usage: /revoke <id>", quote=True); return
    try: uid = int(a[0]); allowed_users.discard(uid); await msg.reply(f"✅ revoked `{uid}`", quote=True)
    except: await msg.reply("bad id", quote=True)

@app.on_message(filters.command(["start", "help"]))
@auth
async def cmd_help(_, msg):
    await msg.reply("**transfers:** /ul /dl /tr /gf /sf /cancel\n"
                    "**shell:** /sh /stdin /ps /top /free /uptime /whoami /netstat\n"
                    "**fs:** /ls /cat /rm /mv /cp\n"
                    "**info:** /ping /status  **auth:** /allow /revoke", quote=True)

@app.on_message(filters.command("ping"))
async def cmd_ping(_, msg):
    t0 = time.time(); r = await msg.reply("…", quote=True)
    await r.edit(f"pong `{(time.time()-t0)*1000:.0f}ms`")

@app.on_message(filters.command("status"))
@auth
async def cmd_status(_, msg):
    uid, parts = msg.from_user.id, []
    if uid in transfers:
        t = transfers[uid]
        parts.append(f"**xfer:** `{t['name']}` {ftime(time.time()-t['start_time'])}")
    if uid in shells:
        s = shells[uid]
        tail = "\n".join(list(s["lines"])[-5:]) or "(none)"
        if len(tail) > 1500: tail = "…" + tail[-1499:]
        parts.append(f"**shell:** `{s['cmd']}` {ftime(time.time()-s['start_time'])}\n```\n{tail}\n```")
    await msg.reply("\n".join(parts) or "idle", quote=True)

@app.on_message(filters.command("cancel"))
@auth
async def cmd_cancel(_, msg):
    uid, done = msg.from_user.id, []
    if uid in transfers:
        t = transfers.pop(uid)
        if ce := t.get("cancel_event"): ce.set()
        if (tk := t.get("task")) and not tk.done(): tk.cancel()
        done.append(f"`{t['name']}`")
    if uid in shells:
        s = shells.pop(uid); await _kill(s); done.append(f"`{s['cmd']}`")
    if uid in psf:
        psf.pop(uid); done.append("sf session")
    await msg.reply("cancelled: " + " ".join(done) if done else "nothing active", quote=True)

@app.on_message(filters.command(["ul", "upload"]))
@auth
async def cmd_upload(client, msg):
    uid = msg.from_user.id; a = _args(msg)
    if not a: await msg.reply("usage: /ul <path>", quote=True); return
    if uid in transfers: await msg.reply(BUSY_MSG, quote=True); return
    path = a[0]
    if _sensitive(path): await msg.reply("denied", quote=True); return
    if not os.path.isfile(path): await msg.reply(f"not found: `{path}`", quote=True); return
    name = os.path.basename(path); t0 = time.time()
    status = await msg.reply(f"↑ `{name}` ({fsize(os.path.getsize(path))})…", quote=True)
    transfers[uid] = {"type": "upload", "name": name, "start_time": t0}
    async def _r():
        try: await _tgup(client, msg, path, status)
        except asyncio.CancelledError: await _edit(status, f"cancelled: `{name}`")
        except Exception as e: await _edit(status, f"failed: `{e}`")
    _mktask(uid, _r())

@app.on_message(filters.command(["dl", "download"]))
@auth
async def cmd_download(client, msg):
    uid = msg.from_user.id
    if uid in transfers: await msg.reply(BUSY_MSG, quote=True); return
    r = msg.reply_to_message
    media = r and (r.document or r.video or r.audio or r.photo)
    if media:
        name = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        dest = _dl_dest(name); t0 = time.time()
        status = await msg.reply(f"↓ `{name}`…", quote=True)
        transfers[uid] = {"type": "download", "name": name, "start_time": t0}
        _mktask(uid, _dl(client=client, msg=msg, status=status, uid=uid,
                         name=name, dest=dest, t0=t0, tg_media=media))
        return
    a = _args(msg, n=2)
    if not a: await msg.reply("usage: /dl <url> [name]  or reply to file", quote=True); return
    url = a[0]
    if TORRENT_RE.search(url) or not url.startswith(("http://", "https://")):
        await msg.reply("http/https only, no torrents", quote=True); return
    name = a[1] if len(a) > 1 else (os.path.basename(url.split("?")[0]) or "download")
    dest = _dl_dest(name); ev = asyncio.Event(); t0 = time.time()
    status = await msg.reply(f"↓ `{name}`…", quote=True)
    transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": ev}
    _mktask(uid, _dl(client=client, msg=msg, status=status, uid=uid,
                     name=name, dest=dest, t0=t0, url=url, ev=ev))

@app.on_message(filters.command(["tr", "transfer"]))
@auth
async def cmd_transfer(client, msg):
    uid = msg.from_user.id
    if uid in transfers: await msg.reply(BUSY_MSG, quote=True); return
    pos, flags = _flags(_args(msg, n=10))
    do_tg = "gf" not in flags; do_gf = "gf" in flags or "both" in flags
    r = msg.reply_to_message
    media = r and (r.document or r.video or r.audio or r.photo)
    if media:
        name = getattr(media, "file_name", None) or f"tg_{media.file_id[:8]}"
        dest = _dl_dest(name); t0 = time.time()
        transfers[uid] = {"type": "download", "name": name, "start_time": t0}
        _mktask(uid,
                _dl(client=client, msg=msg,
                    status=await msg.reply(f"↓↑ `{name}`…", quote=True),
                    uid=uid, name=name, dest=dest, t0=t0, tg_media=media,
                    then_upload=True, do_tg=do_tg, do_gf=do_gf),
                cleanup=lambda: _rm(dest))
        return
    if not pos: await msg.reply("usage: /tr <url|path> [name] [--gf|--both]", quote=True); return
    target = pos[0]
    if not target.startswith(("http://", "https://")):
        if _sensitive(target): await msg.reply("denied", quote=True); return
        if not os.path.isfile(target): await msg.reply(f"not found: `{target}`", quote=True); return
        name = os.path.basename(target); t0 = time.time()
        transfers[uid] = {"type": "upload", "name": name, "start_time": t0}
        async def _lu():
            try: await _upload(client, msg, target,
                               await msg.reply(f"↑ `{name}`…", quote=True), do_tg, do_gf, t0)
            except asyncio.CancelledError: pass
            except Exception as e: print(f"[tr] {e}")
        _mktask(uid, _lu()); return
    if TORRENT_RE.search(target): await msg.reply("no torrents", quote=True); return
    name = pos[1] if len(pos) > 1 else (os.path.basename(target.split("?")[0]) or "download")
    dest = _dl_dest(name); ev = asyncio.Event(); t0 = time.time()
    transfers[uid] = {"type": "download", "name": name, "start_time": t0, "cancel_event": ev}
    _mktask(uid,
            _dl(client=client, msg=msg,
                status=await msg.reply(f"↓↑ `{name}`…", quote=True),
                uid=uid, name=name, dest=dest, t0=t0, url=target, ev=ev,
                then_upload=True, do_tg=do_tg, do_gf=do_gf),
            cleanup=lambda: _rm(dest))

@app.on_message(filters.command(["gf", "gofile"]))
@auth
async def cmd_gofile(_, msg):
    a = _args(msg)
    if not a: await msg.reply("usage: /gf <path>", quote=True); return
    path = a[0]
    if _sensitive(path): await msg.reply("denied", quote=True); return
    if not os.path.isfile(path): await msg.reply(f"not found: `{path}`", quote=True); return
    size = os.path.getsize(path)
    status = await msg.reply(f"↑ `{os.path.basename(path)}`  gofile…", quote=True)
    try:
        link = await _gofile(path, status)
        await _edit(status, f"done\nsize: {fsize(size)}\nlink: {link}")
    except Exception as e:
        await _edit(status, f"failed: `{e}`")

@app.on_message(filters.command("sf"))
@auth
async def cmd_sf(_, msg):
    uid = msg.from_user.id
    if uid in transfers: await msg.reply(BUSY_MSG, quote=True); return
    pos, flags = _flags(_args(msg, n=10))
    if not pos: await msg.reply("usage: /sf <path> [folder] [--yaap]", quote=True); return
    path = pos[0]
    if _sensitive(path): await msg.reply("denied", quote=True); return
    if not os.path.isfile(path): await msg.reply(f"not found: `{path}`", quote=True); return
    if "yaap" in flags:
        await _sfexec(uid, await msg.reply("↑ xenxynon-roms/yaap…", quote=True),
                      path, SF_YAAP_PRJ, SF_YAAP_DIR)
        return
    if len(pos) >= 2:
        await _sfexec(uid, await msg.reply(f"↑ bot-uploads/{pos[1]}…", quote=True),
                      path, SF_PROJECT, pos[1])
        return
    psf[uid] = {"path": path, "awaiting_custom": False, "ts": time.time()}
    r1 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[:2]]
    r2 = [InlineKeyboardButton(f, callback_data=f"sf:{f}") for f in SF_FOLDERS[2:]]
    await msg.reply(
        f"folder for `{os.path.basename(path)}`:",
        reply_markup=InlineKeyboardMarkup(
            [r1, r2, [InlineKeyboardButton("custom…", callback_data="sf:__custom__")]]),
        quote=True)

@app.on_callback_query(filters.regex(r"^sf:"))
async def cb_sf(_, cq):
    uid, choice = cq.from_user.id, cq.data.split(":", 1)[1]
    info = _sfses(uid)
    if not info: await cq.answer("expired — resend /sf", show_alert=True); return
    await cq.answer()
    if choice == "__custom__":
        info["awaiting_custom"] = True; info["ts"] = time.time()
        await cq.message.edit("send folder name:"); return
    psf.pop(uid)
    await cq.message.edit(f"↑ bot-uploads/{choice}…")
    await _sfexec(uid, cq.message, info["path"], SF_PROJECT, choice)

@app.on_message(filters.text & ~filters.regex(r"^/"))
@auth
async def catch_sf_custom(_, msg):
    uid = msg.from_user.id
    info = _sfses(uid)
    if not info or not info.get("awaiting_custom"): return
    folder = msg.text.strip()
    if not folder: return
    psf.pop(uid)
    await _sfexec(uid, await msg.reply(f"↑ bot-uploads/{folder}…", quote=True),
                  info["path"], SF_PROJECT, folder)

@app.on_message(filters.command("sh"))
@auth
async def cmd_sh(_, msg):
    uid = msg.from_user.id
    if uid in shells:
        await msg.reply(f"busy: `{shells[uid]['cmd']}` — /cancel", quote=True); return
    cmd = _sharg(msg)
    if not cmd: await msg.reply("usage: /sh <cmd>", quote=True); return
    if not _shell_safe(cmd): await msg.reply("denied", quote=True); return
    asyncio.create_task(_runsh(msg, cmd))

@app.on_message(filters.command("stdin"))
@auth
async def cmd_stdin(_, msg):
    uid = msg.from_user.id
    if uid not in shells: await msg.reply("no shell", quote=True); return
    text = _sharg(msg)
    if not text: await msg.reply("usage: /stdin <text>", quote=True); return
    shell = shells[uid]
    proc = shell.get("proc")
    if not proc or proc.returncode is not None:
        shells.pop(uid, None)
        await msg.reply("shell already exited", quote=True); return
    if proc.stdin:
        try:
            proc.stdin.write((text + "\n").encode())
            await proc.stdin.drain()
            await msg.reply("✓", quote=True)
        except Exception as e:
            await msg.reply(f"error: `{e}`", quote=True)
    else:
        await msg.reply("n/a", quote=True)


# ── Shell convenience commands ────────────────────────────────────────────────

def _make_shell_handler(sc):
    @auth
    async def handler(_, msg):
        uid = msg.from_user.id
        if uid in shells:
            await msg.reply(f"busy: `{shells[uid]['cmd']}` — /cancel", quote=True); return
        asyncio.create_task(_runsh(msg, sc))
    handler.__name__ = f"cmd_{sc.split()[0]}"
    return handler

for _cmd, _sc in SHELL_CMDS.items():
    app.on_message(filters.command(_cmd))(_make_shell_handler(_sc))


# ── Filesystem commands ────────────────────────────────────────────────────────

@app.on_message(filters.command("ls"))
@auth
async def cmd_ls(_, msg):
    a = _args(msg); path = a[0] if a else "."
    try:
        entries = sorted(os.scandir(path), key=lambda e: (not e.is_dir(), e.name.lower()))
        if not entries: await msg.reply("empty", quote=True); return
        rows = []
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
                rows.append(
                    f"{'d' if e.is_dir() else 'l' if e.is_symlink() else '-'} "
                    f"{fsize(st.st_size):>10}  {e.name}{'/' if e.is_dir() else ''}")
            except:
                rows.append(f"? {'?':>10}  {e.name}")
        await msg.reply(
            f"`{os.path.abspath(path)}` ({len(entries)})\n```\n" + "\n".join(rows) + "\n```",
            quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("cat"))
@auth
async def cmd_cat(_, msg):
    a = _args(msg)
    if not a: await msg.reply("usage: /cat <file>", quote=True); return
    if _sensitive(a[0]): await msg.reply("denied", quote=True); return
    try:
        with open(a[0], "rb") as f: raw = f.read(8192)
        try:    content = raw.decode()
        except: content = raw.decode("latin-1")
        if len(content) > 4000: content = content[:4000] + "\n…"
        await msg.reply(f"```\n{content}\n```", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)

@app.on_message(filters.command("rm"))
@auth
async def cmd_rm(_, msg):
    a = _args(msg)
    if not a: await msg.reply("usage: /rm <path>", quote=True); return
    if _sensitive(a[0]): await msg.reply("denied", quote=True); return
    try:
        t = a[0]
        if os.path.isdir(t) and not os.path.islink(t):
            shutil.rmtree(t); await msg.reply(f"✓ `{t}`", quote=True)
        else:
            os.remove(t); await msg.reply(f"✓ `{t}`", quote=True)
    except Exception as e:
        await msg.reply(f"error: `{e}`", quote=True)


def _register_2path(name, fn):
    @app.on_message(filters.command(name))
    @auth
    async def handler(_, msg):
        a = _args(msg, n=2)
        if len(a) < 2: await msg.reply(f"usage: /{name} <src> <dst>", quote=True); return
        if _sensitive(a[0]) or _sensitive(a[1]): await msg.reply("denied", quote=True); return
        try:
            fn(a[0], a[1]); await msg.reply(f"✓ `{a[0]}` → `{a[1]}`", quote=True)
        except Exception as e:
            await msg.reply(f"error: `{e}`", quote=True)
    handler.__name__ = f"cmd_{name}"

_register_2path("mv", shutil.move)
_register_2path("cp", shutil.copy2)


# ── Entry point ────────────────────────────────────────────────────────────────

async def main():
    from web import start_web
    await start_web()
    await app.start()
    print("bot running")
    await idle()
    await app.stop()

if __name__ == "__main__":
    app.run(main())
