import asyncio
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

from aiohttp import web, ClientSession, ClientTimeout
from dotenv import load_dotenv

load_dotenv()

WEB_PORT       = int(os.environ.get("WEB_PORT", 8080))
WEB_ADMIN_PASS = os.environ.get("WEB_ADMIN_PASS", "")
LINK_SECRET    = os.environ.get("LINK_SECRET", secrets.token_hex(32))
DOWNLOADS_DIR  = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(DOWNLOADS_DIR, 0o750)

_HERE      = Path(__file__).parent
HTML_DIR   = _HERE / "html"
STATIC_DIR = _HERE / "static"
FLAGS_FILE = _HERE / "flags.json"
USERS_FILE = _HERE / "users.json"
META_FILE  = _HERE / "file_meta.json"

SESSION_TTL       = 86400
COOKIE_NAME       = "fsid"
MAX_UPLOAD_BYTES  = int(os.environ.get("MAX_UPLOAD_MB", 2048)) * 1024 * 1024
MAX_FETCH_BYTES   = int(os.environ.get("MAX_FETCH_MB", 4096)) * 1024 * 1024
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 30

BLOCKED_EXTS = {
    "exe","bat","cmd","com","scr","pif","vbs","vbe","js","jse",
    "wsf","wsh","ps1","ps2","msi","msp","hta","cpl","dll","sys",
    "sh","bash","zsh","fish","run","elf","dex",
}

EXT_CATS = {
    **{e: "archive" for e in "zip gz xz zst tar 7z bz2 lz4 br rar".split()},
    **{e: "image"   for e in "jpg jpeg png gif webp svg bmp avif ico".split()},
    **{e: "video"   for e in "mp4 mkv avi mov webm flv m4v ts".split()},
    **{e: "audio"   for e in "mp3 flac aac wav ogg m4a opus".split()},
    **{e: "doc"     for e in "txt log md json xml yaml toml cfg py js ts html css pdf doc docx xls xlsx csv".split()},
}

_sessions: dict = {}
_rate:     dict = {}
_torrent_jobs: dict = {}
_fetch_jobs:   dict = {}


def _atomic_write(path, text):
    tmp = str(path) + ".tmp"
    try:
        with open(tmp, "w") as f: f.write(text)
        os.replace(tmp, str(path))
    except Exception as e:
        print(f"[warn] write {path}: {e}")

def _pw_hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

def _sanitize_filename(name):
    name = Path(name).name
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    return name or "upload"

def _is_blocked(name):
    parts = name.lower().split(".")
    return any(p in BLOCKED_EXTS for p in parts[1:])

def _rate_ok(ip):
    now = time.time()
    bucket = _rate.setdefault(ip, [])
    _rate[ip] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(_rate[ip]) >= RATE_LIMIT_MAX: return False
    _rate[ip].append(now); return True

def _cat_from_ext(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return EXT_CATS.get(ext, "other")

def _cat_from_mime(mime):
    if not mime: return "other"
    m = mime.lower()
    if m.startswith("image/"): return "image"
    if m.startswith("video/"): return "video"
    if m.startswith("audio/"): return "audio"
    if m in ("application/pdf","text/plain","text/html","text/csv"): return "doc"
    if any(x in m for x in ("zip","tar","compress","7z")): return "archive"
    return "other"


_flags_cache = {}

def _load_flags():
    global _flags_cache
    try: _flags_cache = json.loads(FLAGS_FILE.read_text())
    except Exception: _flags_cache = {}

def get_flag(k, default=False): return _flags_cache.get(k, default)

def set_flag(k, v):
    _flags_cache[k] = v
    _atomic_write(FLAGS_FILE, json.dumps(_flags_cache))

_load_flags()


def _load_users():
    try: return json.loads(USERS_FILE.read_text())
    except Exception: return {"users": {}}

def _save_users(db): _atomic_write(USERS_FILE, json.dumps(db))

def _ensure_admin():
    if not WEB_ADMIN_PASS: return
    db = _load_users()
    if not any(d.get("role") == "admin" for d in db["users"].values()):
        db["users"]["admin"] = {"pw_hash": _pw_hash(WEB_ADMIN_PASS), "role": "admin"}
        _save_users(db)

_ensure_admin()


def _load_meta():
    try: return json.loads(META_FILE.read_text())
    except Exception: return {}

def _save_meta(m): _atomic_write(META_FILE, json.dumps(m))
def _set_owner(name, username): m = _load_meta(); m[name] = username; _save_meta(m)
def _get_owner(name): return _load_meta().get(name)


def _new_session(username, role):
    tok = secrets.token_hex(32)
    _sessions[tok] = {"exp": time.time() + SESSION_TTL, "user": username, "role": role}
    return tok

def _get_session(req):
    tok = req.cookies.get(COOKIE_NAME)
    if not tok: return None
    s = _sessions.get(tok)
    if not s or time.time() > s["exp"]:
        _sessions.pop(tok, None); return None
    return s

def _check(req):    return _get_session(req) is not None
def _is_admin(req): s = _get_session(req); return bool(s and s.get("role") == "admin")
def _who(req):      s = _get_session(req); return s.get("user") if s else None

def _can_modify(req, name):
    if _is_admin(req): return True
    u = _who(req); return u is not None and _get_owner(name) == u

def _set_cookie(resp, tok):
    resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                    httponly=True, samesite="Strict", secure=False)


def _safe(rel_path):
    """Resolve a relative path (may contain subdirs) to an absolute path within DOWNLOADS_DIR.
    Returns the Path if it exists as a file, else None."""
    try:
        # Strip leading slashes so Path() doesn't treat it as absolute
        rel_path = rel_path.lstrip("/")
        p = (DOWNLOADS_DIR / rel_path).resolve()
        if str(p).startswith(str(DOWNLOADS_DIR) + os.sep) or p == DOWNLOADS_DIR:
            if p.is_file():
                return p
    except Exception:
        pass
    return None

def _safe_dir(rel):
    try:
        if rel in ("", ".", "/"): return DOWNLOADS_DIR
        p = (DOWNLOADS_DIR / Path(rel)).resolve()
        if str(p).startswith(str(DOWNLOADS_DIR)): return p
    except Exception: pass
    return None


def make_dl_token(name):
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok, name):
    return hmac.compare_digest(tok, make_dl_token(name))


def _tpl(name, **ctx):
    text = (HTML_DIR / name).read_text()
    for k, v in ctx.items(): text = text.replace(f"{{{{{k}}}}}", v)
    return text


async def _stream(req, path, name):
    ct, _ = mimetypes.guess_type(str(path))
    resp = web.StreamResponse(headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Content-Type":        ct or "application/octet-stream",
        "Content-Length":      str(path.stat().st_size),
    })
    await resp.prepare(req)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536): await resp.write(chunk)
    except (ConnectionError, ConnectionResetError): pass
    return resp


async def _run_fetch(job_id, url, dest_name, username):
    job = _fetch_jobs[job_id]
    tmp = DOWNLOADS_DIR / (dest_name + ".part")
    try:
        timeout = ClientTimeout(total=None, connect=15, sock_read=60)
        async with ClientSession(timeout=timeout) as sess:
            async with sess.get(url, allow_redirects=True, max_redirects=10) as resp:
                if resp.status >= 400:
                    job["status"] = "failed"
                    job["error"]  = f"HTTP {resp.status}"
                    return
                total = int(resp.headers.get("Content-Length", 0))
                job["total"] = total
                if total > MAX_FETCH_BYTES:
                    job["status"] = "failed"
                    job["error"]  = f"Remote file too large ({total // 1024 // 1024} MB)"
                    return
                mime = resp.content_type or ""
                job["category"] = _cat_from_mime(mime) if mime else _cat_from_ext(dest_name)
                job["status"]   = "downloading"
                done = 0; t_start = time.monotonic(); last_time = t_start; last_done = 0
                with open(tmp, "wb") as f:
                    async for chunk in resp.content.iter_chunked(65536):
                        if job.get("cancelled"):
                            job["status"] = "cancelled"; tmp.unlink(missing_ok=True); return
                        f.write(chunk); done += len(chunk); job["done"] = done
                        now = time.monotonic(); dt = now - last_time
                        if dt >= 0.5:
                            speed = (done - last_done) / dt; job["speed"] = int(speed)
                            if total > 0:
                                job["progress"] = min(99, int(done / total * 100))
                                rem = total - done
                                job["eta"] = int(rem / speed) if speed > 0 else -1
                            last_time = now; last_done = done
                        if done > MAX_FETCH_BYTES:
                            job["status"] = "failed"; job["error"] = "File exceeded size limit"
                            tmp.unlink(missing_ok=True); return
        dest = DOWNLOADS_DIR / dest_name; tmp.rename(dest)
        _set_owner(dest_name, username)
        job["status"] = "done"; job["progress"] = 100; job["done"] = done; job["total"] = done
    except asyncio.CancelledError:
        job["status"] = "cancelled"; tmp.unlink(missing_ok=True)
    except Exception as ex:
        job["status"] = "failed"; job["error"] = str(ex); tmp.unlink(missing_ok=True)


async def handle_root(req):
    if _check(req): return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")

async def handle_login(req):
    if not _rate_ok(req.remote): return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = (data.get("username") or "").strip(); password = data.get("pass", "")
    db = _load_users(); user = db["users"].get(username)
    if not user or not secrets.compare_digest(_pw_hash(password), user["pw_hash"]):
        err = '<p class="error">Wrong credentials.</p>'
        return web.Response(text=_tpl("login.html", error=err), content_type="text/html", status=401)
    tok = _new_session(username, user["role"]); resp = web.HTTPFound("/")
    _set_cookie(resp, tok); return resp

async def handle_register(req):
    if not get_flag("registration_open", True):
        return web.Response(text=_tpl("login.html",
            error='<p class="error">Registration is closed.</p>'),
            content_type="text/html", status=403)
    if not _rate_ok(req.remote): return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = re.sub(r"[^\w.\-]", "", (data.get("username") or "")).strip()
    password = data.get("pass", "")
    if not username or len(password) < 6:
        err = '<p class="error">Username required; password must be ≥ 6 chars.</p>'
        return web.Response(text=_tpl("login.html", error=err), content_type="text/html", status=400)
    db = _load_users()
    if username in db["users"]:
        err = '<p class="error">Username already taken.</p>'
        return web.Response(text=_tpl("login.html", error=err), content_type="text/html", status=409)
    db["users"][username] = {"pw_hash": _pw_hash(password), "role": "user"}
    _save_users(db); tok = _new_session(username, "user"); resp = web.HTTPFound("/")
    _set_cookie(resp, tok); return resp

async def handle_logout(req):
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    resp = web.HTTPFound("/"); resp.del_cookie(COOKIE_NAME); return resp

async def handle_session(req):
    if not _check(req):
        return web.json_response({"admin": False, "can_write": False,
                                  "torrent_enabled": False, "username": None,
                                  "registration_open": get_flag("registration_open", True)})
    user = _who(req); is_admin = _is_admin(req)
    db = _load_users(); avatar = db["users"].get(user, {}).get("avatar")
    return web.json_response({
        "admin": is_admin, "can_write": True,
        "torrent_enabled": is_admin and get_flag("torrent_enabled", False),
        "username": user, "avatar": avatar,
        "registration_open": get_flag("registration_open", True),
    })

async def handle_files(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path", ""); base = _safe_dir(rel)
    if base is None or not base.exists():
        return web.json_response({"error": "not found"}, status=404)
    user = _who(req); is_admin = _is_admin(req); meta = _load_meta()
    files, dirs = [], []
    try:
        for e in os.scandir(base):
            st = e.stat(follow_symlinks=False)
            if e.is_dir(follow_symlinks=False):
                dirs.append({"name": e.name, "type": "dir", "size": 0, "mtime": int(st.st_mtime)})
            elif e.is_file(follow_symlinks=False):
                rp = str(Path(e.path).relative_to(DOWNLOADS_DIR))
                owner = meta.get(e.name)
                files.append({"name": e.name, "rel": rp, "type": "file",
                              "size": st.st_size, "mtime": int(st.st_mtime),
                              "owner": owner, "can_modify": is_admin or owner == user})
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"dirs": dirs, "files": files, "path": rel})

async def handle_delete(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/")
    fname = Path(rel).name
    if not _can_modify(req, fname):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    try:
        path.unlink(); m = _load_meta(); m.pop(fname, None); _save_meta(m)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True})

async def handle_rename(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body     = await req.json()
        old_rel  = body.get("old", "").lstrip("/")          # relative path from downloads root
        new_name = _sanitize_filename(body.get("new", ""))  # just a filename, no slashes
        if not old_rel or not new_name: raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    old_name = Path(old_rel).name
    if not _can_modify(req, old_name):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    if _is_blocked(new_name):
        return web.json_response({"error": "file type not allowed"}, status=400)
    src = _safe(old_rel)
    if src is None: raise web.HTTPNotFound()
    dst = src.parent / new_name   # rename within same directory
    if dst.exists(): return web.json_response({"error": "name already taken"}, status=409)
    try:
        src.rename(dst); m = _load_meta()
        if old_name in m: m[new_name] = m.pop(old_name); _save_meta(m)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": new_name})

async def handle_upload(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    username = _who(req)
    try:
        reader = await req.multipart(); field = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        filename = _sanitize_filename(field.filename or "upload")
        if _is_blocked(filename):
            return web.json_response({"error": "executable file types are not allowed"}, status=400)
        dest = DOWNLOADS_DIR / filename; tmp = dest.with_suffix(dest.suffix + ".part")
        received = 0
        try:
            with open(tmp, "wb") as f:
                while chunk := await field.read_chunk(65536):
                    received += len(chunk)
                    if received > MAX_UPLOAD_BYTES:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "file too large"}, status=413)
                    f.write(chunk)
            tmp.rename(dest); _set_owner(filename, username)
        except Exception: tmp.unlink(missing_ok=True); raise
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": filename})

async def handle_download(req):
    if not _check(req): raise web.HTTPFound("/")
    rel = req.match_info["tail"].lstrip("/")
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, path.name)

async def handle_token_download(req):
    tok = req.match_info["token"]
    rel = req.match_info["tail"].lstrip("/")
    if not verify_dl_token(tok, rel): raise web.HTTPForbidden()
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, path.name)

async def handle_make_token(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/")
    if _safe(rel) is None: raise web.HTTPNotFound()
    return web.json_response({"url": f"/get/{make_dl_token(rel)}/{rel}"})

async def handle_torrent(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not get_flag("torrent_enabled", False):
        return web.json_response({"error": "torrent downloads are disabled"}, status=403)
    ct = req.content_type or ""
    if "multipart" in ct:
        try:
            reader = await req.multipart(); field = await reader.next()
            if field is None or field.name != "file": raise ValueError("missing file field")
            data = await field.read(decode=True)
            if not data: raise ValueError("empty file")
        except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
        fd, tmp_path = tempfile.mkstemp(suffix=".torrent")
        try:
            with os.fdopen(fd, "wb") as f: f.write(data)
            proc = subprocess.Popen(
                ["aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
                 "--max-connection-per-server=4","--split=4","--seed-time=0",tmp_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        except FileNotFoundError: return web.json_response({"error": "aria2c not found"}, status=500)
        except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
        _torrent_jobs[proc.pid] = {
            "status": "starting", "progress": 0, "speed": 0, "eta": -1,
            "total": 0, "done": 0, "name": "torrent file", "started": time.time(), "log": "",
        }
        asyncio.create_task(_watch_torrent(proc.pid, proc))
        return web.json_response({"ok": True, "pid": proc.pid})
    try:
        body = await req.json(); uri = (body.get("uri") or "").strip()
        if not uri: raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    if not (uri.lower().startswith("magnet:") or uri.lower().endswith(".torrent")):
        return web.json_response({"error": "not a magnet link or .torrent URL"}, status=400)
    name = uri
    if "dn=" in uri:
        m = re.search(r"dn=([^&]+)", uri)
        if m: name = urllib.parse.unquote_plus(m.group(1))
    elif "/" in uri: name = uri.rsplit("/", 1)[-1]
    try:
        proc = subprocess.Popen(
            ["aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
             "--max-connection-per-server=4","--split=4","--seed-time=0",uri],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        _torrent_jobs[proc.pid] = {
            "status": "starting", "progress": 0, "speed": 0, "eta": -1,
            "total": 0, "done": 0, "name": name[:120], "started": time.time(), "log": "",
        }
        asyncio.create_task(_watch_torrent(proc.pid, proc))
        return web.json_response({"ok": True, "pid": proc.pid})
    except FileNotFoundError: return web.json_response({"error": "aria2c not found"}, status=500)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def _watch_torrent(pid, proc):
    """Background task: read aria2c stdout and parse progress."""
    job = _torrent_jobs.get(pid)
    if not job: return
    log_buf = ""
    loop = asyncio.get_event_loop()
    try:
        while True:
            line = await loop.run_in_executor(None, proc.stdout.readline)
            if not line: break
            text = line.decode(errors="replace").rstrip()
            log_buf += text + "\n"
            job["log"] = log_buf[-3000:]
            # Parse aria2c progress output
            # Format: [#abc 1.0MiB/10MiB(10%) CN:4 DL:500KiB ETA:18s]
            m = re.search(r"\((\d+)%\)", text)
            if m: job["progress"] = int(m.group(1)); job["status"] = "downloading"
            m = re.search(r"DL:([\d.]+\s*\w+)", text)
            if m: job["speed_str"] = m.group(1).replace(" ","")
            m = re.search(r"ETA:(\S+)", text)
            if m: job["eta_str"] = m.group(1)
            m = re.search(r"([\d.]+\s*\w+)/([\d.]+\s*\w+)\(", text)
            if m: job["done_str"] = m.group(1).strip(); job["total_str"] = m.group(2).strip()
    except Exception:
        pass
    ret = await loop.run_in_executor(None, proc.wait)
    if job["status"] not in ("cancelled",):
        job["status"]   = "done" if ret == 0 else "failed"
        job["progress"] = 100    if ret == 0 else job["progress"]
        if ret != 0 and not job.get("error"):
            job["error"] = log_buf[-400:] or f"aria2c exit {ret}"

async def handle_torrent_progress(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    return web.json_response(dict(_torrent_jobs))

async def handle_torrent_cancel(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    try: pid = int(req.match_info["pid"])
    except Exception: return web.json_response({"error": "bad pid"}, status=400)
    job = _torrent_jobs.get(pid)
    if not job: return web.json_response({"error": "not found"}, status=404)
    try: os.kill(pid, 15)
    except Exception: pass
    job["status"] = "cancelled"
    return web.json_response({"ok": True})

async def handle_fetch_url(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json(); url = (body.get("url") or "").strip()
        if not url: raise ValueError("missing url")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return web.json_response({"error": "only http/https URLs supported"}, status=400)
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    raw_name = parsed.path.rsplit("/", 1)[-1] or "download"
    raw_name = urllib.parse.unquote(raw_name)
    filename = _sanitize_filename(raw_name)
    if _is_blocked(filename):
        return web.json_response({"error": "file type not allowed"}, status=400)
    dest = DOWNLOADS_DIR / filename
    if dest.exists():
        for jid, j in _fetch_jobs.items():
            if j.get("name") == filename and j["status"] not in ("done","failed","cancelled"):
                return web.json_response({"error": "already downloading this file", "job_id": jid}, status=409)
        return web.json_response({
            "error": f'"{filename}" already exists. Rename or delete it first.',
            "duplicate": True}, status=409)
    # HEAD check
    try:
        timeout = ClientTimeout(connect=10, total=15)
        async with ClientSession(timeout=timeout) as sess:
            async with sess.head(url, allow_redirects=True) as hr:
                cl = int(hr.headers.get("Content-Length", 0))
                if cl > MAX_FETCH_BYTES:
                    mb = MAX_FETCH_BYTES // 1024 // 1024
                    return web.json_response({"error": f"File too large (>{mb} MB limit)"}, status=413)
    except Exception: pass
    job_id = secrets.token_hex(8); username = _who(req)
    _fetch_jobs[job_id] = {
        "status": "starting", "progress": 0, "speed": 0, "eta": -1,
        "total": 0, "done": 0, "name": filename, "url": url,
        "started": time.time(), "error": None, "category": _cat_from_ext(filename),
        "owner": username,
    }
    asyncio.create_task(_run_fetch(job_id, url, filename, username))
    return web.json_response({"ok": True, "job_id": job_id, "name": filename})

async def handle_fetch_progress(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    user = _who(req)
    if _is_admin(req):
        return web.json_response(dict(_fetch_jobs))
    # Regular users see only their own jobs
    own = {jid: j for jid, j in _fetch_jobs.items() if j.get("owner") == user}
    return web.json_response(own)

async def handle_fetch_cancel(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    job_id = req.match_info["job_id"]; job = _fetch_jobs.get(job_id)
    if not job: return web.json_response({"error": "not found"}, status=404)
    if not _is_admin(req) and job.get("owner") != _who(req):
        return web.json_response({"error": "forbidden"}, status=403)
    job["cancelled"] = True; job["status"] = "cancelled"
    return web.json_response({"ok": True})

async def handle_fetch_retry(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    job_id = req.match_info["job_id"]; old = _fetch_jobs.get(job_id)
    if not old or old["status"] not in ("failed","cancelled"):
        return web.json_response({"error": "job not retryable"}, status=400)
    username = _who(req)
    if not _is_admin(req) and old.get("owner") != username:
        return web.json_response({"error": "forbidden"}, status=403)
    url = old["url"]; filename = old["name"]
    new_id = secrets.token_hex(8)
    _fetch_jobs[new_id] = {
        "status": "starting", "progress": 0, "speed": 0, "eta": -1,
        "total": 0, "done": 0, "name": filename, "url": url,
        "started": time.time(), "error": None, "category": old.get("category","other"),
        "owner": username,
    }
    asyncio.create_task(_run_fetch(new_id, url, filename, username))
    return web.json_response({"ok": True, "job_id": new_id})

async def handle_flag_get(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response(dict(_flags_cache))

async def handle_flag_set(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await req.json()
        if not isinstance(body, dict): raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    for k, v in body.items(): set_flag(str(k), v)
    return web.json_response({"ok": True, "flags": dict(_flags_cache)})

async def handle_admin_users(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    db = _load_users()
    return web.json_response({u: {"role": d["role"], "avatar": d.get("avatar")}
                               for u, d in db["users"].items()})

async def handle_admin_user_delete(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info["username"]
    if username == _who(req):
        return web.json_response({"error": "cannot delete yourself"}, status=400)
    db = _load_users()
    if username not in db["users"] or db["users"][username].get("role") == "admin":
        return web.json_response({"error": "not found or protected"}, status=404)
    db["users"].pop(username); _save_users(db)
    return web.json_response({"ok": True})

async def handle_avatar_upload(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = _who(req)
    try:
        reader = await req.multipart(); field = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        data = await field.read(decode=True)
        if len(data) > 2 * 1024 * 1024:
            return web.json_response({"error": "avatar too large (max 2 MB)"}, status=413)
        ext = Path(field.filename or "avatar.png").suffix.lower().lstrip(".")
        if ext not in ("jpg","jpeg","png","gif","webp"):
            return web.json_response({"error": "image files only"}, status=400)
        mime = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png",
                "gif":"image/gif","webp":"image/webp"}.get(ext,"image/png")
        data_url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
        db = _load_users(); db["users"][username]["avatar"] = data_url; _save_users(db)
        return web.json_response({"ok": True, "avatar": data_url})
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def handle_static(req):
    name = req.match_info["name"]
    path = (STATIC_DIR / name).resolve()
    if not str(path).startswith(str(STATIC_DIR)) or not path.is_file():
        raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    return web.Response(body=path.read_bytes(), content_type=ct or "application/octet-stream")


def create_app():
    app = web.Application(client_max_size=MAX_UPLOAD_BYTES + 65536)
    r = app.router
    r.add_get   ("/",                          handle_root)
    r.add_post  ("/login",                     handle_login)
    r.add_post  ("/register",                  handle_register)
    r.add_post  ("/logout",                    handle_logout)
    r.add_get   ("/session",                   handle_session)
    r.add_get   ("/files",                     handle_files)
    r.add_route ("DELETE", "/files/{tail:.*}", handle_delete)
    r.add_post  ("/rename",                    handle_rename)
    r.add_post  ("/upload",                    handle_upload)
    r.add_post  ("/torrent",                   handle_torrent)
    r.add_get   ("/torrent/progress",          handle_torrent_progress)
    r.add_post  ("/torrent/{pid}/cancel",      handle_torrent_cancel)
    r.add_post  ("/fetch",                     handle_fetch_url)
    r.add_get   ("/fetch/progress",            handle_fetch_progress)
    r.add_post  ("/fetch/{job_id}/cancel",     handle_fetch_cancel)
    r.add_post  ("/fetch/{job_id}/retry",      handle_fetch_retry)
    r.add_get   ("/flags",                     handle_flag_get)
    r.add_post  ("/flags",                     handle_flag_set)
    r.add_get   ("/token/{tail:.*}",           handle_make_token)
    r.add_get   ("/get/{token}/{tail:.*}",     handle_token_download)
    r.add_get   ("/dl/{tail:.*}",              handle_download)
    r.add_get   ("/admin/users",               handle_admin_users)
    r.add_delete("/admin/users/{username}",    handle_admin_user_delete)
    r.add_post  ("/admin/avatar",              handle_avatar_upload)
    r.add_get   ("/static/{name}",             handle_static)
    return app

async def start_web():
    runner = web.AppRunner(create_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", WEB_PORT).start()
    base = os.environ.get("WEB_BASE", f"http://localhost:{WEB_PORT}")
    print(f"web: {base}")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start_web())
    loop.run_forever()
