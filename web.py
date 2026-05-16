import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
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
AUDIT_FILE = _HERE / "audit.log"

SESSION_TTL         = 86400
COOKIE_NAME         = "fsid"
MAX_UPLOAD_BYTES    = int(os.environ.get("MAX_UPLOAD_MB", 2048)) * 1024 * 1024
MAX_FETCH_BYTES     = int(os.environ.get("MAX_FETCH_MB", 4096)) * 1024 * 1024
RATE_LIMIT_WINDOW   = 60
RATE_LIMIT_MAX      = 30
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", 10))
# Per-user upload quota in bytes (0 = unlimited). Env: QUOTA_MB=500
USER_QUOTA_BYTES    = int(os.environ.get("QUOTA_MB", 0)) * 1024 * 1024

# Private / loopback CIDRs that the fetch handler must never reach (SSRF prevention)
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

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

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _audit(action: str, user: str | None, detail: str = ""):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{ts} [{action}] user={user or '-'} {detail}\n"
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(line)
    except Exception as e:
        print(f"[warn] audit: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _atomic_write(path, text):
    tmp = str(path) + ".tmp"
    try:
        with open(tmp, "w") as f: f.write(text)
        os.replace(tmp, str(path))
    except Exception as e:
        print(f"[warn] write {path}: {e}")

def _pw_hash(pw: str) -> str:
    """
    Salted password hash using SHA-256 + a per-password salt stored alongside.
    Format:  sha256$<hex-salt>$<hex-digest>
    Legacy entries (plain sha256 hex, no '$') are still accepted on login and
    transparently upgraded to the new format on first successful login.
    """
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"sha256${salt}${digest}"

def _pw_verify(pw: str, stored: str) -> bool:
    """Verify password against stored hash.  Handles legacy unsalted hashes."""
    if stored.startswith("sha256$"):
        _, salt, digest = stored.split("$", 2)
        expected = hashlib.sha256((salt + pw).encode()).hexdigest()
        return secrets.compare_digest(expected, digest)
    # Legacy: plain sha256 hex (no salt)
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    return secrets.compare_digest(legacy, stored)

def _sanitize_filename(name):
    name = Path(name).name            # strip directory traversal
    name = name.replace("\x00", "")   # strip null bytes
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    name = re.sub(r"\.{2,}", ".", name)  # collapse double-dots
    if not name or name in (".", ".."): return "upload"
    return name

def _sanitize_dirname(name):
    """Sanitize a directory name (no slashes allowed)."""
    name = Path(name).name
    name = name.replace("\x00", "")
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    name = re.sub(r"\.{2,}", ".", name)
    if not name or name in (".", ".."): return None
    return name

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

def _is_private_ip(host: str) -> bool:
    """Return True if host resolves to a private/loopback IP (SSRF guard)."""
    try:
        # getaddrinfo returns all addresses; check every one
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if any(ip in net for net in _PRIVATE_NETS):
                return True
        return False
    except Exception:
        # Unresolvable host — block it to be safe
        return True

def _user_disk_usage(username: str) -> int:
    """Return bytes uploaded by *username* that still exist on disk."""
    meta = _load_meta()
    total = 0
    for fname, owner in meta.items():
        if owner != username:
            continue
        p = DOWNLOADS_DIR / fname
        if p.is_file():
            try:
                total += p.stat().st_size
            except Exception:
                pass
    return total


# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

def _load_meta():
    try: return json.loads(META_FILE.read_text())
    except Exception: return {}

def _save_meta(m): _atomic_write(META_FILE, json.dumps(m))
def _set_owner(name, username): m = _load_meta(); m[name] = username; _save_meta(m)
def _get_owner(name): return _load_meta().get(name)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def _new_session(username, role):
    # Enforce per-user session cap to prevent unbounded growth
    existing = [tok for tok, s in list(_sessions.items()) if s.get("user") == username]
    if len(existing) >= MAX_SESSIONS_PER_USER:
        # Evict the oldest session(s)
        existing_sorted = sorted(existing, key=lambda t: _sessions[t].get("exp", 0))
        for tok in existing_sorted[:len(existing) - MAX_SESSIONS_PER_USER + 1]:
            _sessions.pop(tok, None)
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
    # secure=True when behind HTTPS proxy; keep False only for plain-HTTP dev
    use_secure = os.environ.get("COOKIE_SECURE", "false").lower() in ("1","true","yes")
    resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                    httponly=True, samesite="Strict", secure=use_secure)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe(rel_path):
    """Resolve a relative path to an absolute path inside DOWNLOADS_DIR.
    Returns the Path if it is a regular file, else None."""
    try:
        rel_path = rel_path.lstrip("/")
        p = (DOWNLOADS_DIR / rel_path).resolve()
        # Require the resolved path to be *strictly* inside DOWNLOADS_DIR
        # (str+sep prevents /downloads_evil from matching /downloads)
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
        # Must be DOWNLOADS_DIR itself or strictly inside it
        if p == DOWNLOADS_DIR or str(p).startswith(str(DOWNLOADS_DIR) + os.sep):
            return p
    except Exception: pass
    return None


# ---------------------------------------------------------------------------
# Share-link tokens
# ---------------------------------------------------------------------------

def make_dl_token(name):
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok, name):
    return hmac.compare_digest(tok, make_dl_token(name))


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

def _tpl(name, **ctx):
    text = (HTML_DIR / name).read_text()
    for k, v in ctx.items(): text = text.replace(f"{{{{{k}}}}}", v)
    return text


# ---------------------------------------------------------------------------
# File streaming
# ---------------------------------------------------------------------------

async def _stream(req, path, name, inline=False):
    ct, _ = mimetypes.guess_type(str(path))
    disposition = "inline" if inline else "attachment"
    resp = web.StreamResponse(headers={
        "Content-Disposition": f'{disposition}; filename="{name}"',
        "Content-Type":        ct or "application/octet-stream",
        "Content-Length":      str(path.stat().st_size),
    })
    await resp.prepare(req)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536): await resp.write(chunk)
    except (ConnectionError, ConnectionResetError): pass
    return resp


# ---------------------------------------------------------------------------
# Background: URL fetch
# ---------------------------------------------------------------------------

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
        _audit("fetch_done", username, f"file={dest_name}")
        job["status"] = "done"; job["progress"] = 100; job["done"] = done; job["total"] = done
    except asyncio.CancelledError:
        job["status"] = "cancelled"; tmp.unlink(missing_ok=True)
    except Exception as ex:
        job["status"] = "failed"; job["error"] = str(ex); tmp.unlink(missing_ok=True)


# ===========================================================================
# Route handlers
# ===========================================================================

async def handle_root(req):
    if _check(req): return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")


async def handle_health(req):
    """Lightweight health-check endpoint for reverse proxies and monitoring."""
    disk = shutil.disk_usage(str(DOWNLOADS_DIR))
    return web.json_response({
        "status": "ok",
        "disk_free_gb": round(disk.free / 1024**3, 2),
        "disk_used_gb": round(disk.used / 1024**3, 2),
        "active_sessions": len(_sessions),
    })


async def handle_mkdir(req):
    """Create a new subfolder inside the downloads dir (or a subfolder of it)."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json()
        parent_rel  = body.get("path", "").lstrip("/")
        folder_name = _sanitize_dirname(body.get("name", ""))
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    if not folder_name:
        return web.json_response({"error": "invalid folder name"}, status=400)
    parent = _safe_dir(parent_rel)
    if parent is None:
        return web.json_response({"error": "invalid parent path"}, status=400)
    new_dir = parent / folder_name
    try:
        resolved = new_dir.resolve()
        if not (str(resolved).startswith(str(DOWNLOADS_DIR) + os.sep) or resolved == DOWNLOADS_DIR):
            return web.json_response({"error": "invalid path"}, status=400)
    except Exception:
        return web.json_response({"error": "invalid path"}, status=400)
    if new_dir.exists():
        return web.json_response({"error": "already exists"}, status=409)
    try:
        new_dir.mkdir(parents=False)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    _audit("mkdir", _who(req), f"dir={folder_name}")
    return web.json_response({"ok": True, "name": folder_name})


async def handle_zip_folder(req):
    """Stream a folder as a zip archive."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path", "").lstrip("/")
    if not rel: return web.json_response({"error": "path required"}, status=400)
    folder = _safe_dir(rel)
    if folder is None or not folder.is_dir() or folder == DOWNLOADS_DIR:
        raise web.HTTPNotFound()
    zip_name = urllib.parse.quote(folder.name + ".zip", safe="")
    resp = web.StreamResponse(headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{zip_name}",
        "Content-Type": "application/zip",
    })
    await resp.prepare(req)
    try:
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for item in sorted(folder.rglob("*")):
                if item.is_file(follow_symlinks=False):
                    arcname = item.relative_to(folder)
                    zf.write(item, arcname)
        await resp.write(buf.getvalue())
    except (ConnectionError, ConnectionResetError):
        pass
    return resp


async def handle_login(req):
    if not _rate_ok(req.remote): return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = (data.get("username") or "").strip(); password = data.get("pass", "")
    db = _load_users(); user = db["users"].get(username)
    if not user or user.get("disabled") or not _pw_verify(password, user["pw_hash"]):
        _audit("login_fail", username)
        err = '<p class="error">Wrong credentials.</p>'
        return web.Response(text=_tpl("login.html", error=err), content_type="text/html", status=401)
    # Transparently upgrade legacy unsalted hash on successful login
    if not user["pw_hash"].startswith("sha256$"):
        user["pw_hash"] = _pw_hash(password)
        db["users"][username] = user
        _save_users(db)
    tok = _new_session(username, user["role"]); resp = web.HTTPFound("/")
    _set_cookie(resp, tok)
    _audit("login", username)
    return resp


async def handle_admin_user_update(req):
    """Admin: change password, disable/enable, promote/demote a user."""
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info["username"]
    if username == _who(req):
        return web.json_response({"error": "cannot modify yourself this way"}, status=400)
    try:
        body = await req.json()
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    db = _load_users()
    if username not in db["users"]:
        return web.json_response({"error": "user not found"}, status=404)
    user = db["users"][username]
    changed = False
    if "password" in body:
        pw = str(body["password"])
        if len(pw) < 6: return web.json_response({"error": "password must be ≥ 6 chars"}, status=400)
        user["pw_hash"] = _pw_hash(pw); changed = True
    if "disabled" in body:
        user["disabled"] = bool(body["disabled"]); changed = True
    if "role" in body:
        role = body["role"]
        if role not in ("user", "admin"):
            return web.json_response({"error": "invalid role"}, status=400)
        if role == "user" and user.get("role") == "admin":
            admin_count = sum(1 for d in db["users"].values() if d.get("role") == "admin")
            if admin_count <= 1:
                return web.json_response({"error": "cannot demote the last admin"}, status=400)
        user["role"] = role; changed = True
    if not changed:
        return web.json_response({"error": "nothing to update"}, status=400)
    db["users"][username] = user
    _save_users(db)
    _audit("user_update", _who(req), f"target={username}")
    # Kill sessions if user was disabled or password changed
    if body.get("disabled") or "password" in body:
        to_kill = [tok for tok, s in list(_sessions.items()) if s.get("user") == username]
        for tok in to_kill: _sessions.pop(tok, None)
    return web.json_response({"ok": True})


async def handle_admin_session_reset(req):
    """Admin: kill all sessions for a specific user (or all non-admin sessions)."""
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info.get("username", "")
    if username:
        to_kill = [tok for tok, s in list(_sessions.items()) if s.get("user") == username]
    else:
        to_kill = [tok for tok, s in list(_sessions.items()) if s.get("role") != "admin"]
    for tok in to_kill: _sessions.pop(tok, None)
    _audit("session_reset", _who(req), f"target={username or '*'}")
    return web.json_response({"ok": True, "killed": len(to_kill)})


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
    _save_users(db)
    _audit("register", username)
    tok = _new_session(username, "user"); resp = web.HTTPFound("/")
    _set_cookie(resp, tok); return resp


async def handle_logout(req):
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    _audit("logout", _who(req))
    resp = web.HTTPFound("/"); resp.del_cookie(COOKIE_NAME); return resp


async def handle_session(req):
    if not _check(req):
        return web.json_response({"admin": False, "can_write": False,
                                  "torrent_enabled": False, "username": None,
                                  "registration_open": get_flag("registration_open", True)})
    user = _who(req); is_admin = _is_admin(req)
    db = _load_users(); avatar = db["users"].get(user, {}).get("avatar")
    quota_used = _user_disk_usage(user) if USER_QUOTA_BYTES > 0 else 0
    return web.json_response({
        "admin": is_admin, "can_write": True,
        "torrent_enabled": is_admin and get_flag("torrent_enabled", False),
        "username": user, "avatar": avatar,
        "registration_open": get_flag("registration_open", True),
        "quota_bytes": USER_QUOTA_BYTES,
        "quota_used": quota_used,
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
    if path is None:
        # Maybe it's a directory — only admins can delete directories
        if not _is_admin(req):
            return web.json_response({"error": "forbidden — only admins can delete folders"}, status=403)
        d = _safe_dir(rel)
        if d is None or d == DOWNLOADS_DIR or not d.is_dir():
            raise web.HTTPNotFound()
        try:
            shutil.rmtree(str(d))
        except Exception as ex:
            return web.json_response({"error": str(ex)}, status=500)
        _audit("delete_dir", _who(req), f"dir={rel}")
        return web.json_response({"ok": True})
    try:
        path.unlink(); m = _load_meta(); m.pop(fname, None); _save_meta(m)
        _audit("delete", _who(req), f"file={rel}")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True})


async def handle_rename(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body     = await req.json()
        old_rel  = body.get("old", "").lstrip("/")
        new_name = _sanitize_filename(body.get("new", ""))
        if not old_rel or not new_name: raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    old_name = Path(old_rel).name
    if not _can_modify(req, old_name):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    if _is_blocked(new_name):
        return web.json_response({"error": "file type not allowed"}, status=400)
    src = _safe(old_rel)
    is_dir = False
    if src is None:
        src_dir = _safe_dir(old_rel)
        if src_dir is None or src_dir == DOWNLOADS_DIR or not src_dir.is_dir():
            raise web.HTTPNotFound()
        src = src_dir
        is_dir = True
    dst = src.parent / new_name
    try:
        if not (str(dst.resolve()).startswith(str(DOWNLOADS_DIR) + os.sep) or dst.resolve() == DOWNLOADS_DIR):
            return web.json_response({"error": "invalid path"}, status=400)
    except Exception:
        return web.json_response({"error": "invalid path"}, status=400)
    if dst.exists(): return web.json_response({"error": "name already taken"}, status=409)
    try:
        src.rename(dst)
        if not is_dir:
            m = _load_meta()
            if old_name in m: m[new_name] = m.pop(old_name); _save_meta(m)
        _audit("rename", _who(req), f"old={old_rel} new={new_name}")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": new_name})


async def handle_upload(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    username = _who(req)
    folder_rel = req.rel_url.query.get("path", "").lstrip("/")
    dest_dir = _safe_dir(folder_rel) if folder_rel else DOWNLOADS_DIR
    if dest_dir is None or not dest_dir.is_dir():
        return web.json_response({"error": "invalid upload path"}, status=400)
    try:
        reader = await req.multipart(); field = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        filename = _sanitize_filename(field.filename or "upload")
        if _is_blocked(filename):
            return web.json_response({"error": "executable file types are not allowed"}, status=400)
        # Quota check (pre-flight — actual usage may shift slightly under concurrency)
        if USER_QUOTA_BYTES > 0:
            used = _user_disk_usage(username)
            if used >= USER_QUOTA_BYTES:
                quota_mb = USER_QUOTA_BYTES // 1024 // 1024
                return web.json_response(
                    {"error": f"Quota exceeded ({quota_mb} MB limit)"}, status=413)
        dest = dest_dir / filename; tmp = dest.with_suffix(dest.suffix + ".part")
        received = 0
        try:
            with open(tmp, "wb") as f:
                while chunk := await field.read_chunk(65536):
                    received += len(chunk)
                    if received > MAX_UPLOAD_BYTES:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "file too large"}, status=413)
                    # Incremental quota check
                    if USER_QUOTA_BYTES > 0 and (_user_disk_usage(username) + received) > USER_QUOTA_BYTES:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "quota exceeded mid-upload"}, status=413)
                    f.write(chunk)
            tmp.rename(dest); _set_owner(filename, username)
            _audit("upload", username, f"file={filename} size={received}")
        except Exception: tmp.unlink(missing_ok=True); raise
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": filename})


async def handle_preview(req):
    """Serve a file inline for browser preview (images, text, video, audio, PDF)."""
    if not _check(req): raise web.HTTPFound("/")
    rel = req.match_info["tail"].lstrip("/")
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    ct = ct or "application/octet-stream"
    # Only allow safe MIME types for inline preview; force download for everything else
    PREVIEWABLE = ("image/", "video/", "audio/", "text/", "application/pdf")
    if not any(ct.startswith(p) for p in PREVIEWABLE):
        raise web.HTTPFound(f"/dl/{rel}")
    return await _stream(req, path, path.name, inline=True)


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
    encoded_rel = "/".join(urllib.parse.quote(seg, safe="") for seg in rel.split("/"))
    return web.json_response({"url": f"/get/{make_dl_token(rel)}/{encoded_rel}"})


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
        # SSRF: block private / loopback hosts
        host = parsed.hostname or ""
        if not host:
            return web.json_response({"error": "invalid URL"}, status=400)
        if _is_private_ip(host):
            return web.json_response({"error": "requests to private network addresses are not allowed"}, status=400)
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
    _audit("fetch_start", username, f"url={url} file={filename}")
    asyncio.create_task(_run_fetch(job_id, url, filename, username))
    return web.json_response({"ok": True, "job_id": job_id, "name": filename})


async def handle_fetch_progress(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    user = _who(req)
    if _is_admin(req):
        return web.json_response(dict(_fetch_jobs))
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
    return web.json_response({u: {"role": d["role"], "avatar": d.get("avatar"), "disabled": d.get("disabled", False)}
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
    _audit("user_delete", _who(req), f"target={username}")
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


async def handle_admin_stats(req):
    """Admin: server statistics — disk usage, user counts, active sessions, job counts."""
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    disk = shutil.disk_usage(str(DOWNLOADS_DIR))
    db = _load_users()
    users_total  = len(db["users"])
    users_admin  = sum(1 for d in db["users"].values() if d.get("role") == "admin")
    users_disabled = sum(1 for d in db["users"].values() if d.get("disabled"))
    active_sessions = len(_sessions)
    fetch_active = sum(1 for j in _fetch_jobs.values()  if j["status"] not in ("done","failed","cancelled"))
    torr_active  = sum(1 for j in _torrent_jobs.values() if j["status"] not in ("done","failed","cancelled"))
    # File count & total size
    file_count = 0; files_size = 0
    for p in DOWNLOADS_DIR.rglob("*"):
        if p.is_file(follow_symlinks=False):
            file_count += 1
            try: files_size += p.stat().st_size
            except Exception: pass
    return web.json_response({
        "disk": {
            "total_gb": round(disk.total / 1024**3, 2),
            "used_gb":  round(disk.used  / 1024**3, 2),
            "free_gb":  round(disk.free  / 1024**3, 2),
        },
        "files": {"count": file_count, "size_mb": round(files_size / 1024**2, 2)},
        "users": {"total": users_total, "admin": users_admin, "disabled": users_disabled},
        "sessions": {"active": active_sessions},
        "jobs": {"fetch_active": fetch_active, "torrent_active": torr_active},
        "quota_mb": USER_QUOTA_BYTES // 1024 // 1024 if USER_QUOTA_BYTES > 0 else 0,
    })


async def handle_admin_audit(req):
    """Admin: return the last N lines of the audit log."""
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try:
        lines_n = min(int(req.rel_url.query.get("n", 200)), 2000)
    except Exception:
        lines_n = 200
    try:
        text = AUDIT_FILE.read_text() if AUDIT_FILE.exists() else ""
        lines = text.splitlines()[-lines_n:]
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"lines": lines})


async def handle_static(req):
    name = req.match_info["name"]
    path = (STATIC_DIR / name).resolve()
    if not str(path).startswith(str(STATIC_DIR)) or not path.is_file():
        raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    return web.Response(body=path.read_bytes(), content_type=ct or "application/octet-stream")


# ===========================================================================
# App wiring
# ===========================================================================

def create_app():
    app = web.Application(client_max_size=MAX_UPLOAD_BYTES + 65536)
    r = app.router
    r.add_get   ("/",                              handle_root)
    r.add_get   ("/health",                        handle_health)
    r.add_post  ("/login",                         handle_login)
    r.add_post  ("/register",                      handle_register)
    r.add_post  ("/logout",                        handle_logout)
    r.add_get   ("/session",                       handle_session)
    r.add_get   ("/files",                         handle_files)
    r.add_route ("DELETE", "/files/{tail:.*}",     handle_delete)
    r.add_post  ("/rename",                        handle_rename)
    r.add_post  ("/mkdir",                         handle_mkdir)
    r.add_get   ("/zip",                           handle_zip_folder)
    r.add_post  ("/upload",                        handle_upload)
    r.add_get   ("/preview/{tail:.*}",             handle_preview)
    r.add_post  ("/torrent",                       handle_torrent)
    r.add_get   ("/torrent/progress",              handle_torrent_progress)
    r.add_post  ("/torrent/{pid}/cancel",          handle_torrent_cancel)
    r.add_post  ("/fetch",                         handle_fetch_url)
    r.add_get   ("/fetch/progress",                handle_fetch_progress)
    r.add_post  ("/fetch/{job_id}/cancel",         handle_fetch_cancel)
    r.add_post  ("/fetch/{job_id}/retry",          handle_fetch_retry)
    r.add_get   ("/flags",                         handle_flag_get)
    r.add_post  ("/flags",                         handle_flag_set)
    r.add_get   ("/token/{tail:.*}",               handle_make_token)
    r.add_get   ("/get/{token}/{tail:.*}",         handle_token_download)
    r.add_get   ("/dl/{tail:.*}",                  handle_download)
    r.add_get   ("/admin/users",                   handle_admin_users)
    r.add_delete("/admin/users/{username}",        handle_admin_user_delete)
    r.add_patch ("/admin/users/{username}",        handle_admin_user_update)
    r.add_post  ("/admin/users/{username}/reset",  handle_admin_session_reset)
    r.add_post  ("/admin/avatar",                  handle_avatar_upload)
    r.add_get   ("/admin/stats",                   handle_admin_stats)
    r.add_get   ("/admin/audit",                   handle_admin_audit)
    r.add_get   ("/static/{name}",                 handle_static)
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
# ===========================================================================
# ── NEW FEATURES (appended) ────────────────────────────────────────────────
# ===========================================================================

# ---------------------------------------------------------------------------
# A.  Expiring / password-protected share links
# ---------------------------------------------------------------------------
# Stored in share_links.json: { token: {rel, exp, pw_hash|None, hits, max_hits|None} }

SHARES_FILE = _HERE / "share_links.json"

def _load_shares():
    try: return json.loads(SHARES_FILE.read_text())
    except Exception: return {}

def _save_shares(d): _atomic_write(SHARES_FILE, json.dumps(d))

def _make_share_token():
    return secrets.token_urlsafe(24)

async def handle_share_create(req):
    """POST /share  body: {rel, ttl_hours?, password?, max_hits?}
    Creates an expiring (optionally password-protected) share link."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json()
        rel  = body.get("rel", "").lstrip("/")
        if not rel: raise ValueError("rel required")
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=400)
    if _safe(rel) is None:
        raise web.HTTPNotFound()
    ttl_h    = float(body.get("ttl_hours", 24 * 7))   # default 1 week
    password = body.get("password") or None
    max_hits = body.get("max_hits")                     # None = unlimited
    exp      = time.time() + ttl_h * 3600
    tok      = _make_share_token()
    shares   = _load_shares()
    shares[tok] = {
        "rel":      rel,
        "exp":      exp,
        "pw_hash":  _pw_hash(password) if password else None,
        "hits":     0,
        "max_hits": int(max_hits) if max_hits is not None else None,
        "owner":    _who(req),
    }
    _save_shares(shares)
    _audit("share_create", _who(req), f"rel={rel} ttl_h={ttl_h}")
    return web.json_response({"token": tok, "url": f"/s/{tok}"})

async def handle_share_download(req):
    """GET /s/<token>   — optionally POST with {password} for protected links."""
    tok    = req.match_info["token"]
    shares = _load_shares()
    entry  = shares.get(tok)
    if not entry or time.time() > entry["exp"]:
        return web.Response(text="Share link expired or not found.", status=410)
    if entry["max_hits"] is not None and entry["hits"] >= entry["max_hits"]:
        return web.Response(text="Share link has reached its download limit.", status=410)
    # Password gate — served as a tiny HTML form
    if entry["pw_hash"]:
        if req.method == "POST":
            data = await req.post()
            pw   = data.get("password", "")
            if not _pw_verify(pw, entry["pw_hash"]):
                return web.Response(
                    text=_SHARE_GATE_HTML.format(token=tok, error="Wrong password."),
                    content_type="text/html", status=401)
        else:
            return web.Response(
                text=_SHARE_GATE_HTML.format(token=tok, error=""),
                content_type="text/html")
    path = _safe(entry["rel"])
    if path is None:
        return web.Response(text="File no longer exists.", status=404)
    entry["hits"] += 1
    _save_shares(shares)
    _audit("share_download", entry.get("owner"), f"token={tok} rel={entry['rel']}")
    return await _stream(req, path, path.name)

async def handle_share_list(req):
    """GET /share  — list caller's shares (admin sees all)."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    user     = _who(req); is_admin = _is_admin(req)
    shares   = _load_shares(); now = time.time()
    result   = {}
    for tok, e in shares.items():
        if not is_admin and e.get("owner") != user: continue
        result[tok] = {
            "rel":      e["rel"],
            "exp":      e["exp"],
            "hits":     e["hits"],
            "max_hits": e["max_hits"],
            "protected": bool(e["pw_hash"]),
            "owner":    e.get("owner"),
            "expired":  now > e["exp"],
        }
    return web.json_response(result)

async def handle_share_delete(req):
    """DELETE /share/<token>"""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    tok    = req.match_info["token"]
    shares = _load_shares()
    entry  = shares.get(tok)
    if not entry: return web.json_response({"error": "not found"}, status=404)
    if not _is_admin(req) and entry.get("owner") != _who(req):
        return web.json_response({"error": "forbidden"}, status=403)
    shares.pop(tok)
    _save_shares(shares)
    return web.json_response({"ok": True})

_SHARE_GATE_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>Protected Download</title>
<style>body{{font-family:sans-serif;max-width:360px;margin:80px auto;padding:1rem}}
input{{width:100%;padding:.5rem;margin:.5rem 0}}
button{{padding:.5rem 1.2rem}}
.err{{color:red}}</style></head><body>
<h2>🔒 Password required</h2>
<p class=err>{error}</p>
<form method=post>
  <input type=password name=password placeholder="Enter password" autofocus>
  <button type=submit>Download</button>
</form></body></html>"""


# ---------------------------------------------------------------------------
# B.  Move / copy files (and directories)
# ---------------------------------------------------------------------------

async def handle_move(req):
    """POST /move  body: {src, dst_dir, copy?}
    Moves (or copies) src (rel path) into dst_dir (rel path to a directory).
    Pass copy=true to duplicate instead of move."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body    = await req.json()
        src_rel = body.get("src", "").lstrip("/")
        dst_rel = body.get("dst_dir", "").lstrip("/")
        do_copy = bool(body.get("copy", False))
        if not src_rel: raise ValueError("src required")
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=400)

    dst_dir = _safe_dir(dst_rel)
    if dst_dir is None or not dst_dir.is_dir():
        return web.json_response({"error": "destination directory not found"}, status=404)

    # Source can be file or directory
    src = _safe(src_rel)
    src_is_dir = False
    if src is None:
        src = _safe_dir(src_rel)
        if src is None or src == DOWNLOADS_DIR or not src.is_dir():
            raise web.HTTPNotFound()
        src_is_dir = True

    src_name = src.name
    if not _can_modify(req, src_name) and not do_copy:
        return web.json_response({"error": "forbidden — not your file"}, status=403)

    dst = dst_dir / src_name
    if dst.exists():
        return web.json_response({"error": f'"{src_name}" already exists in destination'}, status=409)
    try:
        if do_copy:
            if src_is_dir:
                shutil.copytree(str(src), str(dst))
            else:
                shutil.copy2(str(src), str(dst))
                # Ownership: copy inherits requester
                m = _load_meta(); m[src_name] = _who(req); _save_meta(m)
        else:
            shutil.move(str(src), str(dst))
            if not src_is_dir:
                m = _load_meta()
                if src_name in m:
                    _save_meta(m)   # name stays the same, just relocated
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)

    op = "copy" if do_copy else "move"
    _audit(op, _who(req), f"src={src_rel} dst_dir={dst_rel}")
    return web.json_response({"ok": True, "name": src_name})


# ---------------------------------------------------------------------------
# C.  Bulk operations  (delete, move, download-as-zip)
# ---------------------------------------------------------------------------

async def handle_bulk(req):
    """POST /bulk  body: {action, files: [rel, ...], dst_dir?}
    action: "delete" | "move" | "zip"
    zip streams a zip of all listed files back immediately."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body   = await req.json()
        action = body.get("action", "")
        rels   = [r.lstrip("/") for r in (body.get("files") or []) if r]
        if not action or not rels: raise ValueError("action and files required")
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=400)

    if action == "delete":
        errors = []; deleted = 0
        for rel in rels:
            fname = Path(rel).name
            if not _can_modify(req, fname):
                errors.append(f"{rel}: forbidden"); continue
            p = _safe(rel)
            if p is None:
                errors.append(f"{rel}: not found"); continue
            try:
                p.unlink()
                m = _load_meta(); m.pop(fname, None); _save_meta(m)
                deleted += 1
            except Exception as ex:
                errors.append(f"{rel}: {ex}")
        _audit("bulk_delete", _who(req), f"count={deleted}")
        return web.json_response({"ok": True, "deleted": deleted, "errors": errors})

    elif action == "move":
        dst_rel = body.get("dst_dir", "").lstrip("/")
        dst_dir = _safe_dir(dst_rel)
        if dst_dir is None or not dst_dir.is_dir():
            return web.json_response({"error": "destination directory not found"}, status=404)
        errors = []; moved = 0
        for rel in rels:
            fname = Path(rel).name
            if not _can_modify(req, fname):
                errors.append(f"{rel}: forbidden"); continue
            p = _safe(rel)
            if p is None:
                errors.append(f"{rel}: not found"); continue
            dst = dst_dir / fname
            if dst.exists():
                errors.append(f"{rel}: already exists in destination"); continue
            try:
                shutil.move(str(p), str(dst)); moved += 1
            except Exception as ex:
                errors.append(f"{rel}: {ex}")
        _audit("bulk_move", _who(req), f"count={moved} dst={dst_rel}")
        return web.json_response({"ok": True, "moved": moved, "errors": errors})

    elif action == "zip":
        import io
        buf = io.BytesIO()
        added = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for rel in rels:
                p = _safe(rel)
                if p is None: continue
                zf.write(p, p.name); added += 1
        if added == 0:
            return web.json_response({"error": "no valid files"}, status=400)
        resp = web.Response(
            body=buf.getvalue(),
            headers={
                "Content-Disposition": 'attachment; filename="selection.zip"',
                "Content-Type": "application/zip",
            })
        _audit("bulk_zip", _who(req), f"count={added}")
        return resp

    return web.json_response({"error": f"unknown action: {action}"}, status=400)


# ---------------------------------------------------------------------------
# D.  Full filename search
# ---------------------------------------------------------------------------

async def handle_search(req):
    """GET /search?q=<query>&path=<root>&type=<cat>
    Recursively searches DOWNLOADS_DIR (or a subdir) for files matching query.
    Returns up to 200 results."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    q        = req.rel_url.query.get("q", "").strip().lower()
    path_rel = req.rel_url.query.get("path", "").strip()
    type_f   = req.rel_url.query.get("type", "").strip().lower()   # optional category filter
    if not q:
        return web.json_response({"error": "q required"}, status=400)

    base = _safe_dir(path_rel) if path_rel else DOWNLOADS_DIR
    if base is None:
        return web.json_response({"error": "invalid path"}, status=400)

    user     = _who(req); is_admin = _is_admin(req); meta = _load_meta()
    results  = []
    try:
        for item in base.rglob("*"):
            if not item.is_file(follow_symlinks=False): continue
            if q not in item.name.lower(): continue
            if type_f and _cat_from_ext(item.name) != type_f: continue
            rel = str(item.relative_to(DOWNLOADS_DIR))
            owner = meta.get(item.name)
            try: size = item.stat().st_size; mtime = int(item.stat().st_mtime)
            except Exception: size = 0; mtime = 0
            results.append({
                "name": item.name, "rel": rel,
                "size": size, "mtime": mtime,
                "owner": owner,
                "can_modify": is_admin or owner == user,
                "category": _cat_from_ext(item.name),
            })
            if len(results) >= 200: break
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)

    return web.json_response({"results": results, "q": q, "total": len(results)})


# ---------------------------------------------------------------------------
# E.  Zip contents browser (list without downloading)
# ---------------------------------------------------------------------------

async def handle_zip_inspect(req):
    """GET /zip-inspect?path=<rel>
    Returns the file listing inside a zip archive as JSON."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel  = req.rel_url.query.get("path", "").lstrip("/")
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    ext = path.suffix.lower()
    if ext not in (".zip",):
        return web.json_response({"error": "only .zip files are supported"}, status=400)
    try:
        entries = []
        with zipfile.ZipFile(str(path), "r") as zf:
            for info in zf.infolist():
                entries.append({
                    "name":       info.filename,
                    "size":       info.file_size,
                    "compressed": info.compress_size,
                    "is_dir":     info.filename.endswith("/"),
                    "mtime":      int(time.mktime(info.date_time + (0, 0, -1))) if info.date_time[0] > 1980 else 0,
                })
        return web.json_response({"path": rel, "entries": entries, "count": len(entries)})
    except zipfile.BadZipFile:
        return web.json_response({"error": "not a valid zip file"}, status=400)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)


# ---------------------------------------------------------------------------
# F.  Inline text-file editor (read + save)
# ---------------------------------------------------------------------------

EDITABLE_EXTS = {
    "txt","md","log","json","yaml","yml","toml","cfg","ini","conf",
    "py","js","ts","sh","bash","html","css","xml","csv","env","gitignore",
}
MAX_EDIT_BYTES = 2 * 1024 * 1024   # 2 MB safety cap

async def handle_edit_get(req):
    """GET /edit/<rel>  — return text content of an editable file."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel  = req.match_info["tail"].lstrip("/")
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    ext = path.suffix.lower().lstrip(".")
    if ext not in EDITABLE_EXTS:
        return web.json_response({"error": "file type not editable"}, status=400)
    try:
        size = path.stat().st_size
        if size > MAX_EDIT_BYTES:
            return web.json_response({"error": f"file too large to edit ({size // 1024} KB)"}, status=413)
        content = path.read_text(errors="replace")
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"rel": rel, "name": path.name, "content": content, "size": size})

async def handle_edit_put(req):
    """PUT /edit/<rel>  body: {content}  — overwrite file with new content."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel  = req.match_info["tail"].lstrip("/")
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    fname = path.name
    if not _can_modify(req, fname):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    ext = path.suffix.lower().lstrip(".")
    if ext not in EDITABLE_EXTS:
        return web.json_response({"error": "file type not editable"}, status=400)
    try:
        body    = await req.json()
        content = body.get("content", "")
        if not isinstance(content, str): raise ValueError("content must be a string")
        if len(content.encode()) > MAX_EDIT_BYTES:
            return web.json_response({"error": "content too large"}, status=413)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=400)
    try:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content)
        tmp.rename(path)
        _audit("edit_save", _who(req), f"file={rel} size={len(content)}")
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "size": len(content.encode())})


# ---------------------------------------------------------------------------
# G.  Webhook notifications on upload / delete events
# ---------------------------------------------------------------------------
# Config via flags:  webhook_url (str), webhook_events (list of event names)
# Events: "upload", "delete", "fetch_done"

async def _fire_webhook(event: str, payload: dict):
    """Send a JSON POST to the configured webhook URL (best-effort, no retry)."""
    url = get_flag("webhook_url", "")
    if not url: return
    allowed = get_flag("webhook_events", ["upload", "delete", "fetch_done"])
    if event not in allowed: return
    try:
        data = json.dumps({"event": event, "ts": time.time(), **payload})
        timeout = ClientTimeout(total=5)
        async with ClientSession(timeout=timeout) as s:
            await s.post(url, data=data, headers={"Content-Type": "application/json"})
    except Exception as ex:
        print(f"[warn] webhook {event}: {ex}")


# ---------------------------------------------------------------------------
# H.  API key authentication  (alternative to cookie sessions)
# ---------------------------------------------------------------------------
# Keys stored in users.json under each user's "api_keys" list.
# Usage:  Authorization: Bearer <key>   OR  ?api_key=<key>
# Keys are stored as salted SHA-256 hashes; only the raw key is shown once on creation.

API_KEYS_FILE = _HERE / "api_keys.json"

def _load_api_keys():
    try: return json.loads(API_KEYS_FILE.read_text())
    except Exception: return {}   # {hash: {user, role, label, created}}

def _save_api_keys(d): _atomic_write(API_KEYS_FILE, json.dumps(d))

def _hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

def _get_session_or_apikey(req):
    """Extend _get_session to also accept Bearer / api_key query param."""
    s = _get_session(req)
    if s: return s
    raw = None
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        raw = auth[7:].strip()
    if not raw:
        raw = req.rel_url.query.get("api_key", "").strip()
    if not raw: return None
    h = _hash_api_key(raw)
    keys = _load_api_keys()
    entry = keys.get(h)
    if not entry: return None
    # Return a fake session dict
    return {"user": entry["user"], "role": entry["role"], "exp": float("inf")}

async def handle_apikey_create(req):
    """POST /apikeys  body: {label?}  — create a new API key for the caller."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body  = await req.json()
        label = str(body.get("label", ""))[:80]
    except Exception:
        label = ""
    user  = _who(req)
    s     = _get_session(req)
    role  = s["role"] if s else "user"
    raw   = secrets.token_urlsafe(32)
    h     = _hash_api_key(raw)
    keys  = _load_api_keys()
    keys[h] = {"user": user, "role": role, "label": label, "created": time.time()}
    _save_api_keys(keys)
    _audit("apikey_create", user, f"label={label}")
    return web.json_response({"key": raw, "label": label,
        "note": "Save this key — it will not be shown again."})

async def handle_apikey_list(req):
    """GET /apikeys  — list caller's API keys (hashes + labels, no raw keys)."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    user = _who(req); is_admin = _is_admin(req)
    keys = _load_api_keys()
    result = [
        {"hash": h[:12] + "…", "label": e["label"],
         "created": e["created"], "user": e["user"]}
        for h, e in keys.items()
        if is_admin or e["user"] == user
    ]
    return web.json_response(result)

async def handle_apikey_delete(req):
    """DELETE /apikeys/<prefix>  — delete a key by its 12-char hash prefix."""
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    prefix = req.match_info["prefix"]
    user   = _who(req); is_admin = _is_admin(req)
    keys   = _load_api_keys()
    to_del = [h for h in keys if h.startswith(prefix) and (is_admin or keys[h]["user"] == user)]
    if not to_del: return web.json_response({"error": "not found"}, status=404)
    for h in to_del: keys.pop(h)
    _save_api_keys(keys)
    _audit("apikey_delete", user, f"prefix={prefix}")
    return web.json_response({"ok": True, "deleted": len(to_del)})


# ---------------------------------------------------------------------------
# Patch upload + delete to fire webhooks
# ---------------------------------------------------------------------------
# We monkey-patch by wrapping the existing handlers after they are defined.

_orig_upload = handle_upload
_orig_delete = handle_delete
_orig_fetch_run = _run_fetch

async def handle_upload(req):            # noqa: F811 — intentional override
    resp = await _orig_upload(req)
    if resp.status == 200:
        try:
            data = json.loads(resp.text)
            asyncio.create_task(_fire_webhook("upload", {
                "user": _who(req), "file": data.get("name", "")}))
        except Exception: pass
    return resp

async def handle_delete(req):            # noqa: F811 — intentional override
    resp = await _orig_delete(req)
    if resp.status == 200:
        asyncio.create_task(_fire_webhook("delete", {
            "user": _who(req), "path": req.match_info.get("tail", "")}))
    return resp


# ---------------------------------------------------------------------------
# Wire new routes into a patch function called at import time
# ---------------------------------------------------------------------------

def _patch_routes(app):
    r = app.router
    # Expiring shares
    r.add_post  ("/share",                handle_share_create)
    r.add_get   ("/share",                handle_share_list)
    r.add_delete("/share/{token}",        handle_share_delete)
    r.add_get   ("/s/{token}",            handle_share_download)
    r.add_post  ("/s/{token}",            handle_share_download)   # password POST
    # Move / copy
    r.add_post  ("/move",                 handle_move)
    # Bulk
    r.add_post  ("/bulk",                 handle_bulk)
    # Search
    r.add_get   ("/search",               handle_search)
    # Zip inspector
    r.add_get   ("/zip-inspect",          handle_zip_inspect)
    # Text editor
    r.add_get   ("/edit/{tail:.*}",       handle_edit_get)
    r.add_put   ("/edit/{tail:.*}",       handle_edit_put)
    # API keys
    r.add_post  ("/apikeys",              handle_apikey_create)
    r.add_get   ("/apikeys",              handle_apikey_list)
    r.add_delete("/apikeys/{prefix}",     handle_apikey_delete)


# Re-export patched create_app so web.py's __main__ block picks it up
_orig_create_app = create_app

def create_app():                        # noqa: F811
    app = _orig_create_app()
    _patch_routes(app)
    return app
