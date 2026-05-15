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
from pathlib import Path

from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

WEB_PORT       = int(os.environ.get("WEB_PORT", 8080))
WEB_ADMIN_PASS = os.environ.get("WEB_ADMIN_PASS", "")
LINK_SECRET    = os.environ.get("LINK_SECRET", secrets.token_hex(32))
DOWNLOADS_DIR  = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
# Strict permissions on downloads folder
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
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 30

# Blocked extension set — single or double-ext tricks (.jpg.exe)
BLOCKED_EXTS = {
    "exe","bat","cmd","com","scr","pif","vbs","vbe","js","jse",
    "wsf","wsh","ps1","ps2","msi","msp","hta","cpl","dll","sys",
    "sh","bash","zsh","fish","run","elf","dex",
}

_sessions: dict[str, dict] = {}
_rate:     dict[str, list] = {}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _atomic_write(path: Path, text: str) -> None:
    tmp = str(path) + ".tmp"
    try:
        with open(tmp, "w") as f: f.write(text)
        os.replace(tmp, str(path))
    except Exception as e:
        print(f"[warn] write {path}: {e}")

def _pw_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def _sanitize_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    return name or "upload"

def _is_blocked(name: str) -> bool:
    parts = name.lower().split(".")
    return any(p in BLOCKED_EXTS for p in parts[1:])

def _rate_ok(ip: str) -> bool:
    now = time.time()
    bucket = _rate.setdefault(ip, [])
    _rate[ip] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(_rate[ip]) >= RATE_LIMIT_MAX: return False
    _rate[ip].append(now)
    return True


# ── Feature flags ──────────────────────────────────────────────────────────────

_flags_cache: dict = {}

def _load_flags() -> None:
    global _flags_cache
    try: _flags_cache = json.loads(FLAGS_FILE.read_text())
    except Exception: _flags_cache = {}

def get_flag(k, default=False): return _flags_cache.get(k, default)

def set_flag(k, v):
    _flags_cache[k] = v
    _atomic_write(FLAGS_FILE, json.dumps(_flags_cache))

_load_flags()


# ── User DB ────────────────────────────────────────────────────────────────────
# {"users": {username: {pw_hash, role, avatar?}}}  role: "admin"|"user"

def _load_users() -> dict:
    try: return json.loads(USERS_FILE.read_text())
    except Exception: return {"users": {}}

def _save_users(db: dict) -> None:
    _atomic_write(USERS_FILE, json.dumps(db))

def _ensure_admin() -> None:
    if not WEB_ADMIN_PASS: return
    db = _load_users()
    if not any(d.get("role") == "admin" for d in db["users"].values()):
        db["users"]["admin"] = {"pw_hash": _pw_hash(WEB_ADMIN_PASS), "role": "admin"}
        _save_users(db)

_ensure_admin()


# ── File ownership ─────────────────────────────────────────────────────────────

def _load_meta() -> dict:
    try: return json.loads(META_FILE.read_text())
    except Exception: return {}

def _save_meta(m: dict) -> None:
    _atomic_write(META_FILE, json.dumps(m))

def _set_owner(name: str, username: str) -> None:
    m = _load_meta(); m[name] = username; _save_meta(m)

def _get_owner(name: str) -> str | None:
    return _load_meta().get(name)


# ── Sessions ───────────────────────────────────────────────────────────────────

def _new_session(username: str, role: str) -> str:
    tok = secrets.token_hex(32)
    _sessions[tok] = {"exp": time.time() + SESSION_TTL, "user": username, "role": role}
    return tok

def _get_session(req: web.Request) -> dict | None:
    tok = req.cookies.get(COOKIE_NAME)
    if not tok: return None
    s = _sessions.get(tok)
    if not s or time.time() > s["exp"]:
        _sessions.pop(tok, None); return None
    return s

def _check(req)    -> bool:       return _get_session(req) is not None
def _is_admin(req) -> bool:       s = _get_session(req); return bool(s and s.get("role") == "admin")
def _who(req)      -> str | None: s = _get_session(req); return s.get("user") if s else None

def _can_modify(req, name: str) -> bool:
    if _is_admin(req): return True
    u = _who(req)
    return u is not None and _get_owner(name) == u

def _set_cookie(resp, tok: str) -> None:
    resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                    httponly=True, samesite="Strict", secure=False)


# ── Path safety ────────────────────────────────────────────────────────────────

def _safe(name: str) -> Path | None:
    try:
        name = Path(name).name
        p = (DOWNLOADS_DIR / name).resolve()
        if p.parent == DOWNLOADS_DIR and p.is_file(): return p
    except Exception: pass
    return None

def _safe_dir(rel: str) -> Path | None:
    try:
        if rel in ("", ".", "/"): return DOWNLOADS_DIR
        p = (DOWNLOADS_DIR / Path(rel)).resolve()
        if str(p).startswith(str(DOWNLOADS_DIR)): return p
    except Exception: pass
    return None


# ── Token links ────────────────────────────────────────────────────────────────

def make_dl_token(name: str) -> str:
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok: str, name: str) -> bool:
    return hmac.compare_digest(tok, make_dl_token(name))


# ── Template ───────────────────────────────────────────────────────────────────

def _tpl(name: str, **ctx) -> str:
    text = (HTML_DIR / name).read_text()
    for k, v in ctx.items(): text = text.replace(f"{{{{{k}}}}}", v)
    return text


# ── Streaming ──────────────────────────────────────────────────────────────────

async def _stream(req: web.Request, path: Path, name: str) -> web.Response:
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


# ── Handlers ───────────────────────────────────────────────────────────────────

async def handle_root(req):
    if _check(req):
        return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")

async def handle_login(req):
    if not _rate_ok(req.remote):
        return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = (data.get("username") or "").strip()
    password = data.get("pass", "")
    db = _load_users()
    user = db["users"].get(username)
    if not user or not secrets.compare_digest(_pw_hash(password), user["pw_hash"]):
        err = '<p class="error">Wrong credentials.</p>'
        return web.Response(text=_tpl("login.html", error=err),
                            content_type="text/html", status=401)
    tok  = _new_session(username, user["role"])
    resp = web.HTTPFound("/")
    _set_cookie(resp, tok)
    return resp

async def handle_register(req):
    if not get_flag("registration_open", True):
        return web.Response(text=_tpl("login.html",
            error='<p class="error">Registration is closed.</p>'),
            content_type="text/html", status=403)
    if not _rate_ok(req.remote):
        return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = re.sub(r"[^\w.\-]", "", (data.get("username") or "")).strip()
    password = data.get("pass", "")
    if not username or len(password) < 6:
        err = '<p class="error">Username required; password must be ≥ 6 chars.</p>'
        return web.Response(text=_tpl("login.html", error=err),
                            content_type="text/html", status=400)
    db = _load_users()
    if username in db["users"]:
        err = '<p class="error">Username already taken.</p>'
        return web.Response(text=_tpl("login.html", error=err),
                            content_type="text/html", status=409)
    db["users"][username] = {"pw_hash": _pw_hash(password), "role": "user"}
    _save_users(db)
    tok  = _new_session(username, "user")
    resp = web.HTTPFound("/")
    _set_cookie(resp, tok)
    return resp

async def handle_logout(req):
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    resp = web.HTTPFound("/")
    resp.del_cookie(COOKIE_NAME)
    return resp

async def handle_session(req):
    if not _check(req):
        return web.json_response({"admin": False, "can_write": False,
                                  "torrent_enabled": False, "username": None,
                                  "registration_open": get_flag("registration_open", True)})
    user = _who(req); is_admin = _is_admin(req)
    db = _load_users()
    avatar = db["users"].get(user, {}).get("avatar")
    return web.json_response({
        "admin":             is_admin,
        "can_write":         True,
        "torrent_enabled":   is_admin and get_flag("torrent_enabled", False),
        "username":          user,
        "avatar":            avatar,
        "registration_open": get_flag("registration_open", True),
    })

async def handle_files(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    rel  = req.rel_url.query.get("path", "")
    base = _safe_dir(rel)
    if base is None or not base.exists():
        return web.json_response({"error": "not found"}, status=404)
    user = _who(req); is_admin = _is_admin(req)
    meta = _load_meta()
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
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    name = req.match_info["name"]
    if not _can_modify(req, name):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    try:
        path.unlink()
        m = _load_meta(); m.pop(name, None); _save_meta(m)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True})

async def handle_rename(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body     = await req.json()
        old_name = Path(body.get("old", "")).name
        new_name = _sanitize_filename(body.get("new", ""))
        if not old_name or not new_name: raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    if not _can_modify(req, old_name):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    if _is_blocked(new_name):
        return web.json_response({"error": "file type not allowed"}, status=400)
    src = _safe(old_name)
    if src is None: raise web.HTTPNotFound()
    dst = DOWNLOADS_DIR / new_name
    if dst.exists():
        return web.json_response({"error": "name already taken"}, status=409)
    try:
        src.rename(dst)
        m = _load_meta()
        if old_name in m: m[new_name] = m.pop(old_name); _save_meta(m)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": new_name})

async def handle_upload(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    username = _who(req)
    try:
        reader = await req.multipart()
        field  = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        filename = _sanitize_filename(field.filename or "upload")
        if _is_blocked(filename):
            return web.json_response({"error": "executable file types are not allowed"}, status=400)
        dest = DOWNLOADS_DIR / filename
        tmp  = dest.with_suffix(dest.suffix + ".part")
        received = 0
        try:
            with open(tmp, "wb") as f:
                while chunk := await field.read_chunk(65536):
                    received += len(chunk)
                    if received > MAX_UPLOAD_BYTES:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "file too large"}, status=413)
                    f.write(chunk)
            tmp.rename(dest)
            _set_owner(filename, username)
        except Exception:
            tmp.unlink(missing_ok=True); raise
    except web.HTTPException: raise
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": filename})

async def handle_download(req):
    if not _check(req): raise web.HTTPFound("/")
    path = _safe(req.match_info["name"])
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, path.name)

async def handle_token_download(req):
    tok, name = req.match_info["token"], req.match_info["name"]
    if not verify_dl_token(tok, name): raise web.HTTPForbidden()
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, name)

async def handle_make_token(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    name = req.match_info["name"]
    if _safe(name) is None: raise web.HTTPNotFound()
    return web.json_response({"url": f"/get/{make_dl_token(name)}/{name}"})

async def handle_torrent(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not get_flag("torrent_enabled", False):
        return web.json_response({"error": "torrent downloads are disabled"}, status=403)
    ct = req.content_type or ""
    if "multipart" in ct:
        try:
            reader = await req.multipart()
            field  = await reader.next()
            if field is None or field.name != "file": raise ValueError("missing file field")
            data = await field.read(decode=True)
            if not data: raise ValueError("empty file")
        except Exception as ex:
            return web.json_response({"error": str(ex)}, status=400)
        fd, tmp_path = tempfile.mkstemp(suffix=".torrent")
        try:
            with os.fdopen(fd, "wb") as f: f.write(data)
            proc = subprocess.Popen(
                ["aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
                 "--quiet=true","--max-connection-per-server=4","--split=4","--seed-time=0",tmp_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            return web.json_response({"error": "aria2c not found"}, status=500)
        except Exception as ex:
            return web.json_response({"error": str(ex)}, status=500)
        return web.json_response({"ok": True, "pid": proc.pid})
    try:
        body = await req.json(); uri = (body.get("uri") or "").strip()
        if not uri: raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    if not (uri.lower().startswith("magnet:") or uri.lower().endswith(".torrent")):
        return web.json_response({"error": "not a magnet link or .torrent URL"}, status=400)
    try:
        proc = subprocess.Popen(
            ["aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
             "--quiet=true","--max-connection-per-server=4","--split=4","--seed-time=0",uri],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return web.json_response({"ok": True, "pid": proc.pid})
    except FileNotFoundError:
        return web.json_response({"error": "aria2c not found"}, status=500)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)

async def handle_flag_get(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response(dict(_flags_cache))

async def handle_flag_set(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await req.json()
        if not isinstance(body, dict): raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
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
        reader = await req.multipart()
        field  = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        data = await field.read(decode=True)
        if len(data) > 2 * 1024 * 1024:
            return web.json_response({"error": "avatar too large (max 2 MB)"}, status=413)
        ext = Path(field.filename or "avatar.png").suffix.lower().lstrip(".")
        if ext not in ("jpg","jpeg","png","gif","webp"):
            return web.json_response({"error": "image files only"}, status=400)
        mime = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png",
                "gif":"image/gif","webp":"image/webp"}.get(ext, "image/png")
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


# ── App factory ────────────────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application(client_max_size=MAX_UPLOAD_BYTES + 65536)
    r = app.router
    r.add_get   ("/",                       handle_root)
    r.add_post  ("/login",                  handle_login)
    r.add_post  ("/register",               handle_register)
    r.add_post  ("/logout",                 handle_logout)
    r.add_get   ("/session",                handle_session)
    r.add_get   ("/files",                  handle_files)
    r.add_delete("/files/{name}",           handle_delete)
    r.add_post  ("/rename",                 handle_rename)
    r.add_post  ("/upload",                 handle_upload)
    r.add_post  ("/torrent",                handle_torrent)
    r.add_get   ("/flags",                  handle_flag_get)
    r.add_post  ("/flags",                  handle_flag_set)
    r.add_get   ("/token/{name}",           handle_make_token)
    r.add_get   ("/get/{token}/{name}",     handle_token_download)
    r.add_get   ("/dl/{name}",              handle_download)
    r.add_get   ("/admin/users",            handle_admin_users)
    r.add_delete("/admin/users/{username}", handle_admin_user_delete)
    r.add_post  ("/admin/avatar",           handle_avatar_upload)
    r.add_get   ("/static/{name}",          handle_static)
    return app

async def start_web() -> None:
    runner = web.AppRunner(create_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", WEB_PORT).start()
    base = os.environ.get("WEB_BASE", f"http://localhost:{WEB_PORT}")
    print(f"web: {base}")

if __name__ == "__main__":
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start_web())
    loop.run_forever()
