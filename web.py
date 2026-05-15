import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import subprocess
import time
from pathlib import Path

from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

WEB_PORT        = int(os.environ.get("WEB_PORT", 8080))
WEB_PASS        = os.environ["WEB_PASS"]
WEB_ADMIN_PASS  = os.environ.get("WEB_ADMIN_PASS", "")
LINK_SECRET     = os.environ.get("LINK_SECRET", secrets.token_hex(32))
DOWNLOADS_DIR   = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

_HERE      = Path(__file__).parent
HTML_DIR   = _HERE / "html"
STATIC_DIR = _HERE / "static"
FLAGS_FILE = _HERE / "flags.json"

SESSION_TTL = 86400
COOKIE_NAME = "fsid"
_sessions: dict[str, dict] = {}


# ── Feature flags ──────────────────────────────────────────────────────────────

_flags_cache: dict = {}

def _load_flags() -> dict:
    global _flags_cache
    try:
        _flags_cache = json.loads(FLAGS_FILE.read_text())
    except Exception:
        _flags_cache = {}
    return _flags_cache

def _save_flags(d: dict) -> None:
    global _flags_cache
    _flags_cache = d
    tmp = str(FLAGS_FILE) + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, str(FLAGS_FILE))
    except Exception as e:
        print(f"[warn] flags save: {e}")

def get_flag(key: str, default=False):
    return _flags_cache.get(key, default)

def set_flag(key: str, value) -> None:
    d = dict(_flags_cache)
    d[key] = value
    _save_flags(d)

_load_flags()


# ── Auth ───────────────────────────────────────────────────────────────────────

def _new_session(is_admin: bool = False, uid=None) -> str:
    tok = secrets.token_hex(32)
    _sessions[tok] = {"exp": time.time() + SESSION_TTL, "admin": is_admin, "uid": uid}
    return tok

def _valid(tok) -> bool:
    if not tok: return False
    s = _sessions.get(tok)
    if not s: return False
    if time.time() > s["exp"]:
        _sessions.pop(tok, None); return False
    return True

def _check(req: web.Request) -> bool:
    return _valid(req.cookies.get(COOKIE_NAME))

def _is_admin(req: web.Request) -> bool:
    tok = req.cookies.get(COOKIE_NAME)
    if not tok: return False
    s = _sessions.get(tok)
    return bool(s and time.time() <= s["exp"] and s.get("admin"))

def _session_uid(req: web.Request):
    tok = req.cookies.get(COOKIE_NAME)
    if not tok: return None
    s = _sessions.get(tok)
    return s.get("uid") if s else None

def _pw_ok(pw: str) -> tuple:
    a = hashlib.sha256(pw.encode()).digest()
    b = hashlib.sha256(WEB_PASS.encode()).digest()
    if secrets.compare_digest(a, b):
        return True, False
    if WEB_ADMIN_PASS:
        c = hashlib.sha256(WEB_ADMIN_PASS.encode()).digest()
        if secrets.compare_digest(a, c):
            return True, True
    return False, False

def _safe(name: str):
    try:
        p = (DOWNLOADS_DIR / name).resolve()
        if p.parent == DOWNLOADS_DIR and p.is_file():
            return p
    except Exception:
        pass
    return None

def _safe_dir(rel: str):
    try:
        if rel in ("", ".", "/"):
            return DOWNLOADS_DIR
        p = (DOWNLOADS_DIR / rel).resolve()
        if str(p).startswith(str(DOWNLOADS_DIR)):
            return p
    except Exception:
        pass
    return None


# ── Permission sync with bot ───────────────────────────────────────────────────

ALLOWED_FILE = _HERE / "allowed_users.json"

def _load_allowed() -> set:
    try:
        with open(ALLOWED_FILE) as f:
            return {int(x) for x in json.load(f)}
    except Exception:
        return set()

def _get_superusers() -> set:
    try:
        return {int(x) for x in os.environ.get("SUPER_USERS", "").split(",") if x.strip()}
    except Exception:
        return set()

def _uid_can_delete(uid) -> bool:
    if uid is None: return False
    if uid in _get_superusers(): return True
    return uid in _load_allowed()

def _can_delete(req: web.Request) -> bool:
    if _is_admin(req): return True
    return _uid_can_delete(_session_uid(req))

def _can_write(req: web.Request) -> bool:
    return _is_admin(req)


# ── Token links ────────────────────────────────────────────────────────────────

def make_dl_token(name: str) -> str:
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok: str, name: str) -> bool:
    return hmac.compare_digest(tok, make_dl_token(name))


# ── Template loader ────────────────────────────────────────────────────────────

def _tpl(name: str, **ctx) -> str:
    text = (HTML_DIR / name).read_text()
    for k, v in ctx.items():
        text = text.replace(f"{{{{{k}}}}}", v)
    return text


# ── Streaming ──────────────────────────────────────────────────────────────────

async def _stream(req: web.Request, path: Path, name: str) -> web.Response:
    ct, _ = mimetypes.guess_type(str(path))
    resp  = web.StreamResponse(headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Content-Type":        ct or "application/octet-stream",
        "Content-Length":      str(path.stat().st_size),
    })
    await resp.prepare(req)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                await resp.write(chunk)
    except (ConnectionError, ConnectionResetError):
        pass
    return resp


# ── Handlers ───────────────────────────────────────────────────────────────────

async def handle_root(req):
    if _check(req):
        return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")

async def handle_login(req):
    data = await req.post()
    ok, is_admin = _pw_ok(data.get("pass", ""))
    uid = None
    try:
        raw = data.get("uid", "")
        if raw: uid = int(raw)
    except Exception:
        pass
    if ok:
        tok  = _new_session(is_admin, uid)
        resp = web.HTTPFound("/")
        resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                        httponly=True, samesite="Strict")
        return resp
    err = '<p class="error">Wrong password. Try again.</p>'
    return web.Response(text=_tpl("login.html", error=err),
                        content_type="text/html", status=401)

async def handle_logout(req):
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    resp = web.HTTPFound("/")
    resp.del_cookie(COOKIE_NAME)
    return resp

async def handle_session(req):
    if not _check(req):
        return web.json_response({"admin": False, "can_delete": False,
                                  "torrent_enabled": False, "can_write": False})
    return web.json_response({
        "admin":           _is_admin(req),
        "can_delete":      _can_delete(req),
        "can_write":       _can_write(req),
        "torrent_enabled": get_flag("torrent_enabled", False),
    })

async def handle_files(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path", "")
    base = _safe_dir(rel)
    if base is None or not base.exists():
        return web.json_response({"error": "not found"}, status=404)
    files, dirs = [], []
    try:
        for e in os.scandir(base):
            st = e.stat(follow_symlinks=False)
            if e.is_dir(follow_symlinks=False):
                dirs.append({"name": e.name, "type": "dir", "size": 0, "mtime": int(st.st_mtime)})
            elif e.is_file(follow_symlinks=False):
                rp = str(Path(e.path).relative_to(DOWNLOADS_DIR))
                files.append({"name": e.name, "rel": rp, "type": "file",
                              "size": st.st_size, "mtime": int(st.st_mtime)})
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"dirs": dirs, "files": files, "path": rel})

async def handle_delete(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not _can_delete(req):
        return web.json_response({"error": "forbidden"}, status=403)
    name = req.match_info["name"]
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    try:
        path.unlink()
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True})

async def handle_rename(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not _can_write(req):
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await req.json()
        old_name = Path(body.get("old", "")).name
        new_name = Path(body.get("new", "")).name
        if not old_name or not new_name: raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    src = _safe(old_name)
    if src is None: raise web.HTTPNotFound()
    dst = DOWNLOADS_DIR / new_name
    if dst.exists():
        return web.json_response({"error": "name already taken"}, status=409)
    try:
        src.rename(dst)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": new_name})

async def handle_upload(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not _can_write(req):
        return web.json_response({"error": "forbidden"}, status=403)
    try:
        reader  = await req.multipart()
        field   = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        filename = Path(field.filename or "upload").name
        if not filename: raise web.HTTPBadRequest()
        dest = DOWNLOADS_DIR / filename
        tmp  = dest.with_suffix(dest.suffix + ".part")
        try:
            with open(tmp, "wb") as f:
                while True:
                    chunk = await field.read_chunk(65536)
                    if not chunk: break
                    f.write(chunk)
            tmp.rename(dest)
        except Exception:
            try: tmp.unlink()
            except OSError: pass
            raise
    except web.HTTPException:
        raise
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": filename})

async def handle_torrent(req):
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not get_flag("torrent_enabled", False):
        return web.json_response({"error": "torrent downloads are disabled"}, status=403)
    try:
        body = await req.json()
        uri = (body.get("uri") or "").strip()
        if not uri: raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    is_magnet  = uri.lower().startswith("magnet:")
    is_torrent_url = uri.lower().endswith(".torrent")
    if not (is_magnet or is_torrent_url):
        return web.json_response({"error": "not a magnet link or .torrent URL"}, status=400)
    try:
        cmd = ["aria2c", "--dir", str(DOWNLOADS_DIR), "--daemon=false",
               "--quiet=true", "--max-connection-per-server=4",
               "--split=4", "--seed-time=0", uri]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return web.json_response({"ok": True, "pid": proc.pid})
    except FileNotFoundError:
        return web.json_response({"error": "aria2c not found on server"}, status=500)
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)

async def handle_flag_get(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response(dict(_flags_cache))

async def handle_flag_set(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await req.json()
        if not isinstance(body, dict): raise ValueError
    except Exception:
        return web.json_response({"error": "bad request"}, status=400)
    for k, v in body.items():
        set_flag(str(k), v)
    return web.json_response({"ok": True, "flags": dict(_flags_cache)})

async def handle_make_token(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    name = req.match_info["name"]
    if _safe(name) is None: raise web.HTTPNotFound()
    return web.json_response({"url": f"/get/{make_dl_token(name)}/{name}"})

async def handle_token_download(req):
    tok, name = req.match_info["token"], req.match_info["name"]
    if not verify_dl_token(tok, name): raise web.HTTPForbidden()
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, name)

async def handle_download(req):
    if not _check(req): raise web.HTTPFound("/")
    name = req.match_info["name"]
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, name)

async def handle_static(req):
    name = req.match_info["name"]
    path = (STATIC_DIR / name).resolve()
    if not str(path).startswith(str(STATIC_DIR)) or not path.is_file():
        raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    return web.Response(body=path.read_bytes(),
                        content_type=ct or "application/octet-stream")


# ── App factory ────────────────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get   ("/",                   handle_root)
    app.router.add_post  ("/login",              handle_login)
    app.router.add_post  ("/logout",             handle_logout)
    app.router.add_get   ("/session",            handle_session)
    app.router.add_get   ("/files",              handle_files)
    app.router.add_delete("/files/{name}",       handle_delete)
    app.router.add_post  ("/rename",             handle_rename)
    app.router.add_post  ("/upload",             handle_upload)
    app.router.add_post  ("/torrent",            handle_torrent)
    app.router.add_get   ("/flags",              handle_flag_get)
    app.router.add_post  ("/flags",              handle_flag_set)
    app.router.add_get   ("/token/{name}",       handle_make_token)
    app.router.add_get   ("/get/{token}/{name}", handle_token_download)
    app.router.add_get   ("/dl/{name}",          handle_download)
    app.router.add_get   ("/static/{name}",      handle_static)
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
