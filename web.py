import hashlib
import hmac
import mimetypes
import os
import secrets
import time
from pathlib import Path

from aiohttp import web
from dotenv import load_dotenv

load_dotenv()

WEB_PORT      = int(os.environ.get("WEB_PORT", 8080))
WEB_PASS      = os.environ["WEB_PASS"]
LINK_SECRET   = os.environ.get("LINK_SECRET", secrets.token_hex(32))
DOWNLOADS_DIR = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

_HERE         = Path(__file__).parent
HTML_DIR = _HERE / "html"
STATIC_DIR    = _HERE / "static"

SESSION_TTL = 86400
COOKIE_NAME = "fsid"
_sessions: dict[str, float] = {}


# ── Auth ───────────────────────────────────────────────────────────────────────

def _new_session() -> str:
    tok = secrets.token_hex(32)
    _sessions[tok] = time.time() + SESSION_TTL
    return tok

def _valid(tok: str | None) -> bool:
    if not tok: return False
    exp = _sessions.get(tok)
    if not exp: return False
    if time.time() > exp:
        _sessions.pop(tok, None); return False
    return True

def _check(req: web.Request) -> bool:
    return _valid(req.cookies.get(COOKIE_NAME))

def _pw_ok(pw: str) -> bool:
    a = hashlib.sha256(pw.encode()).digest()
    b = hashlib.sha256(WEB_PASS.encode()).digest()
    return secrets.compare_digest(a, b)

def _safe(name: str) -> Path | None:
    try:
        p = (DOWNLOADS_DIR / name).resolve()
        if p.parent == DOWNLOADS_DIR and p.is_file():
            return p
    except Exception:
        pass
    return None


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


# ── Streaming helper ───────────────────────────────────────────────────────────

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

# ── Route handlers ─────────────────────────────────────────────────────────────

async def handle_root(req: web.Request) -> web.Response:
    if _check(req):
        return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")

async def handle_login(req: web.Request) -> web.Response:
    data = await req.post()
    if _pw_ok(data.get("pass", "")):
        tok  = _new_session()
        resp = web.HTTPFound("/")
        resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                        httponly=True, samesite="Strict")
        return resp
    err = '<p class="error">Wrong password. Try again.</p>'
    return web.Response(text=_tpl("login.html", error=err),
                        content_type="text/html", status=401)

async def handle_logout(req: web.Request) -> web.Response:
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    resp = web.HTTPFound("/")
    resp.del_cookie(COOKIE_NAME)
    return resp

async def handle_files(req: web.Request) -> web.Response:
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    files = []
    try:
        for e in os.scandir(DOWNLOADS_DIR):
            if not e.is_file(follow_symlinks=False): continue
            st = e.stat()
            files.append({"name": e.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    except Exception as ex:
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response(files)

async def handle_make_token(req: web.Request) -> web.Response:
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    name = req.match_info["name"]
    if _safe(name) is None: raise web.HTTPNotFound()
    return web.json_response({"url": f"/get/{make_dl_token(name)}/{name}"})

async def handle_token_download(req: web.Request) -> web.Response:
    tok, name = req.match_info["token"], req.match_info["name"]
    if not verify_dl_token(tok, name): raise web.HTTPForbidden()
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, name)

async def handle_download(req: web.Request) -> web.Response:
    if not _check(req): raise web.HTTPFound("/")
    name = req.match_info["name"]
    path = _safe(name)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, name)

async def handle_static(req: web.Request) -> web.Response:
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
    app.router.add_get("/",                   handle_root)
    app.router.add_post("/login",             handle_login)
    app.router.add_post("/logout",            handle_logout)
    app.router.add_get("/files",              handle_files)
    app.router.add_get("/token/{name}",       handle_make_token)
    app.router.add_get("/get/{token}/{name}", handle_token_download)
    app.router.add_get("/dl/{name}",          handle_download)
    app.router.add_get("/static/{name}",      handle_static)
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
