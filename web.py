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
LINK_SECRET   = os.environ.get("LINK_SECRET", secrets.token_hex(32))  # set in .env for stable links
DOWNLOADS_DIR = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

SESSION_TTL = 86400
COOKIE_NAME = "fsid"
_sessions: dict[str, float] = {}


# ── Session auth ───────────────────────────────────────────────────────────────

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


# ── Token-based download links (no session needed) ─────────────────────────────
# Token is HMAC(secret, filename) — permanent, no expiry, tied to filename.
# Anyone with the token URL can download that specific file.

def make_dl_token(name: str) -> str:
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok: str, name: str) -> bool:
    return hmac.compare_digest(tok, make_dl_token(name))


# ── HTML ───────────────────────────────────────────────────────────────────────

_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fileserv</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@300;400;500&family=Geist:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --transition: 0.2s ease; }
[data-theme="dark"] {
  --bg: #0a0a0a; --surface: #111; --border: #1f1f1f; --border-focus: #3a3a3a;
  --text: #e5e5e5; --text-muted: #555; --text-subtle: #333;
  --error: #f87171; --error-bg: rgba(248,113,113,0.06);
  --btn-bg: #e5e5e5; --btn-text: #0a0a0a; --btn-hover: #ccc;
}
[data-theme="light"] {
  --bg: #fafafa; --surface: #fff; --border: #e5e5e5; --border-focus: #aaa;
  --text: #111; --text-muted: #999; --text-subtle: #ccc;
  --error: #dc2626; --error-bg: rgba(220,38,38,0.05);
  --btn-bg: #111; --btn-text: #fafafa; --btn-hover: #333;
}
html, body {
  height: 100%; background: var(--bg); color: var(--text);
  font-family: 'Geist', sans-serif; font-size: 14px;
  -webkit-font-smoothing: antialiased;
  transition: background var(--transition), color var(--transition);
}
body { display: flex; align-items: center; justify-content: center; padding: 24px; }
.theme-toggle {
  position: fixed; top: 20px; right: 20px;
  width: 32px; height: 32px;
  border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface); color: var(--text-muted);
  cursor: pointer; display: flex; align-items: center; justify-content: center;
  font-size: 14px;
  transition: border-color var(--transition), color var(--transition);
}
.theme-toggle:hover { border-color: var(--border-focus); color: var(--text); }
.card { width: 100%; max-width: 320px; }
.logo {
  font-family: 'Geist Mono', monospace; font-size: 11px; font-weight: 400;
  color: var(--text-muted); letter-spacing: 0.08em; margin-bottom: 36px;
}
h1 { font-size: 20px; font-weight: 500; color: var(--text); margin-bottom: 4px; letter-spacing: -0.02em; }
.sub { font-size: 13px; color: var(--text-muted); margin-bottom: 28px; font-weight: 300; }
label {
  display: block; font-family: 'Geist Mono', monospace; font-size: 10px;
  font-weight: 400; color: var(--text-muted); letter-spacing: 0.06em;
  text-transform: uppercase; margin-bottom: 7px;
}
input {
  width: 100%; background: var(--surface); border: 1px solid var(--border);
  color: var(--text); font-family: 'Geist Mono', monospace; font-size: 13px;
  padding: 10px 12px; border-radius: 6px; outline: none; -webkit-appearance: none;
  transition: border-color var(--transition);
}
input:focus { border-color: var(--border-focus); }
input::placeholder { color: var(--text-subtle); }
.btn {
  margin-top: 10px; width: 100%; padding: 10px 16px;
  background: var(--btn-bg); color: var(--btn-text);
  font-family: 'Geist Mono', monospace; font-size: 11px; font-weight: 500;
  letter-spacing: 0.05em; text-transform: uppercase;
  border: none; border-radius: 6px; cursor: pointer;
  transition: background var(--transition);
}
.btn:hover { background: var(--btn-hover); }
.err {
  margin-top: 10px; font-family: 'Geist Mono', monospace; font-size: 11px;
  color: var(--error); padding: 9px 12px; background: var(--error-bg);
  border: 1px solid rgba(248,113,113,0.15); border-radius: 6px;
}
</style>
</head>
<body>
<button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">
  <span id="theme-icon">☀</span>
</button>
<div class="card">
  <div class="logo">fileserv</div>
  <h1>Sign in</h1>
  <p class="sub">Enter your password to continue.</p>
  <form method="POST" action="/login">
    <label for="pw">Password</label>
    <input id="pw" type="password" name="pass" autofocus autocomplete="current-password" placeholder="············">
    <button class="btn" type="submit">Continue</button>
    {error}
  </form>
</div>
<script>
function getTheme() {
  return localStorage.getItem('theme') ||
    (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('theme-icon').textContent = t === 'dark' ? '☀' : '☾';
}
function toggleTheme() {
  const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', t); applyTheme(t);
}
applyTheme(getTheme());
</script>
</body>
</html>
"""

_EXPLORER_HTML = """\
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>fileserv</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@300;400;500&family=Geist:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root { --transition: 0.15s ease; }
[data-theme="dark"] {
  --bg: #0a0a0a; --surface: #111; --surface2: #161616; --surface3: #1a1a1a;
  --border: #1f1f1f; --border2: #2a2a2a;
  --text: #e5e5e5; --text2: #999; --text3: #555; --text4: #2e2e2e;
  --green: #4ade80; --green-bg: rgba(74,222,128,0.06); --green-border: rgba(74,222,128,0.2);
  --blue: #60a5fa; --orange: #fb923c; --purple: #a78bfa;
  --row-hover: #111; --pill-bg: #1a1a1a;
}
[data-theme="light"] {
  --bg: #fafafa; --surface: #fff; --surface2: #f5f5f5; --surface3: #f0f0f0;
  --border: #e8e8e8; --border2: #d5d5d5;
  --text: #111; --text2: #666; --text3: #aaa; --text4: #ddd;
  --green: #16a34a; --green-bg: rgba(22,163,74,0.06); --green-border: rgba(22,163,74,0.2);
  --blue: #2563eb; --orange: #ea580c; --purple: #7c3aed;
  --row-hover: #f5f5f5; --pill-bg: #ebebeb;
}
html, body {
  min-height: 100%; background: var(--bg); color: var(--text);
  font-family: 'Geist', sans-serif; font-size: 13px;
  -webkit-font-smoothing: antialiased;
  transition: background var(--transition), color var(--transition);
}
::-webkit-scrollbar { width: 3px; height: 3px; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }
::-webkit-scrollbar-track { background: transparent; }

/* topbar */
.topbar {
  position: sticky; top: 0; z-index: 100; height: 44px;
  background: var(--bg); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 16px; gap: 12px;
}
.logo {
  font-family: 'Geist Mono', monospace; font-size: 11px; font-weight: 400;
  color: var(--text3); letter-spacing: 0.06em; flex-shrink: 0;
  padding-right: 12px; border-right: 1px solid var(--border);
}
.search-wrap { flex: 1; display: flex; align-items: center; gap: 8px; min-width: 0; }
.search-icon { color: var(--text3); flex-shrink: 0; }
#q {
  flex: 1; background: transparent; border: none;
  color: var(--text); font-family: 'Geist', sans-serif; font-size: 13px;
  outline: none; min-width: 0;
}
#q::placeholder { color: var(--text3); }
.topbar-actions {
  display: flex; align-items: center; gap: 6px; flex-shrink: 0;
  padding-left: 12px; border-left: 1px solid var(--border);
}
.icon-btn {
  width: 28px; height: 28px; border: 1px solid var(--border); border-radius: 5px;
  background: transparent; color: var(--text3); cursor: pointer;
  display: flex; align-items: center; justify-content: center; font-size: 13px;
  transition: all var(--transition); flex-shrink: 0;
}
.icon-btn:hover { border-color: var(--border2); color: var(--text); background: var(--surface2); }
.logout-btn {
  font-family: 'Geist Mono', monospace; font-size: 10px; font-weight: 400;
  color: var(--text3); letter-spacing: 0.05em; text-transform: uppercase;
  border: 1px solid var(--border); border-radius: 5px; background: transparent;
  padding: 0 10px; height: 28px; cursor: pointer;
  transition: color var(--transition), border-color var(--transition);
}
.logout-btn:hover { color: var(--text); border-color: var(--border2); }

/* statbar */
.statbar {
  height: 30px; background: var(--surface); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 16px; gap: 0;
  overflow-x: auto; scrollbar-width: none;
}
.statbar::-webkit-scrollbar { display: none; }
.stat {
  font-family: 'Geist Mono', monospace; font-size: 10px; color: var(--text3);
  padding-right: 16px; margin-right: 16px; border-right: 1px solid var(--border);
  white-space: nowrap; flex-shrink: 0;
}
.stat:last-child { border-right: none; }
.stat b { color: var(--text2); font-weight: 400; }

/* tabs */
.tabs {
  display: flex; align-items: center; border-bottom: 1px solid var(--border);
  padding: 0 12px; overflow-x: auto; scrollbar-width: none; background: var(--bg);
}
.tabs::-webkit-scrollbar { display: none; }
.tab {
  font-family: 'Geist Mono', monospace; font-size: 10px; font-weight: 400;
  color: var(--text3); letter-spacing: 0.04em;
  padding: 0 8px; height: 34px; cursor: pointer; border: none; background: transparent;
  border-bottom: 1.5px solid transparent;
  transition: color var(--transition), border-color var(--transition);
  display: flex; align-items: center; gap: 5px; white-space: nowrap; flex-shrink: 0;
}
.tab:hover { color: var(--text2); }
.tab.active { color: var(--text); border-bottom-color: var(--text); }
.tab .count {
  font-size: 9px; color: var(--text4); background: var(--pill-bg);
  padding: 1px 4px; border-radius: 3px;
}
.tab.active .count { color: var(--text3); }

/* table */
.table-head {
  display: grid; grid-template-columns: 1fr 80px 120px 84px;
  padding: 0 16px; height: 30px; align-items: center;
  background: var(--surface); border-bottom: 1px solid var(--border);
  position: sticky; top: 44px; z-index: 50;
}
.th {
  font-family: 'Geist Mono', monospace; font-size: 9px; font-weight: 400;
  color: var(--text3); letter-spacing: 0.08em; text-transform: uppercase;
  background: transparent; border: none; padding: 0; cursor: pointer;
  display: flex; align-items: center; gap: 3px;
  transition: color var(--transition); text-align: left;
}
.th:hover { color: var(--text2); }
.th.active { color: var(--text2); }
.th-right { justify-content: flex-end; text-align: right; }
.th-center { justify-content: center; cursor: default; }
.sort-arrow { color: var(--text); font-size: 8px; }
.row {
  display: grid; grid-template-columns: 1fr 80px 120px 84px;
  padding: 0 16px; height: 44px; align-items: center;
  border-bottom: 1px solid var(--border);
  transition: background var(--transition);
}
.row:last-child { border-bottom: none; }
.row:hover { background: var(--row-hover); }
.file-name-cell { display: flex; align-items: center; gap: 9px; min-width: 0; }
.ext-tag {
  flex-shrink: 0; font-family: 'Geist Mono', monospace; font-size: 8px;
  font-weight: 500; letter-spacing: 0.04em; text-transform: uppercase;
  padding: 2px 5px; border-radius: 3px; border: 1px solid;
}
.ext-zip  { color: var(--orange); border-color: rgba(251,146,60,0.25); background: rgba(251,146,60,0.05); }
.ext-img  { color: var(--purple); border-color: rgba(167,139,250,0.25); background: rgba(167,139,250,0.05); }
.ext-apk  { color: var(--green);  border-color: var(--green-border);    background: var(--green-bg); }
.ext-txt  { color: var(--blue);   border-color: rgba(96,165,250,0.25);  background: rgba(96,165,250,0.05); }
.ext-misc { color: var(--text3);  border-color: var(--border2);         background: var(--surface2); }
.file-name {
  font-size: 13px; font-weight: 400; color: var(--text);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.file-meta { font-family: 'Geist Mono', monospace; font-size: 9px; color: var(--text3); margin-top: 2px; }
.cell-size { font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--text2); text-align: right; white-space: nowrap; }
.cell-date { font-family: 'Geist Mono', monospace; font-size: 10px; color: var(--text3); white-space: nowrap; }

/* action buttons */
.actions { display: flex; align-items: center; justify-content: flex-end; gap: 4px; }
.act-btn {
  width: 26px; height: 26px; border-radius: 4px; border: 1px solid var(--border);
  background: transparent; color: var(--text3); cursor: pointer;
  display: flex; align-items: center; justify-content: center; font-size: 11px;
  transition: all var(--transition); flex-shrink: 0;
}
.act-btn:hover { color: var(--text); border-color: var(--border2); background: var(--surface2); }
.act-btn.copied, .act-btn.done {
  color: var(--green); border-color: var(--green-border); background: var(--green-bg); pointer-events: none;
}
.act-btn.spinning { color: var(--text3); pointer-events: none; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* empty */
.empty {
  padding: 80px 24px; text-align: center;
  font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--text3); letter-spacing: 0.04em;
}

/* toast */
.toast {
  position: fixed; bottom: 24px; left: 50%;
  transform: translateX(-50%) translateY(8px);
  background: var(--surface); border: 1px solid var(--border2);
  color: var(--text2); font-family: 'Geist Mono', monospace; font-size: 11px;
  padding: 8px 14px; border-radius: 6px;
  opacity: 0; transition: opacity 0.15s, transform 0.15s;
  pointer-events: none; white-space: nowrap; z-index: 999;
}
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }

/* mobile */
@media (max-width: 580px) {
  .table-head { display: none; }
  .row { grid-template-columns: 1fr 84px; height: 52px; }
  .cell-size, .cell-date { display: none; }
  .file-meta { display: block !important; }
}
@media (min-width: 581px) { .file-meta { display: none; } }
</style>
</head>
<body>

<header class="topbar">
  <div class="logo">fileserv</div>
  <div class="search-wrap">
    <svg class="search-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input id="q" type="search" placeholder="Search files…" autocomplete="off" spellcheck="false">
  </div>
  <div class="topbar-actions">
    <button class="icon-btn" onclick="load()" title="Refresh">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
    </button>
    <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme">
      <svg id="theme-sun" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      <svg id="theme-moon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="display:none"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
    </button>
    <button class="logout-btn" onclick="doLogout()">Logout</button>
  </div>
</header>

<div class="statbar">
  <div class="stat"><b id="s-count">—</b> files</div>
  <div class="stat"><b id="s-size">—</b> total</div>
  <div class="stat" id="s-filtered-wrap" style="display:none"><b id="s-filtered">—</b> shown</div>
  <div class="stat">sorted by <b id="s-sort-label">modified ↓</b></div>
</div>

<div class="tabs" id="tabs"></div>

<div class="table-head">
  <button class="th" data-col="name">Name <span class="sort-arrow" id="arr-name"></span></button>
  <button class="th th-right" data-col="size">Size <span class="sort-arrow" id="arr-size"></span></button>
  <button class="th" data-col="mtime">Modified <span class="sort-arrow" id="arr-mtime"></span></button>
  <div class="th th-center">Get</div>
</div>

<div id="rows"></div>
<div class="toast" id="toast"></div>

<script>
let _files = [], _ext = null, _sort = { col: 'mtime', dir: -1 };

// theme
function getTheme() {
  return localStorage.getItem('theme') ||
    (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  document.getElementById('theme-sun').style.display  = t === 'dark'  ? '' : 'none';
  document.getElementById('theme-moon').style.display = t === 'light' ? '' : 'none';
}
function toggleTheme() {
  const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  localStorage.setItem('theme', t); applyTheme(t);
}
applyTheme(getTheme());

// utils
const fsize = b => {
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (b >= 1024 && i < 4) { b /= 1024; i++; }
  return b.toFixed(i ? 1 : 0) + '\u202f' + u[i];
};
const fdate = ts => {
  const d = new Date(ts * 1000), n = new Date();
  if (d.toDateString() === n.toDateString())
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (n - d < 7 * 86400e3)
    return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
  return d.toLocaleDateString([], { year: '2-digit', month: 'short', day: 'numeric' });
};
const gext = n => { const i = n.lastIndexOf('.'); return i > 0 ? n.slice(i+1).toLowerCase() : ''; };
const extClass = e => {
  if (['zip','gz','xz','zst','tar','7z','bz2','lz4','br'].includes(e)) return 'ext-zip';
  if (['img','iso','bin','raw','dmg','rom','dat'].includes(e))          return 'ext-img';
  if (['apk','ota','deb','rpm','pkg'].includes(e))                      return 'ext-apk';
  if (['txt','log','md','json','xml','sh','yaml','toml','cfg'].includes(e)) return 'ext-txt';
  return 'ext-misc';
};
const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

// toast
let _toastTimer;
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 2000);
}

// data
async function load() {
  try {
    const r = await fetch('/files');
    if (r.status === 401) { location.href = '/'; return; }
    _files = await r.json();
  } catch { return; }
  buildTabs(); render();
}

// tabs
function buildTabs() {
  const m = {};
  _files.forEach(f => { const e = gext(f.name) || 'other'; m[e] = (m[e] || 0) + 1; });
  const entries = Object.entries(m).sort((a, b) => b[1] - a[1]);
  document.getElementById('tabs').innerHTML =
    `<button class="tab${_ext === null ? ' active' : ''}" onclick="setExt(null)">all <span class="count">${_files.length}</span></button>` +
    entries.map(([e, n]) =>
      `<button class="tab${_ext === e ? ' active' : ''}" onclick="setExt('${esc(e)}')">.${esc(e)} <span class="count">${n}</span></button>`
    ).join('');
}
function setExt(e) { _ext = e; buildTabs(); render(); }

// render
const COPY_ICON = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const DL_ICON   = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`;
const CHECK_ICON= `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>`;
const SPIN_ICON = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22" opacity=".3"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76" opacity=".8"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07" opacity=".2"/><line x1="2" y1="12" x2="6" y2="12" opacity=".6"/><line x1="18" y1="12" x2="22" y2="12" opacity=".1"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24" opacity=".4"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93" opacity=".9"/></svg>`;

function render() {
  const q = document.getElementById('q').value.toLowerCase().trim();
  let rows = _files.filter(f =>
    (_ext ? gext(f.name) === _ext : true) &&
    (!q || f.name.toLowerCase().includes(q))
  );
  const { col, dir } = _sort;
  rows.sort((a, b) => {
    let av = a[col], bv = b[col];
    if (typeof av === 'string') { av = av.toLowerCase(); bv = bv.toLowerCase(); }
    return av < bv ? -dir : av > bv ? dir : 0;
  });

  document.getElementById('s-count').textContent = _files.length;
  document.getElementById('s-size').textContent = fsize(_files.reduce((s, f) => s + f.size, 0));
  const fw = document.getElementById('s-filtered-wrap');
  if (rows.length < _files.length) {
    fw.style.display = '';
    document.getElementById('s-filtered').textContent = rows.length;
  } else fw.style.display = 'none';

  const labels = { name: 'name', size: 'size', mtime: 'modified' };
  document.getElementById('s-sort-label').textContent = `${labels[col]} ${dir > 0 ? '↑' : '↓'}`;

  ['name','size','mtime'].forEach(c => {
    const el = document.getElementById('arr-' + c);
    const th = document.querySelector(`[data-col="${c}"]`);
    if (c === col) { th.classList.add('active'); el.textContent = dir > 0 ? '↑' : '↓'; }
    else           { th.classList.remove('active'); el.textContent = ''; }
  });

  const wrap = document.getElementById('rows');
  if (!rows.length) {
    wrap.innerHTML = `<div class="empty">${q ? 'no matches for "' + esc(q) + '"' : 'no files'}</div>`;
    return;
  }
  wrap.innerHTML = rows.map((f, i) => {
    const e = gext(f.name);
    return `<div class="row">
      <div class="file-name-cell">
        <span class="ext-tag ${extClass(e)}">${esc(e) || '?'}</span>
        <div>
          <div class="file-name" title="${esc(f.name)}">${esc(f.name)}</div>
          <div class="file-meta">${fsize(f.size)} · ${fdate(f.mtime)}</div>
        </div>
      </div>
      <div class="cell-size">${fsize(f.size)}</div>
      <div class="cell-date">${fdate(f.mtime)}</div>
      <div class="actions">
        <button class="act-btn" id="cb${i}" onclick="copyLink('${esc(f.name)}','cb${i}')" title="Copy download link">${COPY_ICON}</button>
        <button class="act-btn" id="db${i}" onclick="dl('${esc(f.name)}','db${i}')" title="Download">${DL_ICON}</button>
      </div>
    </div>`;
  }).join('');
}

// sort
document.querySelectorAll('.th[data-col]').forEach(th => {
  th.addEventListener('click', () => {
    const c = th.dataset.col;
    _sort = { col: c, dir: _sort.col === c ? -_sort.dir : -1 };
    render();
  });
});

// search
document.getElementById('q').addEventListener('input', render);

// copy link — fetches token from server, copies full URL
async function copyLink(name, btnId) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  try {
    const r = await fetch('/token/' + encodeURIComponent(name));
    if (!r.ok) { showToast('failed to get link'); return; }
    const { url } = await r.json();
    await navigator.clipboard.writeText(location.origin + url);
    btn.classList.add('copied');
    btn.innerHTML = CHECK_ICON;
    showToast('link copied');
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = COPY_ICON; }, 2500);
  } catch {
    showToast('copy failed');
  }
}

// download (browser, uses session cookie)
function dl(name, btnId) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.classList.add('spinning'); btn.innerHTML = SPIN_ICON;
  const a = document.createElement('a');
  a.href = '/dl/' + encodeURIComponent(name);
  a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => {
    btn.classList.remove('spinning'); btn.classList.add('done'); btn.innerHTML = CHECK_ICON;
    setTimeout(() => { btn.classList.remove('done'); btn.innerHTML = DL_ICON; }, 3000);
  }, 900);
}

// logout
async function doLogout() {
  await fetch('/logout', { method: 'POST' });
  location.href = '/';
}

load();
setInterval(load, 30000);
</script>
</body>
</html>
"""


# ── Routes ─────────────────────────────────────────────────────────────────────

async def handle_root(req: web.Request) -> web.Response:
    if _check(req):
        return web.Response(text=_EXPLORER_HTML, content_type="text/html")
    return web.Response(text=_LOGIN_HTML.replace("{error}", ""), content_type="text/html")

async def handle_login(req: web.Request) -> web.Response:
    data = await req.post()
    pw   = data.get("pass", "")
    if _pw_ok(pw):
        tok  = _new_session()
        resp = web.HTTPFound("/")
        resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                        httponly=True, samesite="Strict")
        return resp
    err = '<div class="err">incorrect password</div>'
    return web.Response(
        text=_LOGIN_HTML.replace("{error}", err),
        content_type="text/html",
        status=401)

async def handle_logout(req: web.Request) -> web.Response:
    tok = req.cookies.get(COOKIE_NAME)
    _sessions.pop(tok, None)
    resp = web.HTTPFound("/")
    resp.del_cookie(COOKIE_NAME)
    return resp

async def handle_files(req: web.Request) -> web.Response:
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    files = []
    try:
        for entry in os.scandir(DOWNLOADS_DIR):
            if not entry.is_file(follow_symlinks=False): continue
            st = entry.stat()
            files.append({"name": entry.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)
    return web.json_response(files)

async def handle_make_token(req: web.Request) -> web.Response:
    """Return a signed token URL for a file. Requires session. Token never expires."""
    if not _check(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    name = req.match_info["name"]
    if _safe(name) is None:
        raise web.HTTPNotFound()
    tok = make_dl_token(name)
    return web.json_response({"url": f"/get/{tok}/{name}"})

async def handle_token_download(req: web.Request) -> web.Response:
    """Download a file using a signed token. No session needed — safe for wget/aria2."""
    tok  = req.match_info["token"]
    name = req.match_info["name"]
    if not verify_dl_token(tok, name):
        raise web.HTTPForbidden()
    path = _safe(name)
    if path is None:
        raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    resp = web.StreamResponse(headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Content-Type":        ct or "application/octet-stream",
        "Content-Length":      str(path.stat().st_size),
    })
    await resp.prepare(req)
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            await resp.write(chunk)
    return resp

async def handle_download(req: web.Request) -> web.Response:
    """Browser download — requires session cookie."""
    if not _check(req):
        raise web.HTTPFound("/")
    name = req.match_info["name"]
    path = _safe(name)
    if path is None:
        raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    resp = web.StreamResponse(headers={
        "Content-Disposition": f'attachment; filename="{name}"',
        "Content-Type":        ct or "application/octet-stream",
        "Content-Length":      str(path.stat().st_size),
    })
    await resp.prepare(req)
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            await resp.write(chunk)
    return resp


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/",                handle_root)
    app.router.add_post("/login",          handle_login)
    app.router.add_post("/logout",         handle_logout)
    app.router.add_get("/files",           handle_files)
    app.router.add_get("/token/{name}",    handle_make_token)
    app.router.add_get("/get/{token}/{name}", handle_token_download)
    app.router.add_get("/dl/{name}",       handle_download)
    return app

async def start_web() -> None:
    runner = web.AppRunner(create_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", WEB_PORT)
    await site.start()
    base = os.environ.get("WEB_BASE", f"http://localhost:{WEB_PORT}")
    print(f"web: {base}")

if __name__ == "__main__":
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start_web())
    loop.run_forever()
