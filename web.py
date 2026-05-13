import hashlib
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
DOWNLOADS_DIR = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)

SESSION_TTL = 86400
COOKIE_NAME = "fsid"
_sessions: dict[str, float] = {}


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


# ── HTML ───────────────────────────────────────────────────────────────────────

_LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fileserv</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f5f5;--sur:#ffffff;--bor:#e5e5e5;
  --txt:#0a0a0a;--sub:#737373;--acc:#6366f1;--err:#ef4444;
}
@media(prefers-color-scheme:dark){:root{
  --bg:#0a0a0a;--sur:#141414;--bor:#262626;
  --txt:#fafafa;--sub:#737373;--acc:#818cf8;--err:#f87171;
}}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:'Inter',system-ui,sans-serif;font-size:14px}
body{display:flex;align-items:center;justify-content:center;padding:20px}
.card{
  width:100%;max-width:360px;
  background:var(--sur);border:1px solid var(--bor);
  border-radius:12px;padding:32px 28px;
}
.title{font-size:20px;font-weight:600;letter-spacing:-.02em;margin-bottom:4px}
.sub{font-size:13px;color:var(--sub);margin-bottom:28px}
label{display:block;font-size:12px;font-weight:500;color:var(--sub);margin-bottom:6px}
input{
  width:100%;background:var(--bg);border:1px solid var(--bor);
  color:var(--txt);font-family:inherit;font-size:14px;
  padding:10px 12px;border-radius:8px;outline:none;
  transition:border-color .15s,box-shadow .15s;-webkit-appearance:none;
}
input:focus{border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 20%,transparent)}
input::placeholder{color:var(--bor)}
.btn{
  margin-top:12px;width:100%;padding:10px 16px;
  background:var(--acc);color:#fff;
  font-family:inherit;font-size:14px;font-weight:500;
  border:none;border-radius:8px;cursor:pointer;
  transition:opacity .15s;-webkit-appearance:none;
}
.btn:hover{opacity:.88}
.btn:active{opacity:.75}
.err{
  margin-top:12px;font-size:13px;color:var(--err);
  padding:9px 12px;background:color-mix(in srgb,var(--err) 10%,transparent);
  border:1px solid color-mix(in srgb,var(--err) 25%,transparent);
  border-radius:6px;text-align:center;
}
</style>
</head>
<body>
<div class="card">
  <div class="title">fileserv</div>
  <div class="sub">Sign in to access downloads</div>
  <form method="POST" action="/login">
    <label for="pw">Password</label>
    <input id="pw" type="password" name="pass" autofocus autocomplete="current-password" placeholder="Enter password">
    <button class="btn" type="submit">Continue</button>
    {error}
  </form>
</div>
</body>
</html>
"""

_EXPLORER_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>fileserv</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

/* ── THEME ── */
:root{
  --bg:#f5f5f5;--sur:#ffffff;--sur2:#f0f0f0;--bor:#e5e5e5;
  --txt:#0a0a0a;--sub:#737373;--sub2:#a3a3a3;
  --acc:#6366f1;--acc-bg:rgba(99,102,241,.1);--acc-bor:rgba(99,102,241,.3);
  --green:#16a34a;--green-bg:rgba(22,163,74,.1);--green-bor:rgba(22,163,74,.3);
  --row-hover:#f9f9f9;
  --shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.05);
}
[data-theme=dark]{
  --bg:#0a0a0a;--sur:#141414;--sur2:#1f1f1f;--bor:#262626;
  --txt:#fafafa;--sub:#737373;--sub2:#525252;
  --acc:#818cf8;--acc-bg:rgba(129,140,248,.12);--acc-bor:rgba(129,140,248,.3);
  --green:#4ade80;--green-bg:rgba(74,222,128,.1);--green-bor:rgba(74,222,128,.25);
  --row-hover:#1a1a1a;
  --shadow:0 1px 3px rgba(0,0,0,.4);
}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#0a0a0a;--sur:#141414;--sur2:#1f1f1f;--bor:#262626;
  --txt:#fafafa;--sub:#737373;--sub2:#525252;
  --acc:#818cf8;--acc-bg:rgba(129,140,248,.12);--acc-bor:rgba(129,140,248,.3);
  --green:#4ade80;--green-bg:rgba(74,222,128,.1);--green-bor:rgba(74,222,128,.25);
  --row-hover:#1a1a1a;
  --shadow:0 1px 3px rgba(0,0,0,.4);
}}

html,body{min-height:100%;background:var(--bg);color:var(--txt);
  font-family:'Inter',system-ui,sans-serif;font-size:14px;
  transition:background .2s,color .2s}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-thumb{background:var(--bor);border-radius:2px}
::-webkit-scrollbar-track{background:transparent}

/* ── TOPBAR ── */
.top{
  position:sticky;top:0;z-index:30;
  height:52px;background:color-mix(in srgb,var(--bg) 85%,transparent);
  backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
  border-bottom:1px solid var(--bor);
  display:flex;align-items:center;gap:8px;padding:0 16px;
}
.logo{font-size:15px;font-weight:600;letter-spacing:-.02em;flex-shrink:0;color:var(--txt)}
.logo span{color:var(--acc)}
.sep{color:var(--bor);flex-shrink:0;font-size:16px;margin:0 2px}

.search{flex:1;max-width:320px;position:relative;display:flex;align-items:center}
.search svg{position:absolute;left:9px;width:14px;height:14px;
  stroke:var(--sub);fill:none;stroke-width:2;stroke-linecap:round;pointer-events:none}
#q{
  width:100%;background:var(--sur2);border:1px solid var(--bor);
  color:var(--txt);font-family:inherit;font-size:13px;
  padding:7px 10px 7px 30px;border-radius:8px;outline:none;
  transition:border-color .15s,box-shadow .15s;-webkit-appearance:none;
}
#q:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--acc-bg)}
#q::placeholder{color:var(--sub2)}

.topright{margin-left:auto;display:flex;align-items:center;gap:6px}
.ibtn{
  background:var(--sur);border:1px solid var(--bor);color:var(--sub);
  width:32px;height:32px;border-radius:8px;cursor:pointer;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;font-size:15px;
  transition:color .15s,border-color .15s,background .15s;-webkit-tap-highlight-color:transparent;
}
.ibtn:hover{color:var(--txt);border-color:var(--sub)}
.ibtn:active{background:var(--sur2)}
.logout-btn{
  background:none;border:1px solid var(--bor);color:var(--sub);
  padding:0 12px;height:32px;border-radius:8px;cursor:pointer;
  font-family:inherit;font-size:13px;font-weight:500;
  transition:color .15s,border-color .15s;-webkit-tap-highlight-color:transparent;
}
.logout-btn:hover{color:var(--txt);border-color:var(--sub)}

/* ── SUBBAR (chips + stats) ── */
.subbar{
  display:flex;align-items:center;gap:0;
  border-bottom:1px solid var(--bor);background:var(--sur);
  overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch;
}
.subbar::-webkit-scrollbar{display:none}
.chips{display:flex;align-items:center;gap:6px;padding:8px 16px;flex-shrink:0}
.chip{
  flex-shrink:0;font-size:12px;font-weight:500;
  padding:4px 10px;border-radius:6px;cursor:pointer;
  border:1px solid var(--bor);color:var(--sub);
  background:var(--sur);transition:all .12s;
  -webkit-tap-highlight-color:transparent;white-space:nowrap;
}
.chip:hover{color:var(--txt);border-color:var(--sub)}
.chip.on{color:var(--acc);background:var(--acc-bg);border-color:var(--acc-bor)}
.chip .n{margin-left:4px;opacity:.5;font-weight:400}
.statsdiv{width:1px;background:var(--bor);align-self:stretch;flex-shrink:0;margin:6px 4px}
.stats{display:flex;align-items:center;gap:16px;padding:8px 16px;flex-shrink:0}
.stat{font-size:12px;color:var(--sub);white-space:nowrap}
.stat b{color:var(--txt);font-weight:500}

/* ── LAYOUT ── */
.layout{display:flex;min-height:calc(100vh - 52px - 40px)}

/* ── SIDEBAR ── */
.sidebar{
  width:200px;flex-shrink:0;border-right:1px solid var(--bor);
  padding:16px 12px;position:sticky;top:52px;
  height:calc(100vh - 52px);overflow-y:auto;background:var(--sur);
}
.slabel{font-size:11px;font-weight:600;color:var(--sub2);letter-spacing:.06em;
  text-transform:uppercase;padding:0 6px;margin-bottom:4px;margin-top:8px}
.slabel:first-child{margin-top:0}
.srow{display:flex;justify-content:space-between;align-items:center;
  padding:4px 6px;border-radius:6px}
.sk{font-size:13px;color:var(--sub)}
.sv{font-size:13px;font-weight:500}
.sdiv{border:none;border-top:1px solid var(--bor);margin:10px 4px}
.sf{
  display:flex;justify-content:space-between;align-items:center;
  font-size:13px;padding:5px 8px;border-radius:6px;cursor:pointer;
  color:var(--sub);transition:all .1s;-webkit-tap-highlight-color:transparent;
  font-family:inherit;
}
.sf:hover{color:var(--txt);background:var(--sur2)}
.sf.on{color:var(--acc);background:var(--acc-bg);font-weight:500}
.sf .n{font-size:11px;color:var(--sub2);background:var(--sur2);
  padding:1px 6px;border-radius:10px}
.sf.on .n{background:var(--acc-bg)}

/* ── MAIN ── */
.main{flex:1;min-width:0;padding:16px}

/* ── FILE TABLE ── */
.tbl{
  background:var(--sur);border:1px solid var(--bor);
  border-radius:10px;overflow:hidden;box-shadow:var(--shadow);
}
.thead{
  display:grid;grid-template-columns:1fr 80px 120px 80px;
  padding:8px 14px;border-bottom:1px solid var(--bor);
  background:var(--sur2);
}
.th{
  font-size:11px;font-weight:600;color:var(--sub2);letter-spacing:.04em;
  text-transform:uppercase;cursor:pointer;user-select:none;
  display:flex;align-items:center;gap:4px;background:none;
  border:none;font-family:inherit;padding:2px 4px;border-radius:4px;
  transition:color .12s;-webkit-tap-highlight-color:transparent;
}
.th:hover{color:var(--sub)}
.th.on{color:var(--txt)}
.th .arr{font-size:10px;opacity:.5}
.th-r{justify-content:flex-end}
.th-last{justify-content:flex-end;cursor:default}

.frow{
  display:grid;grid-template-columns:1fr 80px 120px 80px;
  align-items:center;padding:10px 14px;
  border-bottom:1px solid var(--bor);
  transition:background .08s;
  animation:up .15s ease both;
}
.frow:last-child{border-bottom:none}
.frow:hover{background:var(--row-hover)}
@keyframes up{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}

.fname{display:flex;align-items:center;gap:8px;min-width:0}
.ext{
  flex-shrink:0;font-size:10px;font-weight:600;padding:2px 6px;
  border-radius:4px;letter-spacing:.04em;text-transform:uppercase;
  font-family:'Inter',sans-serif;
}
.ez{background:rgba(251,146,60,.15);color:#f97316}
.ei{background:rgba(167,139,250,.15);color:#8b5cf6}
.ea{background:rgba(52,211,153,.15);color:#10b981}
.et{background:rgba(56,189,248,.15);color:#0ea5e9}
.ed{background:var(--sur2);color:var(--sub)}

.fn{font-size:13px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fmeta{font-size:11px;color:var(--sub);margin-top:1px}

.fsz{font-size:12px;color:var(--sub);text-align:right;white-space:nowrap}
.fdt{font-size:12px;color:var(--sub);white-space:nowrap}

.dlb{
  margin-left:auto;display:flex;align-items:center;justify-content:center;
  width:32px;height:32px;border-radius:8px;cursor:pointer;
  border:1px solid var(--bor);background:var(--sur);color:var(--sub);
  font-size:16px;transition:all .15s;-webkit-tap-highlight-color:transparent;
}
.dlb:hover{color:var(--acc);border-color:var(--acc-bor);background:var(--acc-bg)}
.dlb:active{transform:scale(.9)}
.dlb.done{color:var(--green);border-color:var(--green-bor);background:var(--green-bg)}
.dlb:disabled{opacity:.4;cursor:default;transform:none}

/* ── EMPTY ── */
.empty{padding:56px 24px;text-align:center;color:var(--sub);font-size:13px}
.empty-icon{font-size:28px;margin-bottom:12px;opacity:.2}

/* ── MOBILE ── */
@media(max-width:639px){
  .sidebar,.thead,.fsz,.fdt{display:none}
  .layout{display:block}
  .main{padding:10px}
  .top{gap:6px}
  .search{max-width:none;flex:1}
  .logout-btn span{display:none}
  .tbl{border-radius:8px}
  .frow{
    grid-template-columns:1fr auto;
    gap:8px;padding:11px 12px;
  }
  .fmeta{display:block}
  .dlb{width:36px;height:36px;font-size:17px}
}
@media(min-width:640px){
  .subbar .chips{border-right:1px solid var(--bor)}
  .fmeta{display:none}
  .main{padding:20px}
  .top{padding:0 20px;gap:10px}
}
</style>
</head>
<body>

<header class="top">
  <div class="logo">file<span>serv</span></div>
  <span class="sep">/</span>
  <div class="search">
    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input id="q" type="search" placeholder="Search files…" autocomplete="off" spellcheck="false">
  </div>
  <div class="topright">
    <button class="ibtn" id="theme-btn" onclick="toggleTheme()" title="Toggle theme">◐</button>
    <button class="ibtn" onclick="load()" title="Refresh">↺</button>
    <button class="logout-btn" onclick="doLogout()"><span>Logout</span> ⏻</button>
  </div>
</header>

<div class="subbar">
  <div class="chips" id="chips"></div>
  <div class="statsdiv"></div>
  <div class="stats">
    <span class="stat" id="s-files">—</span>
    <span class="stat" id="s-size">—</span>
    <span class="stat" id="s-vis" style="display:none">—</span>
  </div>
</div>

<div class="layout">
  <aside class="sidebar">
    <div class="slabel">Vault</div>
    <div class="srow"><span class="sk">Files</span><span class="sv" id="d-cnt">—</span></div>
    <div class="srow"><span class="sk">Total</span><span class="sv" id="d-sz">—</span></div>
    <hr class="sdiv">
    <div class="slabel">Type</div>
    <div id="sfilter"></div>
  </aside>

  <main class="main">
    <div class="tbl">
      <div class="thead">
        <button class="th" data-col="name">Name <span class="arr" id="arr-name"></span></button>
        <button class="th th-r" data-col="size">Size <span class="arr" id="arr-size"></span></button>
        <button class="th" data-col="mtime">Modified <span class="arr" id="arr-mtime"></span></button>
        <div class="th th-last">Get</div>
      </div>
      <div id="rows"></div>
    </div>
  </main>
</div>

<script>
let _all=[], _ext=null, _sort={col:'mtime',dir:-1};

// ── theme ──────────────────────────────────────────────────────────────────
const root = document.documentElement;
const saved = localStorage.getItem('theme');
if(saved) root.setAttribute('data-theme', saved);

function toggleTheme(){
  const cur = root.getAttribute('data-theme');
  const sys = window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark':'light';
  const now = cur || sys;
  const next = now==='dark' ? 'light':'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
}

// ── utils ──────────────────────────────────────────────────────────────────
const fsize=b=>{const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++;}return b.toFixed(i?1:0)+' '+u[i];};
const fdate=ts=>{
  const d=new Date(ts*1000),n=new Date();
  if(d.toDateString()===n.toDateString())
    return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  if(n-d<604800e3)
    return d.toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});
  return d.toLocaleDateString([],{month:'short',day:'numeric',year:'numeric'});
};
const gext=n=>{const i=n.lastIndexOf('.');return i>0?n.slice(i+1).toLowerCase():'';};
const ecls=e=>{
  if(['zip','gz','xz','zst','tar','br','7z'].includes(e))return'ez';
  if(['img','raw','iso','bin','dat','rom'].includes(e))  return'ei';
  if(['apk','ota'].includes(e))                          return'ea';
  if(['txt','log','md','json','xml','cfg'].includes(e))  return'et';
  return'ed';
};
const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

// ── data ───────────────────────────────────────────────────────────────────
async function load(){
  try{
    const r=await fetch('/files');
    if(r.status===401){location.href='/';return;}
    _all=await r.json();
  }catch{return;}
  buildFilters();render();
}

// ── filters ────────────────────────────────────────────────────────────────
function buildFilters(){
  const m={};
  _all.forEach(f=>{const e=gext(f.name)||'other';m[e]=(m[e]||0)+1;});
  const entries=Object.entries(m).sort((a,b)=>b[1]-a[1]);

  const makeChip=(cls,val,label,n)=>
    `<div class="${cls} ${_ext===val?'on':''}" onclick="setExt(${val===null?'null':`'${esc(val)}'`})">${esc(label)}<span class="n">${n}</span></div>`;
  const makeSf=(val,label,n)=>
    `<button class="sf ${_ext===val?'on':''}" onclick="setExt(${val===null?'null':`'${esc(val)}'`})"><span>${esc(label)}</span><span class="n">${n}</span></button>`;

  document.getElementById('chips').innerHTML=
    makeChip('chip',null,'All',_all.length)+
    entries.map(([e,n])=>makeChip('chip',e,'.'+e,n)).join('');

  document.getElementById('sfilter').innerHTML=
    makeSf(null,'All',_all.length)+
    entries.map(([e,n])=>makeSf(e,'.'+e,n)).join('');
}

function setExt(e){_ext=e;buildFilters();render();}

// ── render ─────────────────────────────────────────────────────────────────
function render(){
  const q=document.getElementById('q').value.toLowerCase();
  let rows=_all.filter(f=>(_ext?gext(f.name)===_ext:true)&&f.name.toLowerCase().includes(q));
  const{col,dir}=_sort;
  rows.sort((a,b)=>{
    let av=a[col],bv=b[col];
    if(typeof av==='string'){av=av.toLowerCase();bv=bv.toLowerCase();}
    return av<bv?-dir:av>bv?dir:0;
  });

  const total=_all.reduce((s,f)=>s+f.size,0);
  ['d-cnt','d-sz'].forEach((id,i)=>{
    document.getElementById(id).textContent=i?fsize(total):_all.length;
  });
  document.getElementById('s-files').innerHTML=`<b>${_all.length}</b> files`;
  document.getElementById('s-size').innerHTML=`<b>${fsize(total)}</b>`;
  const vis=document.getElementById('s-vis');
  if(rows.length<_all.length){
    vis.style.display='';vis.innerHTML=`<b>${rows.length}</b> shown`;
  } else vis.style.display='none';

  // sort arrows
  ['name','size','mtime'].forEach(c=>{
    const el=document.getElementById('arr-'+c);
    const th=document.querySelector(`[data-col="${c}"]`);
    if(c===col){th.classList.add('on');el.textContent=dir>0?'↑':'↓';}
    else{th.classList.remove('on');el.textContent='';}
  });

  const wrap=document.getElementById('rows');
  if(!rows.length){
    wrap.innerHTML=`<div class="empty"><div class="empty-icon">⊘</div>No files found</div>`;
    return;
  }
  wrap.innerHTML=rows.map((f,i)=>{
    const e=gext(f.name);
    return`<div class="frow" style="animation-delay:${Math.min(i,30)*10}ms">
      <div class="fname">
        <span class="ext ${ecls(e)}">${esc(e)||'—'}</span>
        <div>
          <div class="fn" title="${esc(f.name)}">${esc(f.name)}</div>
          <div class="fmeta">${fsize(f.size)} · ${fdate(f.mtime)}</div>
        </div>
      </div>
      <div class="fsz">${fsize(f.size)}</div>
      <div class="fdt">${fdate(f.mtime)}</div>
      <button class="dlb" id="b${i}" onclick="dl('${esc(f.name)}','b${i}')" title="Download">↓</button>
    </div>`;
  }).join('');
}

// ── sort ───────────────────────────────────────────────────────────────────
document.querySelectorAll('.th[data-col]').forEach(th=>{
  th.addEventListener('click',()=>{
    const c=th.dataset.col;
    _sort={col:c,dir:_sort.col===c?-_sort.dir:-1};
    render();
  });
});

// ── download ───────────────────────────────────────────────────────────────
function dl(name,bid){
  const b=document.getElementById(bid);
  if(b){b.textContent='…';b.disabled=true;}
  window.location.href='/dl/'+encodeURIComponent(name);
  setTimeout(()=>{if(b){b.classList.add('done');b.textContent='✓';b.disabled=false;}},1800);
}

document.getElementById('q').addEventListener('input',render);
async function doLogout(){await fetch('/logout',{method:'POST'});location.href='/';}

load();
setInterval(load,30000);
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
    err = '<div class="err">Incorrect password</div>'
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

async def handle_download(req: web.Request) -> web.Response:
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
    app.router.add_get("/",          handle_root)
    app.router.add_post("/login",    handle_login)
    app.router.add_post("/logout",   handle_logout)
    app.router.add_get("/files",     handle_files)
    app.router.add_get("/dl/{name}", handle_download)
    return app

async def start_web() -> None:
    runner = web.AppRunner(create_app())
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", WEB_PORT)
    await site.start()
    print(f"web: http://0.0.0.0:{WEB_PORT}")
