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
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d;--sur:#141414;--bor:#222;--bor2:#2a2a2a;
  --txt:#e8e8e8;--sub:#666;--sub2:#444;
  --acc:#e8ff47;--acc-dim:#b8cc38;
  --err:#ff4444;--err-bg:rgba(255,68,68,.08);
  --mono:'JetBrains Mono',monospace;
  --sans:'DM Sans',sans-serif;
}
html,body{height:100%;background:var(--bg);color:var(--txt);font-family:var(--sans);font-size:14px;-webkit-font-smoothing:antialiased}
body{display:flex;align-items:center;justify-content:center;padding:20px}

.card{width:100%;max-width:340px}
.brand{font-family:var(--mono);font-size:11px;font-weight:700;color:var(--sub);letter-spacing:.15em;text-transform:uppercase;margin-bottom:32px}
.brand span{color:var(--acc)}

h1{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--txt);margin-bottom:4px;letter-spacing:-.02em}
.tagline{font-size:13px;color:var(--sub);margin-bottom:28px}

label{display:block;font-family:var(--mono);font-size:10px;font-weight:700;color:var(--sub);letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}
.field{position:relative}
input{
  width:100%;background:var(--sur);border:1px solid var(--bor2);
  color:var(--txt);font-family:var(--mono);font-size:13px;
  padding:11px 14px;border-radius:4px;outline:none;
  transition:border-color .15s;-webkit-appearance:none;
}
input:focus{border-color:var(--acc)}
input::placeholder{color:var(--sub2)}

.btn{
  margin-top:10px;width:100%;padding:11px 16px;
  background:var(--acc);color:#0d0d0d;
  font-family:var(--mono);font-size:12px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;border:none;border-radius:4px;cursor:pointer;
  transition:background .1s,transform .1s;
}
.btn:hover{background:var(--acc-dim)}
.btn:active{transform:scale(.98)}

.err{
  margin-top:10px;font-family:var(--mono);font-size:12px;color:var(--err);
  padding:9px 12px;background:var(--err-bg);
  border:1px solid rgba(255,68,68,.2);border-radius:4px;
}
</style>
</head>
<body>
<div class="card">
  <div class="brand">file<span>serv</span> / auth</div>
  <h1>Sign in</h1>
  <p class="tagline">Access restricted. Enter your password.</p>
  <form method="POST" action="/login">
    <label for="pw">Password</label>
    <div class="field">
      <input id="pw" type="password" name="pass" autofocus autocomplete="current-password" placeholder="••••••••••••">
    </div>
    <button class="btn" type="submit">Continue →</button>
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
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0d0d0d;--sur:#111;--sur2:#161616;--sur3:#1c1c1c;
  --bor:#1e1e1e;--bor2:#252525;--bor3:#2e2e2e;
  --txt:#e8e8e8;--txt2:#aaa;--sub:#555;--sub2:#333;
  --acc:#e8ff47;--acc-dim:#b8cc38;--acc-mute:rgba(232,255,71,.08);--acc-bor:rgba(232,255,71,.2);
  --red:#ff4444;--grn:#39d353;--blu:#4ea8de;--ora:#f5a623;
  --mono:'JetBrains Mono',monospace;
  --sans:'DM Sans',sans-serif;
  --r:4px;
}

html,body{min-height:100%;background:var(--bg);color:var(--txt);
  font-family:var(--sans);font-size:14px;-webkit-font-smoothing:antialiased}

/* scrollbar */
::-webkit-scrollbar{width:3px;height:3px}
::-webkit-scrollbar-thumb{background:var(--bor3)}
::-webkit-scrollbar-track{background:transparent}
* { scrollbar-width:thin;scrollbar-color:var(--bor3) transparent }

/* ── TOPBAR ── */
.top{
  position:sticky;top:0;z-index:50;height:48px;
  background:rgba(13,13,13,.92);
  backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border-bottom:1px solid var(--bor);
  display:flex;align-items:center;gap:0;padding:0;
}
.brand{
  font-family:var(--mono);font-size:12px;font-weight:700;
  color:var(--sub);letter-spacing:.12em;text-transform:uppercase;
  padding:0 18px;border-right:1px solid var(--bor);height:100%;
  display:flex;align-items:center;gap:6px;flex-shrink:0;
  white-space:nowrap;
}
.brand-dot{width:6px;height:6px;background:var(--acc);border-radius:50%;flex-shrink:0}

.searchbar{
  flex:1;display:flex;align-items:center;
  padding:0 14px;border-right:1px solid var(--bor);height:100%;
}
.searchbar svg{width:13px;height:13px;stroke:var(--sub);fill:none;
  stroke-width:2;stroke-linecap:round;flex-shrink:0;margin-right:9px}
#q{
  flex:1;background:transparent;border:none;
  color:var(--txt);font-family:var(--mono);font-size:12px;
  outline:none;-webkit-appearance:none;min-width:0;
}
#q::placeholder{color:var(--sub)}

.topactions{display:flex;align-items:center;height:100%;margin-left:auto}
.tbtn{
  font-family:var(--mono);font-size:11px;font-weight:700;color:var(--sub);
  letter-spacing:.08em;text-transform:uppercase;
  border:none;border-left:1px solid var(--bor);background:transparent;
  height:100%;padding:0 16px;cursor:pointer;
  transition:color .12s,background .12s;white-space:nowrap;
}
.tbtn:hover{color:var(--txt);background:var(--sur2)}
.tbtn.accent{color:var(--acc)}
.tbtn.accent:hover{background:var(--acc-mute)}

/* ── STATUS BAR ── */
.statusbar{
  height:32px;border-bottom:1px solid var(--bor);background:var(--sur);
  display:flex;align-items:center;gap:0;overflow-x:auto;
  scrollbar-width:none;
}
.statusbar::-webkit-scrollbar{display:none}
.sstat{
  font-family:var(--mono);font-size:10px;color:var(--sub);
  padding:0 16px;border-right:1px solid var(--bor);
  height:100%;display:flex;align-items:center;gap:6px;
  white-space:nowrap;flex-shrink:0;
}
.sstat b{color:var(--txt2);font-weight:500}
.sstat.hi b{color:var(--acc)}

/* ── FILTER TABS ── */
.filtertabs{
  display:flex;align-items:center;overflow-x:auto;
  border-bottom:1px solid var(--bor);background:var(--bg);
  scrollbar-width:none;padding:0 4px;
}
.filtertabs::-webkit-scrollbar{display:none}
.ftab{
  font-family:var(--mono);font-size:11px;font-weight:500;
  color:var(--sub);padding:0 14px;height:36px;cursor:pointer;
  border:none;background:transparent;
  border-bottom:2px solid transparent;
  transition:color .12s,border-color .12s;
  display:flex;align-items:center;gap:6px;
  white-space:nowrap;flex-shrink:0;
}
.ftab:hover{color:var(--txt2)}
.ftab.on{color:var(--acc);border-bottom-color:var(--acc)}
.ftab .n{
  font-size:10px;color:var(--sub2);
  background:var(--sur3);padding:1px 5px;border-radius:2px;
}
.ftab.on .n{color:var(--sub);background:var(--acc-mute)}

/* ── LAYOUT ── */
.wrap{display:flex;min-height:calc(100vh - 48px - 32px - 36px)}

/* ── SIDEBAR ── */
.sidebar{
  width:180px;flex-shrink:0;border-right:1px solid var(--bor);
  background:var(--sur);
  position:sticky;top:calc(48px + 32px + 36px);
  height:calc(100vh - 48px - 32px - 36px);
  overflow-y:auto;
}
.slabel{
  font-family:var(--mono);font-size:9px;font-weight:700;color:var(--sub2);
  letter-spacing:.14em;text-transform:uppercase;
  padding:16px 14px 6px;
}
.srow{
  display:flex;justify-content:space-between;align-items:center;
  padding:5px 14px;
}
.sk{font-size:12px;color:var(--sub)}
.sv{font-family:var(--mono);font-size:12px;color:var(--txt2)}
.sdiv{border:none;border-top:1px solid var(--bor);margin:8px 0}
.sext{
  display:flex;justify-content:space-between;align-items:center;
  padding:5px 14px;cursor:pointer;border:none;background:transparent;
  width:100%;transition:background .1s;font-family:inherit;
}
.sext:hover{background:var(--sur2)}
.sext.on{background:var(--acc-mute)}
.sext-name{font-family:var(--mono);font-size:11px;color:var(--sub)}
.sext.on .sext-name{color:var(--acc)}
.sext-n{font-family:var(--mono);font-size:10px;color:var(--sub2)}

/* ── MAIN ── */
.main{flex:1;min-width:0;padding:0}

/* ── TABLE ── */
.tbl{border-bottom:1px solid var(--bor)}
.thead{
  display:grid;grid-template-columns:1fr 90px 130px 52px;
  padding:0 16px;height:34px;align-items:center;
  background:var(--sur);border-bottom:1px solid var(--bor);
  position:sticky;top:calc(48px + 32px + 36px);z-index:10;
}
.th{
  font-family:var(--mono);font-size:9px;font-weight:700;
  color:var(--sub2);letter-spacing:.12em;text-transform:uppercase;
  cursor:pointer;border:none;background:transparent;
  font-family:var(--mono);padding:0;
  display:flex;align-items:center;gap:4px;
  transition:color .1s;-webkit-tap-highlight-color:transparent;
}
.th:hover{color:var(--sub)}
.th.on{color:var(--txt2)}
.th .arr{font-size:9px;color:var(--acc)}
.th-r{justify-content:flex-end}
.th-last{cursor:default;justify-content:center}

.frow{
  display:grid;grid-template-columns:1fr 90px 130px 52px;
  align-items:center;padding:0 16px;height:46px;
  border-bottom:1px solid var(--bor);
  transition:background .08s;
  cursor:default;
}
.frow:last-child{border-bottom:none}
.frow:hover{background:var(--sur)}

.fname{display:flex;align-items:center;gap:10px;min-width:0}
.badge{
  flex-shrink:0;font-family:var(--mono);font-size:9px;font-weight:700;
  padding:2px 5px;border-radius:2px;letter-spacing:.04em;text-transform:uppercase;
  border:1px solid;
}
.bz{color:#f97316;border-color:rgba(249,115,22,.3);background:rgba(249,115,22,.06)}
.bi{color:#a78bfa;border-color:rgba(167,139,250,.3);background:rgba(167,139,250,.06)}
.ba{color:var(--grn);border-color:rgba(57,211,83,.3);background:rgba(57,211,83,.06)}
.bt{color:var(--blu);border-color:rgba(78,168,222,.3);background:rgba(78,168,222,.06)}
.bd{color:var(--sub);border-color:var(--bor3);background:var(--sur3)}

.fn{
  font-size:13px;font-weight:500;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  color:var(--txt);
}
.fmeta{font-family:var(--mono);font-size:10px;color:var(--sub);margin-top:2px}

.fsz{font-family:var(--mono);font-size:11px;color:var(--txt2);text-align:right;white-space:nowrap}
.fdt{font-family:var(--mono);font-size:11px;color:var(--sub);white-space:nowrap}

.dlwrap{display:flex;justify-content:center}
.dlb{
  width:28px;height:28px;border-radius:var(--r);
  border:1px solid var(--bor3);background:transparent;
  color:var(--sub);font-size:13px;cursor:pointer;
  display:flex;align-items:center;justify-content:center;
  transition:color .12s,border-color .12s,background .12s,transform .1s;
  -webkit-tap-highlight-color:transparent;
}
.dlb:hover{color:var(--acc);border-color:var(--acc-bor);background:var(--acc-mute)}
.dlb:active{transform:scale(.88)}
.dlb.spin{animation:spin .7s linear infinite;pointer-events:none;color:var(--sub)}
.dlb.done{color:var(--grn);border-color:rgba(57,211,83,.3);background:rgba(57,211,83,.06);pointer-events:none}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── EMPTY ── */
.empty{
  padding:64px 24px;text-align:center;
  font-family:var(--mono);font-size:12px;color:var(--sub);
}
.empty-glyph{font-size:24px;margin-bottom:12px;opacity:.15}

/* ── MOBILE ── */
@media(max-width:600px){
  .sidebar,.thead,.fsz,.fdt{display:none}
  .wrap{display:block}
  .main{padding:0}
  .brand{padding:0 14px}
  .frow{height:52px;grid-template-columns:1fr 44px;padding:0 12px}
  .fmeta{display:block}
  .dlb{width:34px;height:34px}
  .ftab{padding:0 10px}
}
@media(min-width:601px){
  .fmeta{display:none}
}
</style>
</head>
<body>

<header class="top">
  <div class="brand">
    <div class="brand-dot"></div>
    fileserv
  </div>
  <div class="searchbar">
    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input id="q" type="search" placeholder="filter files…" autocomplete="off" spellcheck="false">
  </div>
  <div class="topactions">
    <button class="tbtn" onclick="load()" title="Refresh">↺ refresh</button>
    <button class="tbtn accent" onclick="doLogout()">logout</button>
  </div>
</header>

<div class="statusbar">
  <div class="sstat hi"><b id="s-files">—</b> files</div>
  <div class="sstat"><b id="s-size">—</b> total</div>
  <div class="sstat" id="s-vis-wrap" style="display:none"><b id="s-vis">—</b> shown</div>
  <div class="sstat" id="s-sort">sort: <b id="s-sort-v">modified ↓</b></div>
</div>

<div class="filtertabs" id="filtertabs"></div>

<div class="wrap">
  <aside class="sidebar">
    <div class="slabel">Vault</div>
    <div class="srow"><span class="sk">count</span><span class="sv" id="d-cnt">—</span></div>
    <div class="srow"><span class="sk">size</span><span class="sv" id="d-sz">—</span></div>
    <hr class="sdiv">
    <div class="slabel">By type</div>
    <div id="sext-list"></div>
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

// ── utils ──────────────────────────────────────────────────────────────────
const fsize=b=>{const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++;}return b.toFixed(i?1:0)+'\u202f'+u[i];};
const fdate=ts=>{
  const d=new Date(ts*1000),n=new Date();
  if(d.toDateString()===n.toDateString())
    return d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  if(n-d<7*86400e3)
    return d.toLocaleDateString([],{weekday:'short',month:'short',day:'numeric'});
  return d.toLocaleDateString([],{year:'2-digit',month:'short',day:'numeric'});
};
const gext=n=>{const i=n.lastIndexOf('.');return i>0?n.slice(i+1).toLowerCase():'';};
const bcls=e=>{
  if(['zip','gz','xz','zst','tar','br','7z','lz4','bz2'].includes(e)) return 'bz';
  if(['img','raw','iso','bin','dat','rom','dmg','vhd'].includes(e))   return 'bi';
  if(['apk','ota','deb','rpm','pkg'].includes(e))                      return 'ba';
  if(['txt','log','md','json','xml','cfg','yaml','toml','sh'].includes(e)) return 'bt';
  return 'bd';
};
const esc=s=>s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

// ── data ───────────────────────────────────────────────────────────────────
async function load(){
  try{
    const r=await fetch('/files');
    if(r.status===401){location.href='/';return;}
    _all=await r.json();
  }catch{return;}
  buildSidebar();buildTabs();render();
}

// ── sidebar + tabs ─────────────────────────────────────────────────────────
function buildSidebar(){
  const m={};
  _all.forEach(f=>{const e=gext(f.name)||'other';m[e]=(m[e]||0)+1;});
  const entries=Object.entries(m).sort((a,b)=>b[1]-a[1]);
  const total=_all.reduce((s,f)=>s+f.size,0);
  document.getElementById('d-cnt').textContent=_all.length;
  document.getElementById('d-sz').textContent=fsize(total);
  document.getElementById('sext-list').innerHTML=
    `<button class="sext${_ext===null?' on':''}" onclick="setExt(null)">
       <span class="sext-name">all</span><span class="sext-n">${_all.length}</span>
     </button>`+
    entries.map(([e,n])=>
      `<button class="sext${_ext===e?' on':''}" onclick="setExt('${esc(e)}')">
         <span class="sext-name">.${esc(e)}</span><span class="sext-n">${n}</span>
       </button>`).join('');
}

function buildTabs(){
  const m={};
  _all.forEach(f=>{const e=gext(f.name)||'other';m[e]=(m[e]||0)+1;});
  const entries=Object.entries(m).sort((a,b)=>b[1]-a[1]);
  document.getElementById('filtertabs').innerHTML=
    `<button class="ftab${_ext===null?' on':''}" onclick="setExt(null)">all <span class="n">${_all.length}</span></button>`+
    entries.map(([e,n])=>
      `<button class="ftab${_ext===e?' on':''}" onclick="setExt('${esc(e)}')">.${esc(e)} <span class="n">${n}</span></button>`
    ).join('');
}

function setExt(e){_ext=e;buildSidebar();buildTabs();render();}

// ── render ─────────────────────────────────────────────────────────────────
function render(){
  const q=document.getElementById('q').value.toLowerCase().trim();
  let rows=_all.filter(f=>(_ext?gext(f.name)===_ext:true)&&(!q||f.name.toLowerCase().includes(q)));
  const{col,dir}=_sort;
  rows.sort((a,b)=>{
    let av=a[col],bv=b[col];
    if(typeof av==='string'){av=av.toLowerCase();bv=bv.toLowerCase();}
    return av<bv?-dir:av>bv?dir:0;
  });

  // stats
  document.getElementById('s-files').textContent=_all.length;
  document.getElementById('s-size').textContent=fsize(_all.reduce((s,f)=>s+f.size,0));
  const visWrap=document.getElementById('s-vis-wrap');
  if(rows.length<_all.length){
    visWrap.style.display='';
    document.getElementById('s-vis').textContent=rows.length;
  } else visWrap.style.display='none';

  const colLabel={name:'name',size:'size',mtime:'modified'};
  document.getElementById('s-sort-v').textContent=`${colLabel[col]} ${dir>0?'↑':'↓'}`;

  // sort arrows
  ['name','size','mtime'].forEach(c=>{
    const el=document.getElementById('arr-'+c);
    const th=document.querySelector(`[data-col="${c}"]`);
    if(c===col){th.classList.add('on');el.textContent=dir>0?' ↑':' ↓';}
    else{th.classList.remove('on');el.textContent='';}
  });

  const wrap=document.getElementById('rows');
  if(!rows.length){
    wrap.innerHTML=`<div class="empty"><div class="empty-glyph">∅</div>${q?'no matches':'vault empty'}</div>`;
    return;
  }
  wrap.innerHTML=rows.map((f,i)=>{
    const e=gext(f.name);
    const bc=bcls(e);
    // swap bz→bz, bi→bi, ba→ba, bt→bt, bd→bd class prefix
    const cls=bc.replace('b','b');
    return`<div class="frow">
      <div class="fname">
        <span class="badge ${cls}">${esc(e)||'?'}</span>
        <div>
          <div class="fn" title="${esc(f.name)}">${esc(f.name)}</div>
          <div class="fmeta">${fsize(f.size)} &middot; ${fdate(f.mtime)}</div>
        </div>
      </div>
      <div class="fsz">${fsize(f.size)}</div>
      <div class="fdt">${fdate(f.mtime)}</div>
      <div class="dlwrap">
        <button class="dlb" id="b${i}" onclick="dl('${esc(f.name)}','b${i}')" title="Download ${esc(f.name)}">↓</button>
      </div>
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

// ── search ─────────────────────────────────────────────────────────────────
document.getElementById('q').addEventListener('input',render);

// ── download ───────────────────────────────────────────────────────────────
function dl(name,bid){
  const b=document.getElementById(bid);
  if(!b)return;
  b.innerHTML='⟳';b.classList.add('spin');
  const a=document.createElement('a');
  a.href='/dl/'+encodeURIComponent(name);
  a.download=name;
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  setTimeout(()=>{
    b.classList.remove('spin');
    b.innerHTML='✓';b.classList.add('done');
    setTimeout(()=>{b.classList.remove('done');b.innerHTML='↓';},3000);
  },800);
}

// ── logout ─────────────────────────────────────────────────────────────────
async function doLogout(){await fetch('/logout',{method:'POST'});location.href='/';}

// ── init ───────────────────────────────────────────────────────────────────
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


if __name__ == "__main__":
    import asyncio
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start_web())
    loop.run_forever()
