package portal

// dashboardHTML is the single-page operator console. It is fully self-contained:
// all styling is inline, all data loads from the /dashboard JSON and SSE
// endpoints with vanilla JavaScript, and there are no external assets or CDN
// calls, so the management plane never reaches off-host. Every attacker
// controlled field is rendered through textContent, so a captured username,
// command, or path can never inject markup into the console. Static icon markup
// is the only innerHTML, and it is always a hardcoded literal, never request
// data.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<style>
:root{
--bg:#09090b;--panel:#141416;--panel2:#1b1b1e;--elev:#26262b;
--bd:rgba(255,255,255,.08);--bd2:rgba(255,255,255,.14);
--fg:#fafafa;--mut:#a1a1aa;--mut2:#71717a;
--acc:#3b82f6;
--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,sans-serif;
--r:11px;--r2:8px;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--fg);font-family:var(--sans);font-size:13px;-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#2a2a30;border-radius:8px;border:2px solid var(--bg)}
::-webkit-scrollbar-thumb:hover{background:#3a3a42}
svg{display:block}
#app{display:grid;grid-template-columns:240px 1fr;height:100%}

#sidebar{background:var(--panel);border-right:1px solid var(--bd);display:flex;flex-direction:column;min-width:0}
.brand{display:flex;align-items:center;gap:11px;padding:17px 16px 15px}
.brand .mark{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--acc),#7c3aed);display:flex;align-items:center;justify-content:center;color:#fff;flex:none}
.brand .mark svg{width:18px;height:18px}
.brand .bt{font-weight:650;font-size:15px;letter-spacing:-.01em;line-height:1.05}
.brand .bs{font-size:9.5px;color:var(--mut2);text-transform:uppercase;letter-spacing:.14em;margin-top:4px}
nav{flex:1;overflow-y:auto;padding:4px 10px 10px}
.navsec{font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:var(--mut2);font-weight:600;margin:16px 8px 7px}
.navitem{display:flex;align-items:center;gap:11px;height:35px;padding:0 11px;border-radius:var(--r2);color:var(--mut);cursor:pointer;font-weight:500;margin-bottom:2px}
.navitem svg{width:17px;height:17px;flex:none}
.navitem:hover{background:var(--panel2);color:var(--fg)}
.navitem.active{background:var(--panel2);color:var(--fg)}
.navitem .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.navbadge{background:var(--elev);color:var(--mut);font-size:11px;padding:1px 8px;border-radius:999px;font-variant-numeric:tabular-nums}
.navitem.active .navbadge{background:var(--acc);color:#fff}
.sidefoot{padding:10px;border-top:1px solid var(--bd)}
.logoutbtn{display:flex;align-items:center;gap:11px;width:100%;height:35px;padding:0 11px;border-radius:var(--r2);background:transparent;border:0;color:var(--mut);cursor:pointer;font:inherit;font-weight:500}
.logoutbtn:hover{background:var(--panel2);color:#fff}
.logoutbtn svg{width:17px;height:17px}

#main{display:flex;flex-direction:column;min-width:0;height:100%}
#topbar{display:flex;align-items:center;gap:16px;height:64px;flex:none;padding:0 22px;border-bottom:1px solid var(--bd);background:rgba(9,9,11,.72);backdrop-filter:blur(8px);position:sticky;top:0;z-index:10}
#topbar .tt{font-size:16px;font-weight:600;letter-spacing:-.01em}
#topbar .ts{font-size:12px;color:var(--mut2);margin-top:2px}
#topbar .sp{flex:1}
.clock{font-family:var(--mono);font-size:12px;color:var(--mut);font-variant-numeric:tabular-nums}
.conn{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mut);background:var(--panel);border:1px solid var(--bd);padding:5px 11px;border-radius:999px}
.conn i{width:7px;height:7px;border-radius:50%;background:#22c55e;animation:pulse 2.2s infinite}
.conn.down i{background:#ef4444;animation:none}
.conn.down{color:var(--mut2)}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}70%{box-shadow:0 0 0 6px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}

#content{flex:1;min-height:0;padding:20px 22px;display:flex;flex-direction:column}
.view{display:none;flex:1;min-height:0;flex-direction:column}
.view.active{display:flex}

.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:18px;flex:none}
.recon{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;flex:1;min-height:0}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r)}
.statcard{padding:16px}
.statcard .top{display:flex;align-items:center;gap:11px}
.statcard .ico{width:33px;height:33px;border-radius:9px;display:flex;align-items:center;justify-content:center;flex:none}
.statcard .ico svg{width:17px;height:17px}
.statcard .lbl{font-size:12px;color:var(--mut);font-weight:500}
.statcard .num{font-size:27px;font-weight:680;letter-spacing:-.02em;margin-top:13px;line-height:1;font-variant-numeric:tabular-nums}
.statcard.click{cursor:pointer;transition:border-color .15s,background .15s}
.statcard.click:hover{border-color:var(--bd2);background:var(--panel2)}
.t-blue{background:rgba(59,130,246,.15);color:#60a5fa}
.t-green{background:rgba(34,197,94,.15);color:#4ade80}
.t-red{background:rgba(239,68,68,.15);color:#f87171}
.t-teal{background:rgba(20,184,166,.16);color:#2dd4bf}

.panel{position:relative;background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);display:flex;flex-direction:column;min-height:0;flex:1}
.panelhead{display:flex;align-items:center;gap:10px;padding:13px 16px;border-bottom:1px solid var(--bd);font-weight:600;font-size:13px;flex:none}
.panelhead .count{font-size:11px;color:var(--mut2);font-weight:500;background:var(--panel2);padding:2px 9px;border-radius:999px;font-variant-numeric:tabular-nums}
.scroll{flex:1;min-height:0;overflow-y:auto}

.row{display:flex;gap:14px;align-items:center;padding:9px 16px;border-bottom:1px solid var(--bd);cursor:pointer;transition:background .1s}
.row:hover{background:var(--panel2)}
.row .t{color:var(--mut2);width:60px;flex:none;font-family:var(--mono);font-size:12px}
.badge{display:inline-flex;align-items:center;gap:7px;width:150px;flex:none;font-size:11px;font-weight:600;font-family:var(--mono);letter-spacing:.01em}
.badge .bd{width:7px;height:7px;border-radius:2px;flex:none}
.badge .bn{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .ip{width:142px;flex:none;color:var(--mut);font-family:var(--mono);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .msg{flex:1;color:#d4d4d8;font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.empty{padding:40px 16px;text-align:center;color:var(--mut2);font-size:13px}

.chips{display:flex;flex-wrap:wrap;gap:8px;padding:14px 16px;border-bottom:1px solid var(--bd)}
.chip{display:inline-flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--bd);border-radius:999px;padding:5px 12px;font-size:12px}
.chip b{font-variant-numeric:tabular-nums;color:#fff}
.chip .ck{color:var(--mut)}
.htbar{display:flex;gap:20px;padding:14px 16px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
.htbar .m{display:flex;flex-direction:column;gap:3px}
.htbar .m b{font-size:20px;font-weight:680;font-variant-numeric:tabular-nums}
.htbar .m span{font-size:11px;color:var(--mut2);text-transform:uppercase;letter-spacing:.07em}
.htrow{display:flex;gap:14px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--bd);cursor:pointer}
.htrow:hover{background:var(--panel2)}
.htrow .hc{flex:none;width:42px;text-align:center;color:#2dd4bf;font-weight:700;font-family:var(--mono);font-size:13px}
.htrow .hip{flex:none;width:150px;color:var(--mut);font-family:var(--mono);font-size:12px}
.geotag{flex:none;width:78px}
.tag{display:inline-block;font-size:10.5px;padding:2px 8px;border-radius:999px;background:var(--elev);color:var(--mut);letter-spacing:.02em}
.htrow .htk{flex:1;color:#d4d4d8;font-family:var(--mono);font-size:12px;word-break:break-word}

#backdrop{position:fixed;inset:0;background:rgba(0,0,0,.5);opacity:0;visibility:hidden;transition:opacity .2s,visibility .2s;z-index:55}
#backdrop.open{opacity:1;visibility:visible}
#detail{position:fixed;top:0;right:0;bottom:0;width:min(580px,48%);background:var(--panel);border-left:1px solid var(--bd2);display:flex;flex-direction:column;transform:translateX(100%);transition:transform .22s ease;z-index:60}
#detail.open{transform:none}
.drawerhead{display:flex;align-items:flex-start;gap:12px;padding:18px 20px;border-bottom:1px solid var(--bd);flex:none}
.drawerhead .dtitle{font-size:16px;font-weight:600;word-break:break-all;font-family:var(--mono)}
.drawerhead .dsub{font-size:12px;color:var(--mut2);margin-top:3px}
.drawerhead .grow{flex:1;min-width:0}
.iconbtn{background:transparent;border:1px solid var(--bd);color:var(--mut);width:30px;height:30px;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex:none}
.iconbtn:hover{color:#fff;border-color:var(--bd2)}
.iconbtn svg{width:15px;height:15px}
#detailbody{flex:1;min-height:0;overflow-y:auto;padding:6px 20px 24px}
.sect{font-size:10.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--mut2);font-weight:600;margin:20px 0 8px}
.item{padding:7px 0;border-bottom:1px solid var(--bd);word-break:break-word;font-size:12.5px;font-family:var(--mono);color:#d4d4d8}
.item.muted{color:var(--mut2);font-family:var(--sans)}
.tline{display:flex;gap:11px;padding:5px 0;align-items:baseline}
.tline .tt{color:var(--mut2);flex:none;width:58px;font-family:var(--mono);font-size:11.5px}
.tline .te{flex:none;width:120px;font-weight:600;font-size:11px;font-family:var(--mono);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tline .tm{flex:1;color:#cbcbcb;word-break:break-word;font-family:var(--mono);font-size:12px}
.replaylink{color:var(--acc);cursor:pointer;font-weight:600;margin-left:8px}
.replaylink:hover{text-decoration:underline}
#replay{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:80}
#replay.open{display:flex}
.replaybox{width:min(900px,92%);height:min(560px,82%);background:#0c0c0e;border:1px solid var(--bd2);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.replayhead{display:flex;align-items:center;gap:10px;padding:12px 15px;border-bottom:1px solid var(--bd);font-size:13px;font-weight:600}
.replayhead svg{width:16px;height:16px}
.replayhead .rid{font-family:var(--mono);color:var(--mut);font-weight:500}
.replayhead .spd{color:var(--mut2);font-size:11px;font-weight:500}
#term{flex:1;margin:0;padding:14px 16px;overflow-y:auto;font-family:var(--mono);font-size:12.5px;line-height:1.5;color:#d4d4d8;white-space:pre-wrap;word-break:break-word}
.row.new{animation:rowin 1.05s ease-out}
@keyframes rowin{0%{background:var(--flash,rgba(59,130,246,.16))}100%{background:transparent}}

.spark{display:inline-flex;align-items:flex-end;gap:1px;height:16px;margin-right:8px}
.spark i{width:2px;min-height:2px;background:var(--bd2);border-radius:1px;display:block}

.sndbtn{display:flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:8px;background:var(--panel);border:1px solid var(--bd);color:var(--mut2);cursor:pointer;flex:none}
.sndbtn svg{width:15px;height:15px}
.sndbtn:hover{color:var(--fg);border-color:var(--bd2)}
.sndbtn.on{color:var(--acc);border-color:rgba(59,130,246,.5)}

.newpill{position:absolute;top:50px;left:50%;transform:translateX(-50%);display:none;align-items:center;gap:6px;background:var(--acc);color:#fff;font-size:11.5px;font-weight:600;font:inherit;padding:5px 13px;border-radius:999px;cursor:pointer;z-index:6;box-shadow:0 4px 14px rgba(0,0,0,.45);border:0}
.newpill:hover{background:#2f6fe0}

#toasts{position:fixed;top:74px;right:18px;display:flex;flex-direction:column;gap:10px;z-index:90;width:330px;max-width:calc(100vw - 36px)}
.toast{display:flex;gap:11px;align-items:flex-start;background:var(--panel2);border:1px solid var(--bd2);border-left:3px solid var(--tc,var(--acc));border-radius:10px;padding:11px 13px;cursor:pointer;box-shadow:0 8px 24px rgba(0,0,0,.45);animation:toastin .26s ease-out}
.toast .ti{width:26px;height:26px;border-radius:7px;display:flex;align-items:center;justify-content:center;flex:none;background:var(--elev);color:var(--tc,var(--acc))}
.toast .ti svg{width:15px;height:15px}
.toast .tx{min-width:0}
.toast .th{font-size:12px;font-weight:650;color:#fff;margin-bottom:2px}
.toast .tb{font-size:11.5px;color:var(--mut);font-family:var(--mono);word-break:break-word;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.toast.prize{border-left-color:#fbbf24;background:linear-gradient(135deg,#241c08,#1b1b1e)}
.toast.prize .th{color:#fbbf24}
.toast.out{animation:toastout .25s ease-in forwards}
@keyframes toastin{from{opacity:0;transform:translateX(22px)}to{opacity:1;transform:none}}
@keyframes toastout{to{opacity:0;transform:translateX(22px)}}

#confetti{position:fixed;inset:0;width:100%;height:100%;pointer-events:none;z-index:85;display:none}
#confetti.on{display:block}

@media(max-width:1100px){#app{grid-template-columns:64px 1fr}.brand .bt,.brand .bs,.navitem .grow,.navbadge,.navsec,.logoutbtn span:not([data-icon]){display:none}.navitem,.logoutbtn{justify-content:center;gap:0}.recon{grid-template-columns:1fr}}
</style></head>
<body>
<div id="app">
<aside id="sidebar">
<div class="brand"><span class="mark" data-icon="brand"></span><div><div class="bt">sweetty</div><div class="bs">sensor console</div></div></div>
<nav>
<div class="navsec">Monitor</div>
<div class="navitem active" data-view="feed"><span data-icon="feed"></span><span class="grow">Live feed</span></div>
<div class="navitem" data-view="sources"><span data-icon="sources"></span><span class="grow">Sources</span><span class="navbadge" id="nav_src">0</span></div>
<div class="navitem" data-view="recon"><span data-icon="scan"></span><span class="grow">Recon</span></div>
<div class="navitem" data-view="honeytokens"><span data-icon="bait"></span><span class="grow">Honeytokens</span><span class="navbadge" id="nav_ht">0</span></div>
<div class="navsec" id="consoles_sec" style="display:none">Consoles</div>
<div id="consoles"></div>
</nav>
</aside>
<div id="main">
<header id="topbar">
<div><div class="tt" id="view_title">Live feed</div><div class="ts" id="view_sub">streaming events as they arrive</div></div>
<div class="sp"></div>
<button class="sndbtn" id="sndbtn" data-icon="soundoff" title="Sound alerts off"></button>
<span class="clock" id="clock"></span>
<span class="conn" id="conn"><i></i><span id="conn_t">live</span></span>
</header>
<div id="content">

<section class="view active" id="view_feed">
<div class="cards">
<div class="card statcard"><div class="top"><span class="ico t-blue" data-icon="sessions"></span><span class="lbl">Sessions today</span></div><div class="num" id="s_sessions">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-green" data-icon="ips"></span><span class="lbl">Unique sources</span></div><div class="num" id="s_ips">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-red" data-icon="downloads"></span><span class="lbl">Download attempts</span></div><div class="num" id="s_dl">0</div></div>
<div class="card statcard click" id="bait_card"><div class="top"><span class="ico t-teal" data-icon="bait"></span><span class="lbl">Bait tripped</span></div><div class="num" id="s_ht">0</div></div>
<div class="card statcard click" id="scan_card"><div class="top"><span class="ico t-red" data-icon="scan"></span><span class="lbl">Port scans</span></div><div class="num" id="s_scans">0</div></div>
</div>
<div class="panel">
<div class="panelhead"><span data-icon="feed"></span>Event stream<span class="sp" style="flex:1"></span><span class="spark" id="spark"></span><span class="count" id="feed_count">0</span></div>
<button class="newpill" id="newpill"></button>
<div class="scroll" id="feed"></div>
</div>
</section>

<section class="view" id="view_sources">
<div class="panel">
<div class="panelhead"><span data-icon="sources"></span>Sources<span class="sp" style="flex:1"></span><span class="count" id="src_count">0</span></div>
<div class="scroll" id="sources"></div>
</div>
</section>

<section class="view" id="view_honeytokens">
<div class="panel">
<div class="panelhead"><span data-icon="bait"></span>Honeytokens<span class="sp" style="flex:1"></span><span class="count" id="htv_count">0</span></div>
<div class="scroll" id="htview"></div>
</div>
</section>

<section class="view" id="view_recon">
<div class="cards">
<div class="card statcard"><div class="top"><span class="ico t-red" data-icon="scan"></span><span class="lbl">Port scans</span></div><div class="num" id="r_scans">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-blue" data-icon="ips"></span><span class="lbl">Countries</span></div><div class="num" id="r_countries">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-green" data-icon="console"></span><span class="lbl">Client agents</span></div><div class="num" id="r_agents">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-teal" data-icon="downloads"></span><span class="lbl">Attempts</span></div><div class="num" id="r_attempts">0</div></div>
</div>
<div class="recon">
<div class="panel"><div class="panelhead"><span data-icon="scan"></span>Ports &amp; scans<span class="sp" style="flex:1"></span><span class="count" id="rp_count">0</span></div><div class="scroll" id="rec_ports"></div></div>
<div class="panel"><div class="panelhead"><span data-icon="ips"></span>Countries<span class="sp" style="flex:1"></span><span class="count" id="rc_count">0</span></div><div class="scroll" id="rec_countries"></div></div>
<div class="panel"><div class="panelhead"><span data-icon="console"></span>User agents<span class="sp" style="flex:1"></span><span class="count" id="ra_count">0</span></div><div class="scroll" id="rec_agents"></div></div>
</div>
</section>

</div>
</div>
</div>

<div id="backdrop"></div>
<aside id="detail">
<div class="drawerhead"><div class="grow"><div class="dtitle" id="detail_ip"></div><div class="dsub" id="detail_sub"></div></div><button class="iconbtn" id="detail_close"><span data-icon="close"></span></button></div>
<div id="detailbody"></div>
</aside>

<div id="replay"><div class="replaybox"><div class="replayhead"><span data-icon="feed"></span>Session replay<span class="rid" id="replay_title"></span><span class="grow" style="flex:1"></span><span class="spd">1.6x</span><button class="iconbtn" id="replay_close"><span data-icon="close"></span></button></div><pre id="term"></pre></div></div>

<div id="toasts"></div>
<canvas id="confetti"></canvas>

<script>
var ICONS={
brand:'<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
feed:'<path d="M3 12h4l3 8 4-16 3 8h4"/>',
sources:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
bait:'<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
sessions:'<path d="M4.9 19.1a10 10 0 0 1 0-14.2"/><path d="M7.8 16.2a6 6 0 0 1 0-8.4"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8a6 6 0 0 1 0 8.4"/><path d="M19.1 4.9a10 10 0 0 1 0 14.2"/>',
ips:'<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20"/>',
downloads:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
console:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><line x1="13" y1="15" x2="17" y2="15"/>',
logout:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
close:'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
sound:'<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><path d="M19.5 5a9 9 0 0 1 0 14"/>',
soundoff:'<polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/>',
star:'<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
scan:'<circle cx="12" cy="12" r="9"/><line x1="12" y1="3" x2="12" y2="7"/><line x1="12" y1="17" x2="12" y2="21"/><line x1="3" y1="12" x2="7" y2="12"/><line x1="17" y1="12" x2="21" y2="12"/><circle cx="12" cy="12" r="2.5"/>'
};
function setIcon(node,name){if(ICONS[name])node.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'+ICONS[name]+'</svg>';}
function paintIcons(root){var ns=(root||document).querySelectorAll('[data-icon]');for(var i=0;i<ns.length;i++)setIcon(ns[i],ns[i].getAttribute('data-icon'));}

var COLORS={
SESSION_START:'#3b82f6',SESSION_END:'#71717a',
CREDENTIAL:'#f59e0b',COMMAND:'#22c55e',
DOWNLOAD_ATTEMPT:'#ef4444',EXEC_ATTEMPT:'#ef4444',
HTTP_REQUEST:'#6366f1',HTTP_POST:'#a855f7',
HONEYTOKEN:'#14b8a6',PORT_SCAN:'#71717a',
SYSTEM:'#52525b',TLS_HELLO:'#14b4ff',SSH_CLIENT:'#14b4ff',SSH_KEX:'#14b4ff'
};
function colorOf(ev){return COLORS[ev]||'#8b8b94';}

var entries=[];
var feedEl=document.getElementById('feed');

function hostOnly(addr){
if(!addr)return '';
var first=addr.indexOf(':'),last=addr.lastIndexOf(':');
if(first>=0&&first===last)return addr.slice(0,last);
return addr;
}
function srcOf(e){return e.src_ip||hostOnly(e.ip)||'';}
function hms(t){return t?String(t).slice(11,19):'';}
function summary(e){
if(e.message)return e.message;
if(e.command)return e.command;
if(e.username&&e.password)return e.username+' / '+e.password;
if(e.username)return 'user='+e.username;
if(e.url)return e.url;
if(e.request)return e.request;
if(e.path)return e.path;
return '';
}
function el(tag,cls,text){
var n=document.createElement(tag);
if(cls)n.className=cls;
if(text!==undefined&&text!==null)n.textContent=text;
return n;
}
function badgeEl(ev){
var b=el('span','badge');
var dot=el('span','bd');dot.style.background=colorOf(ev);
var nm=el('span','bn',ev);nm.style.color=colorOf(ev);
b.appendChild(dot);b.appendChild(nm);
return b;
}

function rowEl(e){
var div=el('div','row');
div.appendChild(el('span','t',hms(e.time)));
div.appendChild(badgeEl(e.event));
div.appendChild(el('span','ip',srcOf(e)));
div.appendChild(el('span','msg',summary(e)));
var ip=srcOf(e);
div.addEventListener('click',function(){openIP(ip);});
return div;
}

function todayUTC(){return new Date().toISOString().slice(0,10);}
function computeStats(){
var today=todayUTC(),sessions=0,downloads=0,bait=0,scans=0,ips={};
for(var i=0;i<entries.length;i++){
var e=entries[i],s=srcOf(e);
if(s)ips[s]=true;
if(e.event==='SESSION_START'&&String(e.time).slice(0,10)===today)sessions++;
if(e.event==='DOWNLOAD_ATTEMPT')downloads++;
if(e.event==='HONEYTOKEN')bait++;
if(e.event==='PORT_SCAN')scans++;
}
var nip=Object.keys(ips).length;
setNum('s_sessions',sessions);setNum('s_ips',nip);setNum('s_dl',downloads);setNum('s_ht',bait);setNum('s_scans',scans);
setNum('nav_ht',bait);
setNum('feed_count',entries.length);
}
function setNum(id,v){var n=document.getElementById(id);if(n)n.textContent=v;}

function renderFeed(){
feedEl.textContent='';
if(!entries.length){feedEl.appendChild(el('div','empty','No events yet. The console is listening.'));return;}
for(var i=0;i<entries.length;i++)feedEl.appendChild(rowEl(entries[i]));
}
function prepend(e){
entries.unshift(e);
if(entries.length>2000)entries.pop();
var first=feedEl.firstChild;
if(first&&first.className==='empty')feedEl.textContent='';
var atTop=feedEl.scrollTop<40;
var node=rowEl(e);
node.classList.add('new');
node.style.setProperty('--flash',flashColor(e.event));
feedEl.insertBefore(node,feedEl.firstChild);
if(atTop){feedEl.scrollTop=0;}else{pendingNew++;showPill();}
computeStats();
sparkBump();
notify(e);
bumpUnseen();
if(curView==='sources'||curView==='recon')scheduleOverview();
if(curView==='honeytokens'&&e.event==='HONEYTOKEN')loadHoneytokens();
if(e.event==='SESSION_END')loadRecordings();
if(detailIP&&srcOf(e)===detailIP)scheduleDetailRefresh();
}

var VIEWS={feed:['Live feed','streaming events as they arrive'],sources:['Sources','every host that has touched the sensor'],recon:['Recon','port scans, geography, and client tooling'],honeytokens:['Honeytokens','planted bait and who tripped it']};
var curView='feed';
function showView(name){
curView=name;
var items=document.querySelectorAll('.navitem');
for(var i=0;i<items.length;i++)items[i].classList.toggle('active',items[i].getAttribute('data-view')===name);
var vs=document.querySelectorAll('.view');
for(var j=0;j<vs.length;j++)vs[j].classList.toggle('active',vs[j].id==='view_'+name);
document.getElementById('view_title').textContent=VIEWS[name][0];
document.getElementById('view_sub').textContent=VIEWS[name][1];
if(name==='sources'||name==='recon')loadOverview();
if(name==='honeytokens')loadHoneytokens();
}

// Sources and Recon are driven by the server-side /dashboard/overview rollup, so
// they show the complete picture (every source, geo-resolved) rather than only the
// last few hundred streamed events the feed holds.
function renderSources(){
var box=document.getElementById('sources');
box.textContent='';
var list=(overview&&overview.sources)||[];
setNum('src_count',(overview&&overview.totals&&overview.totals.sources)||list.length);
if(!list.length){box.appendChild(el('div','empty','No sources yet.'));return;}
for(var n=0;n<list.length;n++)box.appendChild(srcRow(list[n]));
}
function srcRow(r){
var div=el('div','row');
div.appendChild(el('span','ip',r.ip));
var g=el('span','geotag');g.appendChild(el('span','tag',r.country||r.scope||'?'));div.appendChild(g);
var c=el('span','badge');c.style.width='64px';
var cd=el('span','bd');cd.style.background=r.scanned?'#f87171':var_acc;c.appendChild(cd);
c.appendChild(el('span','bn',(r.events||0)+' ev'));
div.appendChild(c);
var det=(r.protocols||[]).join(', ');
if(r.ports&&r.ports.length)det+=(det?'   ':'')+r.ports.map(function(x){return ':'+x;}).join(' ');
if(r.scanned)det+='   · scanned';
div.appendChild(el('span','msg',det));
div.appendChild(el('span','t',hms(r.last_seen)));
div.addEventListener('click',function(){openIP(r.ip);});
return div;
}
var var_acc='#60a5fa';

function renderRecon(){
var o=overview||{},ports=o.by_port||[],ctys=o.by_country||[],uas=o.user_agents||[];
var pb=document.getElementById('rec_ports');pb.textContent='';setNum('rp_count',ports.length);
if(!ports.length)pb.appendChild(el('div','empty','No port activity yet.'));
for(var i=0;i<ports.length;i++)pb.appendChild(portRow(ports[i]));
var cb=document.getElementById('rec_countries');cb.textContent='';setNum('rc_count',ctys.length);
if(!ctys.length)cb.appendChild(el('div','empty','No sources yet.'));
for(var j=0;j<ctys.length;j++)cb.appendChild(countryRow(ctys[j]));
var ab=document.getElementById('rec_agents');ab.textContent='';setNum('ra_count',(o.totals&&o.totals.user_agents)||uas.length);
if(!uas.length)ab.appendChild(el('div','empty','No client agents seen yet.'));
for(var k=0;k<uas.length;k++)ab.appendChild(agentRow(uas[k]));
}
function portRow(p){
var div=el('div','row');
div.appendChild(el('span','ip',':'+p.port));
var b=el('span','badge');b.style.width='92px';var bd=el('span','bd');bd.style.background=var_acc;b.appendChild(bd);b.appendChild(el('span','bn',p.protocol||'—'));div.appendChild(b);
div.appendChild(el('span','msg',p.hits+(p.hits===1?' hit':' hits')));
var sc=el('span','t');sc.style.width='84px';if(p.scans){sc.textContent=p.scans+(p.scans===1?' scan':' scans');sc.style.color='#f87171';}div.appendChild(sc);
return div;
}
function countryRow(cc){
var div=el('div','row');
var g=el('span','geotag');g.style.width='84px';g.appendChild(el('span','tag',cc.country));div.appendChild(g);
var b=el('span','badge');b.style.width='92px';var bd=el('span','bd');bd.style.background=var_acc;b.appendChild(bd);b.appendChild(el('span','bn',cc.sources+(cc.sources===1?' src':' srcs')));div.appendChild(b);
div.appendChild(el('span','msg',cc.events+' events'));
return div;
}
function agentRow(a){
var div=el('div','row');
var b=el('span','badge');b.style.width='62px';var bd=el('span','bd');bd.style.background=var_acc;b.appendChild(bd);b.appendChild(el('span','bn','×'+a.count));div.appendChild(b);
div.appendChild(el('span','msg',a.agent));
div.appendChild(el('span','t',a.sources+(a.sources===1?' src':' srcs')));
return div;
}
function loadOverview(){
fetch('/dashboard/overview',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){overview=d;applyOverview();})
.catch(function(){});
}
// scheduleOverview coalesces refreshes so a burst of events triggers at most one
// full-log re-aggregation every couple of seconds.
function scheduleOverview(){if(overviewT)return;overviewT=setTimeout(function(){overviewT=0;loadOverview();},2500);}
function applyOverview(){
if(!overview)return;
var t=overview.totals||{};
// The sidebar "Sources" badge shares the full-log total with the Sources panel
// header, so the two never disagree. The feed stat cards (including port scans)
// stay window-scoped and live via computeStats.
setNum('nav_src',t.sources||0);
setNum('r_scans',t.port_scans||0);
setNum('r_countries',(overview.by_country||[]).length);
setNum('r_agents',t.user_agents||0);
setNum('r_attempts',(t.credentials||0)+(t.http_requests||0)+(t.exec||0)+(t.downloads||0));
if(curView==='sources')renderSources();
if(curView==='recon')renderRecon();
}

function loadHoneytokens(){
fetch('/dashboard/honeytokens',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(renderHoneytokens).catch(function(){});
}
function renderHoneytokens(d){
var box=document.getElementById('htview');
box.textContent='';
var srcs=d.sources||[];
setNum('htv_count',srcs.length);
var bar=el('div','htbar');
bar.appendChild(metric(d.total||0,'triggers'));
bar.appendChild(metric(d.unique_srcs||0,'sources'));
var geo=el('div','m');geo.appendChild(el('b',null,d.geo_active?'on':'off'));geo.appendChild(el('span',null,'country db'));
bar.appendChild(geo);
box.appendChild(bar);
var byTok=d.by_token||{};
var toks=Object.keys(byTok).sort(function(a,b){return byTok[b]-byTok[a];});
if(toks.length){
var chips=el('div','chips');
for(var i=0;i<toks.length;i++){
var ch=el('span','chip');
ch.appendChild(el('span','ck',toks[i]));
ch.appendChild(el('b',null,'x'+byTok[toks[i]]));
chips.appendChild(ch);
}
box.appendChild(chips);
}
if(!srcs.length){box.appendChild(el('div','empty','No bait has been tripped yet.'));return;}
for(var j=0;j<srcs.length;j++)box.appendChild(htRow(srcs[j]));
}
function metric(v,label){var m=el('div','m');m.appendChild(el('b',null,v));m.appendChild(el('span',null,label));return m;}
function htRow(s){
var div=el('div','htrow');
div.appendChild(el('span','hc','x'+s.count));
div.appendChild(el('span','hip',s.ip));
var g=el('span','geotag');g.appendChild(el('span','tag',s.country||s.scope||'?'));
div.appendChild(g);
var when=hms(s.last_seen),tk=(s.tokens||[]).join(', ');
div.appendChild(el('span','htk',tk+(when?'   '+when:'')));
div.addEventListener('click',function(){openIP(s.ip);});
return div;
}

var detailEl=document.getElementById('detail');
var detailBody=document.getElementById('detailbody');
var backdrop=document.getElementById('backdrop');
function closeDrawer(){detailIP=null;detailEl.classList.remove('open');backdrop.classList.remove('open');}
document.getElementById('detail_close').addEventListener('click',closeDrawer);
backdrop.addEventListener('click',closeDrawer);

function openIP(ip){
if(!ip)return;
detailIP=ip;
fetch('/dashboard/ip/'+encodeURIComponent(ip),{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){renderDetail(ip,d.entries||[]);})
.catch(function(){});
}
// scheduleDetailRefresh coalesces a burst of events from the open IP into one
// re-fetch; refreshDetail re-renders the drawer while preserving scroll position.
function scheduleDetailRefresh(){if(detailT)return;detailT=setTimeout(function(){detailT=0;refreshDetail();},400);}
function refreshDetail(){
if(!detailIP)return;
var ip=detailIP,keep=detailBody.scrollTop;
fetch('/dashboard/ip/'+encodeURIComponent(ip),{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){if(detailIP===ip){renderDetail(ip,d.entries||[],true);detailBody.scrollTop=keep;}})
.catch(function(){});
}
function sect(title){detailBody.appendChild(el('div','sect',title));}
function renderDetail(ip,list,preserve){
document.getElementById('detail_ip').textContent=ip;
document.getElementById('detail_sub').textContent=list.length+' events';
detailBody.textContent='';
var sessions={},creds=[],cmds=[],dls=[];
for(var i=0;i<list.length;i++){
var e=list[i];
if(e.session)sessions[e.session]=(sessions[e.session]||0)+1;
if(e.username||e.password)creds.push(e);
if(e.event==='COMMAND'||e.command)cmds.push(e);
if(e.event==='DOWNLOAD_ATTEMPT')dls.push(e);
}
var sids=Object.keys(sessions);
sect('Sessions ('+sids.length+')');
if(!sids.length)detailBody.appendChild(el('div','item muted','none'));
for(var a=0;a<sids.length;a++){
var it=el('div','item');
it.appendChild(el('span',null,sids[a]+'  ('+sessions[sids[a]]+' events)'));
if(recordings[sids[a]]){
var rp=el('span','replaylink','replay');
(function(id){rp.addEventListener('click',function(){playCast(id);});})(sids[a]);
it.appendChild(rp);
}
detailBody.appendChild(it);
}
sect('Credentials ('+creds.length+')');
if(!creds.length)detailBody.appendChild(el('div','item muted','none'));
for(var b=0;b<creds.length;b++){
var c=creds[b],txt=(c.username||'')+' / '+(c.password||'');
if(c.protocol)txt+='   ['+c.protocol+(c.port?':'+c.port:'')+']';
detailBody.appendChild(el('div','item',txt));
}
sect('Commands ('+cmds.length+')');
if(!cmds.length)detailBody.appendChild(el('div','item muted','none'));
for(var m=0;m<cmds.length;m++)detailBody.appendChild(el('div','item',cmds[m].command||summary(cmds[m])));
sect('Downloads ('+dls.length+')');
if(!dls.length)detailBody.appendChild(el('div','item muted','none'));
for(var x=0;x<dls.length;x++){var dd=dls[x];detailBody.appendChild(el('div','item',dd.url||dd.filename||summary(dd)));}
sect('Transcript ('+list.length+')');
for(var t=0;t<list.length;t++){
var ee=list[t];
var line=el('div','tline');
var te=el('span','te',ee.event);te.style.color=colorOf(ee.event);
line.appendChild(el('span','tt',hms(ee.time)));
line.appendChild(te);
line.appendChild(el('span','tm',summary(ee)));
detailBody.appendChild(line);
}
if(!preserve)detailBody.scrollTop=0;
detailEl.classList.add('open');backdrop.classList.add('open');
}

var recordings={};
function loadRecordings(){
fetch('/dashboard/recordings',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){recordings={};var ids=d.recordings||[];for(var i=0;i<ids.length;i++)recordings[ids[i]]=true;})
.catch(function(){});
}

var replayEl=document.getElementById('replay');
var termEl=document.getElementById('term');
var replayActive=false;
document.getElementById('replay_close').addEventListener('click',function(){replayActive=false;replayEl.classList.remove('open');});

function cleanTerm(s){
s=s.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g,'');
s=s.replace(/\x1b[\(\)][AB0-9]/g,'');
s=s.replace(/\x1b[=>NM]/g,'');
return s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g,'');
}
function parseCast(text){
var out=[],lines=text.split('\n');
for(var i=1;i<lines.length;i++){
var ln=lines[i];if(!ln)continue;
try{var a=JSON.parse(ln);if(a&&a.length===3&&a[1]==='o')out.push({t:a[0],d:a[2]});}catch(e){}
}
return out;
}
function playCast(id){
document.getElementById('replay_title').textContent=id;
termEl.textContent='';
replayEl.classList.add('open');
fetch('/dashboard/cast/'+encodeURIComponent(id),{credentials:'same-origin'})
.then(function(r){return r.text();})
.then(function(text){playFrames(parseCast(text));})
.catch(function(){termEl.textContent='(recording unavailable)';});
}
function playFrames(frames){
replayActive=true;
var i=0;
function step(){
if(!replayActive||i>=frames.length)return;
termEl.textContent+=cleanTerm(frames[i].d);
termEl.scrollTop=termEl.scrollHeight;
var gap=i+1<frames.length?Math.min(frames[i+1].t-frames[i].t,1.2):0;
i++;
setTimeout(step,Math.max(gap*1000/1.6,8));
}
step();
}

function loadConsoles(){
fetch('/dashboard/consoles',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){
var box=document.getElementById('consoles'),cs=d.consoles||[];
box.textContent='';
document.getElementById('consoles_sec').style.display=cs.length?'block':'none';
for(var i=0;i<cs.length;i++){
var a=document.createElement('a');a.className='navitem';
a.href='/dashboard/console/'+encodeURIComponent(cs[i].name)+'/';
a.target='_blank';a.rel='noopener';
var ic=document.createElement('span');setIcon(ic,'console');a.appendChild(ic);
a.appendChild(el('span','grow',cs[i].label||cs[i].name));
box.appendChild(a);
}
}).catch(function(){});
}

function tickClock(){var n=document.getElementById('clock');if(n)n.textContent=new Date().toISOString().slice(11,19)+' UTC';}
function setConn(up){var c=document.getElementById('conn');c.classList.toggle('down',!up);document.getElementById('conn_t').textContent=up?'live':'reconnecting';}

// --- liveness state -------------------------------------------------------
// detailIP is the IP shown in the open drawer (null when closed); detailT holds
// a pending coalesced refresh. knownIPs is every source seen so a genuinely new
// one can be called out; hydrated gates that callout past the initial load so the
// first 200 history rows do not each fire a "new source" toast.
var detailIP=null,detailT=0,knownIPs={},hydrated=false;
// suppressNotify mutes the alarms (toasts, sound, confetti) while a reconnect
// backfills the events missed during the gap, so a brief blip cannot storm them.
var suppressNotify=false,sseStarted=false,suppressT=0;
// overview holds the server-side recon rollup (scans, geography, user agents)
// that drives the Sources and Recon views and the port-scan stat card.
var overview=null,overviewT=0;
var NOTABLE={DOWNLOAD_ATTEMPT:1,EXEC_ATTEMPT:1,HONEYTOKEN:1};
var LABELS={DOWNLOAD_ATTEMPT:'Download attempt',EXEC_ATTEMPT:'Exec attempt',HONEYTOKEN:'Bait tripped'};
function labelOf(ev){return LABELS[ev]||ev;}

// flashColor turns an event colour into the translucent tint a new row briefly
// glows, stronger for the high-signal events so they catch the eye.
function flashColor(ev){
var c=colorOf(ev);
if(c.charAt(0)!=='#'||c.length<7)return 'rgba(59,130,246,.16)';
var r=parseInt(c.slice(1,3),16),g=parseInt(c.slice(3,5),16),b=parseInt(c.slice(5,7),16);
return 'rgba('+r+','+g+','+b+','+(NOTABLE[ev]?'.30':'.16')+')';
}

// --- toasts ---------------------------------------------------------------
var toastsEl=document.getElementById('toasts');
function toast(o){
var t=el('div','toast'+(o.prize?' prize':''));
if(!o.prize&&o.event)t.style.setProperty('--tc',colorOf(o.event));
var ic=el('div','ti');setIcon(ic,o.icon||'feed');
var tx=el('div','tx');
tx.appendChild(el('div','th',o.title||''));
if(o.body!==undefined&&o.body!=='')tx.appendChild(el('div','tb',o.body));
t.appendChild(ic);t.appendChild(tx);
function dismiss(){if(t.parentNode){t.classList.add('out');setTimeout(function(){if(t.parentNode)t.parentNode.removeChild(t);},240);}}
if(o.ip)t.addEventListener('click',function(){openIP(o.ip);dismiss();});
toastsEl.insertBefore(t,toastsEl.firstChild);
while(toastsEl.children.length>4)toastsEl.removeChild(toastsEl.lastChild);
setTimeout(dismiss,o.prize?9000:6000);
}
// notify decides what an incoming event is worth surfacing: a never-seen source,
// a high-signal attempt (sound too), or the ultimate prize of bait being tripped.
function notify(e){
var s=srcOf(e);
var fresh=s&&!knownIPs[s];
if(fresh)knownIPs[s]=true;
// Keep the new-source bookkeeping above even for a backfilled burst, but mute
// the alarms below so a reconnect cannot replay them as a storm.
if(suppressNotify)return;
if(fresh&&hydrated)toast({icon:'sources',event:'SESSION_START',title:'New source',body:s,ip:s});
if(e.event==='HONEYTOKEN'){prizeMoment(e);return;}
if(NOTABLE[e.event]){toast({icon:'downloads',event:e.event,title:labelOf(e.event),body:(summary(e)?summary(e)+'  ':'')+s,ip:s});playAlert();}
}

// --- the ultimate prize ---------------------------------------------------
// A honeytoken trip is the whole point of the trap: the attacker took the bait.
// We mark it with a gold toast (a wink to turn-of-the-millennium pop), a confetti
// burst, and an upbeat synthesized riff when sound is on.
var PRIZE_LINES=['Bye bye bye — they took the bait','It’s gonna be ME: bait tripped','Cry me a river — attacker snared','SexyBack? more like trace-back','No strings attached, just a honeytoken'];
var prizeIdx=0;
function prizeMoment(e){
var line=PRIZE_LINES[prizeIdx%PRIZE_LINES.length];prizeIdx++;
toast({prize:true,icon:'star',title:'⭐ ULTIMATE PRIZE',body:line+'  '+srcOf(e),ip:srcOf(e)});
burstConfetti();
playPrize();
}

// --- audio (opt-in, synthesized, no assets) -------------------------------
var soundOn=false,actx=null;
function ensureAudio(){
if(!actx){try{actx=new (window.AudioContext||window.webkitAudioContext)();}catch(x){actx=null;}}
if(actx&&actx.state==='suspended'){try{actx.resume();}catch(x){}}
return actx;
}
function tone(freq,start,dur,type,peak){
var a=actx;if(!a)return;
var o=a.createOscillator(),g=a.createGain(),t0=a.currentTime+start;
o.type=type||'triangle';o.frequency.value=freq;
g.gain.setValueAtTime(0.0001,t0);
g.gain.linearRampToValueAtTime(peak||0.16,t0+0.012);
g.gain.exponentialRampToValueAtTime(0.0001,t0+dur);
o.connect(g);g.connect(a.destination);
o.start(t0);o.stop(t0+dur+0.02);
}
function playAlert(){if(!soundOn||!ensureAudio())return;tone(660,0,0.12,'square',0.11);tone(440,0.10,0.16,'square',0.11);}
function playPrize(){
if(!soundOn||!ensureAudio())return;
var seq=[[523.25,0],[659.25,0.12],[783.99,0.24],[1046.50,0.36],[783.99,0.50],[1046.50,0.62],[1318.51,0.78]];
for(var i=0;i<seq.length;i++)tone(seq[i][0],seq[i][1],0.18,'triangle',0.15);
tone(130.81,0,0.5,'sine',0.12);tone(196.00,0.40,0.42,'sine',0.10);
}
var sndBtn=document.getElementById('sndbtn');
function setSound(on){
soundOn=on;
sndBtn.classList.toggle('on',on);
setIcon(sndBtn,on?'sound':'soundoff');
sndBtn.title=on?'Sound alerts on':'Sound alerts off';
try{localStorage.setItem('sweetty_snd',on?'1':'0');}catch(x){}
if(on)ensureAudio();
}
sndBtn.addEventListener('click',function(){setSound(!soundOn);});
// Browsers keep a freshly created AudioContext suspended until a user gesture;
// resume it on the first click anywhere so a restored "on" preference can sound.
function gestureResume(){if(soundOn)ensureAudio();document.removeEventListener('pointerdown',gestureResume);}

// --- tab-title unread badge ------------------------------------------------
var unseen=0;
function bumpUnseen(){if(document.hidden){unseen++;updateTitle();}}
function updateTitle(){document.title=unseen>0?'('+unseen+') ●':'';}
document.addEventListener('visibilitychange',function(){if(!document.hidden){unseen=0;updateTitle();}});

// --- "N new" pill ----------------------------------------------------------
var pendingNew=0,newpill=document.getElementById('newpill');
function showPill(){newpill.style.display=pendingNew>0?'flex':'none';newpill.textContent='↑ '+pendingNew+' new';}
newpill.addEventListener('click',function(){feedEl.scrollTop=0;pendingNew=0;showPill();});
feedEl.addEventListener('scroll',function(){if(feedEl.scrollTop<40&&pendingNew){pendingNew=0;showPill();}});

// --- sparkline (event tempo) ----------------------------------------------
var SPK=36,spk=[],spkEl=document.getElementById('spark');
for(var spki=0;spki<SPK;spki++)spk.push(0);
function renderSpark(){
spkEl.textContent='';
var mx=1,i;for(i=0;i<spk.length;i++)if(spk[i]>mx)mx=spk[i];
for(i=0;i<spk.length;i++){var bar=document.createElement('i');bar.style.height=Math.max(Math.round(spk[i]/mx*100),8)+'%';if(spk[i]>0)bar.style.background='var(--acc)';spkEl.appendChild(bar);}
}
function sparkBump(){spk[spk.length-1]++;renderSpark();}
function sparkTick(){spk.push(0);if(spk.length>SPK)spk.shift();renderSpark();}

// --- confetti (prize burst) ------------------------------------------------
var confCanvas=document.getElementById('confetti'),cctx=confCanvas.getContext('2d'),confP=[],confRAF=0;
function burstConfetti(){
if(confP.length>330)return; // a burst is already saturating the canvas; don't pile on
confCanvas.width=window.innerWidth;confCanvas.height=window.innerHeight;
confCanvas.classList.add('on');
var cols=['#fbbf24','#3b82f6','#22c55e','#ef4444','#a855f7','#2dd4bf','#fafafa'];
for(var i=0;i<110;i++)confP.push({x:Math.random()*confCanvas.width,y:-20-Math.random()*confCanvas.height*0.3,vx:(Math.random()-0.5)*6,vy:2+Math.random()*5,s:4+Math.random()*5,rot:Math.random()*6.28,vr:(Math.random()-0.5)*0.4,c:cols[(Math.random()*cols.length)|0],life:1});
if(!confRAF)confRAF=requestAnimationFrame(confStep);
}
function confStep(){
cctx.clearRect(0,0,confCanvas.width,confCanvas.height);
var alive=0;
for(var i=0;i<confP.length;i++){
var p=confP[i];if(p.life<=0)continue;
p.x+=p.vx;p.y+=p.vy;p.vy+=0.12;p.rot+=p.vr;
if(p.y>confCanvas.height+30){p.life=0;continue;}
p.life-=0.004;alive++;
cctx.save();cctx.translate(p.x,p.y);cctx.rotate(p.rot);cctx.globalAlpha=Math.max(p.life,0);cctx.fillStyle=p.c;cctx.fillRect(-p.s/2,-p.s/2,p.s,p.s*0.62);cctx.restore();
}
if(alive>0){confRAF=requestAnimationFrame(confStep);return;}
confRAF=0;confP=[];cctx.clearRect(0,0,confCanvas.width,confCanvas.height);confCanvas.classList.remove('on');
}

function load(){
fetch('/dashboard/log?limit=200',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){entries=d.entries||[];for(var i=0;i<entries.length;i++){var s=srcOf(entries[i]);if(s)knownIPs[s]=true;}renderFeed();computeStats();if(curView==='sources')renderSources();})
.catch(function(){});
}
function connect(){
var es=new EventSource('/dashboard/events');
es.onopen=function(){
setConn(true);
// The first open seeks to end-of-file, so there is no backlog. A later open is
// a reconnect that backfills every missed event at once; mute the alarms for a
// moment while that burst drains, then resume live alerting.
if(sseStarted){suppressNotify=true;if(suppressT)clearTimeout(suppressT);suppressT=setTimeout(function(){suppressNotify=false;suppressT=0;},1500);}
sseStarted=true;
};
es.addEventListener('log',function(ev){var e;try{e=JSON.parse(ev.data);}catch(x){return;}prepend(e);});
es.onerror=function(){setConn(false);};
}

var navs=document.querySelectorAll('.navitem[data-view]');
for(var i=0;i<navs.length;i++)navs[i].addEventListener('click',function(){showView(this.getAttribute('data-view'));});
document.getElementById('bait_card').addEventListener('click',function(){showView('honeytokens');});
document.getElementById('scan_card').addEventListener('click',function(){showView('recon');});

paintIcons();
tickClock();setInterval(tickClock,1000);
renderSpark();setInterval(sparkTick,2500);
try{if(localStorage.getItem('sweetty_snd')==='1')setSound(true);}catch(x){}
document.addEventListener('pointerdown',gestureResume);
setTimeout(function(){hydrated=true;},1500);
load();connect();loadConsoles();loadRecordings();loadOverview();
// Refresh the recon rollup (and the port-scan stat card it feeds) on a slow,
// bounded timer so it stays current without re-reading the whole log per event.
setInterval(loadOverview,30000);
</script>
</body></html>`
