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
.recon{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;flex:1;min-height:0}
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
.row .svc{width:104px;flex:none;color:var(--acc);font-family:var(--mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .msg{flex:1;color:#d4d4d8;font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.row .cc{width:26px;flex:none;color:var(--mut2);font-family:var(--mono);font-size:11px}
.row .tag{flex:none;font-family:var(--mono);font-size:10px;color:var(--mut);border:1px solid var(--bd);border-radius:9px;padding:1px 7px;white-space:nowrap}
.row .tag.ret{color:#fbbf24;border-color:rgba(251,191,36,.35)}
.empty{padding:40px 16px;text-align:center;color:var(--mut2);font-size:13px}

.chips{display:flex;flex-wrap:wrap;gap:8px;padding:14px 16px;border-bottom:1px solid var(--bd)}
.chip{display:inline-flex;align-items:center;gap:8px;background:var(--panel2);border:1px solid var(--bd);border-radius:999px;padding:5px 12px;font-size:12px}
.chip b{font-variant-numeric:tabular-nums;color:#fff}
.chip .ck{color:var(--mut)}
.filterbar{display:flex;gap:7px;padding:11px 16px;border-bottom:1px solid var(--bd);flex-wrap:wrap;flex:none}
.fbtn{background:var(--panel2);border:1px solid var(--bd);color:var(--mut);font:inherit;font-size:12px;font-weight:500;padding:4px 12px;border-radius:999px;cursor:pointer}
.fbtn:hover{color:var(--fg);border-color:var(--bd2)}
.fbtn.active{background:var(--acc);border-color:var(--acc);color:#fff}
.scopebar{display:flex;gap:6px;margin-bottom:14px;flex:none}
.scbtn{background:var(--panel);border:1px solid var(--bd);color:var(--mut);font:inherit;font-size:12px;font-weight:500;padding:5px 14px;border-radius:999px;cursor:pointer}
.scbtn:hover{color:var(--fg);border-color:var(--bd2)}
.scbtn.active{background:var(--acc);border-color:var(--acc);color:#fff}
.kindcell{flex:none;width:74px}
.kindtag{display:inline-block;font-size:10px;font-weight:600;font-family:var(--mono);padding:2px 7px;border-radius:999px;border:1px solid currentColor;letter-spacing:.02em}
.retbadge{flex:none;color:#fbbf24;font-family:var(--mono);font-size:11px;font-weight:600;width:48px;text-align:right}
.fsel,.fsearch{background:var(--panel2);border:1px solid var(--bd);color:var(--fg);font:inherit;font-size:12px;padding:4px 10px;border-radius:8px;outline:none}
.fsearch{min-width:190px}
.fsel:focus,.fsearch:focus{border-color:var(--bd2)}
.fsearch::placeholder{color:var(--mut2)}
.htbar{display:flex;gap:20px;padding:14px 16px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
.htbar .m{display:flex;flex-direction:column;gap:3px}
.htbar .m b{font-size:20px;font-weight:680;font-variant-numeric:tabular-nums}
.htbar .m span{font-size:11px;color:var(--mut2);text-transform:uppercase;letter-spacing:.07em}
.htrow{display:flex;gap:14px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--bd);cursor:pointer}
.htrow:hover{background:var(--panel2)}
.htrow .hc{flex:none;width:42px;text-align:center;color:#2dd4bf;font-weight:700;font-family:var(--mono);font-size:13px}
.htrow .hip{flex:none;width:150px;color:var(--mut);font-family:var(--mono);font-size:12px}
.geotag{flex:none;width:78px}
.row .isp{flex:none;width:168px;color:var(--mut2);font-family:var(--mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
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
.assess{background:var(--panel2);border:1px solid var(--bd);border-radius:var(--r2);padding:13px 14px;margin:14px 0 4px}
.assesshead{display:flex;align-items:center;gap:10px}
.assesshead .verdict{font-size:14px;font-weight:680;font-family:var(--mono)}
.assesshead .conf{font-size:11px;color:var(--mut);background:var(--elev);padding:2px 8px;border-radius:999px;font-variant-numeric:tabular-nums}
.assesshead .retflag{font-size:11px;color:#fbbf24;font-weight:600;margin-left:auto}
.assessmeta{font-size:11px;color:var(--mut2);margin-top:6px;font-family:var(--mono)}
.reasons{margin-top:11px;display:flex;flex-direction:column;gap:5px}
.reason{display:flex;gap:8px;font-size:12px;color:#cbcbcb;align-items:flex-start}
.reason .rdot{color:var(--mut2);flex:none}
.ribbon{display:flex;align-items:center;gap:7px;margin-top:13px;flex-wrap:wrap}
.rstep{font-size:11px;font-weight:600;font-family:var(--mono);color:var(--mut2);text-transform:uppercase;letter-spacing:.04em}
.rarrow{color:var(--mut2);font-size:12px}
.tlwrap{margin-top:12px}
.tlbar{position:relative;height:14px;background:var(--elev);border-radius:4px;overflow:hidden}
.tlseg{position:absolute;top:0;height:100%;border-radius:3px;min-width:3px}
.replaylink{color:var(--acc);cursor:pointer;font-weight:600;margin-left:8px}
.replaylink:hover{text-decoration:underline}
#replay{position:fixed;inset:0;background:rgba(0,0,0,.62);display:none;align-items:center;justify-content:center;z-index:80}
#replay.open{display:flex}
.replaybox{width:min(900px,92%);height:min(560px,82%);background:#0c0c0e;border:1px solid var(--bd2);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.replayhead{display:flex;align-items:center;gap:10px;padding:12px 15px;border-bottom:1px solid var(--bd);font-size:13px;font-weight:600}
.replayhead svg{width:16px;height:16px}
.replayhead .rid{font-family:var(--mono);color:var(--mut);font-weight:500}
.replayhead .spd{color:var(--mut2);font-size:11px;font-weight:500}
#term{flex:1;margin:0;padding:14px 16px;overflow-y:auto;font-family:var(--mono);font-size:12.5px;line-height:1.5;color:#d4d4d8;white-space:pre-wrap;word-break:break-word;background:radial-gradient(120% 80% at 50% 0,rgba(30,30,36,.5),#0c0c0e 70%)}
.replayhead .livepill{display:none;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;background:rgba(239,68,68,.14);color:#f87171;font-size:10px;font-weight:700;letter-spacing:.07em}
.replayhead .livepill i{width:6px;height:6px;border-radius:50%;background:#ef4444;animation:lpulse 1.6s infinite}
.replayhead .livepill.on{display:inline-flex}
.replaybox.live{border-color:rgba(239,68,68,.5)}
@keyframes lpulse{0%{box-shadow:0 0 0 0 rgba(239,68,68,.55)}70%{box-shadow:0 0 0 7px rgba(239,68,68,0)}100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}}
.replayfoot{padding:8px 15px;border-top:1px solid var(--bd);font-size:11px;color:var(--mut2);font-family:var(--mono);min-height:15px;display:flex;align-items:center;gap:12px}
#term .ti{color:#4ade80}
.termph{color:var(--mut2);font-style:italic;opacity:.7}
.replayfoot .sinfo{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.replayfoot .schip{padding:1px 7px;border-radius:999px;background:var(--panel2);border:1px solid var(--bd);color:var(--mut);font-size:10.5px;white-space:nowrap}
.replayfoot .sst{color:#f87171}
.replayfoot .cur{display:none;width:7px;height:13px;background:#22c55e;vertical-align:middle}
.replayfoot.live .cur{display:inline-block;animation:blink 1.05s step-end infinite}
@keyframes blink{50%{opacity:0}}
.livecount.on{background:#ef4444;color:#fff}
.livedot{display:none;width:7px;height:7px;border-radius:50%;background:#ef4444;margin-left:8px;animation:lpulse 1.6s infinite}
.livedot.on{display:inline-block}
.liverail{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:12px;padding:14px;overflow-y:auto}
.liveempty{padding:44px 20px;text-align:center;color:var(--mut2);font-size:13px;line-height:1.6}
.livecard{background:var(--panel2);border:1px solid var(--bd);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:11px;transition:border-color .15s,transform .15s}
.livecard:hover{border-color:rgba(239,68,68,.4);transform:translateY(-1px)}
.livecard .lc_top{display:flex;align-items:center;gap:8px}
.livecard .lc_dot{width:7px;height:7px;border-radius:50%;background:#ef4444;animation:lpulse 1.6s infinite;flex:none}
.livecard .lc_ip{font-family:var(--mono);font-weight:600;font-size:13px;color:var(--fg)}
.livecard .lc_flag{font-size:11px;color:var(--mut2);margin-left:auto}
.livecard .lc_meta{display:flex;gap:16px;font-size:11px;color:var(--mut2)}
.livecard .lc_meta b{color:var(--fg);font-weight:600}
.lc_watch{display:flex;align-items:center;justify-content:center;gap:7px;padding:8px;border-radius:9px;background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.25);cursor:pointer;font-weight:600;font-size:12.5px}
.lc_watch:hover{background:rgba(239,68,68,.2)}
.lc_watch svg{width:15px;height:15px}
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
#jtflash{position:fixed;inset:0;z-index:87;display:none;align-items:center;justify-content:center;pointer-events:none;background:rgba(0,0,0,.4)}
#jtflash.on{display:flex;animation:jtflash 2.8s cubic-bezier(.2,.7,.3,1) forwards}
#jtflash img{max-width:min(68vw,480px);max-height:76vh;border-radius:16px;border:3px solid #fbbf24;box-shadow:0 16px 70px rgba(0,0,0,.75),0 0 44px rgba(251,191,36,.35)}
@keyframes jtflash{0%{opacity:0;transform:scale(.82) rotate(-3deg)}12%{opacity:1;transform:scale(1) rotate(0)}80%{opacity:1;transform:scale(1) rotate(0)}100%{opacity:0;transform:scale(1.03)}}

#splash{position:fixed;inset:0;z-index:200;display:flex;flex-direction:column;align-items:center;justify-content:center;overflow:hidden;background:radial-gradient(120% 120% at 50% 38%,#16161c,#0a0a0c 68%);cursor:pointer}
#splash.hide{opacity:0;transition:opacity .5s ease;pointer-events:none}
#splash.gone{display:none}
.splashwrap{display:flex;flex-direction:column;align-items:center;gap:16px;animation:splashIn .55s cubic-bezier(.2,.75,.25,1) both}
#splash_canvas{display:block;image-rendering:pixelated;border-radius:10px;box-shadow:0 24px 90px rgba(0,0,0,.7),0 0 0 1px rgba(255,255,255,.05)}
.splashcap{font-family:var(--mono);font-size:11px;letter-spacing:.32em;color:var(--mut2);text-transform:uppercase;animation:capblink 1.1s ease-in-out infinite}
@keyframes splashIn{0%{opacity:0;transform:translateY(26px) scale(.84)}100%{opacity:1;transform:translateY(0) scale(1)}}
@keyframes capblink{0%,100%{opacity:.3}50%{opacity:.85}}

@media(max-width:1100px){#app{grid-template-columns:64px 1fr}.brand .bt,.brand .bs,.navitem .grow,.navbadge,.navsec,.logoutbtn span:not([data-icon]){display:none}.navitem,.logoutbtn{justify-content:center;gap:0}.recon{grid-template-columns:1fr}}
</style></head>
<body>
<div id="app">
<aside id="sidebar">
<div class="brand"><span class="mark" data-icon="brand"></span><div><div class="bt">sweeTTY</div><div class="bs">honeypot console</div></div></div>
<nav>
<div class="navsec">Monitor</div>
<div class="navitem active" data-view="feed"><span data-icon="feed"></span><span class="grow">Live feed</span></div>
<div class="navitem" data-view="live"><span data-icon="live"></span><span class="grow">Live sessions</span><span class="navbadge livecount" id="nav_live">0</span></div>
<div class="navitem" data-view="sources"><span data-icon="sources"></span><span class="grow">Sources</span><span class="navbadge" id="nav_src">0</span></div>
<div class="navitem" data-view="recon"><span data-icon="scan"></span><span class="grow">Recon</span></div>
<div class="navitem" data-view="payloads"><span data-icon="downloads"></span><span class="grow">Payload pulls</span><span class="navbadge" id="nav_pl">0</span></div>
<div class="navitem" data-view="honeytokens"><span data-icon="bait"></span><span class="grow">90s JT Reveals</span><span class="navbadge" id="nav_ht">0</span></div>
<div class="navsec" id="consoles_sec" style="display:none">Consoles</div>
<div id="consoles"></div>
</nav>
</aside>
<div id="main">
<header id="topbar">
<div><div class="tt" id="view_title">Live feed</div><div class="ts" id="view_sub">streaming events as they arrive</div></div>
<div class="sp"></div>
<button class="sndbtn" id="sndbtn" data-icon="soundoff" title="Sound alerts off"></button>
<span class="clock" id="build_ver" title="build version"></span>
<span class="clock" id="clock"></span>
<span class="conn" id="conn"><i></i><span id="conn_t">live</span></span>
</header>
<div id="content">

<section class="view active" id="view_feed">
<div class="scopebar">
<button class="scbtn active" data-scope="today">Today</button>
<button class="scbtn" data-scope="all">All time</button>
</div>
<div class="cards">
<div class="card statcard"><div class="top"><span class="ico t-blue" data-icon="sessions"></span><span class="lbl">Sessions</span></div><div class="num" id="s_sessions">0</div></div>
<div class="card statcard"><div class="top"><span class="ico t-green" data-icon="ips"></span><span class="lbl">Unique sources</span></div><div class="num" id="s_ips">0</div></div>
<div class="card statcard click" id="dl_card"><div class="top"><span class="ico t-red" data-icon="downloads"></span><span class="lbl">Payload pulls</span></div><div class="num" id="s_dl">0</div></div>
<div class="card statcard click" id="bait_card"><div class="top"><span class="ico t-teal" data-icon="bait"></span><span class="lbl">90s JT Reveals</span></div><div class="num" id="s_ht">0</div></div>
<div class="card statcard click" id="scan_card"><div class="top"><span class="ico t-red" data-icon="scan"></span><span class="lbl">Port scans</span></div><div class="num" id="s_scans">0</div></div>
</div>
<div class="panel">
<div class="panelhead"><span data-icon="feed"></span>Event stream<span class="sp" style="flex:1"></span><span class="spark" id="spark"></span><span class="count" id="feed_count">0</span></div>
<button class="newpill" id="newpill"></button>
<div class="scroll" id="feed"></div>
</div>
</section>

<section class="view" id="view_live">
<div class="panel">
<div class="panelhead"><span data-icon="live"></span>Sessions in progress<span class="livedot" id="live_pulse"></span><span class="sp" style="flex:1"></span><span class="count" id="live_count">0</span></div>
<div class="liverail" id="live_rail"></div>
<div class="liveempty" id="live_empty">No live sessions right now. When an attacker is at the keyboard, they appear here to watch in real time.</div>
</div>
</section>

<section class="view" id="view_sources">
<div class="panel">
<div class="panelhead"><span data-icon="sources"></span>Sources<span class="sp" style="flex:1"></span><span class="count" id="src_count">0</span></div>
<div class="filterbar">
<button class="fbtn active" data-srcfilter="all">All</button>
<button class="fbtn" data-srcfilter="returning">Returning</button>
<button class="fbtn" data-srcfilter="bots">Bots</button>
<button class="fbtn" data-srcfilter="human">Human?</button>
<select class="fsel" id="src_country"><option value="">All countries</option></select>
<input class="fsearch" id="src_search" type="text" placeholder="search ip / country / isp" autocomplete="off">
</div>
<div class="scroll" id="sources"></div>
</div>
</section>

<section class="view" id="view_payloads">
<div class="panel">
<div class="panelhead"><span data-icon="downloads"></span>Payload pulls<span class="sp" style="flex:1"></span><span class="count" id="plv_count">0</span></div>
<div class="scroll" id="plview"></div>
</div>
</section>

<section class="view" id="view_honeytokens">
<div class="panel">
<div class="panelhead"><span data-icon="bait"></span>90s JT Reveals<span class="sp" style="flex:1"></span><span class="count" id="htv_count">0</span></div>
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
<div class="panel"><div class="panelhead"><span data-icon="ips"></span>Top ISPs<span class="sp" style="flex:1"></span><span class="count" id="ri_count">0</span></div><div class="scroll" id="rec_isps"></div></div>
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

<div id="replay"><div class="replaybox">
<div class="replayhead"><span class="rmode" id="replay_mode" data-icon="live"></span><span id="replay_kind">Session replay</span><span class="rid" id="replay_title"></span><span class="livepill" id="replay_live"><i></i>LIVE</span><span class="grow" style="flex:1"></span><span class="spd" id="replay_meta"></span><button class="iconbtn" id="replay_close"><span data-icon="close"></span></button></div>
<pre id="term"></pre>
<div class="replayfoot" id="replay_foot"></div>
</div></div>

<div id="toasts"></div>
<canvas id="confetti"></canvas>
<div id="jtflash"><img src="/dashboard/jt-prize.jpg" alt=""></div>
<div id="splash"><div class="splashwrap"><canvas id="splash_canvas"></canvas><div class="splashcap" id="splash_cap">booting console</div></div></div>

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
scan:'<circle cx="12" cy="12" r="9"/><line x1="12" y1="3" x2="12" y2="7"/><line x1="12" y1="17" x2="12" y2="21"/><line x1="3" y1="12" x2="7" y2="12"/><line x1="17" y1="12" x2="21" y2="12"/><circle cx="12" cy="12" r="2.5"/>',
live:'<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>'
};
function setIcon(node,name){if(ICONS[name])node.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'+ICONS[name]+'</svg>';}
function paintIcons(root){var ns=(root||document).querySelectorAll('[data-icon]');for(var i=0;i<ns.length;i++)setIcon(ns[i],ns[i].getAttribute('data-icon'));}

var COLORS={
SESSION_START:'#3b82f6',SESSION_END:'#71717a',
CREDENTIAL:'#f59e0b',COMMAND:'#22c55e',
DOWNLOAD_ATTEMPT:'#ef4444',EXEC_ATTEMPT:'#ef4444',
HTTP_REQUEST:'#6366f1',HTTP_POST:'#a855f7',
HONEYTOKEN:'#14b8a6',PORT_SCAN:'#71717a',FLOOD_BLOCKED:'#f97316',
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
function svcOf(e){if(!e.protocol&&!e.port)return '';return (e.protocol||'?')+(e.port?':'+e.port:'');}
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
// Portal-plane context the server attaches to each feed event: country (org on
// hover), the classifier's verdict, and whether this source has been here before.
var g=e.geo||{};
var cc=el('span','cc',g.country||'');
if(g.org)cc.title=g.org;
div.appendChild(cc);
div.appendChild(el('span','svc',svcOf(e)));
div.appendChild(el('span','msg',summary(e)));
if(g.kind)div.appendChild(el('span','tag',g.kind));
if(g.returning)div.appendChild(el('span','tag ret',g.visits>=2?'returning · '+g.visits:'returning'));
var ip=srcOf(e);
div.addEventListener('click',function(){openIP(ip);});
return div;
}

// The five stat cards are whole-UTC-day aggregates, so they are driven by the
// server-side /dashboard/overview rollup (see applyOverview), not the capped
// in-page event buffer, which only ever holds the last few hundred events and so
// undercounts a busy sensor. The feed counter is the one genuine buffer measure.
function computeStats(){
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
// The stat cards are the server-side whole-day rollup, normally refreshed on a
// slow timer. A notable event (a JT reveal, a payload pull) is rare and high-signal,
// so refresh promptly on it too, keeping the cards in step with the confetti/flash
// instead of lagging up to the poll interval. High-volume events stay on the timer.
if(curView==='sources'||curView==='recon'||NOTABLE[e.event])scheduleOverview();
if(curView==='honeytokens'&&e.event==='HONEYTOKEN')loadHoneytokens();
if(curView==='payloads'&&e.event==='DOWNLOAD_ATTEMPT')loadPayloads();
if(e.event==='SESSION_END')loadRecordings();
// Update the live rail the instant an event streams, from the event's own data, so
// a new session pops in immediately rather than waiting on the poll; scheduleActive
// then reconciles with the backend (country, ISP, verdict, recorded flag).
if(e.event==='SESSION_START')addActiveOptimistic(e);
else if(e.event==='SESSION_END')removeActiveSession(e.session);
else if(e.event==='COMMAND')bumpActiveCmds(e.session);
if(e.event==='SESSION_START'||e.event==='SESSION_END')scheduleActive();
if(detailIP&&srcOf(e)===detailIP)scheduleDetailRefresh();
}

var VIEWS={feed:['Live feed','streaming events as they arrive'],live:['Live sessions','watch an attacker at the keyboard, right now'],sources:['Sources','every host that has touched the honeypot'],recon:['Recon','port scans, geography, and client tooling'],payloads:['Payload pulls','the malware URLs attackers tried to fetch, by source'],honeytokens:['90s JT Reveals','attackers who dug far enough to hit a Justin Timberlake reveal']};
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
if(name==='payloads')loadPayloads();
if(name==='honeytokens')loadHoneytokens();
}

// Sources and Recon are driven by the server-side /dashboard/overview rollup, so
// they show the complete picture (every source, geo-resolved) rather than only the
// last few hundred streamed events the feed holds.
// KINDS maps a source's assessed kind to a short label and colour for its row
// chip. A kind with no entry (unknown) shows no chip.
var KINDS={
'bot:loader':['loader','#f87171'],
'bot:bruteforce':['brute','#fb923c'],
'scanner':['scan','#60a5fa'],
'human?':['human?','#4ade80']
};
function kindTag(kind){
var k=KINDS[kind];
if(!k)return null;
var t=el('span','kindtag',k[0]);
t.style.color=k[1];
return t;
}
var statScope='today';
var srcFilter='all',srcCountry='',srcSearch='';
function matchSrcFilter(r){
if(srcFilter==='returning'&&!r.returning)return false;
if(srcFilter==='bots'&&(r.kind||'').slice(0,3)!=='bot')return false;
if(srcFilter==='human'&&r.kind!=='human?')return false;
if(srcCountry&&(r.country||r.scope||'')!==srcCountry)return false;
if(srcSearch){
var hay=((r.ip||'')+' '+(r.country||'')+' '+(r.scope||'')+' '+(r.org||'')).toLowerCase();
if(hay.indexOf(srcSearch)<0)return false;
}
return true;
}
// populateCountryFilter fills the country dropdown from the loaded sources
// (busiest-country first, since the list is sorted by events), preserving the
// current selection across data refreshes.
function optEl(v,t){var o=document.createElement('option');o.value=v;o.textContent=t;return o;}
function populateCountryFilter(list){
var sel=document.getElementById('src_country');
if(!sel)return;
var cur=sel.value,seen={},countries=[];
for(var i=0;i<list.length;i++){var c=list[i].country||list[i].scope||'';if(c&&!seen[c]){seen[c]=true;countries.push(c);}}
sel.textContent='';
sel.appendChild(optEl('','All countries'));
for(var j=0;j<countries.length;j++)sel.appendChild(optEl(countries[j],countries[j]));
sel.value=cur;
}
function renderSources(){
var box=document.getElementById('sources');
box.textContent='';
var list=(overview&&overview.sources)||[];
setNum('src_count',(overview&&overview.totals&&overview.totals.sources)||list.length);
var shown=0;
for(var n=0;n<list.length;n++){
if(!matchSrcFilter(list[n]))continue;
box.appendChild(srcRow(list[n]));shown++;
}
if(!shown)box.appendChild(el('div','empty',list.length?'No sources match this filter.':'No sources yet.'));
}
function srcRow(r){
var div=el('div','row');
div.appendChild(el('span','ip',r.ip));
var g=el('span','geotag');g.appendChild(el('span','tag',r.country||r.scope||'?'));div.appendChild(g);
var isp=el('span','isp');if(r.org){isp.textContent=r.org;if(r.asn)isp.title='AS'+r.asn+' · '+r.org;}else if(r.asn){isp.textContent='AS'+r.asn;}div.appendChild(isp);
var kc=el('span','kindcell');var kt=kindTag(r.kind);if(kt){if(r.confidence)kt.title=r.confidence+'% confidence';kc.appendChild(kt);}div.appendChild(kc);
var c=el('span','badge');c.style.width='64px';
var cd=el('span','bd');cd.style.background=r.scanned?'#f87171':var_acc;c.appendChild(cd);
c.appendChild(el('span','bn',(r.events||0)+' ev'));
div.appendChild(c);
var det=(r.protocols||[]).join(', ');
if(r.ports&&r.ports.length)det+=(det?'   ':'')+r.ports.map(function(x){return ':'+x;}).join(' ');
if(r.scanned)det+='   · scanned';
div.appendChild(el('span','msg',det));
var rb=el('span','retbadge');if(r.returning){rb.textContent='↩'+(r.visits||2);rb.title=(r.visits||2)+' visits';}div.appendChild(rb);
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
var isps=o.by_isp||[];var ib=document.getElementById('rec_isps');ib.textContent='';setNum('ri_count',isps.length);
if(!isps.length)ib.appendChild(el('div','empty','No ISP data yet (load an ASN database).'));
for(var m=0;m<isps.length;m++)ib.appendChild(ispRow(isps[m]));
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
function ispRow(s){
var div=el('div','row');
var name=el('span','msg');name.textContent=s.org||('AS'+s.asn);if(s.asn)name.title='AS'+s.asn;div.appendChild(name);
var b=el('span','badge');b.style.width='92px';var bd=el('span','bd');bd.style.background=var_acc;b.appendChild(bd);b.appendChild(el('span','bn',s.sources+(s.sources===1?' src':' srcs')));div.appendChild(b);
var ev=el('span','t');ev.style.width='84px';ev.textContent=s.events+' ev';div.appendChild(ev);
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
// header so the two never disagree, and the five live-feed stat cards are
// whole-UTC-day counts from the server rollup (overview.today), not the capped
// in-page event buffer, so they stay accurate on a busy sensor.
setNum('nav_src',t.sources||0);
setNum('r_scans',t.port_scans||0);
setNum('r_countries',(overview.by_country||[]).length);
setNum('r_agents',t.user_agents||0);
setNum('r_attempts',(t.credentials||0)+(t.http_requests||0)+(t.exec||0)+(t.downloads||0));
// The five stat cards show today (the default) or all-time, per the scope toggle.
// Both datasets are already in the overview rollup, so switching is client-side.
var sc=statScope==='all'?(overview.totals||{}):(overview.today||{});
setNum('s_sessions',sc.sessions||0);setNum('s_ips',sc.sources||0);setNum('s_dl',sc.downloads||0);
setNum('s_ht',sc.bait||0);setNum('s_scans',sc.port_scans||0);setNum('nav_ht',sc.bait||0);setNum('nav_pl',sc.downloads||0);
var bv=document.getElementById('build_ver');if(bv&&overview.version)bv.textContent=overview.version;
populateCountryFilter(overview.sources||[]);
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
if(!srcs.length){box.appendChild(el('div','empty','No JT reveals yet. Attackers have to dig to the loot first.'));return;}
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

function loadPayloads(){
fetch('/dashboard/payloads',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(renderPayloads).catch(function(){});
}
function renderPayloads(d){
var box=document.getElementById('plview');
box.textContent='';
var srcs=d.sources||[];
setNum('plv_count',srcs.length);
var byUrl=d.by_url||{};
var bar=el('div','htbar');
bar.appendChild(metric(d.total||0,'payloads'));
bar.appendChild(metric(d.unique_srcs||0,'sources'));
bar.appendChild(metric(d.dropper_total||0,'droppers'));
bar.appendChild(metric(Object.keys(byUrl).length,'distinct urls'));
var geo=el('div','m');geo.appendChild(el('b',null,d.geo_active?'on':'off'));geo.appendChild(el('span',null,'country db'));
bar.appendChild(geo);
box.appendChild(bar);
var urls=Object.keys(byUrl).sort(function(a,b){return byUrl[b]-byUrl[a];});
if(urls.length){
var chips=el('div','chips');
for(var i=0;i<urls.length;i++){
var ch=el('span','chip');
ch.appendChild(el('span','ck',urls[i]));
ch.appendChild(el('b',null,'x'+byUrl[urls[i]]));
chips.appendChild(ch);
}
box.appendChild(chips);
}
if(!srcs.length){box.appendChild(el('div','empty','No payloads yet. They land here when an attacker fetches a second stage over the wire (wget/curl/tftp), or assembles and runs one in place (the echo-loader dropper).'));return;}
for(var j=0;j<srcs.length;j++)box.appendChild(plRow(srcs[j]));
}
function plRow(s){
var div=el('div','htrow');
div.appendChild(el('span','hc','x'+s.count));
div.appendChild(el('span','hip',s.ip));
var g=el('span','geotag');g.appendChild(el('span','tag',s.country||s.scope||'?'));if(s.org)g.appendChild(el('span','tag',s.org));
div.appendChild(g);
var parts=(s.urls||[]).slice(),drops=s.droppers||[];
for(var i=0;i<drops.length;i++)parts.push('dropper '+(drops[i].filename||'')+(drops[i].sha256?' '+drops[i].sha256.slice(0,12):''));
var when=hms(s.last_seen);
div.appendChild(el('span','htk',parts.join('   ')+(when?'   '+when:'')));
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
.then(function(d){renderDetail(ip,d.entries||[],d.profile||null);})
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
.then(function(d){if(detailIP===ip){renderDetail(ip,d.entries||[],d.profile||null,true);detailBody.scrollTop=keep;}})
.catch(function(){});
}
function sect(title){detailBody.appendChild(el('div','sect',title));}

// --- source assessment (drawer) -------------------------------------------
// The byIP response carries a profile: the bot/human verdict, the evidence, the
// phases reached, and the visit breakdown. These builders render it at the top of
// the drawer so an operator sees what a source is before reading its transcript.
var VERDICTLBL={'bot:loader':'Bot · loader','bot:bruteforce':'Bot · brute-force','scanner':'Scanner','human?':'Human?','unknown':'Unknown'};
var PHASECOL={recon:'#71717a',bruteforce:'#f59e0b',access:'#3b82f6',exploit:'#ef4444'};
function phaseColor(p){return PHASECOL[p]||'#52525b';}
function buildPhases(profile){
var reached={};(profile.phases||[]).forEach(function(p){reached[p]=true;});
var ph=el('div','ribbon');
var order=[['recon','Recon'],['bruteforce','Brute'],['access','Access'],['exploit','Exploit']];
for(var i=0;i<order.length;i++){
var step=el('span','rstep',order[i][1]);
if(reached[order[i][0]])step.style.color=phaseColor(order[i][0]);
ph.appendChild(step);
if(i<order.length-1)ph.appendChild(el('span','rarrow','›'));
}
return ph;
}
function buildTimeline(profile){
var wrap=el('div','tlwrap'),visits=profile.visits||[];
var t0=Date.parse(visits[0].start),t1=Date.parse(visits[visits.length-1].end);
var span=Math.max(t1-t0,1),bar=el('div','tlbar');
for(var i=0;i<visits.length;i++){
var v=visits[i],s=Date.parse(v.start),e=Date.parse(v.end);
var seg=el('span','tlseg');
seg.style.left=((s-t0)/span*100)+'%';
seg.style.width=Math.max((e-s)/span*100,1.5)+'%';
seg.style.background=phaseColor(v.phase);
seg.title='visit '+(i+1)+': '+hms(v.start)+' to '+hms(v.end)+'  ·  '+v.events+' events  ·  '+(v.phase||'')+(v.accepted?'  ·  shell':'');
bar.appendChild(seg);
}
wrap.appendChild(bar);
return wrap;
}
function buildAssessment(profile){
var box=el('div','assess'),head=el('div','assesshead');
var verdict=el('span','verdict',VERDICTLBL[profile.kind]||profile.kind);
var kk=KINDS[profile.kind];if(kk)verdict.style.color=kk[1];
head.appendChild(verdict);
if(profile.confidence)head.appendChild(el('span','conf',profile.confidence+'%'));
if(profile.returning)head.appendChild(el('span','retflag','↩ returning'));
box.appendChild(head);
var meta=[];
if(profile.cadence_ms)meta.push(profile.cadence_ms+'ms between commands');
if((profile.visits||[]).length)meta.push(profile.visits.length+' visit'+(profile.visits.length>1?'s':''));
if(meta.length)box.appendChild(el('div','assessmeta',meta.join('  ·  ')));
var reasons=profile.reasons||[];
if(reasons.length){
var rl=el('div','reasons');
for(var i=0;i<reasons.length;i++){
var rr=el('div','reason');rr.appendChild(el('span','rdot','•'));rr.appendChild(el('span',null,reasons[i]));rl.appendChild(rr);
}
box.appendChild(rl);
}
box.appendChild(buildPhases(profile));
if((profile.visits||[]).length)box.appendChild(buildTimeline(profile));
return box;
}

function renderDetail(ip,list,profile,preserve){
document.getElementById('detail_ip').textContent=ip;
document.getElementById('detail_sub').textContent=list.length+' events';
detailBody.textContent='';
if(profile&&profile.kind)detailBody.appendChild(buildAssessment(profile));
var sessions={},creds=[],cmds=[],dls=[];
for(var i=0;i<list.length;i++){
var e=list[i];
if(e.session)sessions[e.session]=(sessions[e.session]||0)+1;
if(e.username||e.password)creds.push(e);
// Only genuine shell commands: EXEC_ATTEMPT/DOWNLOAD_ATTEMPT carry a derived
// 'command' field too (e.g. "pipe-to-bash: ...", "base64 -d: ..."), and counting
// those here double-listed them against the Downloads section and inflated the count.
if(e.event==='COMMAND')cmds.push(e);
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
var replayBox=replayEl.querySelector('.replaybox');
var termEl=document.getElementById('term');
var replayActive=false;
var liveES=null;
function closeTheater(){
replayActive=false;
if(liveES){liveES.close();liveES=null;}
replayEl.classList.remove('open');
replayBox.classList.remove('live');
document.getElementById('replay_live').classList.remove('on');
document.getElementById('replay_foot').classList.remove('live');
}
document.getElementById('replay_close').addEventListener('click',closeTheater);
replayEl.addEventListener('click',function(e){if(e.target===replayEl)closeTheater();});
document.addEventListener('keydown',function(e){if(e.key==='Escape'&&replayEl.classList.contains('open'))closeTheater();});

function openTheater(id,kind){
closeTheater();
document.getElementById('replay_title').textContent=id;
document.getElementById('replay_kind').textContent=kind;
termEl.textContent='';
replayEl.classList.add('open');
}
function appendTerm(d,input){
var t=cleanTerm(d);if(!t)return false;
var atBottom=termEl.scrollHeight-termEl.scrollTop-termEl.clientHeight<40;
if(input){var sp=document.createElement('span');sp.className='ti';sp.textContent=t;termEl.appendChild(sp);}
else termEl.appendChild(document.createTextNode(t));
if(atBottom)termEl.scrollTop=termEl.scrollHeight;
return true;
}
function cleanTerm(s){
s=s.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g,'');
s=s.replace(/\x1b[\(\)][AB0-9]/g,'');
s=s.replace(/\x1b[=>NM]/g,'');
// C0 controls, DEL, and U+FFFD (the telnet IAC negotiation bytes decode to this)
return s.replace(/[\x00-\x08\x0b-\x1f\x7f\uFFFD]/g,'');
}
function parseCast(text){
var out=[],lines=text.split('\n');
for(var i=1;i<lines.length;i++){
var ln=lines[i];if(!ln)continue;
try{var a=JSON.parse(ln);if(a&&a.length===3&&(a[1]==='o'||a[1]==='i'))out.push({t:a[0],d:a[2],inp:a[1]==='i'});}catch(e){}
}
return out;
}
function playCast(id){
openTheater(id,'Session replay');
document.getElementById('replay_meta').textContent='replay 1.6x';
document.getElementById('replay_foot').textContent='recorded session';
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
appendTerm(frames[i].d,frames[i].inp);
var gap=i+1<frames.length?Math.min(frames[i+1].t-frames[i].t,1.2):0;
i++;
setTimeout(step,Math.max(gap*1000/1.6,8));
}
step();
}
function schip(box,txt){if(txt){box.appendChild(el('span','schip',txt));}}
function watchLive(s){
var id=s.id;
openTheater(id,'Watching live');
replayBox.classList.add('live');
document.getElementById('replay_live').classList.add('on');
document.getElementById('replay_meta').textContent='real time';
var foot=document.getElementById('replay_foot');
foot.classList.add('live');foot.textContent='';
var info=el('span','sinfo','');foot.appendChild(info);
schip(info,s.ip);schip(info,s.country);schip(info,s.org);
if(s.protocol)schip(info,String(s.protocol).toUpperCase());
var st=el('span','sst',' connecting');foot.appendChild(st);
foot.appendChild(el('span','cur',''));
// enrich with the source profile: assessed kind and visit history
fetch('/dashboard/ip/'+encodeURIComponent(s.ip),{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){var p=d.profile||{};if(p.kind&&p.kind!=='unknown')schip(info,p.kind);
var v=(p.visits||[]).length;if(v>1)schip(info,v+' visits'+(p.returning?' • returning':''));else schip(info,'first visit');}).catch(function(){});
var got=false;
var ph=el('div','termph','waiting for terminal activity');termEl.appendChild(ph);
var phT=setTimeout(function(){if(!got)ph.textContent='connected. this source has not been shown or typed anything yet.';},1600);
replayActive=true;
var es=new EventSource('/dashboard/watch/'+encodeURIComponent(id));
liveES=es;
es.addEventListener('frame',function(ev){
st.textContent=' live';
try{var a=JSON.parse(ev.data);if(a&&a.length===3&&(a[1]==='o'||a[1]==='i')){if(appendTerm(a[2],a[1]==='i')&&!got){got=true;if(ph.parentNode)ph.parentNode.removeChild(ph);clearTimeout(phT);}}}catch(e){}
});
es.onerror=function(){st.textContent=' stream ended';};
}

// --- live sessions rail ---------------------------------------------------
var activeSessions=[],activeT=0;
function scheduleActive(){if(activeT)return;activeT=setTimeout(function(){activeT=0;loadActive();},700);}
function fmtElapsed(ms){
var s=Math.max(0,Math.floor((Date.now()-ms)/1000));
if(s<60)return s+'s';
var m=Math.floor(s/60);if(m<60)return m+'m '+(s%60)+'s';
return Math.floor(m/60)+'h '+(m%60)+'m';
}
function loadActive(){
fetch('/dashboard/sessions/active',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){activeSessions=d.sessions||[];renderLiveRail();})
.catch(function(){});
}
// Optimistic rail edits from streamed events, so the list reacts instantly; the next
// loadActive reconciles the details the event alone does not carry.
function addActiveOptimistic(e){
var id=e.session;if(!id)return;
for(var i=0;i<activeSessions.length;i++)if(activeSessions[i].id===id)return;
var t=e.epoch_ms||Date.now();
activeSessions.unshift({id:id,ip:srcOf(e),protocol:e.protocol||'',country:'',org:'',started_ms:t,last_seen_ms:t,commands:0,recorded:true});
renderLiveRail();
}
function removeActiveSession(id){
if(!id)return;var n=activeSessions.length;
activeSessions=activeSessions.filter(function(s){return s.id!==id;});
if(activeSessions.length!==n)renderLiveRail();
}
function bumpActiveCmds(id){
if(!id)return;
for(var i=0;i<activeSessions.length;i++)if(activeSessions[i].id===id){activeSessions[i].commands++;activeSessions[i].last_seen_ms=Date.now();renderLiveRail();return;}
}
function renderLiveRail(){
var n=activeSessions.length;
document.getElementById('live_count').textContent=n;
var badge=document.getElementById('nav_live');badge.textContent=n;badge.classList.toggle('on',n>0);
document.getElementById('live_pulse').classList.toggle('on',n>0);
document.getElementById('live_empty').style.display=n?'none':'block';
var rail=document.getElementById('live_rail');rail.textContent='';
for(var i=0;i<n;i++){(function(s){
var card=el('div','livecard');
var top=el('div','lc_top');
top.appendChild(el('span','lc_dot',''));
top.appendChild(el('span','lc_ip',s.ip||s.id));
if(s.country)top.appendChild(el('span','lc_flag',s.country));
card.appendChild(top);
var meta=el('div','lc_meta');
meta.appendChild(el('span',null,fmtElapsed(s.started_ms)+' connected'));
meta.appendChild(el('span',null,(s.commands||0)+' cmds'));
if(s.protocol)meta.appendChild(el('span',null,String(s.protocol).toUpperCase()));
card.appendChild(meta);
if(s.recorded){
var btn=el('div','lc_watch');var ic=el('span',null,'');setIcon(ic,'live');btn.appendChild(ic);btn.appendChild(el('span',null,'Watch live'));
btn.addEventListener('click',function(){watchLive(s);});
card.appendChild(btn);
}else{
card.appendChild(el('div','lc_meta muted','session recording is off'));
}
rail.appendChild(card);
})(activeSessions[i]);}
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
var LABELS={DOWNLOAD_ATTEMPT:'Payload pull',EXEC_ATTEMPT:'Exec attempt',HONEYTOKEN:'90s JT Reveal'};
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
flashJT();
playPrize();
}
// flashJT flashes the celebration portrait full-screen for ~2s then fades it out,
// riding the same honeytoken (JT reveal) trigger as the confetti. Only prizeMoment,
// which fires solely on a HONEYTOKEN, calls it, so it never appears on other events.
var jtFlashEl=document.getElementById('jtflash'),jtFlashT=0;
function flashJT(){
if(!jtFlashEl)return;
jtFlashEl.classList.remove('on');
void jtFlashEl.offsetWidth; // restart the animation if a second reveal fires quickly
jtFlashEl.classList.add('on');
if(jtFlashT)clearTimeout(jtFlashT);
jtFlashT=setTimeout(function(){jtFlashEl.classList.remove('on');jtFlashT=0;},2800);
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
// Chime on enable, within the click gesture (which also resumes the audio
// context), so turning sound on gives immediate proof it works — the high-signal
// alerts themselves are rare by design, so silence after a toggle reads as broken.
sndBtn.addEventListener('click',function(){setSound(!soundOn);if(soundOn){tone(988,0,0.10,'triangle',0.11);tone(1318.51,0.09,0.13,'triangle',0.11);}});
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
var srcfBtns=document.querySelectorAll('[data-srcfilter]');
for(var sf=0;sf<srcfBtns.length;sf++)srcfBtns[sf].addEventListener('click',function(){
srcFilter=this.getAttribute('data-srcfilter');
for(var z=0;z<srcfBtns.length;z++)srcfBtns[z].classList.toggle('active',srcfBtns[z]===this);
renderSources();
});
var scopeBtns=document.querySelectorAll('[data-scope]');
for(var sb=0;sb<scopeBtns.length;sb++)scopeBtns[sb].addEventListener('click',function(){
statScope=this.getAttribute('data-scope');
for(var z2=0;z2<scopeBtns.length;z2++)scopeBtns[z2].classList.toggle('active',scopeBtns[z2]===this);
applyOverview();
});
var scSel=document.getElementById('src_country');
if(scSel)scSel.addEventListener('change',function(){srcCountry=this.value;renderSources();});
var scInput=document.getElementById('src_search');
if(scInput)scInput.addEventListener('input',function(){srcSearch=this.value.toLowerCase();renderSources();});
document.getElementById('bait_card').addEventListener('click',function(){showView('honeytokens');});
document.getElementById('dl_card').addEventListener('click',function(){showView('payloads');});
document.getElementById('scan_card').addEventListener('click',function(){showView('recon');});

// --- boot splash: the colour-ASCII JT portrait animates up, holds ~1s, then out.
var splashDone=false;
function dismissSplash(){
if(splashDone)return;splashDone=true;
var sp=document.getElementById('splash');if(!sp)return;
sp.classList.add('hide');
setTimeout(function(){sp.classList.add('gone');sp.innerHTML='';},560);
}
function showSplash(){
var sp=document.getElementById('splash');if(!sp)return;
sp.addEventListener('click',dismissSplash);
setTimeout(dismissSplash,3500); // safety: never let a stalled fetch trap the UI
fetch('/dashboard/jt-splash',{credentials:'same-origin'})
.then(function(r){return r.json();})
.then(function(d){if(d&&d.rows)runSplashAnim(d);else dismissSplash();})
.catch(dismissSplash);
}
// runSplashAnim scatters the portrait's pixels, flies them in to assemble it, holds,
// then blows them back out. Each cell is a particle; positions are written straight
// into an ImageData buffer (no per-particle fillStyle), so tens of thousands animate
// smoothly.
function runSplashAnim(d){
var cell=2,W=d.w*cell,H=d.h*cell;
var cv=document.getElementById('splash_canvas');if(!cv)return;
cv.width=W;cv.height=H;
var s=Math.min((window.innerWidth*0.9)/W,(window.innerHeight*0.76)/H,1.4);
cv.style.width=(W*s)+'px';cv.style.height=(H*s)+'px';
var ctx=cv.getContext('2d'),img=ctx.createImageData(W,H),buf=new Uint32Array(img.data.buffer);
var pal=d.pal.map(function(h){return (parseInt(h.substr(4,2),16)<<16)|(parseInt(h.substr(2,2),16)<<8)|parseInt(h.substr(0,2),16);});
var reach=Math.max(W,H),TAU=6.2831853;
var N=d.w*d.h,TX=new Float32Array(N),TY=new Float32Array(N),SX=new Float32Array(N),SY=new Float32Array(N),EDX=new Float32Array(N),EDY=new Float32Array(N),COL=new Uint32Array(N),DLY=new Float32Array(N),n=0;
for(var y=0;y<d.h;y++){var row=d.rows[y],x=0;
for(var k=0;k<row.length;k+=2){var ci=row[k],ln=row[k+1];
for(var j=0;j<ln;j++){
TX[n]=x*cell;TY[n]=y*cell;COL[n]=pal[ci];
var a1=Math.random()*TAU,r1=reach*(0.55+Math.random()*0.8);SX[n]=W/2+Math.cos(a1)*r1;SY[n]=H/2+Math.sin(a1)*r1;
var a2=Math.random()*TAU,r2=reach*(0.7+Math.random()*0.9);EDX[n]=Math.cos(a2)*r2;EDY[n]=Math.sin(a2)*r2;
DLY[n]=Math.random();x++;n++;
}}}
var ASM=700,HOLD=490,EXIT=595,t0=null;
function ease(t){return t<0?0:t>1?1:t*t*(3-2*t);}
var cap=document.getElementById('splash_cap');
function frame(ts){
if(t0===null)t0=ts;var t=ts-t0;
if(t>=ASM+HOLD+EXIT){dismissSplash();return;}
buf.fill(0);
var exiting=t>ASM+HOLD;
if(cap)cap.textContent=(t<ASM)?'assembling':(exiting?'':'console ready');
for(var i=0;i<n;i++){
var px,py,al=255;
if(t<ASM){var p=ease((t/ASM-DLY[i]*0.35)/0.65);px=SX[i]+(TX[i]-SX[i])*p;py=SY[i]+(TY[i]-SY[i])*p;}
else if(!exiting){px=TX[i];py=TY[i];}
else{var q=ease(((t-ASM-HOLD)/EXIT-DLY[i]*0.3)/0.7);px=TX[i]+EDX[i]*q;py=TY[i]+EDY[i]*q;al=(255*(1-q))|0;}
var ix=px|0,iy=py|0;if(ix<0||iy<0||ix>=W-1||iy>=H-1)continue;
var c=(al<<24)|COL[i],b0=iy*W+ix;
buf[b0]=c;buf[b0+1]=c;buf[b0+W]=c;buf[b0+W+1]=c;
}
ctx.putImageData(img,0,0);
requestAnimationFrame(frame);
}
requestAnimationFrame(frame);
}
showSplash();

paintIcons();
tickClock();setInterval(tickClock,1000);
renderSpark();setInterval(sparkTick,2500);
try{if(localStorage.getItem('sweetty_snd')==='1')setSound(true);}catch(x){}
document.addEventListener('pointerdown',gestureResume);
setTimeout(function(){hydrated=true;},1500);
load();connect();loadConsoles();loadRecordings();loadOverview();loadActive();
// Refresh the recon rollup (and the port-scan stat card it feeds) on a slow,
// bounded timer so it stays current without re-reading the whole log per event.
setInterval(loadOverview,30000);
// Poll the live-session rail often enough to feel real time, updating the elapsed
// timers and the nav badge; SESSION_START/END also nudge it immediately.
setInterval(loadActive,3000);
</script>
</body></html>`
