package server

// compactAdminCSS is the approved dense StumpfWorks operations theme. It is
// appended to the established stylesheet so existing templates, permissions,
// forms and security boundaries remain unchanged while the administration UI
// can migrate incrementally.
const compactAdminCSS = `
body:not(.login-page){--bg:#090c10;--bg2:#0c1015;--panel:#0d1218;--panel-solid:#0d1218;--panel-raised:#111923;--line:#242b34;--line-strong:#323c48;--text:#edf2f7;--muted:#7e8b9b;--accent:#39d98a;--accent2:#1685e5;--danger:#ef6478;--shadow:none;background:linear-gradient(115deg,#090c10,#11100d 145%);font-size:12px}
body:not(.login-page):before{display:none}
body:not(.login-page) .sidebar{width:205px;padding:14px 8px 12px;background:#0d1015;border-color:var(--line);backdrop-filter:none}
body:not(.login-page) .brand{gap:9px;padding:3px 7px 16px}
body:not(.login-page) .brand-mark{width:27px;height:27px;border-radius:4px;background:linear-gradient(145deg,#42a5ff,#0f67b6);color:#fff;font-size:14px;box-shadow:0 5px 18px rgba(22,133,229,.24)}
body:not(.login-page) .brand strong{font-size:13px;text-transform:uppercase;letter-spacing:.7px}
body:not(.login-page) .brand small{font-size:7px;letter-spacing:2px}
body:not(.login-page) .sidebar nav{gap:1px;margin-top:12px}
body:not(.login-page) .sidebar nav a{gap:8px;padding:7px 9px;border:0;border-radius:3px;font-size:10px;font-weight:550}
body:not(.login-page) .sidebar nav a span{width:15px;font-size:12px}
body:not(.login-page) .sidebar nav a.active{background:#172335;border:0;box-shadow:inset 2px 0 #1685e5;color:#f3f7fb}
body:not(.login-page) .sidebar nav a.active span{color:#55aaff}
body:not(.login-page) .server-state{padding:8px;border-radius:3px;background:#0f151c}
body:not(.login-page) .server-state strong{font-size:9px}
body:not(.login-page) .server-state small{font-size:8px}
body:not(.login-page) .ghost{padding:7px;border-radius:3px;font-size:9px}
body:not(.login-page) .content{max-width:1720px;padding:20px 24px 45px}
body:not(.login-page) .topbar{min-height:45px;margin:-20px -24px 16px;padding:0 22px;border-bottom:1px solid var(--line);background:rgba(12,16,21,.94)}
body:not(.login-page) .topbar .eyebrow{display:none}
body:not(.login-page) .topbar h1{font-size:14px;letter-spacing:-.2px}
body:not(.login-page) .status-chip{padding:6px 8px;border-radius:3px;font-size:8px}
body:not(.login-page) .panel{margin-top:7px;padding:12px;border-radius:4px;background:#0d1218;box-shadow:none}
body:not(.login-page) .panel h2{font-size:11px}
body:not(.login-page) .panel p{font-size:9px}
body:not(.login-page) .panel-head{margin-bottom:10px;gap:12px}
body:not(.login-page) .hero{min-height:105px;padding:18px 20px;background:linear-gradient(120deg,#101923,#0d1218)}
body:not(.login-page) .hero h2{margin:6px 0 3px;font-size:18px}
body:not(.login-page) .hero p{font-size:10px}
body:not(.login-page) .hero-icon{width:58px;height:58px;border-radius:4px;font-size:25px;box-shadow:none}
body:not(.login-page) .kicker{padding:3px 6px;border-radius:2px;font-size:7px}
body:not(.login-page) .grid{gap:7px}
body:not(.login-page) .stats{grid-template-columns:repeat(4,minmax(0,1fr));margin-top:7px}
body:not(.login-page) .stats article,body:not(.login-page) .status-grid article{padding:11px;border-radius:4px;background:#0d1218}
body:not(.login-page) .stats article{min-height:76px;border-left:2px solid #1685e5}
body:not(.login-page) .stat-icon{width:24px;height:24px;border-radius:3px;font-size:10px}
body:not(.login-page) .grid small{font-size:7px;letter-spacing:.7px}
body:not(.login-page) .grid strong{font-size:18px}
body:not(.login-page) .status-grid article{min-height:105px}
body:not(.login-page) .status-grid strong{margin-top:9px;font-size:15px}
body:not(.login-page) .status-grid p{font-size:8px}
body:not(.login-page) .count,body:not(.login-page) .badge{padding:3px 6px;border-radius:2px;font-size:7px}
body:not(.login-page) .table-wrap{margin:0 -12px -12px}
body:not(.login-page) th,body:not(.login-page) td{padding:8px 12px}
body:not(.login-page) th{font-size:7px;letter-spacing:.7px;background:#0a0f15}
body:not(.login-page) td{font-size:9px}
body:not(.login-page) .mono{font-size:8px}
body:not(.login-page) input,body:not(.login-page) select,body:not(.login-page) textarea,body:not(.login-page) button,body:not(.login-page) .button{padding:7px 9px;border-radius:3px;font-size:9px}
body:not(.login-page) button.small{padding:5px 7px;font-size:8px}
body:not(.login-page) label{gap:4px;font-size:8px}
body:not(.login-page) .notice{border-radius:3px}
body:not(.login-page) .secret{gap:20px}
body:not(.login-page) .secret code{padding:8px;border-radius:3px;font-size:9px}
@media(max-width:1000px){body:not(.login-page) .stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:680px){body:not(.login-page) .sidebar{position:relative;width:100%;height:auto;padding:12px}body:not(.login-page) .sidebar nav{grid-template-columns:repeat(4,1fr)}body:not(.login-page) .content{padding:16px 12px 35px}body:not(.login-page) .topbar{margin:-16px -12px 12px;padding:0 12px}body:not(.login-page) .stats{grid-template-columns:1fr}}
`
