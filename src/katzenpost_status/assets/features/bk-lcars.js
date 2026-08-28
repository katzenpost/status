(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // One LCARS-style status board per major Star Trek series. Homage styling
    // only; every number is the real live consensus. A shared builder is skinned
    // by a per-series palette/shape. The board always identifies the NAMENLOS
    // mixnet (the ship registry is kept as a secondary "vessel designation"),
    // uses authentic LCARS shapes (rounded elbows + a header sweep + a coloured
    // pill rail), and embeds a live "viewscreen" - another visualization running
    // in a small screen inside the panel, with a randomize button and a selector.
    var css = document.createElement('style');
    css.textContent =
        '.lcx{position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:auto;' +
        'letter-spacing:1px;padding:calc(max(12px, env(safe-area-inset-top)) + 96px) 12px 16px}' +
        '.lcx *{box-sizing:border-box}' +
        '.lcx .frame{display:grid;grid-template-columns:172px 1fr;grid-template-rows:auto 1fr;gap:8px}' +
        '.lcx .elbow-tl{grid-column:1;grid-row:1;position:relative;height:90px;background:var(--acc);' +
        'border-top-left-radius:var(--corner);border-bottom-right-radius:8px}' +
        '.lcx .elbow-tl .cap{position:absolute;left:16px;bottom:10px;font-size:11px;font-weight:800;color:var(--bg)}' +
        '.lcx .head{grid-column:2;grid-row:1;background:var(--acc);border-radius:0 var(--pill) var(--pill) 0;' +
        'display:flex;align-items:center;gap:14px;padding:10px 22px;min-height:90px;min-width:0}' +
        '.lcx .title{font-size:26px;font-weight:900;color:var(--bg);line-height:1.05}' +
        '.lcx .vessel{font-size:11px;color:var(--bg);opacity:0.82;margin-top:4px}' +
        '.lcx .sub{margin-left:auto;text-align:right;font-size:11px;color:var(--bg);opacity:0.92;line-height:1.5;white-space:nowrap}' +
        '.lcx .side{grid-column:1;grid-row:2;display:flex;flex-direction:column;gap:6px}' +
        '.lcx .rail{display:flex;flex-direction:column;gap:6px}' +
        '.lcx .pill{background:var(--acc);color:var(--bg);border-radius:var(--pill);padding:12px;font-size:11px;' +
        'font-weight:800;text-align:right;min-height:40px;display:flex;align-items:center;justify-content:flex-end;cursor:pointer}' +
        '.lcx .pill.selp{outline:3px solid var(--ink);outline-offset:-3px}' +
        '.lcx .ntype{opacity:0.5;font-size:8px;margin-left:3px}' +
        '.lcx .elbow-bl{margin-top:auto;height:58px;background:var(--acc);border-bottom-left-radius:var(--corner);border-top-right-radius:8px}' +
        '.lcx .body{grid-column:2;grid-row:2;display:flex;flex-direction:column;gap:10px;min-width:0}' +
        '.lcx .row{display:flex;gap:8px;flex-wrap:wrap}' +
        '.lcx .cell{padding:10px 12px;color:var(--bg);font-weight:800;min-width:104px;flex:1 1 104px;border-radius:var(--pill)}' +
        '.lcx .cell .n{font-size:26px;line-height:1;display:block}' +
        '.lcx .cell .l{font-size:10.5px;opacity:0.85}' +
        '.lcx .panel{padding:6px 0 6px 14px;border-left:14px solid var(--acc2);border-radius:0 0 0 var(--pill)}' +
        '.lcx .panel h3{margin:0 0 6px;font-size:13px;font-weight:800;color:var(--acc2)}' +
        '.lcx .meter{display:grid;grid-template-columns:70px 1fr 60px;gap:6px;align-items:center;margin:3px 0;font-size:11px}' +
        '.lcx .track{height:12px;background:rgba(255,255,255,0.08);border-radius:6px;overflow:hidden}' +
        '.lcx .fill{height:100%;border-radius:6px}' +
        '.lcx .roster{display:flex;flex-wrap:wrap;gap:5px}' +
        '.lcx .node{display:flex;align-items:center;gap:5px;font-size:10px;border-radius:10px;padding:3px 8px 3px 6px;cursor:pointer;border:1px solid transparent}' +
        '.lcx .node:hover{border-color:var(--acc)}' +
        '.lcx .node.sel{border-color:var(--acc);background:rgba(255,255,255,0.14)!important}' +
        '.lcx .dot{width:9px;height:9px;border-radius:50%}' +
        '.lcx .detail{display:grid;grid-template-columns:1fr 1fr;gap:4px 16px}' +
        '.lcx .kv{display:flex;gap:8px;font-size:11px;border-bottom:1px solid rgba(255,255,255,0.08);padding:3px 0}' +
        '.lcx .kv .k{color:var(--acc2);min-width:104px}' +
        '.lcx .kv .v{color:var(--ink);word-break:break-all}' +
        '.lcx .hint{font-size:11px;opacity:0.7;padding:4px 0}' +
        '@media (max-width:600px){.lcx .detail{grid-template-columns:1fr}}' +
        '.lcx .viewer{border-left:16px solid var(--acc);border-radius:0 0 0 var(--pill);padding:8px 8px 8px 14px;' +
        'background:rgba(255,255,255,0.03)}' +
        '.lcx .vbar{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}' +
        '.lcx .vbar h3{margin:0;font-size:13px;font-weight:800;color:var(--acc);margin-right:auto}' +
        '.lcx .vsel{background:#000;color:var(--ink);border:1px solid var(--acc);border-radius:10px;' +
        'font:11px/1 monospace;padding:5px 7px;max-width:240px;cursor:pointer}' +
        '.lcx .vbtn{background:var(--acc);color:var(--bg);border:0;border-radius:var(--pill);' +
        'font:800 11px/1 monospace;padding:8px 14px;cursor:pointer;letter-spacing:1px}' +
        '.lcx .bezel{border:3px solid var(--acc2);border-radius:12px;padding:3px;background:#000}' +
        '.lcx .screen{width:100%;height:300px;border:0;border-radius:8px;background:#04060c;display:block}' +
        '.lcx .blink{animation:lcxblink 1.3s steps(1) infinite}' +
        '@keyframes lcxblink{50%{opacity:0.25}}' +
        '@media (max-width:600px){.lcx .frame{grid-template-columns:74px 1fr}.lcx .title{font-size:17px}' +
        '.lcx .screen{height:200px}}' +
        'body.lcars-active #node-info{display:none!important}';   // node detail lives in the board
    document.head.appendChild(css);

    function mk(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
    var STATUS_COL = { ok: '#66cc66', out: '#ffcc66', down: '#cc6666', unknown: '#8899aa' };

    // Per-series skins. corner: outer elbow radius; pill: pill/cell radius.
    // title is the ship registry (kept as a secondary "vessel designation").
    var SERIES = [
        { id: 'lcarstos', name: 'LCARS - TOS', title: 'U.S.S. Enterprise NCC-1701', bg: '#050505', ink: '#f0c869', accent: '#c9432e', accent2: '#3f6fb0', pills: ['#c9432e', '#e8b84b', '#3f6fb0', '#c98a3a', '#8aa63a', '#c9432e'], panel2: '#3f6fb0', corner: '18px', pill: '4px', font: '"Courier New",monospace', upper: true },
        { id: 'lcarstng', name: 'LCARS - TNG', title: 'U.S.S. Enterprise NCC-1701-D', bg: '#000', ink: '#ffcc99', accent: '#ff9966', accent2: '#cc99cc', pills: ['#cc99cc', '#9999ff', '#ffcc66', '#cc6666', '#ffcc99', '#ff9966'], panel2: '#9999ff', corner: '52px', pill: '18px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsds9', name: 'LCARS - DS9 (Cardassian)', title: 'Deep Space 9', bg: '#0a0805', ink: '#d8b884', accent: '#b87333', accent2: '#7a9a6a', pills: ['#b87333', '#9a7b4f', '#7a9a6a', '#a85a2a', '#c9a05a', '#6a5a3a'], panel2: '#7a9a6a', corner: '14px', pill: '5px', font: 'Georgia,serif', upper: true },
        { id: 'lcarsvoy', name: 'LCARS - Voyager', title: 'U.S.S. Voyager NCC-74656', bg: '#000', ink: '#cdd6ff', accent: '#9aa6ff', accent2: '#cc99cc', pills: ['#9aa6ff', '#cc99cc', '#99cccc', '#ccaa99', '#aabbff', '#8899ee'], panel2: '#99cccc', corner: '48px', pill: '16px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsent', name: 'LCARS - Enterprise NX', title: 'Enterprise NX-01', bg: '#04070a', ink: '#a8c4e0', accent: '#6699cc', accent2: '#88a0b0', pills: ['#6699cc', '#7f8fa0', '#5a7a9a', '#8aa0b8', '#4a6a8a', '#6a8aa8'], panel2: '#88a0b0', corner: '10px', pill: '4px', font: '"Courier New",monospace', upper: false },
        { id: 'lcarsdis', name: 'LCARS - Discovery', title: 'U.S.S. Discovery NCC-1031', bg: '#02060c', ink: '#bfe8ff', accent: '#33ccff', accent2: '#7fd0ff', pills: ['#33ccff', '#7fd0ff', '#4da6ff', '#a0e0ff', '#2b9fe0', '#5fc0ff'], panel2: '#7fd0ff', corner: '26px', pill: '11px', font: '"Segoe UI",Arial,sans-serif', upper: false },
        { id: 'lcarspic', name: 'LCARS - Picard', title: 'La Sirena', bg: '#060606', ink: '#d9c4a8', accent: '#d98a3d', accent2: '#3a6ea5', pills: ['#d98a3d', '#3a6ea5', '#b0894f', '#4a7ab0', '#c07a35', '#5a6a7a'], panel2: '#3a6ea5', corner: '8px', pill: '3px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsld', name: 'LCARS - Lower Decks', title: 'U.S.S. Cerritos NCC-75567', bg: '#000', ink: '#ffe08a', accent: '#ff8800', accent2: '#ffcc00', pills: ['#ff8800', '#ffcc00', '#ff5599', '#66ccff', '#88dd44', '#ff8800'], panel2: '#ff5599', corner: '52px', pill: '20px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarspro', name: 'LCARS - Prodigy', title: 'U.S.S. Protostar NX-76884', bg: '#03040a', ink: '#c8e0ff', accent: '#00e5ff', accent2: '#ff5db1', pills: ['#00e5ff', '#ff5db1', '#8a5bff', '#00d29a', '#ffb454', '#00e5ff'], panel2: '#8a5bff', corner: '30px', pill: '13px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarssnw', name: 'LCARS - Strange New Worlds', title: 'U.S.S. Enterprise NCC-1701', bg: '#040404', ink: '#e6cf8a', accent: '#d13b2f', accent2: '#c79a3a', pills: ['#d13b2f', '#c79a3a', '#3f6fb0', '#c98a3a', '#b0b0b0', '#d13b2f'], panel2: '#3f6fb0', corner: '20px', pill: '9px', font: '"Helvetica Neue",Arial,sans-serif', upper: true }
    ];

    function counts(d) {
        var byType = {}, byStatus = { ok: 0, out: 0, down: 0, unknown: 0 };
        (d.nodes || []).forEach(function (n) { byType[n.type] = (byType[n.type] || 0) + 1; byStatus[n.status] = (byStatus[n.status] || 0) + 1; });
        return { byType: byType, byStatus: byStatus, layers: (d.layers || []).map(function (l) { return l.length; }), total: (d.nodes || []).length };
    }
    function add(a, b) { return a + b; }
    function kv(label, val) {
        var r = mk('div', 'kv'); r.appendChild(mk('span', 'k', label));
        r.appendChild(mk('span', 'v', (val == null || val === '') ? '--' : String(val))); return r;
    }
    function meter(label, val, max, color) {
        var row = mk('div', 'meter'); row.appendChild(mk('span', null, label));
        var track = mk('div', 'track'), fill = mk('div', 'fill');
        fill.style.width = (max > 0 ? Math.max(2, Math.min(100, val / max * 100)) : 2) + '%'; fill.style.background = color;
        track.appendChild(fill); row.appendChild(track);
        row.appendChild(mk('span', null, (val != null ? (+val).toPrecision(3) : '--'))); return row;
    }

    // Build the persistent viewscreen: a live sub-visualization in a framed
    // screen, with a selector and a Random button. Built ONCE (its iframe must
    // not reload every refresh), so it lives outside the per-second update.
    function buildViewer(el, s) {
        var wrap = mk('div', 'viewer');
        var bar = mk('div', 'vbar');
        bar.appendChild(mk('h3', null, 'Viewscreen'));
        var sel = mk('select', 'vsel'); sel.setAttribute('aria-label', 'Choose viewscreen feed');
        var ovs = (window.KATZEN_OVERLAYS || []).filter(function (o) { return o.id.indexOf('lcars') !== 0; })
            .slice().sort(function (a, b) { return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1; });
        ovs.forEach(function (o) { var op = mk('option', null, o.name); op.value = o.id; sel.appendChild(op); });
        var btn = mk('button', 'vbtn', 'Random');
        bar.appendChild(sel); bar.appendChild(btn);
        var bezel = mk('div', 'bezel');
        var scr = document.createElement('iframe'); scr.className = 'screen';
        // NOT loading="lazy": the src is only set while the board is shown, and a
        // lazy iframe whose src is assigned while the panel is still display:none
        // would defer loading (blank viewscreen until the user changed the feed).
        scr.setAttribute('title', 'Live mixnet viewscreen');
        bezel.appendChild(scr);
        wrap.appendChild(bar); wrap.appendChild(bezel);
        el.__scr = scr; el.__vsel = sel; el.__ovs = ovs;
        el.__viewId = ovs.length ? ovs[(Math.random() * ovs.length) | 0].id : '';
        sel.value = el.__viewId;
        function load(id) { if (!id) return; el.__viewId = id; sel.value = id; if (el.__running) scr.src = location.pathname + '?overlay=' + id + '&mini=1'; }
        sel.addEventListener('change', function () { load(sel.value); });
        btn.addEventListener('click', function () {
            if (!ovs.length) return; var id;
            do { id = ovs[(Math.random() * ovs.length) | 0].id; } while (ovs.length > 1 && id === el.__viewId);
            load(id);
        });
        el.__loadView = load;
        return wrap;
    }

    // Build the fixed skeleton once (chrome + viewscreen + empty dynamic slots).
    function mount(el, s) {
        var d = K.data() || {};
        el.style.background = s.bg; el.style.color = s.ink; el.style.fontFamily = s.font;
        el.style.textTransform = s.upper ? 'uppercase' : 'none';
        el.style.setProperty('--acc', s.accent); el.style.setProperty('--acc2', s.accent2);
        el.style.setProperty('--bg', s.bg); el.style.setProperty('--ink', s.ink);
        el.style.setProperty('--pill', s.pill); el.style.setProperty('--corner', s.corner);
        el.innerHTML = '';
        var frame = mk('div', 'frame');
        var etl = mk('div', 'elbow-tl'); etl.appendChild(mk('div', 'cap', 'LCARS 47')); frame.appendChild(etl);
        var head = mk('div', 'head');
        var tblock = mk('div');
        tblock.appendChild(mk('div', 'title', (d.network_name || 'namenlos') + ' mixnet'));
        tblock.appendChild(mk('div', 'vessel', 'Vessel designation: ' + s.title));
        head.appendChild(tblock);
        var sub = mk('div', 'sub'); el.__sub = sub; head.appendChild(sub);
        frame.appendChild(head);
        var side = mk('div', 'side');
        var rail = mk('div', 'rail'); el.__rail = rail; side.appendChild(rail);
        side.appendChild(mk('div', 'elbow-bl'));
        frame.appendChild(side);
        var body = mk('div', 'body');
        var dyn = mk('div'); dyn.style.cssText = 'display:flex;flex-direction:column;gap:10px'; el.__dyn = dyn;
        body.appendChild(dyn);
        body.appendChild(buildViewer(el, s));
        var dynC = mk('div'); dynC.style.cssText = 'display:flex;flex-direction:column;gap:10px'; el.__dynC = dynC;
        body.appendChild(dynC);   // consensus document sits BELOW the viewscreen
        frame.appendChild(body);
        el.appendChild(frame);
        el.__mounted = 1;
    }

    // Update only the live numbers (runs once per second), leaving the
    // viewscreen and frame untouched so the embedded feed keeps running.
    function refresh(el, s) {
        if (!el.__mounted) mount(el, s);
        var d = K.data() || {}, P = d.parameters || {}, c = counts(d);
        // Rail pills double as node-type FILTERS for the roster below. Sensors =
        // the full list (no filter); the active filter pill is outlined. The rail
        // rebuilds every second, so re-apply the active state each refresh.
        var rail = el.__rail; rail.innerHTML = '';
        var mixTotal = c.layers.reduce(add, 0) || (c.byType.mix || 0);
        [['Sensors', c.total, null], ['Gateway', c.byType.gateway || 0, 'gateway'], ['Mix net', mixTotal, 'mix'],
        ['Service', c.byType.service || 0, 'service'], ['Storage', c.byType.storage || 0, 'storage'], ['Dir-auth', c.byType.dirauth || 0, 'dirauth']].forEach(function (r, i) {
            var active = (el.__typeFilter || null) === r[2];
            var p = mk('div', 'pill' + (active ? ' selp' : ''), r[0] + ' ' + r[1]); p.style.background = s.pills[i % s.pills.length];
            p.addEventListener('click', function () { el.__typeFilter = r[2]; refresh(el, s); });
            rail.appendChild(p);
        });
        var now = new Date(), utc = now.toISOString().slice(0, 19).replace('T', ' ');
        var sd = (41000 + (now.getTime() / 8.64e7 % 1000)).toFixed(1);
        el.__sub.innerHTML = 'Stardate ' + sd + '<br>' + utc + ' UTC' + (d.epoch != null ? '<br>Epoch ' + d.epoch : '');

        var dyn = el.__dyn; dyn.innerHTML = '';
        var dynC = el.__dynC; dynC.innerHTML = '';
        var row = mk('div', 'row');
        var cells = [['Gateways', c.byType.gateway || 0]];
        c.layers.forEach(function (n, i) { cells.push(['Mix L' + (i + 1), n]); });
        cells.push(['Service', c.byType.service || 0]); cells.push(['Storage', c.byType.storage || 0]); cells.push(['Dir-auth', c.byType.dirauth || 0]);
        cells.forEach(function (cd, i) { var cell = mk('div', 'cell'); cell.style.background = s.pills[i % s.pills.length]; cell.appendChild(mk('span', 'n', String(cd[1]))); cell.appendChild(mk('span', 'l', cd[0])); row.appendChild(cell); });
        dyn.appendChild(row);

        var sp = mk('div', 'panel'); sp.appendChild(mk('h3', null, 'Node Status'));
        var srow = mk('div', 'row');
        [['Operational', 'ok'], ['Reachable / out', 'out'], ['Down', 'down'], ['Unknown', 'unknown']].forEach(function (st) {
            var cell = mk('div', 'cell'); cell.style.background = STATUS_COL[st[1]];
            cell.appendChild(mk('span', 'n', String(c.byStatus[st[1]] || 0))); cell.appendChild(mk('span', 'l', st[0]));
            if (st[1] === 'down' && (c.byStatus.down || 0) > 0) cell.className += ' blink';
            srow.appendChild(cell);
        });
        sp.appendChild(srow); dyn.appendChild(sp);
        // dyn holds only the top stats (cells + status); the viewscreen sits above
        // dynC, and the roster / selected node / consensus / Loopix all go BELOW
        // the viewscreen (dynC), with Loopix parameters last.

        // Node Roster - filtered by the active rail type (full list by default).
        // Clicking a node shows its detail in the board; selection is kept by a
        // {idx,name,type} key so colliding names (e.g. a dirauth sharing a mix's
        // name) stay distinct and are all listed and selectable.
        var rp = mk('div', 'panel');
        rp.appendChild(mk('h3', null, 'Node Roster' + (el.__typeFilter ? ' - ' + el.__typeFilter : '')));
        var roster = mk('div', 'roster');
        var list = (d.nodes || []).map(function (n, idx) { return { n: n, idx: idx }; })
            .filter(function (e) { return !el.__typeFilter || e.n.type === el.__typeFilter; })
            .sort(function (a, b) { return (a.n.type + a.n.name).localeCompare(b.n.type + b.n.name); });
        if (!list.length) roster.appendChild(mk('div', 'hint', 'No nodes of this type.'));
        list.forEach(function (e) {
            var n = e.n, sk = el.__sel, isSel = sk && sk.idx === e.idx && sk.name === n.name && sk.type === n.type;
            var item = mk('div', 'node' + (isSel ? ' sel' : '')); item.style.color = s.ink; item.style.background = 'rgba(255,255,255,0.06)';
            var dot = mk('span', 'dot'); dot.style.background = STATUS_COL[n.status] || '#8899aa'; if (n.status === 'down') dot.className += ' blink';
            item.appendChild(dot); item.appendChild(mk('span', null, n.name)); item.appendChild(mk('span', 'ntype', n.type));
            item.addEventListener('click', function () { el.__sel = { idx: e.idx, name: n.name, type: n.type }; refresh(el, s); });
            roster.appendChild(item);
        });
        rp.appendChild(roster); dynC.appendChild(rp);

        // Selected node detail - opened by a roster click, closed by its Close
        // button (or by selecting another node). Collision-safe lookup: verify
        // the stored index still points at the same node, else re-find by name+type.
        var np = mk('div', 'panel'); np.style.borderLeftColor = s.accent;
        var nhrow = mk('div'); nhrow.style.cssText = 'display:flex;align-items:center;gap:8px';
        var nh = mk('h3', null, 'Selected Node'); nh.style.color = s.accent; nh.style.margin = '0'; nhrow.appendChild(nh);
        var sel = el.__sel, sn = null;
        if (sel) {
            var at = (d.nodes || [])[sel.idx];
            if (at && at.name === sel.name && at.type === sel.type) sn = at;
            else (d.nodes || []).forEach(function (n) { if (!sn && n.name === sel.name && n.type === sel.type) sn = n; });
        }
        if (sn) {
            var closeB = mk('button', 'vbtn', 'Close'); closeB.style.marginLeft = 'auto'; closeB.style.padding = '4px 10px';
            closeB.addEventListener('click', function () { el.__sel = null; refresh(el, s); });
            nhrow.appendChild(closeB);
        }
        np.appendChild(nhrow);
        if (!sn) { np.appendChild(mk('div', 'hint', 'Select a node from the roster above.')); }
        else {
            nh.textContent = sn.name + ' (' + sn.type + ')';
            var det = sn.details || {}, g = sn.geo || {}, grid = mk('div', 'detail');
            grid.appendChild(kv('Type', sn.type));
            grid.appendChild(kv('Status', sn.status));
            grid.appendChild(kv('Mix layer', sn.layer == null ? '--' : sn.layer));
            grid.appendChild(kv('In consensus', sn.in_consensus ? 'yes' : 'no'));
            grid.appendChild(kv('Reachable', sn.reachable ? 'yes' : 'no'));
            grid.appendChild(kv('Latency', sn.latency_ms == null ? '--' : sn.latency_ms + ' ms'));
            grid.appendChild(kv('Hop count', sn.hop_count == null ? '--' : sn.hop_count));
            grid.appendChild(kv('Auth type', det.auth_type));
            grid.appendChild(kv('Location', g.label));
            grid.appendChild(kv('Address', (det.addresses || []).join(', ')));
            np.appendChild(grid);
        }
        dynC.appendChild(np);

        // Consensus document, styled as part of the LCARS board (below viewscreen).
        var cons = d.consensus || {};
        var cp = mk('div', 'panel'); cp.style.borderLeftColor = s.accent2;
        var ch = mk('h3', null, 'Consensus Document'); ch.style.color = s.accent2; cp.appendChild(ch);
        var cg = mk('div', 'detail');
        cg.appendChild(kv('Epoch', cons.epoch != null ? cons.epoch : d.epoch));
        cg.appendChild(kv('Genesis epoch', cons.genesis_epoch));
        cg.appendChild(kv('Epoch ends', d.epoch_end));
        cg.appendChild(kv('PKI version', cons.version));
        cg.appendChild(kv('Signature', cons.pki_signature_scheme));
        cg.appendChild(kv('Wire protocol', cons.wire));
        cg.appendChild(kv('Nodes', c.total));
        cg.appendChild(kv('Generated', d.generated_at));
        cp.appendChild(cg); dynC.appendChild(cp);

        // Loopix parameters - last, at the very bottom under the consensus.
        var pp = mk('div', 'panel'); pp.style.borderLeftColor = s.panel2;
        var h2 = mk('h3', null, 'Loopix Parameters'); h2.style.color = s.panel2; pp.appendChild(h2);
        var lam = [['lambdaP', P.LambdaP, s.pills[0]], ['lambdaL', P.LambdaL, s.pills[1]], ['lambdaD', P.LambdaD, s.pills[2]], ['lambdaM', P.LambdaM, s.pills[3]], ['lambdaG', P.LambdaG, s.pills[4]], ['lambdaR', P.LambdaR, s.pills[5 % s.pills.length]]];
        var lmax = 0; lam.forEach(function (x) { if (typeof x[1] === 'number' && x[1] > lmax) lmax = x[1]; });
        lam.forEach(function (x) { pp.appendChild(meter(x[0], x[1], lmax, x[2])); });
        if (typeof P.Mu === 'number') pp.appendChild(meter('Mu', P.Mu, P.Mu, s.accent));
        dynC.appendChild(pp);
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    SERIES.forEach(function (s) {
        var el = mk('div', 'lcx'); el.id = s.id + '-overlay'; document.body.appendChild(el);
        var timer = 0;
        K.on('data', function () { if (el.__running) refresh(el, s); });
        window.KATZEN_OVERLAYS.push({
            id: s.id, name: s.name, el: el,
            onShow: function () {
                el.__running = true; refresh(el, s);
                if (!el.__viewId && el.__ovs && el.__ovs.length) { el.__viewId = el.__ovs[(Math.random() * el.__ovs.length) | 0].id; if (el.__vsel) el.__vsel.value = el.__viewId; }
                if (el.__viewId && el.__scr) el.__scr.src = location.pathname + '?overlay=' + el.__viewId + '&mini=1';
                document.body.classList.add('lcars-active');   // node selection shows inside the board
                if (!timer) timer = setInterval(function () { refresh(el, s); }, 1000);
            },
            onHide: function () {
                el.__running = false; if (timer) { clearInterval(timer); timer = 0; }
                if (el.__scr) el.__scr.src = 'about:blank';   // stop the embedded feed while hidden
                document.body.classList.remove('lcars-active');
            }
        });
    });
})();
