(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // One LCARS-style status board per major Star Trek series. Homage styling
    // only; every number is the real live consensus. A shared builder is skinned
    // by a per-series palette/shape.
    var css = document.createElement('style');
    css.textContent =
        '.lcx{position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:auto;' +
        'letter-spacing:1px;padding:calc(max(12px, env(safe-area-inset-top)) + 96px) 12px 12px}' +
        '.lcx *{box-sizing:border-box}' +
        '.lcx .wrap{display:grid;grid-template-columns:150px 1fr;grid-gap:10px}' +
        '.lcx .side{display:flex;flex-direction:column;gap:8px}' +
        '.lcx .elbow{height:70px}' +
        '.lcx .pill{padding:12px 10px;color:#000;font-weight:700;font-size:12px;text-align:right;min-height:34px}' +
        '.lcx .main{display:flex;flex-direction:column;gap:10px;min-width:0}' +
        '.lcx .head{display:flex;align-items:flex-end;gap:10px;padding-bottom:6px}' +
        '.lcx .title{font-size:22px;font-weight:800;line-height:1}' +
        '.lcx .sub{font-size:12px;margin-left:auto;text-align:right;line-height:1.4}' +
        '.lcx .row{display:flex;gap:8px;flex-wrap:wrap}' +
        '.lcx .cell{padding:10px 12px;color:#000;font-weight:700;min-width:104px;flex:1 1 104px}' +
        '.lcx .cell .n{font-size:26px;line-height:1;display:block}' +
        '.lcx .cell .l{font-size:10.5px;opacity:0.85}' +
        '.lcx .panel{padding:6px 0 6px 12px}' +
        '.lcx .panel h3{margin:0 0 6px;font-size:13px;font-weight:800}' +
        '.lcx .meter{display:grid;grid-template-columns:64px 1fr 60px;gap:6px;align-items:center;margin:3px 0;font-size:11px}' +
        '.lcx .track{height:12px;background:rgba(255,255,255,0.08);border-radius:6px;overflow:hidden}' +
        '.lcx .fill{height:100%;border-radius:6px}' +
        '.lcx .roster{display:flex;flex-wrap:wrap;gap:5px}' +
        '.lcx .node{display:flex;align-items:center;gap:5px;font-size:10px;border-radius:10px;padding:2px 7px 2px 5px}' +
        '.lcx .dot{width:9px;height:9px;border-radius:50%}' +
        '.lcx .blink{animation:lcxblink 1.3s steps(1) infinite}' +
        '@keyframes lcxblink{50%{opacity:0.25}}' +
        '@media (max-width:600px){.lcx .wrap{grid-template-columns:70px 1fr}.lcx .title{font-size:16px}}';
    document.head.appendChild(css);

    function mk(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
    var STATUS_COL = { ok: '#66cc66', out: '#ffcc66', down: '#cc6666', unknown: '#8899aa' };

    // Per-series skins. shape: elbow corner radius / pill radius; upper: caps.
    var SERIES = [
        { id: 'lcarstos', name: 'LCARS - TOS', title: 'U.S.S. Enterprise NCC-1701', bg: '#050505', ink: '#f0c869', accent: '#c9432e', accent2: '#3f6fb0', pills: ['#c9432e', '#e8b84b', '#3f6fb0', '#c98a3a', '#8aa63a', '#c9432e'], panel2: '#3f6fb0', corner: '3px', pill: '2px', font: '"Courier New",monospace', upper: true },
        { id: 'lcarstng', name: 'LCARS - TNG', title: 'Katzenpost Mixnet', bg: '#000', ink: '#ffcc99', accent: '#ff9966', accent2: '#cc99cc', pills: ['#cc99cc', '#9999ff', '#ffcc66', '#cc6666', '#ffcc99', '#ff9966'], panel2: '#9999ff', corner: '44px', pill: '16px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsds9', name: 'LCARS - DS9 (Cardassian)', title: 'Deep Space Operations', bg: '#0a0805', ink: '#d8b884', accent: '#b87333', accent2: '#7a9a6a', pills: ['#b87333', '#9a7b4f', '#7a9a6a', '#a85a2a', '#c9a05a', '#6a5a3a'], panel2: '#7a9a6a', corner: '10px', pill: '4px', font: 'Georgia,serif', upper: true },
        { id: 'lcarsvoy', name: 'LCARS - Voyager', title: 'U.S.S. Voyager NCC-74656', bg: '#000', ink: '#cdd6ff', accent: '#9aa6ff', accent2: '#cc99cc', pills: ['#9aa6ff', '#cc99cc', '#99cccc', '#ccaa99', '#aabbff', '#8899ee'], panel2: '#99cccc', corner: '40px', pill: '14px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsent', name: 'LCARS - Enterprise NX', title: 'Enterprise NX-01', bg: '#04070a', ink: '#a8c4e0', accent: '#6699cc', accent2: '#88a0b0', pills: ['#6699cc', '#7f8fa0', '#5a7a9a', '#8aa0b8', '#4a6a8a', '#6a8aa8'], panel2: '#88a0b0', corner: '6px', pill: '3px', font: '"Courier New",monospace', upper: false },
        { id: 'lcarsdis', name: 'LCARS - Discovery', title: 'U.S.S. Discovery NCC-1031', bg: '#02060c', ink: '#bfe8ff', accent: '#33ccff', accent2: '#7fd0ff', pills: ['#33ccff', '#7fd0ff', '#4da6ff', '#a0e0ff', '#2b9fe0', '#5fc0ff'], panel2: '#7fd0ff', corner: '20px', pill: '10px', font: '"Segoe UI",Arial,sans-serif', upper: false },
        { id: 'lcarspic', name: 'LCARS - Picard', title: 'La Sirena', bg: '#060606', ink: '#d9c4a8', accent: '#d98a3d', accent2: '#3a6ea5', pills: ['#d98a3d', '#3a6ea5', '#b0894f', '#4a7ab0', '#c07a35', '#5a6a7a'], panel2: '#3a6ea5', corner: '2px', pill: '2px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarsld', name: 'LCARS - Lower Decks', title: 'U.S.S. Cerritos NCC-75567', bg: '#000', ink: '#ffe08a', accent: '#ff8800', accent2: '#ffcc00', pills: ['#ff8800', '#ffcc00', '#ff5599', '#66ccff', '#88dd44', '#ff8800'], panel2: '#ff5599', corner: '44px', pill: '18px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarspro', name: 'LCARS - Prodigy', title: 'U.S.S. Protostar NX-76884', bg: '#03040a', ink: '#c8e0ff', accent: '#00e5ff', accent2: '#ff5db1', pills: ['#00e5ff', '#ff5db1', '#8a5bff', '#00d29a', '#ffb454', '#00e5ff'], panel2: '#8a5bff', corner: '24px', pill: '12px', font: 'Arial,Helvetica,sans-serif', upper: true },
        { id: 'lcarssnw', name: 'LCARS - Strange New Worlds', title: 'U.S.S. Enterprise NCC-1701', bg: '#040404', ink: '#e6cf8a', accent: '#d13b2f', accent2: '#c79a3a', pills: ['#d13b2f', '#c79a3a', '#3f6fb0', '#c98a3a', '#b0b0b0', '#d13b2f'], panel2: '#3f6fb0', corner: '16px', pill: '8px', font: '"Helvetica Neue",Arial,sans-serif', upper: true }
    ];

    function counts(d) {
        var byType = {}, byStatus = { ok: 0, out: 0, down: 0, unknown: 0 };
        (d.nodes || []).forEach(function (n) { byType[n.type] = (byType[n.type] || 0) + 1; byStatus[n.status] = (byStatus[n.status] || 0) + 1; });
        return { byType: byType, byStatus: byStatus, layers: (d.layers || []).map(function (l) { return l.length; }), total: (d.nodes || []).length };
    }
    function meter(label, val, max, color) {
        var row = mk('div', 'meter'); row.appendChild(mk('span', null, label));
        var track = mk('div', 'track'), fill = mk('div', 'fill');
        fill.style.width = (max > 0 ? Math.max(2, Math.min(100, val / max * 100)) : 2) + '%'; fill.style.background = color;
        track.appendChild(fill); row.appendChild(track);
        row.appendChild(mk('span', null, (val != null ? (+val).toPrecision(3) : '--'))); return row;
    }

    function build(el, s) {
        var d = K.data() || {}, P = d.parameters || {}, c = counts(d);
        el.style.background = s.bg; el.style.color = s.ink; el.style.fontFamily = s.font;
        el.style.textTransform = s.upper ? 'uppercase' : 'none';
        el.innerHTML = '';
        var wrap = mk('div', 'wrap');
        var side = mk('div', 'side');
        var elbow = mk('div', 'elbow'); elbow.style.background = s.accent;
        elbow.style.borderTopLeftRadius = s.corner; elbow.style.borderBottomLeftRadius = s.pill;
        side.appendChild(elbow);
        var rail = [['SENSORS', c.total], ['GATEWAY', c.byType.gateway || 0], ['MIX NET', c.layers.reduce(function (a, b) { return a + b; }, 0) || (c.byType.mix || 0)],
        ['SERVICE', c.byType.service || 0], ['STORAGE', c.byType.storage || 0], ['DIR-AUTH', c.byType.dirauth || 0], ['SYS-47', ''], ['LCARS', '']];
        rail.forEach(function (r, i) { var p = mk('div', 'pill', r[1] === '' ? r[0] : (r[0] + ' ' + r[1])); p.style.background = s.pills[i % s.pills.length]; p.style.borderRadius = s.pill; side.appendChild(p); });
        wrap.appendChild(side);

        var main = mk('div', 'main');
        var head = mk('div', 'head'); head.style.borderBottom = '3px solid ' + s.accent;
        var t = mk('div', 'title', s.title); t.style.color = s.accent; head.appendChild(t);
        var sub = mk('div', 'sub'); sub.style.color = s.accent2;
        var now = new Date(), utc = now.toISOString().slice(0, 19).replace('T', ' ');
        var sd = (41000 + (now.getTime() / 8.64e7 % 1000)).toFixed(1);
        sub.innerHTML = 'Stardate ' + sd + '<br>' + utc + ' UTC' + (d.epoch != null ? '<br>Epoch ' + d.epoch : '');
        head.appendChild(sub); main.appendChild(head);

        var row = mk('div', 'row');
        var cells = [['Gateways', c.byType.gateway || 0]];
        c.layers.forEach(function (n, i) { cells.push(['Mix L' + (i + 1), n]); });
        cells.push(['Service', c.byType.service || 0]); cells.push(['Storage', c.byType.storage || 0]); cells.push(['Dir-auth', c.byType.dirauth || 0]);
        cells.forEach(function (cd, i) { var cell = mk('div', 'cell'); cell.style.background = s.pills[i % s.pills.length]; cell.style.borderRadius = s.pill; cell.appendChild(mk('span', 'n', String(cd[1]))); cell.appendChild(mk('span', 'l', cd[0])); row.appendChild(cell); });
        main.appendChild(row);

        var sp = mk('div', 'panel'); sp.style.borderLeft = '14px solid ' + s.accent2; sp.style.borderRadius = '0 0 0 ' + s.pill;
        var h1 = mk('h3', null, 'Node Status'); h1.style.color = s.accent2; sp.appendChild(h1);
        var srow = mk('div', 'row');
        [['Operational', 'ok'], ['Reachable / out', 'out'], ['Down', 'down'], ['Unknown', 'unknown']].forEach(function (st) {
            var cell = mk('div', 'cell'); cell.style.background = STATUS_COL[st[1]]; cell.style.borderRadius = s.pill;
            cell.appendChild(mk('span', 'n', String(c.byStatus[st[1]] || 0))); cell.appendChild(mk('span', 'l', st[0]));
            if (st[1] === 'down' && (c.byStatus.down || 0) > 0) cell.className += ' blink';
            srow.appendChild(cell);
        });
        sp.appendChild(srow); main.appendChild(sp);

        var pp = mk('div', 'panel'); pp.style.borderLeft = '14px solid ' + s.panel2; pp.style.borderRadius = '0 0 0 ' + s.pill;
        var h2 = mk('h3', null, 'Loopix Parameters'); h2.style.color = s.panel2; pp.appendChild(h2);
        var lam = [['lambdaP', P.LambdaP, s.pills[0]], ['lambdaL', P.LambdaL, s.pills[1]], ['lambdaD', P.LambdaD, s.pills[2]], ['lambdaM', P.LambdaM, s.pills[3]], ['lambdaG', P.LambdaG, s.pills[4]], ['lambdaR', P.LambdaR, s.pills[5 % s.pills.length]]];
        var lmax = 0; lam.forEach(function (x) { if (typeof x[1] === 'number' && x[1] > lmax) lmax = x[1]; });
        lam.forEach(function (x) { pp.appendChild(meter(x[0], x[1], lmax, x[2])); });
        if (typeof P.Mu === 'number') pp.appendChild(meter('Mu', P.Mu, P.Mu, s.accent));
        main.appendChild(pp);

        var rp = mk('div', 'panel'); rp.style.borderLeft = '14px solid ' + s.accent; rp.style.borderRadius = '0 0 0 ' + s.pill;
        var h3 = mk('h3', null, 'Node Roster'); h3.style.color = s.accent; rp.appendChild(h3);
        var roster = mk('div', 'roster');
        (d.nodes || []).slice().sort(function (a, b) { return (a.type + a.name).localeCompare(b.type + b.name); }).forEach(function (n) {
            var item = mk('div', 'node'); item.style.color = s.ink; item.style.background = 'rgba(255,255,255,0.06)';
            var dot = mk('span', 'dot'); dot.style.background = STATUS_COL[n.status] || '#8899aa'; if (n.status === 'down') dot.className += ' blink';
            item.appendChild(dot); item.appendChild(mk('span', null, n.name)); roster.appendChild(item);
        });
        rp.appendChild(roster); main.appendChild(rp);
        wrap.appendChild(main); el.appendChild(wrap);
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    SERIES.forEach(function (s) {
        var el = mk('div', 'lcx'); el.id = s.id + '-overlay'; document.body.appendChild(el);
        var running = false, timer = 0;
        function render() { build(el, s); }
        K.on('data', function () { if (running) render(); });
        window.KATZEN_OVERLAYS.push({
            id: s.id, name: s.name, el: el,
            onShow: function () { running = true; render(); if (!timer) timer = setInterval(render, 1000); },
            onHide: function () { running = false; if (timer) { clearInterval(timer); timer = 0; } }
        });
    });
})();
