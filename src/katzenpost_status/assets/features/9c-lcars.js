(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // Full-screen overlay: an LCARS-style (Star Trek TNG) status board for the
    // mixnet, built from the live consensus. Homage styling; all data is real.
    var css = document.createElement('style');
    css.textContent =
        '#lcars-overlay{position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:auto;' +
        'font-family:Arial,Helvetica,sans-serif;text-transform:uppercase;letter-spacing:1px;color:#ffcc99;padding:12px}' +
        '#lcars-overlay *{box-sizing:border-box}' +
        '.lc-wrap{display:grid;grid-template-columns:150px 1fr;grid-gap:10px}' +
        '.lc-side{display:flex;flex-direction:column;gap:8px}' +
        '.lc-elbow{height:70px;background:#ff9966;border-top-left-radius:44px;border-bottom-left-radius:16px}' +
        '.lc-pill{border-radius:16px;padding:12px 10px;color:#000;font-weight:700;font-size:12px;text-align:right;min-height:34px}' +
        '.lc-main{display:flex;flex-direction:column;gap:10px;min-width:0}' +
        '.lc-head{display:flex;align-items:flex-end;gap:10px;border-bottom:3px solid #ff9966;padding-bottom:6px}' +
        '.lc-title{font-size:22px;font-weight:800;color:#ff9966;line-height:1}' +
        '.lc-sub{color:#cc99cc;font-size:12px;margin-left:auto;text-align:right;line-height:1.4}' +
        '.lc-bar{height:16px;border-radius:8px;flex:none}' +
        '.lc-row{display:flex;gap:8px;flex-wrap:wrap}' +
        '.lc-cell{border-radius:14px;padding:10px 12px;color:#000;font-weight:700;min-width:104px;flex:1 1 104px}' +
        '.lc-cell .n{font-size:26px;line-height:1;display:block}' +
        '.lc-cell .l{font-size:10.5px;opacity:0.85}' +
        '.lc-panel{border-left:14px solid #cc99cc;border-radius:0 0 0 14px;padding:6px 0 6px 12px;background:rgba(204,153,204,0.06)}' +
        '.lc-panel h3{margin:0 0 6px;color:#cc99cc;font-size:13px;font-weight:800}' +
        '.lc-meter{display:grid;grid-template-columns:64px 1fr 60px;gap:6px;align-items:center;margin:3px 0;font-size:11px}' +
        '.lc-track{height:12px;background:#20140a;border-radius:6px;overflow:hidden}' +
        '.lc-fill{height:100%;border-radius:6px}' +
        '.lc-roster{display:flex;flex-wrap:wrap;gap:5px}' +
        '.lc-node{display:flex;align-items:center;gap:5px;font-size:10px;color:#ffcc99;background:rgba(255,153,102,0.08);' +
        'border-radius:10px;padding:2px 7px 2px 5px}' +
        '.lc-dot{width:9px;height:9px;border-radius:50%}' +
        '.lc-blink{animation:lcblink 1.3s steps(1) infinite}' +
        '@keyframes lcblink{50%{opacity:0.25}}' +
        '@media (max-width:600px){.lc-wrap{grid-template-columns:70px 1fr}.lc-title{font-size:16px}}';
    document.head.appendChild(css);

    var el = document.createElement('div');
    el.id = 'lcars-overlay';
    document.body.appendChild(el);

    function mk(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
    var PILL_COLORS = ['#cc99cc', '#9999ff', '#ffcc66', '#cc6666', '#ffcc99', '#ff9966'];
    var STATUS_COL = { ok: '#66cc66', out: '#ffcc66', down: '#cc6666', unknown: '#8899aa' };

    var timer = 0, running = false;

    function counts(d) {
        var byType = {}, byStatus = { ok: 0, out: 0, down: 0, unknown: 0 };
        (d.nodes || []).forEach(function (n) {
            byType[n.type] = (byType[n.type] || 0) + 1;
            byStatus[n.status] = (byStatus[n.status] || 0) + 1;
        });
        var layers = (d.layers || []).map(function (l) { return l.length; });
        return { byType: byType, byStatus: byStatus, layers: layers, total: (d.nodes || []).length };
    }

    function meter(label, val, max, color) {
        var row = mk('div', 'lc-meter');
        row.appendChild(mk('span', null, label));
        var track = mk('div', 'lc-track'), fill = mk('div', 'lc-fill');
        var pct = max > 0 ? Math.max(2, Math.min(100, val / max * 100)) : 2;
        fill.style.width = pct + '%'; fill.style.background = color;
        track.appendChild(fill); row.appendChild(track);
        row.appendChild(mk('span', null, (val != null ? (+val).toPrecision(3) : '--')));
        return row;
    }

    function render() {
        var d = K.data() || {}, P = d.parameters || {}, c = counts(d);
        el.innerHTML = '';
        var wrap = mk('div', 'lc-wrap');

        // Left LCARS rail
        var side = mk('div', 'lc-side');
        side.appendChild(mk('div', 'lc-elbow'));
        var rail = [
            ['SENSORS', c.total], ['GATEWAY', c.byType.gateway || 0], ['MIX NET', (c.layers.reduce(function (a, b) { return a + b; }, 0)) || (c.byType.mix || 0)],
            ['SERVICE', c.byType.service || 0], ['STORAGE', c.byType.storage || 0], ['DIR-AUTH', c.byType.dirauth || 0], ['SYS-47', ''], ['LCARS', '']
        ];
        rail.forEach(function (r, i) {
            var p = mk('div', 'lc-pill', r[1] === '' ? r[0] : (r[0] + ' ' + r[1]));
            p.style.background = PILL_COLORS[i % PILL_COLORS.length];
            side.appendChild(p);
        });
        wrap.appendChild(side);

        // Main column
        var main = mk('div', 'lc-main');
        var head = mk('div', 'lc-head');
        head.appendChild(mk('div', 'lc-title', 'Katzenpost Mixnet'));
        var sub = mk('div', 'lc-sub');
        var now = new Date();
        var utc = now.toISOString().slice(0, 19).replace('T', ' ');
        var sd = (41000 + (now.getTime() / 8.64e7 % 1000)).toFixed(1);
        sub.innerHTML = 'Stardate ' + sd + '<br>' + utc + ' UTC' +
            (d.epoch != null ? '<br>Epoch ' + d.epoch : '');
        head.appendChild(sub);
        main.appendChild(head);

        // Group count cells
        var row = mk('div', 'lc-row');
        var cells = [['Gateways', c.byType.gateway || 0, '#2ec4b6']];
        c.layers.forEach(function (n, i) { cells.push(['Mix L' + (i + 1), n, ['#4d8bf0', '#9b5de5', '#ff5d8f', '#6ce0b0'][i % 4]]); });
        cells.push(['Service', c.byType.service || 0, '#ff8f3f']);
        cells.push(['Storage', c.byType.storage || 0, '#00d2a0']);
        cells.push(['Dir-auth', c.byType.dirauth || 0, '#ffd23f']);
        cells.forEach(function (cd) {
            var cell = mk('div', 'lc-cell'); cell.style.background = cd[2];
            cell.appendChild(mk('span', 'n', String(cd[1])));
            cell.appendChild(mk('span', 'l', cd[0]));
            row.appendChild(cell);
        });
        main.appendChild(row);

        // Status panel
        var sp = mk('div', 'lc-panel'); sp.appendChild(mk('h3', null, 'Node Status'));
        var srow = mk('div', 'lc-row');
        [['Operational', 'ok'], ['Reachable / out', 'out'], ['Down', 'down'], ['Unknown', 'unknown']].forEach(function (s) {
            var cell = mk('div', 'lc-cell'); cell.style.background = STATUS_COL[s[1]];
            cell.appendChild(mk('span', 'n', String(c.byStatus[s[1]] || 0)));
            cell.appendChild(mk('span', 'l', s[0]));
            if (s[1] === 'down' && (c.byStatus.down || 0) > 0) cell.className += ' lc-blink';
            srow.appendChild(cell);
        });
        sp.appendChild(srow); main.appendChild(sp);

        // Loopix parameters panel
        var pp = mk('div', 'lc-panel'); pp.style.borderLeftColor = '#9999ff';
        var h = mk('h3', null, 'Loopix Parameters'); h.style.color = '#9999ff'; pp.appendChild(h);
        var lam = [['lambdaP', P.LambdaP, '#00f3ff'], ['lambdaL', P.LambdaL, '#ffaa00'], ['lambdaD', P.LambdaD, '#ff00aa'],
        ['lambdaM', P.LambdaM, '#8338ec'], ['lambdaG', P.LambdaG, '#00ff88'], ['lambdaR', P.LambdaR, '#66ccff']];
        var lmax = 0; lam.forEach(function (x) { if (typeof x[1] === 'number' && x[1] > lmax) lmax = x[1]; });
        lam.forEach(function (x) { pp.appendChild(meter(x[0], x[1], lmax, x[2])); });
        if (typeof P.Mu === 'number') pp.appendChild(meter('Mu', P.Mu, P.Mu, '#ffcc99'));
        main.appendChild(pp);

        // Roster
        var rp = mk('div', 'lc-panel'); rp.style.borderLeftColor = '#ff9966';
        var rh = mk('h3', null, 'Node Roster'); rh.style.color = '#ff9966'; rp.appendChild(rh);
        var roster = mk('div', 'lc-roster');
        (d.nodes || []).slice().sort(function (a, b) { return (a.type + a.name).localeCompare(b.type + b.name); })
            .forEach(function (n) {
                var item = mk('div', 'lc-node');
                var dot = mk('span', 'lc-dot'); dot.style.background = STATUS_COL[n.status] || '#8899aa';
                if (n.status === 'down') dot.className += ' lc-blink';
                item.appendChild(dot); item.appendChild(mk('span', null, n.name));
                roster.appendChild(item);
            });
        rp.appendChild(roster); main.appendChild(rp);

        wrap.appendChild(main);
        el.appendChild(wrap);
    }

    K.on('data', function () { if (running) render(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'lcars', name: 'LCARS panel', el: el,
        onShow: function () { running = true; render(); if (!timer) timer = setInterval(render, 1000); },
        onHide: function () { running = false; if (timer) { clearInterval(timer); timer = 0; } }
    });
})();
