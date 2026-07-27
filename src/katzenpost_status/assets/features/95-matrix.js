(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var TYPE_ORDER = { dirauth: 0, gateway: 1, mix: 2, service: 3, storage: 4, out: 5 };

    var el = document.createElement('div');
    el.id = 'matrix-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'box-sizing:border-box;padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    el.appendChild(canvas);
    var tip = document.createElement('div');
    tip.style.cssText = 'position:fixed;z-index:26;display:none;pointer-events:none;' +
        'background:rgba(8,12,20,0.95);border:1px solid rgba(255,180,84,0.4);color:#cdd6df;' +
        'font:11px/1.4 monospace;padding:5px 8px;border-radius:5px';
    el.appendChild(tip);
    document.body.appendChild(el);
    var ctx = canvas.getContext('2d');

    var PAD_T = 104, PAD_B = 40, GAP = 12;   // PAD_T clears the title and the top controls
    var cells = [];   // filled-cell hit records: {x,y,w,h,a,b}

    function orderKey(d) {
        var t = TYPE_ORDER[d.type] == null ? 9 : TYPE_ORDER[d.type];
        var ly = (d.type === 'mix' && typeof d.layer === 'number') ? d.layer : 0;
        return { t: t, ly: ly, name: d.name || '' };
    }

    function collect() {
        var list = K.nodes().map(function (o) { return o.data; }).filter(Boolean);
        list.sort(function (a, b) {
            var ka = orderKey(a), kb = orderKey(b);
            return (ka.t - kb.t) || (ka.ly - kb.ly) || ka.name.localeCompare(kb.name);
        });
        return list;
    }

    function buildAdj(nodes) {
        var n = nodes.length, i, j;
        var adj = [];
        for (i = 0; i < n; i++) { adj.push(new Array(n)); }
        function connect(a, b) { if (a !== b) { adj[a][b] = true; adj[b][a] = true; } }
        function hasCap(d, cap) {
            var c = (d.details && d.details.capabilities) || [];
            return c.indexOf(cap) >= 0;
        }
        function layerOf(d) { return (typeof d.layer === 'number') ? d.layer : 0; }

        var lastMix = null;
        for (i = 0; i < n; i++) {
            if (nodes[i].type === 'mix') {
                var ly = layerOf(nodes[i]);
                if (lastMix === null || ly > lastMix) lastMix = ly;
            }
        }

        for (i = 0; i < n; i++) {
            var di = nodes[i];
            for (j = i + 1; j < n; j++) {
                var dj = nodes[j];
                if (di.type === 'dirauth' || dj.type === 'dirauth') { connect(i, j); continue; }
                if ((di.type === 'gateway' && dj.type === 'mix' && layerOf(dj) === 0) ||
                    (dj.type === 'gateway' && di.type === 'mix' && layerOf(di) === 0)) { connect(i, j); continue; }
                if (di.type === 'mix' && dj.type === 'mix' &&
                    Math.abs(layerOf(di) - layerOf(dj)) === 1) { connect(i, j); continue; }
                if (lastMix !== null &&
                    ((di.type === 'mix' && layerOf(di) === lastMix && dj.type === 'service') ||
                     (dj.type === 'mix' && layerOf(dj) === lastMix && di.type === 'service'))) { connect(i, j); continue; }
                if ((di.type === 'service' && hasCap(di, 'courier') && dj.type === 'storage') ||
                    (dj.type === 'service' && hasCap(dj, 'courier') && di.type === 'storage')) { connect(i, j); continue; }
                if (di.type === 'storage' && dj.type === 'storage') { connect(i, j); continue; }
            }
        }
        return adj;
    }

    function groups(nodes) {
        var g = [], start = 0, i;
        for (i = 1; i <= nodes.length; i++) {
            if (i === nodes.length || nodes[i].type !== nodes[start].type) {
                g.push({ type: nodes[start].type, start: start, end: i });
                start = i;
            }
        }
        return g;
    }

    function layout(n) {
        var vw = el.clientWidth || window.innerWidth, vh = el.clientHeight || window.innerHeight;
        var padL = Math.max(72, Math.min(150, Math.floor(vw * 0.30)));
        if (!n) return { vw: vw, vh: vh, cell: 0, padL: padL };
        var availW = vw - padL - 12, availH = vh - PAD_T - PAD_B;
        var cell = Math.max(3, Math.floor(Math.min(availW / n, availH / n)));
        return { vw: vw, vh: vh, cell: cell, padL: padL };
    }

    function draw() {
        if (!ctx) return;
        var nodes = collect();
        var n = nodes.length;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var L = layout(n);
        var W = L.vw, H = L.vh;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.textAlign = 'left';
        ctx.fillText('Connectivity matrix  (' + n + ' nodes)', 24, 16);

        cells = [];
        if (!n) {
            ctx.fillStyle = '#7b8e9d'; ctx.font = '12px monospace';
            ctx.fillText('No nodes in the current consensus.', 24, PAD_T);
            return;
        }

        var adj = buildAdj(nodes);
        var grp = groups(nodes);
        var padL = L.padL, cell = L.cell, gridW = cell * n;
        var showNames = cell >= 9;

        ctx.fillStyle = '#9fb3c2'; ctx.font = '10px monospace';
        ctx.textAlign = 'center'; ctx.textBaseline = 'bottom';
        grp.forEach(function (g) {
            var cx = padL + (g.start + g.end) / 2 * cell;
            ctx.fillText(g.type, cx, PAD_T - 4);
        });

        ctx.textBaseline = 'middle';
        if (showNames) {
            ctx.fillStyle = '#9fb3c2'; ctx.font = '10px monospace'; ctx.textAlign = 'right';
            nodes.forEach(function (d, ri) {
                var y = PAD_T + ri * cell + cell / 2;
                ctx.fillText(d.name || '', padL - 6, y);
            });
        } else {
            ctx.fillStyle = '#9fb3c2'; ctx.font = '10px monospace'; ctx.textAlign = 'right';
            grp.forEach(function (g) {
                var y = PAD_T + (g.start + g.end) / 2 * cell;
                ctx.fillText(g.type, padL - 6, y);
            });
        }

        var i, j;
        for (i = 0; i < n; i++) {
            for (j = 0; j < n; j++) {
                if (i === j || !adj[i][j]) continue;
                var x = padL + j * cell, y = PAD_T + i * cell;
                var dirauthPair = (nodes[i].type === 'dirauth' || nodes[j].type === 'dirauth');
                ctx.fillStyle = dirauthPair ? 'rgba(44,224,192,0.35)' : '#2ce0c0';
                ctx.fillRect(x, y, cell - (cell > 4 ? 1 : 0), cell - (cell > 4 ? 1 : 0));
                cells.push({ x: x, y: y, w: cell, h: cell, a: nodes[j].name || '', b: nodes[i].name || '' });
            }
        }

        ctx.strokeStyle = 'rgba(120,150,175,0.18)'; ctx.lineWidth = 1;
        grp.forEach(function (g) {
            if (g.start === 0) return;
            var p = g.start * cell;
            ctx.beginPath(); ctx.moveTo(padL + p, PAD_T); ctx.lineTo(padL + p, PAD_T + gridW); ctx.stroke();
            ctx.beginPath(); ctx.moveTo(padL, PAD_T + p); ctx.lineTo(padL + gridW, PAD_T + p); ctx.stroke();
        });
        ctx.strokeStyle = 'rgba(120,150,175,0.28)';
        ctx.strokeRect(padL + 0.5, PAD_T + 0.5, gridW, gridW);
    }

    canvas.addEventListener('pointermove', function (ev) {
        var rect = canvas.getBoundingClientRect();
        var mx = ev.clientX - rect.left, my = ev.clientY - rect.top, hit = null;
        for (var i = 0; i < cells.length; i++) {
            var c = cells[i];
            if (mx >= c.x && mx <= c.x + c.w && my >= c.y && my <= c.y + c.h) { hit = c; break; }
        }
        if (!hit) { tip.style.display = 'none'; return; }
        tip.textContent = hit.a + '  <->  ' + hit.b;
        tip.style.display = 'block';
        tip.style.left = Math.min(ev.clientX + 12, window.innerWidth - tip.offsetWidth - 8) + 'px';
        tip.style.top = (ev.clientY + 12) + 'px';
    });
    canvas.addEventListener('pointerleave', function () { tip.style.display = 'none'; });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'matrix', name: 'Matrix', el: el,
        onShow: function () { draw(); },
        onHide: function () { tip.style.display = 'none'; }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
