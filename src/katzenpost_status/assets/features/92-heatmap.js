(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var TYPE_ORDER = { dirauth: 0, gateway: 1, mix: 2, service: 3, storage: 4, out: 5 };
    function base() { return (K.dataUrl() || '').replace(/\.data\.json(\?.*)?$/, '-history/'); }

    var el = document.createElement('div');
    el.id = 'heatmap-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch;box-sizing:border-box;' +
        'padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block';
    el.appendChild(canvas);
    var tip = document.createElement('div');
    tip.style.cssText = 'position:fixed;z-index:26;display:none;pointer-events:none;' +
        'background:rgba(8,12,20,0.95);border:1px solid rgba(255,180,84,0.4);color:#cdd6df;' +
        'font:11px/1.4 monospace;padding:5px 8px;border-radius:5px';
    el.appendChild(tip);
    document.body.appendChild(el);
    if (window.KATZEN_CRT) window.KATZEN_CRT(el);
    var ctx = canvas.getContext('2d');

    var epochs = [];       // [{epoch, time, statusByName}]
    var rows = [];         // [{name, type}]
    var cells = [];        // draw record for hit-testing: {x,y,w,h,name,epoch,status,time}
    var loaded = false, loading = false;

    var PAD_T = 104, PAD_B = 44, GAP = 1;   // PAD_T clears the title, legend and top controls

    function statusHex(s) {
        if (s === 'absent') return '#11161d';
        try { return K.hex6(K.statusColor(s)); } catch (e) { return '#556677'; }
    }

    var RIGHT = 18;   // right margin (also clears a vertical scrollbar)
    function layout() {
        var vw = el.clientWidth || window.innerWidth, vh = el.clientHeight || window.innerHeight;
        var padL = Math.max(72, Math.min(130, Math.floor(vw * 0.32)));
        var nRows = rows.length, availW = vw - padL - RIGHT, minCw = 8;
        var maxCols = Math.max(1, Math.floor((availW + GAP) / (minCw + GAP)));
        var eps = epochs, note = '';
        if (epochs.length > maxCols) { eps = epochs.slice(-maxCols); note = 'last ' + maxCols + ' of ' + epochs.length; }
        var nCols = eps.length;
        if (!nCols || !nRows) return { vw: vw, vh: vh, cw: 0, ch: 0, padL: padL, eps: eps, note: note };
        var cw = Math.max(minCw, Math.floor((availW - (nCols - 1) * GAP) / nCols));
        var ch = Math.max(9, Math.floor((vh - PAD_T - PAD_B - (nRows - 1) * GAP) / nRows));
        return { vw: vw, vh: vh, cw: cw, ch: ch, padL: padL, eps: eps, note: note };
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var L = layout();
        var eps = L.eps, nCols = eps.length, nRows = rows.length;
        var W = L.vw, H = Math.max(L.vh, PAD_T + PAD_B + nRows * (L.ch + GAP));
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H);
        ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        var padL = L.padL;
        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.fillText('Availability  -  nodes x epochs  (' + nRows + ' nodes, ' + epochs.length +
            ' epochs' + (L.note ? ', ' + L.note : '') + ')', padL, 16);

        if (!nCols || !nRows) {
            ctx.fillStyle = '#7b8e9d'; ctx.font = '12px monospace';
            ctx.fillText('Not enough history yet (need at least 2 epochs).', padL, PAD_T);
            return;
        }

        cells = [];
        ctx.font = '10px monospace'; ctx.textBaseline = 'middle';
        rows.forEach(function (r, ri) {
            var y = PAD_T + ri * (L.ch + GAP);
            ctx.fillStyle = '#9fb3c2'; ctx.textAlign = 'right';
            ctx.fillText(r.name, padL - 6, y + L.ch / 2);
            for (var ci = 0; ci < nCols; ci++) {
                var st = eps[ci].statusByName[r.name] || 'absent';
                var x = padL + ci * (L.cw + GAP);
                ctx.fillStyle = statusHex(st);
                ctx.fillRect(x, y, L.cw, L.ch);
                cells.push({ x: x, y: y, w: L.cw, h: L.ch, name: r.name, epoch: eps[ci].epoch, status: st, time: eps[ci].time });
            }
        });
        ctx.fillStyle = '#59707f'; ctx.font = '9px monospace'; ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        var step = Math.max(1, Math.ceil(nCols / 8)), yLab = PAD_T + nRows * (L.ch + GAP) + 4;
        for (var ci = 0; ci < nCols; ci++) {
            if (ci % step && ci !== nCols - 1) continue;
            var x = padL + ci * (L.cw + GAP) + L.cw / 2;
            ctx.fillText('#' + eps[ci].epoch, x, yLab);
        }
        ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
        var items = [['ok', 'in consensus'], ['out', 'reachable, not in'], ['down', 'down'],
            ['unknown', 'addr unknown'], ['absent', 'not present']];
        var lx = padL;
        items.forEach(function (it) {
            ctx.fillStyle = statusHex(it[0]); ctx.fillRect(lx, 40, 10, 10);
            ctx.fillStyle = '#8ba0b0'; ctx.font = '10px monospace';
            ctx.fillText(it[1], lx + 14, 45);
            lx += 16 + ctx.measureText(it[1]).width + 16;
        });
    }

    canvas.addEventListener('pointermove', function (ev) {
        var rect = canvas.getBoundingClientRect();
        var mx = ev.clientX - rect.left, my = ev.clientY - rect.top, hitC = null;
        for (var i = 0; i < cells.length; i++) {
            var c = cells[i];
            if (mx >= c.x && mx <= c.x + c.w && my >= c.y && my <= c.y + c.h) { hitC = c; break; }
        }
        if (!hitC) { tip.style.display = 'none'; return; }
        tip.textContent = hitC.name + '  #' + hitC.epoch + '  ' + hitC.status +
            (hitC.time ? '  (' + hitC.time + ' UTC)' : '');
        tip.style.display = 'block';
        tip.style.left = Math.min(ev.clientX + 12, window.innerWidth - tip.offsetWidth - 8) + 'px';
        tip.style.top = (ev.clientY + 12) + 'px';
    });
    canvas.addEventListener('pointerleave', function () { tip.style.display = 'none'; });
    canvas.addEventListener('click', function (ev) {
        var rect = canvas.getBoundingClientRect(), mx = ev.clientX - rect.left, my = ev.clientY - rect.top;
        for (var i = 0; i < cells.length; i++) {
            var c = cells[i];
            if (mx >= c.x && mx <= c.x + c.w && my >= c.y && my <= c.y + c.h) {
                if (K.reselect) K.reselect(c.name); return;
            }
        }
    });

    function build(index) {
        var evs = (index || []).filter(function (e) { return e && e.epoch; })
            .sort(function (a, b) { return a.epoch - b.epoch; });
        epochs = evs.map(function (e) {
            var byName = {};
            (e.nodes || []).forEach(function (n) { byName[n.name] = n.status; });
            return { epoch: e.epoch, time: e.epoch_time_str || '', statusByName: byName };
        });
        var seen = {}, list = [];
        evs.forEach(function (e) {
            (e.nodes || []).forEach(function (n) {
                if (!seen[n.name]) { seen[n.name] = true; list.push({ name: n.name, type: n.type || 'mix' }); }
            });
        });
        list.sort(function (a, b) {
            var d = (TYPE_ORDER[a.type] == null ? 9 : TYPE_ORDER[a.type]) -
                (TYPE_ORDER[b.type] == null ? 9 : TYPE_ORDER[b.type]);
            return d || a.name.localeCompare(b.name);
        });
        rows = list;
    }

    function load() {
        if (loading) return;
        loading = true;
        fetch(base() + 'index.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (idx) { build(idx || []); loaded = true; loading = false; draw(); })
            .catch(function () { loading = false; draw(); });
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'heatmap', name: 'Heatmap', el: el,
        onShow: function () { if (!loaded) load(); else draw(); },
        onHide: function () { tip.style.display = 'none'; }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (K.on) K.on('theme', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
