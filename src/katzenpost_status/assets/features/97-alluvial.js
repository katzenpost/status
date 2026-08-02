(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var MAXEP = 24;        // bound to the most recent epochs
    var STACK = ['ok', 'out', 'down', 'unknown'];   // ok bottom, unknown top
    function base() { return (K.dataUrl() || '').replace(/\.data\.json(\?.*)?$/, '-history/'); }

    var el = document.createElement('div');
    el.id = 'alluvial-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'box-sizing:border-box;padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    el.appendChild(canvas);
    document.body.appendChild(el);
    if (window.KATZEN_CRT) window.KATZEN_CRT(el);
    var ctx = canvas.getContext('2d');

    var series = [];       // [{epoch, counts:{ok,out,down,unknown}, total}]
    var loaded = false, loading = false, note = '';

    function statusHex(s) {
        try { return K.hex6(K.statusColor(s)); } catch (e) { return '#556677'; }
    }
    function countOf(e, s) {
        var by = (e.counts && e.counts.by_status) || {};
        return by[s] || 0;
    }
    function stackTotal(e) {
        var t = 0;
        for (var i = 0; i < STACK.length; i++) t += countOf(e, STACK[i]);
        return t;
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var W = el.clientWidth || window.innerWidth, H = el.clientHeight || window.innerHeight;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.fillText('Status over time', 24, 16);

        if (!loaded) {
            ctx.fillStyle = '#7b8e9d'; ctx.font = '12px monospace';
            ctx.fillText(loading ? 'Loading history...' : 'No history yet.', 24, 48);
            return;
        }
        if (series.length < 2) {
            ctx.fillStyle = '#7b8e9d'; ctx.font = '12px monospace';
            ctx.fillText('Not enough history yet (need at least 2 epochs).', 24, 48);
            return;
        }

        var L = 52, R = W - 24, T = 104, B = H - 54;   // T clears the top controls
        var n = series.length;
        var maxV = 1;
        series.forEach(function (s) { maxV = Math.max(maxV, stackTotal(s)); });
        var step = niceStep(maxV);
        var top = Math.ceil(maxV / step) * step;
        function px(i) { return L + (R - L) * (n === 1 ? 0.5 : i / (n - 1)); }
        function py(v) { return B - (B - T) * (v / top); }

        ctx.strokeStyle = 'rgba(120,150,175,0.18)'; ctx.lineWidth = 1;
        ctx.fillStyle = '#59707f'; ctx.font = '10px monospace'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
        for (var g = 0; g <= top; g += step) {
            var y = py(g);
            ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(R, y); ctx.stroke();
            ctx.fillText(g + '', L - 6, y);
        }
        ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        var xstep = Math.max(1, Math.ceil(n / 8));
        for (var i = 0; i < n; i++) {
            if (i % xstep && i !== n - 1) continue;
            ctx.fillText('#' + series[i].epoch, px(i), B + 6);
        }

        var lows = [];   // running baseline (bottom of the current band) per epoch
        for (var j = 0; j < n; j++) lows.push(0);
        STACK.forEach(function (st) {
            var highs = [];
            for (var k = 0; k < n; k++) highs.push(lows[k] + countOf(series[k], st));
            ctx.fillStyle = statusHex(st);
            ctx.beginPath();
            for (var a = 0; a < n; a++) { var x = px(a), y = py(highs[a]); if (a === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); }
            for (var b = n - 1; b >= 0; b--) { ctx.lineTo(px(b), py(lows[b])); }
            ctx.closePath();
            ctx.fill();
            lows = highs;
        });

        ctx.textBaseline = 'middle';
        var items = [['ok', 'ok (in consensus)'], ['out', 'out (reachable, not in consensus)'],
            ['down', 'down'], ['unknown', 'unknown']];
        var lx = 24;
        items.forEach(function (it) {
            ctx.fillStyle = statusHex(it[0]); ctx.fillRect(lx, 40, 10, 10);
            ctx.fillStyle = '#8ba0b0'; ctx.textAlign = 'left'; ctx.font = '10px monospace';
            ctx.fillText(it[1], lx + 14, 45);
            lx += 16 + ctx.measureText(it[1]).width + 16;
        });

        var latest = series[n - 1];
        ctx.fillStyle = '#7b8e9d'; ctx.font = '11px monospace'; ctx.textAlign = 'left'; ctx.textBaseline = 'top';
        ctx.fillText('latest #' + latest.epoch + ': ' + stackTotal(latest) + ' nodes' +
            (note ? '   (' + note + ')' : ''), 24, B + 26);
    }

    function niceStep(maxV) {
        var target = maxV / 5;
        var pow = Math.pow(10, Math.floor(Math.log(target) / Math.LN10));
        var cands = [1, 2, 5, 10];
        for (var i = 0; i < cands.length; i++) {
            var s = cands[i] * pow;
            if (s >= target) return Math.max(1, Math.round(s));
        }
        return Math.max(1, Math.round(10 * pow));
    }

    function load() {
        if (loading) return; loading = true; draw();
        fetch(base() + 'index.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (idx) {
                var evs = (idx || []).filter(function (e) { return e && e.epoch; })
                    .sort(function (a, b) { return a.epoch - b.epoch; });
                if (evs.length > MAXEP) { note = 'showing last ' + MAXEP + ' of ' + evs.length; evs = evs.slice(-MAXEP); }
                series = evs.map(function (e) {
                    return { epoch: e.epoch, counts: e.counts || {}, total: (e.counts && e.counts.total) || 0 };
                });
                loaded = true; loading = false; draw();
            })
            .catch(function () { loading = false; draw(); });
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'churn', name: 'Churn', el: el,
        onShow: function () { if (!loaded) load(); else draw(); },
        onHide: function () { }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
