(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var TYPE_ORDER = { dirauth: 0, gateway: 1, mix: 2, service: 3, storage: 4, out: 5 };

    var el = document.createElement('div');
    el.id = 'gantt-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'overflow:auto;-webkit-overflow-scrolling:touch;box-sizing:border-box;' +
        'padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) env(safe-area-inset-left)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block';
    el.appendChild(canvas);
    document.body.appendChild(el);
    var ctx = canvas.getContext('2d');

    var PAD_T = 104, PAD_B = 46, ROW_MIN = 16, RIGHT = 20;   // PAD_T clears title, legend, top controls

    function collect() {
        var out = [];
        var objs = K.nodes() || [];
        objs.forEach(function (o) {
            var d = o && o.data;
            if (!d) return;
            var det = d.details || {};
            var mke = det.mixkey_epochs;
            if (!mke || !mke.length) return;
            var lo = mke[0], hi = mke[0];
            mke.forEach(function (e) { if (e < lo) lo = e; if (e > hi) hi = e; });
            out.push({ name: d.name || '?', type: d.type || 'mix', lo: lo, hi: hi });
        });
        out.sort(function (a, b) {
            var da = (TYPE_ORDER[a.type] == null ? 9 : TYPE_ORDER[a.type]);
            var db = (TYPE_ORDER[b.type] == null ? 9 : TYPE_ORDER[b.type]);
            return (da - db) || a.name.localeCompare(b.name);
        });
        return out;
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var vw = el.clientWidth || window.innerWidth, vh = el.clientHeight || window.innerHeight;
        var rows = collect();
        var data = K.data() || {};
        var cur = data.epoch || 0;

        if (!rows.length) {
            canvas.width = Math.round(vw * dpr); canvas.height = Math.round(vh * dpr);
            canvas.style.width = vw + 'px'; canvas.style.height = vh + 'px';
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.clearRect(0, 0, vw, vh); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, vw, vh);
            ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace';
            ctx.textAlign = 'left'; ctx.textBaseline = 'top';
            ctx.fillText('Mix-key validity (epochs)', 24, 16);
            ctx.fillStyle = '#7b8e9d'; ctx.font = '12px monospace';
            ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
            ctx.fillText('No mix-key data in this consensus.', vw / 2, vh / 2);
            return;
        }

        var minE = cur - 2, maxAll = cur;
        rows.forEach(function (r) { if (r.hi > maxAll) maxAll = r.hi; });
        var maxE = Math.max(maxAll, cur + 3);
        var span = (maxE + 1) - minE;   // each key covers its epoch, so +1 past the last
        if (span < 1) span = 1;

        var padL = Math.max(96, Math.min(170, Math.floor(vw * 0.34)));
        var plotL = padL, plotR = vw - RIGHT;
        var nRows = rows.length;
        var rowH = Math.max(ROW_MIN, Math.floor((vh - PAD_T - PAD_B) / nRows));
        var H = Math.max(vh, PAD_T + PAD_B + nRows * rowH);
        var W = vw;

        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        canvas.style.width = W + 'px'; canvas.style.height = H + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        function xOf(e) { return plotL + (plotR - plotL) * ((e - minE) / span); }

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace';
        ctx.textAlign = 'left'; ctx.textBaseline = 'top';
        ctx.fillText('Mix-key validity (epochs)  (' + nRows + ' nodes)', 24, 16);

        ctx.textBaseline = 'middle';
        var lx = 24;
        ctx.fillStyle = '#2ce0c0'; ctx.fillRect(lx, 40, 10, 10);
        ctx.fillStyle = '#8ba0b0'; ctx.font = '10px monospace';
        ctx.fillText('valid', lx + 14, 45); lx += 14 + ctx.measureText('valid').width + 18;
        ctx.fillStyle = '#ff2d6b'; ctx.fillRect(lx, 40, 10, 10);
        ctx.fillStyle = '#8ba0b0';
        ctx.fillText('expiring at/next epoch', lx + 14, 45);
        lx += 14 + ctx.measureText('expiring at/next epoch').width + 18;
        ctx.strokeStyle = '#ffaa00'; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(lx + 5, 39); ctx.lineTo(lx + 5, 51); ctx.stroke();
        ctx.fillStyle = '#8ba0b0'; ctx.fillText('current epoch', lx + 14, 45);

        var gridB = PAD_T + nRows * rowH;
        ctx.strokeStyle = 'rgba(120,150,175,0.12)'; ctx.lineWidth = 1;
        for (var e = minE; e <= maxE + 1; e++) {
            var gx = Math.round(xOf(e)) + 0.5;
            ctx.beginPath(); ctx.moveTo(gx, PAD_T); ctx.lineTo(gx, gridB); ctx.stroke();
        }

        ctx.font = '10px monospace';
        rows.forEach(function (r, ri) {
            var y = PAD_T + ri * rowH;
            var expiring = r.hi <= cur;
            var col = expiring ? '#ff2d6b' : '#2ce0c0';
            var label = (expiring ? '! ' : '') + r.name;
            ctx.fillStyle = expiring ? '#ff8fb0' : '#9fb3c2';
            ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
            ctx.fillText(label, padL - 6, y + rowH / 2);
            var x1 = Math.max(plotL, xOf(r.lo));
            var x2 = Math.min(plotR, xOf(r.hi + 1));
            var bh = Math.max(6, rowH - 6);
            ctx.fillStyle = col;
            ctx.fillRect(Math.round(x1), Math.round(y + (rowH - bh) / 2), Math.max(2, Math.round(x2 - x1)), bh);
        });

        var nowX = Math.round(xOf(cur)) + 0.5;
        ctx.strokeStyle = '#ffaa00'; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(nowX, PAD_T); ctx.lineTo(nowX, gridB); ctx.stroke();
        ctx.fillStyle = '#ffaa00'; ctx.font = 'bold 10px monospace';
        ctx.textAlign = 'left'; ctx.textBaseline = 'top';
        ctx.fillText('now #' + cur, nowX + 4, PAD_T - 12);

        ctx.fillStyle = '#59707f'; ctx.font = '9px monospace';
        ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        var yLab = gridB + 6;
        var step = Math.max(1, Math.ceil(span / 8));
        for (var t = minE; t <= maxE; t++) {
            if ((t - minE) % step && t !== maxE) continue;
            ctx.fillText('#' + t, xOf(t), yLab);
        }
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'gantt', name: 'Mix keys', el: el,
        onShow: function () { draw(); },
        onHide: function () { }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
