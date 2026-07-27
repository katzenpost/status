(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var MAXEP = 24;        // bound the snapshot fetches to the most recent epochs
    function base() { return (K.dataUrl() || '').replace(/\.data\.json(\?.*)?$/, '-history/'); }

    var el = document.createElement('div');
    el.id = 'diversity-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'box-sizing:border-box;padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    el.appendChild(canvas);
    document.body.appendChild(el);
    var ctx = canvas.getContext('2d');

    var series = [];       // [{epoch, asH, ctH, asN, ctN}]
    var loaded = false, loading = false, note = '';

    function countryOf(n) {
        var g = n.geo;
        if (!g || !g.label) return null;
        var p = g.label.split(',');
        return p[p.length - 1].trim() || null;
    }
    function entropy(keys) {   // Shannon entropy (bits) of a list of category keys
        var m = {}, tot = 0;
        keys.forEach(function (k) { if (k == null) return; m[k] = (m[k] || 0) + 1; tot++; });
        if (!tot) return { h: 0, n: 0 };
        var h = 0;
        Object.keys(m).forEach(function (k) { var p = m[k] / tot; h -= p * Math.log(p) / Math.LN2; });
        return { h: h, n: Object.keys(m).length };
    }
    function metricsFor(snapshot) {
        var mix = (snapshot.nodes || []).filter(function (n) { return n.type === 'mix'; });
        if (!mix.length) mix = (snapshot.nodes || []);   // fall back if no layer tags
        var as = entropy(mix.map(function (n) { return n.asn || null; }));
        var ct = entropy(mix.map(countryOf));
        return { asH: as.h, asN: as.n, ctH: ct.h, ctN: ct.n };
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var W = el.clientWidth || window.innerWidth, H = el.clientHeight || window.innerHeight;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.fillText('Diversity over time  -  mix-layer AS & country entropy (bits)', 24, 16);

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

        var L = 52, R = W - 84, T = 104, B = H - 54;   // T clears the top controls; right margin fits labels
        var n = series.length;
        var maxH = 1;
        series.forEach(function (s) { maxH = Math.max(maxH, s.asH, s.ctH); });
        maxH = Math.ceil(maxH + 0.5);
        function px(i) { return L + (R - L) * (n === 1 ? 0.5 : i / (n - 1)); }
        function py(v) { return B - (B - T) * (v / maxH); }

        ctx.strokeStyle = 'rgba(120,150,175,0.18)'; ctx.lineWidth = 1;
        ctx.fillStyle = '#59707f'; ctx.font = '10px monospace'; ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
        for (var g = 0; g <= maxH; g++) {
            var y = py(g);
            ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(R, y); ctx.stroke();
            ctx.fillText(g + '', L - 6, y);
        }
        ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        var step = Math.max(1, Math.ceil(n / 8));
        for (var i = 0; i < n; i++) {
            if (i % step && i !== n - 1) continue;
            ctx.fillText('#' + series[i].epoch, px(i), B + 6);
        }

        function line(key, color, label) {
            ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
            series.forEach(function (s, i) { var x = px(i), y = py(s[key]); if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y); });
            ctx.stroke();
            ctx.fillStyle = color;
            series.forEach(function (s, i) { ctx.beginPath(); ctx.arc(px(i), py(s[key]), 3, 0, Math.PI * 2); ctx.fill(); });
            var last = series[n - 1];
            ctx.textAlign = 'left'; ctx.textBaseline = 'middle'; ctx.font = '11px monospace';
            ctx.fillText(label, px(n - 1) + 6, py(last[key]));
        }
        line('asH', '#2ce0c0', 'AS');
        line('ctH', '#ffb454', 'country');

        var latest = series[n - 1];
        ctx.fillStyle = '#7b8e9d'; ctx.font = '11px monospace'; ctx.textAlign = 'left'; ctx.textBaseline = 'top';
        ctx.fillText('latest #' + latest.epoch + ': ' + latest.asN + ' distinct AS, ' +
            latest.ctN + ' countries across the mix layer' + (note ? '   (' + note + ')' : ''), 24, B + 26);
    }

    function load() {
        if (loading) return; loading = true; draw();
        fetch(base() + 'index.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (idx) {
                var evs = (idx || []).filter(function (e) { return e && e.epoch && e.file; })
                    .sort(function (a, b) { return a.epoch - b.epoch; });
                if (evs.length > MAXEP) { note = 'showing last ' + MAXEP + ' of ' + evs.length; evs = evs.slice(-MAXEP); }
                return Promise.all(evs.map(function (e) {
                    return fetch(base() + e.file, { cache: 'force-cache' })
                        .then(function (r) { return r.ok ? r.json() : null; })
                        .then(function (snap) { return snap ? { epoch: e.epoch, m: metricsFor(snap) } : null; })
                        .catch(function () { return null; });
                }));
            })
            .then(function (results) {
                series = (results || []).filter(Boolean).map(function (r) {
                    return { epoch: r.epoch, asH: r.m.asH, ctH: r.m.ctH, asN: r.m.asN, ctN: r.m.ctN };
                });
                loaded = true; loading = false; draw();
            })
            .catch(function () { loading = false; draw(); });
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'diversity', name: 'Diversity', el: el,
        onShow: function () { if (!loaded) load(); else draw(); },
        onHide: function () { }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
