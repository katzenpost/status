(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var ROLES = ['dirauth', 'gateway', 'mix', 'service', 'storage', 'out'];
    var HUE = {
        dirauth: '#ffd23f', gateway: '#2ec4b6', mix: '#4d8bf0',
        service: '#ff8f3f', storage: '#00d2a0', out: '#9b5de5'
    };
    var PAD_T = 104;       // clears the title / caption / top controls
    var PAD_B = 40;

    var el = document.createElement('div');
    el.id = 'chord-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'box-sizing:border-box;padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) env(safe-area-inset-left)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    el.appendChild(canvas);
    document.body.appendChild(el);
    var ctx = canvas.getContext('2d');

    function nodesByRole() {
        var by = {};
        ROLES.forEach(function (r) { by[r] = []; });
        (K.nodes() || []).forEach(function (o) {
            var n = o && o.data;
            if (!n) return;
            var t = n.type;
            if (by[t]) by[t].push(n);
        });
        return by;
    }

    function edgesFor(by) {
        var pairs = {};
        function add(a, b, c) {
            if (a === b || c <= 0) return;
            var ia = ROLES.indexOf(a), ib = ROLES.indexOf(b);
            var key = ia < ib ? a + '|' + b : b + '|' + a;
            pairs[key] = (pairs[key] || 0) + c;
        }
        var nDir = by.dirauth.length;
        ROLES.forEach(function (r) {
            if (r !== 'dirauth') add('dirauth', r, nDir * by[r].length);
        });
        var minLayer = null, maxLayer = null;
        by.mix.forEach(function (n) {
            if (n.layer == null) return;
            if (minLayer === null || n.layer < minLayer) minLayer = n.layer;
            if (maxLayer === null || n.layer > maxLayer) maxLayer = n.layer;
        });
        function mixInLayer(L) {
            return by.mix.filter(function (n) { return n.layer === L; }).length;
        }
        var nMixMin = minLayer === null ? by.mix.length : mixInLayer(minLayer);
        var nMixMax = maxLayer === null ? by.mix.length : mixInLayer(maxLayer);
        add('gateway', 'mix', by.gateway.length * nMixMin);
        add('mix', 'service', nMixMax * by.service.length);
        var nCourier = by.service.filter(function (n) {
            var caps = (n.details && n.details.capabilities) || [];
            return caps.indexOf('courier') >= 0;
        }).length;
        add('service', 'storage', nCourier * by.storage.length);
        return pairs;
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var W = el.clientWidth || window.innerWidth, H = el.clientHeight || window.innerHeight;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, W, H);

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace';
        ctx.textAlign = 'left'; ctx.textBaseline = 'top';
        ctx.fillText('Role connectivity', 24, 16);
        ctx.fillStyle = '#7b8e9d'; ctx.font = '11px monospace';
        ctx.fillText('arc size = node count    ribbon width = number of connections', 24, 40);

        var by = nodesByRole();
        var present = ROLES.filter(function (r) { return by[r].length > 0; });
        var total = 0;
        present.forEach(function (r) { total += by[r].length; });
        if (!present.length || !total) {
            ctx.fillStyle = '#9fb3c2'; ctx.font = '12px monospace';
            ctx.fillText('No nodes yet.', 24, PAD_T);
            return;
        }

        var cx = W / 2;
        var cy = PAD_T + (H - PAD_T - PAD_B) / 2;
        var radius = Math.max(60, Math.min(W / 2, (H - PAD_T - PAD_B) / 2) - 100);
        var band = 16;                 // arc band thickness
        var rInner = radius - band;    // ribbons start on the inner edge

        var gap = 0.05;
        var avail = Math.PI * 2 - present.length * gap;
        var arcs = {};
        var ang = -Math.PI / 2 + gap / 2;   // start at top, sweep clockwise
        present.forEach(function (r) {
            var span = avail * (by[r].length / total);
            arcs[r] = { a0: ang, a1: ang + span, mid: ang + span / 2, count: by[r].length };
            ang += span + gap;
        });

        var pairs = edgesFor(by);
        var keys = Object.keys(pairs);
        var maxEdge = 1;
        keys.forEach(function (k) { if (pairs[k] > maxEdge) maxEdge = pairs[k]; });

        keys.sort(function (a, b) { return pairs[b] - pairs[a]; });
        ctx.lineCap = 'round';
        keys.forEach(function (k) {
            var rr = k.split('|'), a = rr[0], b = rr[1];
            if (!arcs[a] || !arcs[b]) return;
            var c = pairs[k];
            if (c <= 0) return;
            var x0 = cx + rInner * Math.cos(arcs[a].mid);
            var y0 = cy + rInner * Math.sin(arcs[a].mid);
            var x1 = cx + rInner * Math.cos(arcs[b].mid);
            var y1 = cy + rInner * Math.sin(arcs[b].mid);
            var w = 1 + (c / maxEdge) * 14;
            ctx.globalAlpha = 0.32;
            ctx.strokeStyle = HUE[a] || '#9fb3c2';
            ctx.lineWidth = w;
            ctx.beginPath();
            ctx.moveTo(x0, y0);
            ctx.quadraticCurveTo(cx, cy, x1, y1);   // routed near the centre
            ctx.stroke();
            ctx.globalAlpha = 1;
        });

        present.forEach(function (r) {
            var arc = arcs[r];
            ctx.strokeStyle = HUE[r] || '#9fb3c2';
            ctx.lineWidth = band;
            ctx.lineCap = 'butt';
            ctx.beginPath();
            ctx.arc(cx, cy, radius - band / 2, arc.a0, arc.a1);
            ctx.stroke();
        });

        ctx.font = '11px monospace'; ctx.textBaseline = 'middle';
        present.forEach(function (r) {
            var arc = arcs[r];
            var lx = cx + (radius + 12) * Math.cos(arc.mid);
            var ly = cy + (radius + 12) * Math.sin(arc.mid);
            ctx.textAlign = Math.cos(arc.mid) < -0.15 ? 'right' : (Math.cos(arc.mid) > 0.15 ? 'left' : 'center');
            ctx.fillStyle = HUE[r] || '#9fb3c2';
            ctx.fillText(r + ' (' + arc.count + ')', lx, ly);
        });
    }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'chord', name: 'Chord', el: el,
        onShow: function () { draw(); },
        onHide: function () { }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
