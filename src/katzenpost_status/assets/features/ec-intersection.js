(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var el = document.createElement('div');
    el.id = 'intersection-attack-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'overflow-x:hidden;overflow-y:auto;-webkit-overflow-scrolling:touch;box-sizing:border-box;' +
        'padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block';
    el.appendChild(canvas);
    document.body.appendChild(el);
    if (window.KATZEN_CRT) window.KATZEN_CRT(el);
    var ctx = canvas.getContext('2d');

    var MAX_ROUNDS = 40, PRESENT_P = 0.42, PAD_T = 84, PAD_B = 30;
    var rows = [], counts = {}, round = 0, target = null, timer = 0;

    function themed(hex) { try { return K.hex6(K.themeColor ? K.themeColor(hex) : hex); } catch (e) { return '#4d8bf0'; } }

    function population() {
        var ns = ((K.data() || {}).nodes || []).slice();
        ns.sort(function (a, b) { return (a.name || '').localeCompare(b.name || ''); });
        return ns;
    }
    function reset() {
        var ns = population();
        rows = ns.map(function (n) { return { name: n.name, type: n.type }; });
        counts = {}; rows.forEach(function (r) { counts[r.name] = 0; });
        round = 0; target = null;
        var i; for (i = 0; i < ns.length; i++) { if (ns[i].type === 'gateway') { target = ns[i].name; break; } }
        if (!target && rows.length) target = rows[0].name;
    }
    function step() {
        if (round >= MAX_ROUNDS) return;
        round++;
        rows.forEach(function (r) {
            var present = (r.name === target) || (Math.random() < PRESENT_P);
            if (present) counts[r.name]++;
        });
        draw();
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var vw = el.clientWidth || window.innerWidth, vh = el.clientHeight || window.innerHeight;
        var padL = Math.max(80, Math.min(150, Math.floor(vw * 0.3))), RIGHT = 60;
        var nRows = rows.length;
        var barH = nRows ? Math.max(6, Math.min(22, Math.floor((vh - PAD_T - PAD_B) / nRows) - 2)) : 10;
        var H = Math.max(vh, PAD_T + PAD_B + nRows * (barH + 2));
        canvas.width = Math.round(vw * dpr); canvas.height = Math.round(H * dpr);
        canvas.style.width = vw + 'px'; canvas.style.height = H + 'px';
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, vw, H);
        ctx.fillStyle = '#030508'; ctx.fillRect(0, 0, vw, H);

        ctx.fillStyle = '#ffb454'; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.textAlign = 'left';
        ctx.fillText('Intersection attack (SIMULATION)', padL, 16);
        ctx.fillStyle = '#7b8e9d'; ctx.font = '11px monospace';
        ctx.fillText('Target sender always present; others random each round. Suspicion = rounds seen. Round '
            + round + ' of ' + MAX_ROUNDS + '.', padL, 38);
        ctx.fillText('Cover traffic would keep every node present, flattening these bars.', padL, 54);

        if (!nRows) { return; }
        var order = rows.slice().sort(function (a, b) { return counts[b.name] - counts[a.name]; });
        var maxW = vw - padL - RIGHT, denom = Math.max(1, round);
        var tgtHex = themed(0xff5d6c), othHex = themed(0x4d8bf0);
        ctx.textBaseline = 'middle';
        order.forEach(function (r, i) {
            var y = PAD_T + i * (barH + 2), frac = counts[r.name] / denom, w = Math.max(1, frac * maxW);
            var isT = (r.name === target);
            ctx.fillStyle = isT ? tgtHex : othHex;
            ctx.fillRect(padL, y, w, barH);
            ctx.fillStyle = isT ? '#ffd23f' : '#9fb3c2'; ctx.textAlign = 'right';
            ctx.font = (isT ? 'bold ' : '') + '10px monospace';
            ctx.fillText(r.name + (isT ? ' *' : ''), padL - 6, y + barH / 2);
            ctx.fillStyle = '#59707f'; ctx.textAlign = 'left';
            ctx.fillText(Math.round(frac * 100) + '%', padL + w + 6, y + barH / 2);
        });
    }

    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (K.on) { K.on('theme', redrawIfShown); K.on('data', function () { if (el.style.display !== 'none') { reset(); draw(); } }); }

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'intersection-attack', name: 'Intersection attack', el: el,
        onShow: function () { reset(); draw(); if (timer) clearInterval(timer); timer = setInterval(step, 500); },
        onHide: function () { if (timer) clearInterval(timer); timer = 0; }
    });
})();
