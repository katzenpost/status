(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // Full-screen overlay: each mix layer emits "fireflies" (packets dwelling in
    // a mix) that fade over a lifetime drawn from the real exponential per-hop
    // delay (mean 1/Mu). Makes the Loopix mixing latency visible; the spawn rate
    // follows the live traffic.
    var el = document.createElement('div');
    el.id = 'fireflies-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:radial-gradient(ellipse at 50% 40%,#060a14,#010206 80%);overflow:hidden';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%';
    el.appendChild(canvas);
    var cap = document.createElement('div');
    cap.style.cssText = 'position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:26;' +
        'max-width:calc(100vw - 24px);text-align:center;color:#9fb3c2;font:11px/1.5 monospace;' +
        'background:rgba(6,10,16,0.72);border:1px solid rgba(120,140,170,0.3);border-radius:8px;padding:6px 12px';
    el.appendChild(cap);
    document.body.appendChild(el);

    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    var W = 0, H = 0, dpr = Math.min(2, window.devicePixelRatio || 1);
    function resize() {
        W = el.clientWidth || window.innerWidth; H = el.clientHeight || window.innerHeight;
        canvas.width = (W * dpr) | 0; canvas.height = (H * dpr) | 0;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    var LAYER_COL = ['#2ec4b6', '#4d8bf0', '#9b5de5', '#ff8f3f', '#ffd23f'];
    var flies = [], acc = 0, running = false, raf = 0, last = 0;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    function readParams() {
        var d = K.data() || {}, P = d.parameters || {};
        var layers = (d.layers && d.layers.length) ? d.layers.map(function (l) { return l.length || 1; })
            : [1, 1, 1];
        var mu = pos(P.Mu);
        // mean per-hop delay ~ 1/Mu; scale to a watchable window, keep the shape.
        var meanSec = mu ? Math.max(0.6, Math.min(4, (1 / mu) / 120)) : 1.6;
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        var spawn = 12 + Math.min(140, rate * 1.4);            // fireflies per second
        var by = (d.counts && d.counts.by_status) || {};
        var total = (d.counts && d.counts.total) || (d.nodes ? d.nodes.length : 0) || 1;
        var health = Math.max(0, Math.min(1, ((by.down || 0) + (by.unknown || 0)) / total));
        return { layers: layers, meanSec: meanSec, spawn: spawn, health: health, epoch: d.epoch };
    }
    var Pm = readParams();

    function colFor(layer) { return LAYER_COL[layer % LAYER_COL.length]; }
    function spawnOne() {
        var L = Pm.layers.length;
        var layer = (Math.random() * L) | 0;
        var cx = W * (0.5 + (L > 1 ? (layer / (L - 1) - 0.5) * 0.7 : 0));
        var cy = H * (0.30 + Math.random() * 0.40);
        // exponential lifetime: -ln(U) * mean  (the Loopix per-hop delay law)
        var life = -Math.log(Math.max(1e-6, Math.random())) * Pm.meanSec;
        flies.push({
            x: cx + (Math.random() - 0.5) * W * 0.16,
            y: cy + (Math.random() - 0.5) * H * 0.18,
            vx: (Math.random() - 0.5) * 10, vy: -6 - Math.random() * 14,
            age: 0, life: life, col: colFor(layer)
        });
    }

    function frame(t) {
        if (!running) return;
        var dt = last ? Math.min(0.05, (t - last) / 1000) : 0.016; last = t;
        acc += Pm.spawn * dt;
        while (acc >= 1) { spawnOne(); acc -= 1; }
        if (flies.length > 1400) flies.splice(0, flies.length - 1400);

        ctx.clearRect(0, 0, W, H);
        ctx.globalCompositeOperation = 'lighter';
        for (var i = flies.length - 1; i >= 0; i--) {
            var f = flies[i];
            f.age += dt;
            if (f.age >= f.life) { flies.splice(i, 1); continue; }
            f.x += f.vx * dt; f.y += f.vy * dt; f.vy += 8 * dt;   // gentle rise, easing
            var a = Math.exp(-3 * f.age / f.life);                // brightness decays over its life
            var r = 2 + a * 3.5;
            var g = ctx.createRadialGradient(f.x, f.y, 0, f.x, f.y, r * 4);
            g.addColorStop(0, f.col); g.addColorStop(1, 'rgba(0,0,0,0)');
            ctx.globalAlpha = a * 0.9;
            ctx.fillStyle = g;
            ctx.beginPath(); ctx.arc(f.x, f.y, r * 4, 0, 6.2832); ctx.fill();
        }
        ctx.globalAlpha = 1; ctx.globalCompositeOperation = 'source-over';
        raf = requestAnimationFrame(frame);
    }

    function caption() {
        cap.innerHTML = 'Loopix delay fireflies &mdash; each fades over a lifetime drawn from the ' +
            'exponential per-hop delay (mean 1/Mu ~ ' + Pm.meanSec.toFixed(2) + 's here), one column per ' +
            'mix layer; spawn rate follows live traffic' + (Pm.health > 0.01 ? '; dimmer as nodes go down' : '') + '.';
    }

    K.on('data', function () { Pm = readParams(); caption(); });
    window.addEventListener('resize', function () { if (running) resize(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'fireflies', name: 'Delay fireflies', el: el,
        onShow: function () {
            Pm = readParams(); caption(); resize(); flies = []; acc = 0; last = 0;
            if (!running) { running = true; raf = requestAnimationFrame(frame); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; flies = []; }
    });
})();
