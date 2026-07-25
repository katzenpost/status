(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // Full-screen overlay: a Gray-Scott reaction-diffusion field whose feed/kill
    // regime (and so the Turing pattern) is set by the live Loopix parameters.
    // Ambient art, not a topology map.
    var el = document.createElement('div');
    el.id = 'reaction-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#02040a;overflow:hidden';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;top:50%;left:50%;width:96vmin;height:96vmin;' +
        'transform:translate(-50%,-50%);image-rendering:pixelated';
    el.appendChild(canvas);
    var cap = document.createElement('div');
    cap.style.cssText = 'position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:26;' +
        'max-width:calc(100vw - 24px);text-align:center;color:#9fb3c2;font:11px/1.5 monospace;' +
        'background:rgba(6,10,16,0.72);border:1px solid rgba(120,140,170,0.3);border-radius:8px;padding:6px 12px';
    el.appendChild(cap);
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var N = mob ? 140 : 210;
    canvas.width = N; canvas.height = N;
    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    var img = ctx.createImageData(N, N);
    var U = new Float32Array(N * N), V = new Float32Array(N * N);
    var U2 = new Float32Array(N * N), V2 = new Float32Array(N * N);
    var Du = 0.16, Dv = 0.08;

    var running = false, raf = 0, lastEpoch = null;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    function readParams() {
        var d = K.data() || {}, P = d.parameters || {};
        var lp = pos(P.LambdaP), ll = pos(P.LambdaL), lm = pos(P.LambdaM), lg = pos(P.LambdaG), mu = pos(P.Mu);
        // Feed from the real-vs-loop traffic balance; kill from the per-hop delay.
        var realFrac = (lp + ll) > 0 ? lp / (lp + ll) : 0.5;
        var f = 0.018 + realFrac * 0.05;                       // 0.018 .. 0.068
        var k = 0.05 + Math.min(0.017, mu ? mu * 0.6 : 0.008);  // ~0.05 .. 0.067
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        var steps = mob ? 6 : (8 + Math.min(8, Math.round(rate / 25)));
        var by = (d.counts && d.counts.by_status) || {};
        var total = (d.counts && d.counts.total) || (d.nodes ? d.nodes.length : 0) || 1;
        var health = Math.max(0, Math.min(1, ((by.down || 0) + (by.unknown || 0)) / total));
        var hue = [lp || 1, lm || 1, lg || 1];
        return { f: f, k: k, steps: steps, health: health, hue: hue, epoch: d.epoch };
    }
    var Pm = readParams();

    function seed() {
        U.fill(1); V.fill(0);
        var blobs = 14 + ((Math.random() * 8) | 0);
        for (var b = 0; b < blobs; b++) {
            var cx = (Math.random() * N) | 0, cy = (Math.random() * N) | 0, r = 3 + ((Math.random() * 4) | 0);
            for (var dy = -r; dy <= r; dy++) for (var dx = -r; dx <= r; dx++) {
                var x = cx + dx, y = cy + dy;
                if (x < 0 || x >= N || y < 0 || y >= N) continue;
                if (dx * dx + dy * dy > r * r) continue;
                V[y * N + x] = 0.5; U[y * N + x] = 0.25;
            }
        }
    }

    function step(f, k) {
        for (var y = 0; y < N; y++) {
            var yu = (y - 1 + N) % N, yd = (y + 1) % N;
            for (var x = 0; x < N; x++) {
                var xl = (x - 1 + N) % N, xr = (x + 1) % N, i = y * N + x;
                var u = U[i], v = V[i];
                var lu = U[y * N + xl] + U[y * N + xr] + U[yu * N + x] + U[yd * N + x]
                    + 0.25 * (U[yu * N + xl] + U[yu * N + xr] + U[yd * N + xl] + U[yd * N + xr]) - 5 * u;
                var lv = V[y * N + xl] + V[y * N + xr] + V[yu * N + x] + V[yd * N + x]
                    + 0.25 * (V[yu * N + xl] + V[yu * N + xr] + V[yd * N + xl] + V[yd * N + xr]) - 5 * v;
                var uvv = u * v * v;
                var nu = u + (Du * lu - uvv + f * (1 - u));
                var nv = v + (Dv * lv + uvv - (f + k) * v);
                U2[i] = nu < 0 ? 0 : nu > 1 ? 1 : nu;
                V2[i] = nv < 0 ? 0 : nv > 1 ? 1 : nv;
            }
        }
        var t = U; U = U2; U2 = t; t = V; V = V2; V2 = t;
    }

    function draw() {
        var hs = Pm.hue[0] + Pm.hue[1] + Pm.hue[2];
        var c1 = Pm.hue[0] / hs, c2 = Pm.hue[1] / hs, red = Pm.health, data = img.data;
        for (var i = 0; i < N * N; i++) {
            var v = V[i], s = v * 3.2; if (s > 1) s = 1;
            // low V -> cyan-ish (lambdaP), high V -> violet (lambdaM), with a green lift
            var r = s * (0.15 + 0.7 * c2) + s * s * 0.3;
            var g = s * (0.55 * c1 + 0.25 * Pm.hue[2] / hs);
            var bl = s * (0.55 + 0.4 * c1);
            if (red > 0) { r = r * (1 - red) + s * red; g *= (1 - 0.6 * red); bl *= (1 - 0.6 * red); }
            var j = i * 4;
            data[j] = r > 1 ? 255 : (r * 255) | 0;
            data[j + 1] = g > 1 ? 255 : (g * 255) | 0;
            data[j + 2] = bl > 1 ? 255 : (bl * 255) | 0;
            data[j + 3] = 255;
        }
        ctx.putImageData(img, 0, 0);
    }

    function caption() {
        cap.innerHTML = 'Reaction-diffusion (Gray-Scott) &mdash; ambient art driven by live parameters. ' +
            'Feed ' + Pm.f.toFixed(3) + ' from real/loop &lambda; balance, kill ' + Pm.k.toFixed(3) +
            ' from delay Mu, hue = &lambda; mix' + (Pm.health > 0.01 ? ', red = nodes down' : '') + '.';
    }

    function loop() {
        if (!running) return;
        for (var s = 0; s < Pm.steps; s++) step(Pm.f, Pm.k);
        draw();
        raf = requestAnimationFrame(loop);
    }

    K.on('data', function () {
        var np = readParams();
        if (np.epoch !== lastEpoch) { Pm = np; lastEpoch = np.epoch; seed(); }
        else { Pm = np; }
        caption();
    });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'reaction', name: 'Reaction-diffusion', el: el,
        onShow: function () {
            Pm = readParams(); lastEpoch = Pm.epoch; caption();
            seed();
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
