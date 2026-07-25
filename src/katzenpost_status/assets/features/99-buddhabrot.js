(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    // Full-screen overlay: a progressive Nebulabrot (a Buddhabrot in three
    // escape-time channels) whose exposure, tint, depth and drift are driven by
    // the live Loopix parameters. Ambient art, not a topology map.
    var el = document.createElement('div');
    el.id = 'buddhabrot-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:hidden';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'position:absolute;top:50%;left:50%;width:auto;height:96vmin;' +
        'transform:translate(-50%,-50%) rotate(90deg);will-change:transform';
    el.appendChild(canvas);
    var cap = document.createElement('div');
    cap.style.cssText = 'position:fixed;left:50%;bottom:16px;transform:translateX(-50%);z-index:26;' +
        'max-width:calc(100vw - 24px);text-align:center;color:#9fb3c2;font:11px/1.5 monospace;' +
        'background:rgba(6,10,16,0.72);border:1px solid rgba(120,140,170,0.3);border-radius:8px;padding:6px 12px';
    el.appendChild(cap);
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var W = mob ? 360 : 520, H = W;         // square internal render buffer
    canvas.width = W; canvas.height = H;
    var ctx = canvas.getContext('2d');
    if (!ctx) return;
    var img = ctx.createImageData(W, H);
    var hist = [new Float32Array(W * H), new Float32Array(W * H), new Float32Array(W * H)];
    var TRAJ = 6000;
    var trx = new Float32Array(TRAJ), tryv = new Float32Array(TRAJ);

    // Classic complex window; the canvas is rotated 90deg for the upright look.
    var RE0 = -2.15, RE1 = 1.0, IM0 = -1.28, IM1 = 1.28;
    var reSpan = RE1 - RE0, imSpan = IM1 - IM0;
    var BUDGET = mob ? 350000 : 1300000;    // iterations per animation frame

    var running = false, raf = 0, lastEpoch = null, t0 = 0;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    function readParams() {
        var d = K.data() || {}, P = d.parameters || {};
        var mu = pos(P.Mu);
        // Longer per-hop delay (smaller Mu) => deeper orbits in the long channel.
        var deep = mu ? Math.max(0.5, Math.min(4, (1 / mu) / 25)) : 1.5;
        var maxIter = [60, 700, Math.max(1400, Math.round(2600 * deep))];
        var lp = pos(P.LambdaP), lm = pos(P.LambdaM), lg = pos(P.LambdaG);
        var w = [lp || 1, lm || 1, lg || 1];
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        var expo = 0.55 + Math.min(2.4, rate / 45);           // busier network -> brighter
        var by = (d.counts && d.counts.by_status) || {};
        var total = (d.counts && d.counts.total) || (d.nodes ? d.nodes.length : 0) || 1;
        var health = Math.max(0, Math.min(1, ((by.down || 0) + (by.unknown || 0)) / total));
        return { maxIter: maxIter, w: w, expo: expo, health: health, epoch: d.epoch };
    }
    var P = readParams();

    // three channel tints: mix loop / real / gateway lambda colours (R,G,B 0..1)
    var TINT = [[0.0, 0.95, 1.0], [0.62, 0.30, 0.98], [0.10, 1.0, 0.55]];

    function inMainBulb(x, y) {
        var xm = x - 0.25, q = xm * xm + y * y;
        if (q * (q + xm) <= 0.25 * y * y) return true;         // main cardioid
        var xp = x + 1;
        return (xp * xp + y * y) <= 0.0625;                    // period-2 bulb
    }

    function accumulate() {
        var ops = 0, mx = P.maxIter[2];
        while (ops < BUDGET) {
            var cx = RE0 + Math.random() * reSpan;
            var cy = IM0 + Math.random() * imSpan;
            if (inMainBulb(cx, cy)) { ops += 8; continue; }    // never escapes; skip
            var x = 0, y = 0, n = 0, keep = (mx < TRAJ ? mx : TRAJ);
            while (n < mx) {
                var x2 = x * x, y2 = y * y;
                if (x2 + y2 > 4) break;
                if (n < keep) { trx[n] = x; tryv[n] = y; }
                y = 2 * x * y + cy; x = x2 - y2 + cx; n++;
            }
            ops += n;
            if (n >= mx) continue;                             // interior: no trajectory
            var lim = n < keep ? n : keep;
            for (var ch = 0; ch < 3; ch++) {
                if (n > P.maxIter[ch]) continue;               // only channels deep enough
                var band = hist[ch];
                for (var i = 0; i < lim; i++) {
                    var px = ((trx[i] - RE0) / reSpan * W) | 0;
                    var py = ((tryv[i] - IM0) / imSpan * H) | 0;
                    if (px >= 0 && px < W && py >= 0 && py < H) band[py * W + px] += 1;
                    var pym = ((-tryv[i] - IM0) / imSpan * H) | 0;   // mirror (symmetry)
                    if (pym >= 0 && pym < H) band[pym * W + px] += 1;
                }
            }
        }
    }

    function tone() {
        var mxv = [1, 1, 1], i, ch;
        for (ch = 0; ch < 3; ch++) {
            var b = hist[ch], m = 1;
            for (i = 0; i < b.length; i++) if (b[i] > m) m = b[i];
            mxv[ch] = m;
        }
        var wsum = P.w[0] + P.w[1] + P.w[2];
        var cw = [P.w[0] / wsum * 3, P.w[1] / wsum * 3, P.w[2] / wsum * 3];
        var data = img.data, expo = P.expo, red = P.health;
        for (i = 0; i < W * H; i++) {
            var r = 0, g = 0, bl = 0;
            for (ch = 0; ch < 3; ch++) {
                var v = hist[ch][i];
                if (v <= 0) continue;
                var s = Math.pow(v / mxv[ch], 0.42) * expo * cw[ch];
                r += TINT[ch][0] * s; g += TINT[ch][1] * s; bl += TINT[ch][2] * s;
            }
            if (red > 0) { r = r * (1 - red) + (r + g + bl) * 0.5 * red; g *= (1 - 0.7 * red); bl *= (1 - 0.7 * red); }
            var k = i * 4;
            data[k] = r > 1 ? 255 : (r * 255) | 0;
            data[k + 1] = g > 1 ? 255 : (g * 255) | 0;
            data[k + 2] = bl > 1 ? 255 : (bl * 255) | 0;
            data[k + 3] = 255;
        }
        ctx.putImageData(img, 0, 0);
    }

    function caption() {
        var mi = P.maxIter;
        cap.innerHTML = 'Loopix Nebulabrot &mdash; ambient art driven by live parameters. ' +
            'Channels = mix layers (depth ' + mi[0] + '/' + mi[1] + '/' + mi[2] + '), ' +
            'brightness = traffic, hue = &lambda; mix' + (P.health > 0.01 ? ', red = nodes down' : '') + '.';
    }

    function reset() {
        for (var ch = 0; ch < 3; ch++) hist[ch].fill(0);
    }

    function loop() {
        if (!running) return;
        accumulate();
        tone();
        // very slow drift: one extra rotation every few minutes, on top of the 90deg.
        var t = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
        var spin = ((t - t0) / 1000) * 0.6;   // degrees
        canvas.style.transform = 'translate(-50%,-50%) rotate(' + (90 + spin).toFixed(2) + 'deg)';
        raf = requestAnimationFrame(loop);
    }

    K.on('data', function () {
        var np = readParams();
        if (np.epoch !== lastEpoch) { P = np; lastEpoch = np.epoch; reset(); caption(); }
        else { P = np; caption(); }
    });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'buddhabrot', name: 'Nebulabrot', el: el,
        onShow: function () {
            P = readParams(); lastEpoch = P.epoch; caption();
            t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
