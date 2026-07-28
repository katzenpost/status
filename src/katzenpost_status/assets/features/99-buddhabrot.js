(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // Full-screen overlay: a 3D Buddhabrot point cloud rendered with three.js.
    // Escape trajectories are plotted at (Re z, Im z) with depth from the seed's
    // real part; the cloud slowly rotates. Exposure/hue follow live parameters.
    var el = document.createElement('div');
    el.id = 'buddhabrot-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:hidden';
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var MAXPTS = mob ? 200000 : 520000;
    var BATCH = mob ? 5000 : 12000;     // new points added per frame while filling

    // complex sampling window and world scaling
    var RE0 = -2.1, RE1 = 0.55, IM0 = -1.25, IM1 = 1.25, reSpan = RE1 - RE0, imSpan = IM1 - IM0;
    var REMID = (RE0 + RE1) / 2;
    var SX = 10, SY = 10, SZ = 9;
    var TRAJ = 4000;
    var trx = new Float32Array(TRAJ), tryv = new Float32Array(TRAJ);

    var renderer = null, scene = null, camera = null, points = null, geo = null;
    var positions = null, colors = null, cursor = 0, filled = 0;
    var running = false, raf = 0, lastEpoch = null;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    var TINT = [[0.25, 0.95, 1.0], [0.72, 0.4, 1.0], [0.25, 1.0, 0.62]];  // cyan/violet/green
    function readParams() {
        var d = K.data() || {}, P = d.parameters || {};
        var mu = pos(P.Mu);
        var deep = mu ? Math.max(0.7, Math.min(1.7, (1 / mu) / 400)) : 1.0;
        var maxIter = [80, 800, Math.round(2600 * deep)];
        var lp = pos(P.LambdaP) || 1, lm = pos(P.LambdaM) || 1, lg = pos(P.LambdaG) || 1;
        var wsum = lp + lm + lg;
        var cw = [0.7 + 1.1 * (lp / wsum), 0.7 + 1.1 * (lm / wsum), 0.7 + 1.1 * (lg / wsum)];
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        var expo = 0.5 + Math.min(0.7, rate / 90);
        var by = (d.counts && d.counts.by_status) || {};
        var total = (d.counts && d.counts.total) || (d.nodes ? d.nodes.length : 0) || 1;
        var health = Math.max(0, Math.min(1, ((by.down || 0) + (by.unknown || 0)) / total));
        return { maxIter: maxIter, cw: cw, expo: expo, health: health, epoch: d.epoch };
    }
    var P = readParams();

    function inMainBulb(x, y) {
        var xm = x - 0.25, q = xm * xm + y * y;
        if (q * (q + xm) <= 0.25 * y * y) return true;
        var xp = x + 1;
        return (xp * xp + y * y) <= 0.0625;
    }

    function initGL() {
        try {
            renderer = new THREE.WebGLRenderer({ antialias: false, alpha: false, powerPreference: 'low-power' });
        } catch (e) { return false; }
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
        el.appendChild(renderer.domElement);
        renderer.domElement.style.cssText = 'display:block;width:100%;height:100%';
        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000);
        positions = new Float32Array(MAXPTS * 3);
        colors = new Float32Array(MAXPTS * 3);
        geo = new THREE.BufferGeometry();
        var pa = new THREE.BufferAttribute(positions, 3); pa.setUsage(THREE.DynamicDrawUsage);
        var ca = new THREE.BufferAttribute(colors, 3); ca.setUsage(THREE.DynamicDrawUsage);
        geo.setAttribute('position', pa);
        geo.setAttribute('color', ca);
        geo.setDrawRange(0, 0);
        var mat = new THREE.PointsMaterial({
            size: mob ? 0.09 : 0.06, vertexColors: true, transparent: true, opacity: 0.95,
            blending: THREE.AdditiveBlending, depthWrite: false, depthTest: false, sizeAttenuation: true
        });
        points = new THREE.Points(geo, mat);
        points.rotation.x = -0.35;
        scene.add(points);
        onResize();
        return true;
    }
    function onResize() {
        if (!renderer) return;
        var w = el.clientWidth || window.innerWidth, h = el.clientHeight || window.innerHeight;
        renderer.setSize(w, h);
        camera.aspect = w / h; camera.updateProjectionMatrix();
        var dist = 46 / Math.min(1.6, Math.max(0.6, w / h));
        camera.position.set(0, 14, 46); camera.lookAt(0, 0, 0);
    }

    function addBatch(target) {
        var added = 0, ops = 0, mx = P.maxIter[2], cap = BATCH * 6000;
        while (added < target && ops < cap) {
            var cx = RE0 + Math.random() * reSpan, cy = IM0 + Math.random() * imSpan;
            if (inMainBulb(cx, cy)) { ops += 8; continue; }
            var x = 0, y = 0, n = 0, keep = (mx < TRAJ ? mx : TRAJ);
            while (n < mx) {
                var x2 = x * x, y2 = y * y;
                if (x2 + y2 > 4) break;
                if (n < keep) { trx[n] = x; tryv[n] = y; }
                y = 2 * x * y + cy; x = x2 - y2 + cx; n++;
            }
            ops += n;
            if (n >= mx) continue;                       // interior: no trajectory
            var ch = n <= P.maxIter[0] ? 0 : (n <= P.maxIter[1] ? 1 : 2);
            var t = TINT[ch], e = P.expo * P.cw[ch];
            var r = t[0] * e, g = t[1] * e, b = t[2] * e;
            var wz = (cx - REMID) * SZ;                  // depth from the seed's real part
            var lim = n < keep ? n : keep;
            for (var i = 0; i < lim && added < target; i++) {
                var px = trx[i] * SX, py = tryv[i] * SY;
                var o = cursor * 3;
                positions[o] = px; positions[o + 1] = py; positions[o + 2] = wz;
                colors[o] = r; colors[o + 1] = g; colors[o + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++;
                added++;
                var o2 = cursor * 3;                     // mirror across the real axis
                positions[o2] = px; positions[o2 + 1] = -py; positions[o2 + 2] = wz;
                colors[o2] = r; colors[o2 + 1] = g; colors[o2 + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++;
                added++;
            }
        }
        return added;
    }

    function loop() {
        if (!running) return;
        if (filled < MAXPTS) {
            addBatch(BATCH);
            geo.attributes.position.needsUpdate = true;
            geo.attributes.color.needsUpdate = true;
            geo.setDrawRange(0, filled);
        }
        points.rotation.y += 0.0035;                     // slow auto-rotation
        renderer.render(scene, camera);
        raf = requestAnimationFrame(loop);
    }

    function resetCloud() { cursor = 0; filled = 0; if (geo) geo.setDrawRange(0, 0); }

    K.on('data', function () {
        var np = readParams();
        if (np.epoch !== lastEpoch) { P = np; lastEpoch = np.epoch; resetCloud(); }
        else { P = np; }
    });
    window.addEventListener('resize', function () { if (running) onResize(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'buddhabrot', name: 'Buddhabrot 3D', el: el,
        onShow: function () {
            P = readParams(); lastEpoch = P.epoch;
            if (!renderer && !initGL()) return;
            onResize();
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
