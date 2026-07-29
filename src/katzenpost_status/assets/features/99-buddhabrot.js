(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // Full-screen overlay: a 3D Buddhabrot point cloud (three.js). Escape
    // trajectories are plotted at (Re z, Im z) with depth from the seed's real
    // part; the mixnet nodes are mapped onto the cloud and packets traverse the
    // mix pipeline between them. The whole thing slowly rotates.
    var el = document.createElement('div');
    el.id = 'buddhabrot-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:hidden';
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var MAXPTS = mob ? 200000 : 520000;
    var BATCH = mob ? 5000 : 12000;
    var PACK_MAX = mob ? 90 : 240;

    var RE0 = -2.1, RE1 = 0.55, IM0 = -1.25, IM1 = 1.25, reSpan = RE1 - RE0, imSpan = IM1 - IM0;
    var REMID = (RE0 + RE1) / 2;
    var SX = 10, SY = 10, SZ = 9;
    var TRAJ = 4000;
    var trx = new Float32Array(TRAJ), tryv = new Float32Array(TRAJ);

    var renderer = null, scene = null, camera = null, world = null, controls = null;
    var points = null, geo = null, positions = null, colors = null, cursor = 0, filled = 0;
    var nodeGroup = null, nodePos = {}, pipeline = [];
    var packets = [], packPts = null, packPos = null, packCol = null, spawnAcc = 0, lastT = 0;
    var running = false, raf = 0, lastEpoch = null;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    var TINT = [[0.25, 0.95, 1.0], [0.72, 0.4, 1.0], [0.25, 1.0, 0.62]];
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
        return { maxIter: maxIter, cw: cw, expo: expo, health: health, rate: rate, epoch: d.epoch };
    }
    var P = readParams();

    function inMainBulb(x, y) {
        var xm = x - 0.25, q = xm * xm + y * y;
        if (q * (q + xm) <= 0.25 * y * y) return true;
        var xp = x + 1;
        return (xp * xp + y * y) <= 0.0625;
    }

    function hashStr(s) {
        var h = 2166136261, i;
        for (i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
        return h >>> 0;
    }
    function hashPos(name) {
        var h = hashStr(name);
        var a = (h & 1023) / 1023, b = ((h >>> 10) & 1023) / 1023, c = ((h >>> 20) & 1023) / 1023;
        return new THREE.Vector3((a * 2 - 1) * 12, (b * 2 - 1) * 13, (c * 2 - 1) * SZ * 1.2);
    }
    function roleColor(n) {
        try { return new THREE.Color(K.groupColor({ data: n })); } catch (e) { return new THREE.Color(0x8aa0b4); }
    }

    function buildNodes() {
        if (nodeGroup) { world.remove(nodeGroup); nodeGroup = null; }
        nodePos = {}; pipeline = [];
        var d = K.data() || {}, nodes = d.nodes || [];
        nodeGroup = new THREE.Group();
        var sphere = new THREE.SphereGeometry(0.65, 10, 10);
        nodes.forEach(function (n) {
            var p = hashPos(n.name); nodePos[n.name] = p;
            var m = new THREE.Mesh(sphere, new THREE.MeshBasicMaterial({ color: roleColor(n) }));
            m.position.copy(p); nodeGroup.add(m);
        });
        world.add(nodeGroup);
        // pipeline: gateways -> mix layers -> services, for packets to traverse
        var byType = { gateway: [], mix: [], service: [] };
        nodes.forEach(function (n) { if (byType[n.type]) byType[n.type].push(n.name); });
        if (byType.gateway.length) pipeline.push(byType.gateway);
        (d.layers || []).forEach(function (l) { if (l && l.length) pipeline.push(l); });
        if (!(d.layers || []).length && byType.mix.length) pipeline.push(byType.mix);
        if (byType.service.length) pipeline.push(byType.service);
    }

    function spawnPacket() {
        if (pipeline.length < 2 || packets.length >= PACK_MAX) return;
        var path = [];
        for (var i = 0; i < pipeline.length; i++) {
            var layer = pipeline[i], nm = layer[(Math.random() * layer.length) | 0], p = nodePos[nm];
            if (p) path.push(p);
        }
        if (path.length >= 2) packets.push({ path: path, seg: 0, t: 0, speed: 7 + Math.random() * 6 });
    }
    function updatePackets(dt) {
        var w = packPos, c = packCol, k = 0;
        for (var i = packets.length - 1; i >= 0; i--) {
            var pk = packets[i], a = pk.path[pk.seg], b = pk.path[pk.seg + 1];
            var segLen = a.distanceTo(b) || 1;
            pk.t += dt * pk.speed / segLen;
            while (pk.t >= 1 && pk.seg < pk.path.length - 2) { pk.t -= 1; pk.seg++; a = pk.path[pk.seg]; b = pk.path[pk.seg + 1]; segLen = a.distanceTo(b) || 1; }
            if (pk.seg >= pk.path.length - 1 || (pk.seg === pk.path.length - 2 && pk.t >= 1)) { packets.splice(i, 1); continue; }
            if (k < PACK_MAX) {
                var t = pk.t < 0 ? 0 : pk.t > 1 ? 1 : pk.t, o = k * 3;
                w[o] = a.x + (b.x - a.x) * t; w[o + 1] = a.y + (b.y - a.y) * t; w[o + 2] = a.z + (b.z - a.z) * t;
                c[o] = 1.0; c[o + 1] = 0.95; c[o + 2] = 0.5;
                k++;
            }
        }
        packPts.geometry.setDrawRange(0, k);
        packPts.geometry.attributes.position.needsUpdate = true;
        packPts.geometry.attributes.color.needsUpdate = true;
    }

    function initGL() {
        try { renderer = new THREE.WebGLRenderer({ antialias: false, alpha: false, powerPreference: 'low-power' }); }
        catch (e) { return false; }
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
        el.appendChild(renderer.domElement);
        renderer.domElement.style.cssText = 'display:block;width:100%;height:100%';
        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000);
        camera.position.set(0, 3, 46);
        world = new THREE.Group(); scene.add(world);   // upright; the real axis is vertical
        if (THREE.OrbitControls) {
            controls = new THREE.OrbitControls(camera, renderer.domElement);
            controls.enableDamping = true; controls.dampingFactor = 0.08;
            controls.autoRotate = true; controls.autoRotateSpeed = 0.7;   // spin around the vertical spine
            controls.minDistance = 12; controls.maxDistance = 170;
            controls.target.set(0, 0, 0);
        }

        positions = new Float32Array(MAXPTS * 3); colors = new Float32Array(MAXPTS * 3);
        geo = new THREE.BufferGeometry();
        var pa = new THREE.BufferAttribute(positions, 3); pa.setUsage(THREE.DynamicDrawUsage);
        var ca = new THREE.BufferAttribute(colors, 3); ca.setUsage(THREE.DynamicDrawUsage);
        geo.setAttribute('position', pa); geo.setAttribute('color', ca); geo.setDrawRange(0, 0);
        points = new THREE.Points(geo, new THREE.PointsMaterial({
            size: mob ? 0.09 : 0.06, vertexColors: true, transparent: true, opacity: 0.95,
            blending: THREE.AdditiveBlending, depthWrite: false, depthTest: false, sizeAttenuation: true
        }));
        world.add(points);

        packPos = new Float32Array(PACK_MAX * 3); packCol = new Float32Array(PACK_MAX * 3);
        var pg = new THREE.BufferGeometry();
        var ppa = new THREE.BufferAttribute(packPos, 3); ppa.setUsage(THREE.DynamicDrawUsage);
        var pca = new THREE.BufferAttribute(packCol, 3); pca.setUsage(THREE.DynamicDrawUsage);
        pg.setAttribute('position', ppa); pg.setAttribute('color', pca); pg.setDrawRange(0, 0);
        packPts = new THREE.Points(pg, new THREE.PointsMaterial({
            size: mob ? 0.9 : 0.7, vertexColors: true, transparent: true, opacity: 1,
            blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true
        }));
        world.add(packPts);

        onResize();
        return true;
    }
    function onResize() {
        if (!renderer) return;
        var w = el.clientWidth || window.innerWidth, h = el.clientHeight || window.innerHeight;
        renderer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix();
    }

    function addBatch(target) {
        var added = 0, ops = 0, mx = P.maxIter[2], cap = target * 6000;
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
            if (n >= mx) continue;
            var ch = n <= P.maxIter[0] ? 0 : (n <= P.maxIter[1] ? 1 : 2);
            var t = TINT[ch], e = P.expo * P.cw[ch], r = t[0] * e, g = t[1] * e, b = t[2] * e;
            var wz = (cx - REMID) * SZ, lim = n < keep ? n : keep;
            for (var i = 0; i < lim && added < target; i++) {
                // upright "sitting monk": horizontal = Im(z), vertical = -Re(z)
                // (so the cardioid base is at the bottom and the antenna/head up).
                var wx = tryv[i] * SX, wy = (REMID - trx[i]) * SY, o = cursor * 3;
                positions[o] = wx; positions[o + 1] = wy; positions[o + 2] = wz;
                colors[o] = r; colors[o + 1] = g; colors[o + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++; added++;
                var o2 = cursor * 3;                     // mirror across the vertical spine
                positions[o2] = -wx; positions[o2 + 1] = wy; positions[o2 + 2] = wz;
                colors[o2] = r; colors[o2 + 1] = g; colors[o2 + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++; added++;
            }
        }
        return added;
    }

    function loop() {
        if (!running) return;
        var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
        var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016; lastT = now;
        if (filled < MAXPTS) {
            addBatch(BATCH);
            geo.attributes.position.needsUpdate = true;
            geo.attributes.color.needsUpdate = true;
            geo.setDrawRange(0, filled);
        }
        spawnAcc += dt * (4 + Math.min(30, P.rate * 0.5));
        while (spawnAcc >= 1) { spawnPacket(); spawnAcc -= 1; }
        updatePackets(dt);
        if (controls) controls.update();   // damping + autoRotate around the vertical axis
        renderer.render(scene, camera);
        raf = requestAnimationFrame(loop);
    }

    function resetCloud() { cursor = 0; filled = 0; if (geo) geo.setDrawRange(0, 0); }

    K.on('data', function () {
        var np = readParams();
        var epochChanged = np.epoch !== lastEpoch;
        P = np; lastEpoch = np.epoch;
        if (epochChanged) resetCloud();
        if (world) buildNodes();
    });
    window.addEventListener('resize', function () { if (running) onResize(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'buddhabrot', name: 'Buddhabrot 3D', el: el,
        onShow: function () {
            P = readParams(); lastEpoch = P.epoch;
            if (!renderer && !initGL()) return;
            buildNodes(); packets = []; spawnAcc = 0; lastT = 0;
            onResize();
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
