(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // Full-screen overlay: a 3D Buddhabrot point cloud (three.js), oriented as
    // the upright "sitting monk". Nodes are not extra geometry -- each node
    // recolours a small cluster of existing cloud points so it reads as some
    // illuminated points of the fractal; packets flow between those points.
    // Rotates around the vertical spine; drag/zoom with the mouse.
    var el = document.createElement('div');
    el.id = 'buddhabrot-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#000;overflow:hidden';
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var MAXPTS = mob ? 200000 : 520000;
    var BATCH = mob ? 5000 : 12000;
    var PACK_MAX = mob ? 90 : 240;

    var RE0 = -2.1, RE1 = 0.55, IM0 = -1.25, IM1 = 1.25, reSpan = RE1 - RE0, imSpan = IM1 - IM0;
    var REMID = (RE0 + RE1) / 2, SX = 10, SY = 10, SZ = 9, TRAJ = 4000;
    var trx = new Float32Array(TRAJ), tryv = new Float32Array(TRAJ);

    var renderer = null, scene = null, camera = null, controls = null, world = null;
    var points = null, geo = null, positions = null, colors = null, cursor = 0, filled = 0;
    var nodePos = {}, nodeData = {}, pipeline = [], nodesBuilt = false;
    var packets = [], packPts = null, packPos = null, packCol = null, spawnAcc = 0, lastT = 0;
    var running = false, raf = 0, lastEpoch = null;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    var TINT = [[0.25, 0.95, 1.0], [0.72, 0.4, 1.0], [0.25, 1.0, 0.62]];
    function readParams() {
        var d = K.data() || {}, P = d.parameters || {};
        var mu = pos(P.Mu);
        var deep = mu ? Math.max(0.7, Math.min(1.7, (1 / mu) / 400)) : 1.0;
        var maxIter = [80, 800, Math.round(2600 * deep)];
        var lp = pos(P.LambdaP) || 1, lm = pos(P.LambdaM) || 1, lg = pos(P.LambdaG) || 1, wsum = lp + lm + lg;
        var cw = [0.7 + 1.1 * (lp / wsum), 0.7 + 1.1 * (lm / wsum), 0.7 + 1.1 * (lg / wsum)];
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        var expo = 0.5 + Math.min(0.7, rate / 90);
        return { maxIter: maxIter, cw: cw, expo: expo, rate: rate, epoch: d.epoch };
    }
    var P = readParams();

    function inMainBulb(x, y) {
        var xm = x - 0.25, q = xm * xm + y * y;
        if (q * (q + xm) <= 0.25 * y * y) return true;
        var xp = x + 1; return (xp * xp + y * y) <= 0.0625;
    }
    function hashStr(s) { var h = 2166136261, i; for (i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
    function roleRGB(n) { try { var c = new THREE.Color(K.groupColor({ data: n })); return [c.r, c.g, c.b]; } catch (e) { return [0.6, 0.7, 0.8]; } }

    function initGL() {
        try { renderer = new THREE.WebGLRenderer({ antialias: false, alpha: false, powerPreference: 'low-power' }); }
        catch (e) { return false; }
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
        el.appendChild(renderer.domElement);
        renderer.domElement.style.cssText = 'display:block;width:100%;height:100%';
        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(55, 1, 0.1, 2000); camera.position.set(0, 0, 46);
        world = new THREE.Group(); scene.add(world);
        if (THREE.OrbitControls) {
            controls = new THREE.OrbitControls(camera, renderer.domElement);
            controls.enableDamping = true; controls.dampingFactor = 0.08;
            controls.autoRotate = true; controls.autoRotateSpeed = 0.7;
            controls.minDistance = 12; controls.maxDistance = 200; controls.target.set(0, 0, 0);
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

        // Click near an illuminated node cluster to select the real node: raycast
        // the cloud itself, then map the hit point to the nearest node.
        var ray = new THREE.Raycaster(), ptr = new THREE.Vector2(), dx = 0, dy = 0;
        ray.params.Points.threshold = 0.6;
        renderer.domElement.addEventListener('pointerdown', function (ev) { dx = ev.clientX; dy = ev.clientY; });
        renderer.domElement.addEventListener('pointerup', function (ev) {
            if (!nodesBuilt || Math.abs(ev.clientX - dx) + Math.abs(ev.clientY - dy) > 6) return;
            var rect = renderer.domElement.getBoundingClientRect();
            ptr.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
            ptr.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
            ray.setFromCamera(ptr, camera);
            var hit = ray.intersectObject(points, false)[0];
            if (!hit || hit.index == null) return;
            var o = hit.index * 3, hx = positions[o], hy = positions[o + 1], hz = positions[o + 2];
            var best = null, bd = 9;   // nearest node within ~3 units
            Object.keys(nodePos).forEach(function (nm) {
                var np = nodePos[nm], d = Math.hypot(np.x - hx, np.y - hy, np.z - hz);
                if (d < bd) { bd = d; best = nm; }
            });
            if (best && nodeData[best] && K.reselect) K.reselect(nodeData[best].name, nodeData[best].type);
        });
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
            while (n < mx) { var x2 = x * x, y2 = y * y; if (x2 + y2 > 4) break; if (n < keep) { trx[n] = x; tryv[n] = y; } y = 2 * x * y + cy; x = x2 - y2 + cx; n++; }
            ops += n;
            if (n >= mx) continue;
            var ch = n <= P.maxIter[0] ? 0 : (n <= P.maxIter[1] ? 1 : 2);
            var t = TINT[ch], e = P.expo * P.cw[ch], r = t[0] * e, g = t[1] * e, b = t[2] * e;
            var wz = (cx - REMID) * SZ, lim = n < keep ? n : keep;
            for (var i = 0; i < lim && added < target; i++) {
                var wx = tryv[i] * SX, wy = (REMID - trx[i]) * SY, o = cursor * 3;   // Im -> x, -Re -> y (head up)
                positions[o] = wx; positions[o + 1] = wy; positions[o + 2] = wz;
                colors[o] = r; colors[o + 1] = g; colors[o + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++; added++;
                var o2 = cursor * 3;
                positions[o2] = -wx; positions[o2 + 1] = wy; positions[o2 + 2] = wz;   // mirror across the spine
                colors[o2] = r; colors[o2 + 1] = g; colors[o2 + 2] = b;
                cursor = (cursor + 1) % MAXPTS; if (filled < MAXPTS) filled++; added++;
            }
        }
        return added;
    }

    function centerView() {
        var n = filled, sx = 0, sy = 0, sz = 0, i;
        for (i = 0; i < n; i++) { sx += positions[i * 3]; sy += positions[i * 3 + 1]; sz += positions[i * 3 + 2]; }
        var cxm = sx / n, cym = sy / n, czm = sz / n;
        if (controls) { controls.target.set(cxm, cym, czm); camera.position.set(cxm, cym, czm + 46); controls.update(); }
    }
    function buildNodesFromCloud() {
        var d = K.data() || {}, nodes = d.nodes || [];
        nodePos = {}; nodeData = {}; pipeline = [];
        var picks = [];   // {name, pos, rgb}
        nodes.forEach(function (nn) {
            if (filled <= 0 || picks.length >= 128) return;
            var idx = hashStr(nn.name) % filled, o = idx * 3;
            var p = new THREE.Vector3(positions[o], positions[o + 1], positions[o + 2]);
            nodePos[nn.name] = p; nodeData[nn.name] = nn;
            picks.push({ pos: p, rgb: roleRGB(nn) });
        });
        // recolour a small cluster of existing cloud points around each node so
        // it lights up as part of the fractal (no separate geometry).
        var r2 = 1.7 * 1.7;
        for (var i = 0; i < filled; i++) {
            var px = positions[i * 3], py = positions[i * 3 + 1], pz = positions[i * 3 + 2];
            for (var j = 0; j < picks.length; j++) {
                var np = picks[j].pos, ddx = px - np.x, ddy = py - np.y, ddz = pz - np.z;
                if (ddx * ddx + ddy * ddy + ddz * ddz < r2) {
                    var c = picks[j].rgb, o2 = i * 3;
                    colors[o2] = c[0] * 1.5; colors[o2 + 1] = c[1] * 1.5; colors[o2 + 2] = c[2] * 1.5;
                    break;
                }
            }
        }
        geo.attributes.color.needsUpdate = true;
        // pipeline for packets: gateway -> mix layers -> service
        var byType = { gateway: [], mix: [], service: [] };
        nodes.forEach(function (n) { if (byType[n.type] && nodePos[n.name]) byType[n.type].push(n.name); });
        if (byType.gateway.length) pipeline.push(byType.gateway);
        (d.layers || []).forEach(function (l) { var a = (l || []).filter(function (nm) { return nodePos[nm]; }); if (a.length) pipeline.push(a); });
        if (!(d.layers || []).length && byType.mix.length) pipeline.push(byType.mix);
        if (byType.service.length) pipeline.push(byType.service);
        nodesBuilt = true;
    }

    function meanDwell() {
        var d = K.data() || {}, mu = (d.parameters && d.parameters.Mu) || 0;
        return mu > 0 ? Math.max(0.25, Math.min(1.4, (1 / mu) / 200)) : 0.6;
    }
    function spawnPacket() {
        if (pipeline.length < 2 || packets.length >= PACK_MAX) return;
        var path = [];
        for (var i = 0; i < pipeline.length; i++) { var layer = pipeline[i], p = nodePos[layer[(Math.random() * layer.length) | 0]]; if (p) path.push(p); }
        if (path.length < 2) return;
        if (Math.random() < 0.5) path = path.slice().reverse();   // both directions
        packets.push({ path: path, seg: 0, t: 0, dwell: 0, speed: 9 + Math.random() * 7 });
    }
    function updatePackets(dt) {
        var w = packPos, c = packCol, k = 0, md = meanDwell();
        for (var i = packets.length - 1; i >= 0; i--) {
            var pk = packets[i], a = pk.path[pk.seg], b = pk.path[pk.seg + 1];
            if (pk.dwell > 0) {   // queued at the mix: dwell an exponential delay, leave shuffled
                pk.dwell -= dt;
                if (k < PACK_MAX) { var o0 = k * 3; w[o0] = b.x; w[o0 + 1] = b.y; w[o0 + 2] = b.z; c[o0] = 1.0; c[o0 + 1] = 0.7; c[o0 + 2] = 0.3; k++; }
                if (pk.dwell <= 0) { pk.seg++; pk.t = 0; if (pk.seg >= pk.path.length - 1) packets.splice(i, 1); }
                continue;
            }
            var segLen = a.distanceTo(b) || 1;
            pk.t += dt * pk.speed / segLen;
            if (pk.t >= 1) { pk.t = 1; pk.dwell = -Math.log(Math.max(1e-6, Math.random())) * md; }
            if (k < PACK_MAX) {
                var t = pk.t, o = k * 3;
                w[o] = a.x + (b.x - a.x) * t; w[o + 1] = a.y + (b.y - a.y) * t; w[o + 2] = a.z + (b.z - a.z) * t;
                c[o] = 1.0; c[o + 1] = 0.96; c[o + 2] = 0.55; k++;
            }
        }
        packPts.geometry.setDrawRange(0, k);
        packPts.geometry.attributes.position.needsUpdate = true;
        packPts.geometry.attributes.color.needsUpdate = true;
    }

    function loop() {
        if (!running) return;
        var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
        var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016; lastT = now;
        if (filled < MAXPTS) {
            addBatch(BATCH);
            geo.attributes.position.needsUpdate = true; geo.attributes.color.needsUpdate = true;
            geo.setDrawRange(0, filled);
        } else if (!nodesBuilt) { centerView(); buildNodesFromCloud(); }
        if (nodesBuilt) {
            spawnAcc += dt * (4 + Math.min(30, P.rate * 0.5));
            while (spawnAcc >= 1) { spawnPacket(); spawnAcc -= 1; }
            updatePackets(dt);
        }
        if (controls) controls.update();
        renderer.render(scene, camera);
        raf = requestAnimationFrame(loop);
    }

    function resetCloud() { cursor = 0; filled = 0; nodesBuilt = false; packets = []; if (geo) geo.setDrawRange(0, 0); }

    K.on('data', function () {
        var np = readParams();
        if (np.epoch !== lastEpoch) { P = np; lastEpoch = np.epoch; if (world) resetCloud(); }
        else { P = np; }
    });
    window.addEventListener('resize', function () { if (running) onResize(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'buddhabrot', name: 'Buddhabrot 3D', el: el,
        onShow: function () {
            P = readParams(); lastEpoch = P.epoch;
            if (!renderer && !initGL()) return;
            spawnAcc = 0; lastT = 0;
            onResize();
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
