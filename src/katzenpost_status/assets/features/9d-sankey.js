(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // Full-screen overlay: a 3D Sankey of the packet path. Nodes are laid out in
    // columns (gateway -> mix layers -> service); every carrying path is a
    // partially transparent tube, and packets flow through the pipe centres.
    var el = document.createElement('div');
    el.id = 'sankey-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#04070d;overflow:hidden';
    document.body.appendChild(el);

    var mob = window.matchMedia('(max-width: 600px)').matches;
    var PACK_MAX = mob ? 120 : 320;
    var SPACING = 15, VS = 5.5, ZJIT = 3.5;

    var renderer = null, scene = null, camera = null, controls = null, world = null;
    var nodeGroup = null, pipeGroup = null, cols = [], nodePos = {}, flowStart = 0, flowEnd = 0;
    var packets = [], packPts = null, packPos = null, packCol = null, spawnAcc = 0, lastT = 0;
    var running = false, raf = 0;

    function pos(x) { return (typeof x === 'number' && x > 0) ? x : 0; }
    function roleColor(n) { try { return new THREE.Color(K.groupColor({ data: n })); } catch (e) { return new THREE.Color(0x8aa0b4); } }

    function buildGraph() {
        if (nodeGroup) { world.remove(nodeGroup); nodeGroup = null; }
        if (pipeGroup) { world.remove(pipeGroup); disposeGroup(pipeGroup); pipeGroup = null; }
        nodePos = {}; cols = [];
        var d = K.data() || {}, nodes = d.nodes || [], byName = {};
        nodes.forEach(function (n) { byName[n.name] = n; });
        // Show every node type as a column: dir-auth, gateways, mix layers,
        // services, storage replicas, and out-of-consensus. Packets flow along
        // the core gateway -> mix -> service span (flowStart..flowEnd).
        var byType = {};
        nodes.forEach(function (n) { (byType[n.type] || (byType[n.type] = [])).push(n); });
        var dirauth = byType.dirauth || [], gws = byType.gateway || [], svcs = byType.service || [];
        var storage = byType.storage || [], out = byType.out || [];
        if (dirauth.length) cols.push(dirauth);
        flowStart = cols.length;
        if (gws.length) cols.push(gws);
        (d.layers || []).forEach(function (names) {
            var arr = names.map(function (nm) { return byName[nm]; }).filter(Boolean);
            if (arr.length) cols.push(arr);
        });
        if (svcs.length) cols.push(svcs);
        flowEnd = cols.length - 1;
        if (storage.length) cols.push(storage);
        if (out.length) cols.push(out);
        if (cols.length < 2) return;

        nodeGroup = new THREE.Group(); pipeGroup = new THREE.Group();
        var sphere = new THREE.SphereGeometry(0.8, 12, 12);
        cols.forEach(function (col, ci) {
            var x = (ci - (cols.length - 1) / 2) * SPACING;
            col.forEach(function (n, j) {
                var y = (j - (col.length - 1) / 2) * VS;
                var z = ((j % 2) * 2 - 1) * (col.length > 1 ? ZJIT : 0);
                var p = new THREE.Vector3(x, y, z);
                nodePos[n.name] = p;
                var m = new THREE.Mesh(sphere, new THREE.MeshBasicMaterial({ color: roleColor(n) }));
                m.position.copy(p); m.userData = { node: n }; nodeGroup.add(m);
            });
        });
        // pipes: full bipartite between consecutive columns (the carrying paths)
        for (var ci = 0; ci < cols.length - 1; ci++) {
            cols[ci].forEach(function (a) {
                cols[ci + 1].forEach(function (b) {
                    var pa = nodePos[a.name], pb = nodePos[b.name];
                    var tube = new THREE.TubeGeometry(new THREE.LineCurve3(pa, pb), 1, 0.34, 8, false);
                    var col = roleColor(a);
                    pipeGroup.add(new THREE.Mesh(tube, new THREE.MeshBasicMaterial({
                        color: col, transparent: true, opacity: 0.16, depthWrite: false, side: THREE.DoubleSide
                    })));
                });
            });
        }
        world.add(pipeGroup); world.add(nodeGroup);
    }
    function disposeGroup(g) {
        g.traverse(function (o) { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); });
    }

    function spawnPacket() {
        if (flowEnd <= flowStart || packets.length >= PACK_MAX) return;
        var path = [];
        for (var i = flowStart; i <= flowEnd; i++) { var c = cols[i], n = c[(Math.random() * c.length) | 0]; path.push(nodePos[n.name]); }
        if (path.length >= 2) packets.push({ path: path, seg: 0, t: 0, speed: 10 + Math.random() * 8 });
    }
    function updatePackets(dt) {
        var w = packPos, c = packCol, k = 0;
        for (var i = packets.length - 1; i >= 0; i--) {
            var pk = packets[i], a = pk.path[pk.seg], b = pk.path[pk.seg + 1], segLen = a.distanceTo(b) || 1;
            pk.t += dt * pk.speed / segLen;
            while (pk.t >= 1 && pk.seg < pk.path.length - 2) { pk.t -= 1; pk.seg++; a = pk.path[pk.seg]; b = pk.path[pk.seg + 1]; segLen = a.distanceTo(b) || 1; }
            if (pk.seg >= pk.path.length - 1 || (pk.seg === pk.path.length - 2 && pk.t >= 1)) { packets.splice(i, 1); continue; }
            if (k < PACK_MAX) {
                var t = pk.t < 0 ? 0 : pk.t > 1 ? 1 : pk.t, o = k * 3;
                w[o] = a.x + (b.x - a.x) * t; w[o + 1] = a.y + (b.y - a.y) * t; w[o + 2] = a.z + (b.z - a.z) * t;
                c[o] = 1.0; c[o + 1] = 0.96; c[o + 2] = 0.55; k++;
            }
        }
        packPts.geometry.setDrawRange(0, k);
        packPts.geometry.attributes.position.needsUpdate = true;
        packPts.geometry.attributes.color.needsUpdate = true;
    }

    function initGL() {
        try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' }); }
        catch (e) { return false; }
        renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
        el.appendChild(renderer.domElement);
        renderer.domElement.style.cssText = 'display:block;width:100%;height:100%';
        scene = new THREE.Scene();
        camera = new THREE.PerspectiveCamera(52, 1, 0.1, 3000);
        camera.position.set(0, 10, 58);
        world = new THREE.Group(); scene.add(world);
        if (THREE.OrbitControls) {
            controls = new THREE.OrbitControls(camera, renderer.domElement);
            controls.enableDamping = true; controls.dampingFactor = 0.08;
            controls.autoRotate = true; controls.autoRotateSpeed = 0.5;
            controls.minDistance = 16; controls.maxDistance = 220; controls.target.set(0, 0, 0);
        }
        packPos = new Float32Array(PACK_MAX * 3); packCol = new Float32Array(PACK_MAX * 3);
        var pg = new THREE.BufferGeometry();
        var ppa = new THREE.BufferAttribute(packPos, 3); ppa.setUsage(THREE.DynamicDrawUsage);
        var pca = new THREE.BufferAttribute(packCol, 3); pca.setUsage(THREE.DynamicDrawUsage);
        pg.setAttribute('position', ppa); pg.setAttribute('color', pca); pg.setDrawRange(0, 0);
        packPts = new THREE.Points(pg, new THREE.PointsMaterial({
            size: mob ? 1.1 : 0.85, vertexColors: true, transparent: true, opacity: 1,
            blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true
        }));
        world.add(packPts);
        // Click a node to select the real network node (shows its info panel).
        var ray = new THREE.Raycaster(), ptr = new THREE.Vector2(), dx = 0, dy = 0;
        renderer.domElement.addEventListener('pointerdown', function (ev) { dx = ev.clientX; dy = ev.clientY; });
        renderer.domElement.addEventListener('pointerup', function (ev) {
            if (!nodeGroup || Math.abs(ev.clientX - dx) + Math.abs(ev.clientY - dy) > 6) return;   // a drag, not a click
            var rect = renderer.domElement.getBoundingClientRect();
            ptr.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
            ptr.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
            ray.setFromCamera(ptr, camera);
            var hit = ray.intersectObjects(nodeGroup.children, false)[0];
            if (hit && hit.object.userData.node && K.reselect) {
                var nd = hit.object.userData.node; K.reselect(nd.name, nd.type);
            }
        });
        onResize();
        return true;
    }
    function onResize() {
        if (!renderer) return;
        var w = el.clientWidth || window.innerWidth, h = el.clientHeight || window.innerHeight;
        renderer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix();
    }

    function loop() {
        if (!running) return;
        var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
        var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016; lastT = now;
        var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
        spawnAcc += dt * (6 + Math.min(40, rate * 0.6));
        while (spawnAcc >= 1) { spawnPacket(); spawnAcc -= 1; }
        updatePackets(dt);
        if (controls) controls.update();
        renderer.render(scene, camera);
        raf = requestAnimationFrame(loop);
    }

    K.on('data', function () { if (world) buildGraph(); });
    window.addEventListener('resize', function () { if (running) onResize(); });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'sankey', name: 'Sankey pipes 3D', el: el,
        onShow: function () {
            if (!renderer && !initGL()) return;
            buildGraph(); packets = []; spawnAcc = 0; lastT = 0;
            onResize();
            if (!running) { running = true; raf = requestAnimationFrame(loop); }
        },
        onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
    });
})();
