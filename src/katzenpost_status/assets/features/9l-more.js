(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function byTN(a, b) { return (a.type + a.name).localeCompare(b.type + b.name); }
    function pipeSpawn(cols, nodePos) {
        return function () {
            if (cols.length < 2) return null;
            var path = [];
            for (var ci = 0; ci < cols.length; ci++) { var c = cols[ci], nm = c[(Math.random() * c.length) | 0].name; if (nodePos[nm]) path.push(nodePos[nm]); }
            return path;
        };
    }
    function circleEdges(cx, cy, R, segs, color, THREE, out) {
        for (var i = 0; i < segs; i++) {
            var a1 = i / segs * PI2, a2 = (i + 1) / segs * PI2;
            out.push({ a: new THREE.Vector3(cx + Math.cos(a1) * R, cy + Math.sin(a1) * R, 0), b: new THREE.Vector3(cx + Math.cos(a2) * R, cy + Math.sin(a2) * R, 0), color: color });
        }
    }
    function placeAnchors(d, THREE, anchors, edges) {
        var order = (d.nodes || []).slice().sort(byTN), nodes = [], nodePos = {};
        order.forEach(function (n, i) {
            var p = anchors.length ? anchors[i % anchors.length].clone() : new THREE.Vector3();
            if (i >= anchors.length) p.z += Math.floor(i / anchors.length) * 2.4;
            nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
        });
        return { nodes: nodes, edges: edges, spawn: pipeSpawn(G.columns(d), nodePos) };
    }

    // Golden spiral (3D logarithmic spiral): nodes in pipeline order along it.
    G.create({
        id: 'goldenspiral', name: 'Golden spiral', rotateSpeed: 0.4, camZ: 66,
        layout: function (d, THREE) {
            var N = 300, pts = [], turns = 3.2, b = Math.log(1.618) / (Math.PI / 2), r0 = 1.4, i;
            for (i = 0; i <= N; i++) { var t = i / N, th = t * turns * PI2, r = r0 * Math.exp(b * th); pts.push(new THREE.Vector3(Math.cos(th) * r, Math.sin(th) * r, (t - 0.5) * 24)); }
            var edges = []; for (i = 0; i < pts.length - 1; i++) edges.push({ a: pts[i], b: pts[i + 1], color: 0xffd23f });
            var cols = G.columns(d), ordered = [];
            cols.forEach(function (c) { c.forEach(function (n) { ordered.push(n); }); });
            (d.nodes || []).forEach(function (n) { if (ordered.indexOf(n) < 0) ordered.push(n); });
            var nodes = [], nodePos = {}, idxOf = {}, n = ordered.length;
            ordered.forEach(function (nd, k) { var ci = n <= 1 ? 0 : Math.round(k / (n - 1) * (pts.length - 1)); var p = pts[ci].clone(); nodes.push({ name: nd.name, type: nd.type, pos: p }); nodePos[nd.name] = p; idxOf[nd.name] = ci; });
            function spawn() {
                if (cols.length < 2) return null;
                var s = cols[0], e = cols[cols.length - 1];
                var a = idxOf[s[(Math.random() * s.length) | 0].name], bb = idxOf[e[(Math.random() * e.length) | 0].name];
                if (a == null || bb == null) return null;
                var lo = Math.min(a, bb), hi = Math.max(a, bb), path = [];
                for (var i = lo; i <= hi; i++) path.push(pts[i]);
                return path.length >= 2 ? path : null;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        }
    });

    // Seed of Life: seven overlapping circles.
    G.create({
        id: 'seedoflife', name: 'Seed of Life', rotateSpeed: 0.35, camZ: 56,
        layout: function (d, THREE) {
            var R = 9, centers = [new THREE.Vector3(0, 0, 0)], i;
            for (i = 0; i < 6; i++) { var a = i * Math.PI / 3; centers.push(new THREE.Vector3(Math.cos(a) * R, Math.sin(a) * R, 0)); }
            var edges = []; centers.forEach(function (c) { circleEdges(c.x, c.y, R, 44, 0x2ec4b6, THREE, edges); });
            var anchors = centers.slice();
            for (i = 0; i < 6; i++) { var a2 = i * Math.PI / 3 + Math.PI / 6; anchors.push(new THREE.Vector3(Math.cos(a2) * R * 1.732, Math.sin(a2) * R * 1.732, 0)); }
            return placeAnchors(d, THREE, anchors, edges);
        }
    });

    // Fruit of Life: thirteen circles on a hexagonal lattice.
    G.create({
        id: 'fruitoflife', name: 'Fruit of Life', rotateSpeed: 0.35, camZ: 62,
        layout: function (d, THREE) {
            var R = 6, centers = [new THREE.Vector3(0, 0, 0)], i, a;
            for (i = 0; i < 6; i++) { a = i * Math.PI / 3; centers.push(new THREE.Vector3(Math.cos(a) * 2 * R, Math.sin(a) * 2 * R, 0)); }
            for (i = 0; i < 6; i++) { a = i * Math.PI / 3 + Math.PI / 6; centers.push(new THREE.Vector3(Math.cos(a) * 2 * Math.sqrt(3) * R, Math.sin(a) * 2 * Math.sqrt(3) * R, 0)); }
            var edges = []; centers.forEach(function (c) { circleEdges(c.x, c.y, R, 40, 0x2ec4b6, THREE, edges); });
            return placeAnchors(d, THREE, centers, edges);
        }
    });

    // Vesica Piscis: two overlapping circles.
    G.create({
        id: 'vesica', name: 'Vesica Piscis', rotateSpeed: 0.35, camZ: 52,
        layout: function (d, THREE) {
            var R = 12, edges = [];
            circleEdges(-R / 2, 0, R, 60, 0x4d8bf0, THREE, edges);
            circleEdges(R / 2, 0, R, 60, 0xff8f3f, THREE, edges);
            var h = Math.sqrt(R * R - (R / 2) * (R / 2));
            var anchors = [new THREE.Vector3(-R / 2, 0, 0), new THREE.Vector3(R / 2, 0, 0), new THREE.Vector3(0, h, 0), new THREE.Vector3(0, -h, 0), new THREE.Vector3(-R, 0, 0), new THREE.Vector3(R, 0, 0), new THREE.Vector3(0, 0, 0)];
            return placeAnchors(d, THREE, anchors, edges);
        }
    });

    // Sri Yantra: interlocking upward and downward triangles.
    G.create({
        id: 'sriyantra', name: 'Sri Yantra', rotateSpeed: 0.35, camZ: 58,
        layout: function (d, THREE) {
            var edges = [], anchors = [];
            function tri(scale, up, z) {
                var pts = [], i;
                for (i = 0; i < 3; i++) { var a = (up ? -Math.PI / 2 : Math.PI / 2) + i * PI2 / 3; pts.push(new THREE.Vector3(Math.cos(a) * scale, Math.sin(a) * scale, z)); }
                for (i = 0; i < 3; i++) { edges.push({ a: pts[i], b: pts[(i + 1) % 3], color: up ? 0xffd23f : 0xff5d8f }); anchors.push(pts[i]); }
            }
            [20, 15, 10].forEach(function (s, i) { tri(s, true, i * 0.7); });
            [22, 16, 11, 7].forEach(function (s, i) { tri(s, false, -i * 0.7); });
            return placeAnchors(d, THREE, anchors, edges);
        }
    });
})();
