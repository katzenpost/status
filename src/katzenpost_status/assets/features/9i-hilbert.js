(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // 3D Hilbert curve: a space-filling fractal path. Nodes are placed in
    // pipeline order along the curve, so a packet literally traverses the
    // fractal as it crosses the network. Standard three.js hilbert3D generator.
    function hilbert3D(center, size, it, v0, v1, v2, v3, v4, v5, v6, v7) {
        var half = size / 2;
        var vs = [
            new THREE.Vector3(center.x - half, center.y + half, center.z - half),
            new THREE.Vector3(center.x - half, center.y + half, center.z + half),
            new THREE.Vector3(center.x - half, center.y - half, center.z + half),
            new THREE.Vector3(center.x - half, center.y - half, center.z - half),
            new THREE.Vector3(center.x + half, center.y - half, center.z - half),
            new THREE.Vector3(center.x + half, center.y - half, center.z + half),
            new THREE.Vector3(center.x + half, center.y + half, center.z + half),
            new THREE.Vector3(center.x + half, center.y + half, center.z - half)
        ];
        var v = [vs[v0], vs[v1], vs[v2], vs[v3], vs[v4], vs[v5], vs[v6], vs[v7]];
        it = it - 1;
        if (it >= 0) {
            var t = [], P = Array.prototype.push;
            P.apply(t, hilbert3D(v[0], half, it, v0, v3, v4, v7, v6, v5, v2, v1));
            P.apply(t, hilbert3D(v[1], half, it, v0, v7, v6, v1, v2, v5, v4, v3));
            P.apply(t, hilbert3D(v[2], half, it, v0, v7, v6, v1, v2, v5, v4, v3));
            P.apply(t, hilbert3D(v[3], half, it, v2, v3, v0, v1, v6, v7, v4, v5));
            P.apply(t, hilbert3D(v[4], half, it, v2, v3, v0, v1, v6, v7, v4, v5));
            P.apply(t, hilbert3D(v[5], half, it, v4, v3, v2, v5, v6, v1, v0, v7));
            P.apply(t, hilbert3D(v[6], half, it, v4, v3, v2, v5, v6, v1, v0, v7));
            P.apply(t, hilbert3D(v[7], half, it, v6, v5, v2, v1, v0, v3, v4, v7));
            return t;
        }
        return v;
    }

    window.KATZEN_GEO3D.create({
        id: 'hilbert', name: 'Hilbert path', rotateSpeed: 0.4, camZ: 66,
        layout: function (d) {
            var pts = hilbert3D(new THREE.Vector3(0, 0, 0), 44, 2, 0, 1, 2, 3, 4, 5, 6, 7);
            var edges = [];
            for (var i = 0; i < pts.length - 1; i++) edges.push({ a: pts[i], b: pts[i + 1], color: 0x2ec4b6 });
            // nodes in pipeline order, evenly spaced along the curve
            var cols = window.KATZEN_GEO3D.columns(d), ordered = [];
            cols.forEach(function (c) { c.forEach(function (n) { ordered.push(n); }); });
            (d.nodes || []).forEach(function (n) { if (ordered.indexOf(n) < 0) ordered.push(n); });
            var nodes = [], nodePos = {}, idxOf = {}, n = ordered.length;
            ordered.forEach(function (nd, i) {
                var ci = n <= 1 ? 0 : Math.round(i / (n - 1) * (pts.length - 1));
                var p = pts[ci].clone();
                nodes.push({ name: nd.name, type: nd.type, pos: p }); nodePos[nd.name] = p; idxOf[nd.name] = ci;
            });
            // packet path follows the curve from a gateway node to a later
            // service node, so it flows along the fractal.
            function spawn() {
                if (cols.length < 2) return null;
                var startCol = cols[0], endCol = cols[cols.length - 1];
                var s = startCol[(Math.random() * startCol.length) | 0], e = endCol[(Math.random() * endCol.length) | 0];
                var a = idxOf[s.name], b = idxOf[e.name];
                if (a == null || b == null) return null;
                var lo = Math.min(a, b), hi = Math.max(a, b), path = [];
                for (var i = lo; i <= hi; i++) path.push(pts[i]);
                return path.length >= 2 ? path : null;
            }
            return { nodes: nodes, edges: edges, spawn: spawn, edgeOpacity: 0.4 };
        }
    });
})();
