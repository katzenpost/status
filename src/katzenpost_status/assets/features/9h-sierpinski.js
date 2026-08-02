(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    // Sierpinski tetrahedron: a 3D fractal. The recursion produces many small
    // tetrahedra; nodes sit on their centroids and packets flow the pipeline
    // along the fractal edges.
    window.KATZEN_GEO3D.create({
        id: 'sierpinski', name: 'Sierpinski tetra', rotateSpeed: 0.55, camZ: 62,
        layout: function (d, THREE) {
            var S = 22;
            var corners = [
                new THREE.Vector3(1, 1, 1), new THREE.Vector3(1, -1, -1),
                new THREE.Vector3(-1, 1, -1), new THREE.Vector3(-1, -1, 1)
            ].map(function (v) { return v.multiplyScalar(S / 1.7); });
            var tetras = [];
            (function sierp(v, depth) {
                if (depth === 0) { tetras.push(v); return; }
                for (var i = 0; i < 4; i++) {
                    var sub = [];
                    for (var j = 0; j < 4; j++) sub.push(v[i].clone().add(v[j]).multiplyScalar(0.5));
                    sierp(sub, depth - 1);
                }
            })(corners, 2);   // 16 small tetrahedra
            var edges = [], centroids = [];
            tetras.forEach(function (t) {
                for (var i = 0; i < 4; i++) for (var j = i + 1; j < 4; j++) edges.push({ a: t[i], b: t[j], color: 0x9b5de5 });
                centroids.push(t[0].clone().add(t[1]).add(t[2]).add(t[3]).multiplyScalar(0.25));
            });
            // order centroids top-to-bottom (by y) so tiers map to fractal depth
            centroids.sort(function (a, b) { return b.y - a.y; });
            var cols = window.KATZEN_GEO3D.columns(d);
            var ordered = []; cols.forEach(function (c) { c.forEach(function (n) { ordered.push(n); }); });
            (d.nodes || []).forEach(function (n) { if (ordered.indexOf(n) < 0) ordered.push(n); });   // include the rest
            var nodes = [], nodePos = {};
            ordered.forEach(function (n, i) {
                var p = centroids.length ? centroids[i % centroids.length].clone() : new THREE.Vector3();
                nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
            });
            function spawn() {
                if (cols.length < 2) return null;
                var path = [];
                for (var ci = 0; ci < cols.length; ci++) { var c = cols[ci], nm = c[(Math.random() * c.length) | 0].name; if (nodePos[nm]) path.push(nodePos[nm]); }
                return path;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        }
    });
})();
