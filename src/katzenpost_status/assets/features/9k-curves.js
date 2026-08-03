(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Places nodes in pipeline order along a parametric curve pt(t)->Vector3 and
    // flows packets along the curve between a start and end column.
    function curveView(id, name, ptFn, color, camZ, samples) {
        G.create({
            id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 62,
            layout: function (d, THREE) {
                var N = samples || 300, pts = [], i;
                for (i = 0; i <= N; i++) pts.push(ptFn(i / N, THREE));
                var edges = [];
                for (i = 0; i < pts.length - 1; i++) edges.push({ a: pts[i], b: pts[i + 1], color: color });
                var cols = G.columns(d), ordered = [];
                cols.forEach(function (c) { c.forEach(function (n) { ordered.push(n); }); });
                (d.nodes || []).forEach(function (n) { if (ordered.indexOf(n) < 0) ordered.push(n); });
                var nodes = [], nodePos = {}, idxOf = {}, n = ordered.length;
                ordered.forEach(function (nd, k) {
                    var ci = n <= 1 ? 0 : Math.round(k / (n - 1) * (pts.length - 1));
                    var p = pts[ci].clone();
                    nodes.push({ name: nd.name, type: nd.type, pos: p }); nodePos[nd.name] = p; idxOf[nd.name] = ci;
                });
                function spawn() {
                    if (cols.length < 2) return null;
                    var s = cols[0], e = cols[cols.length - 1];
                    var a = idxOf[s[(Math.random() * s.length) | 0].name], b = idxOf[e[(Math.random() * e.length) | 0].name];
                    if (a == null || b == null) return null;
                    var lo = Math.min(a, b), hi = Math.max(a, b), path = [];
                    for (var i = lo; i <= hi; i++) path.push(pts[i]);
                    return path.length >= 2 ? path : null;
                }
                return { nodes: nodes, edges: edges, spawn: spawn };
            }
        });
    }
    var PI2 = Math.PI * 2;

    curveView('torusknot', 'Torus knot', function (t, T) {
        var p = 2, q = 3, R = 15, r = 6, ph = t * PI2;
        return new T.Vector3((R + r * Math.cos(q * ph)) * Math.cos(p * ph), (R + r * Math.cos(q * ph)) * Math.sin(p * ph), r * Math.sin(q * ph));
    }, 0x2ec4b6, 62);

    curveView('lissajous', 'Lissajous', function (t, T) {
        var u = t * PI2;
        return new T.Vector3(20 * Math.sin(3 * u + Math.PI / 2), 16 * Math.sin(2 * u), 20 * Math.sin(5 * u));
    }, 0xffb454, 66);

    curveView('rose', 'Rose curve', function (t, T) {
        var th = t * PI2 * 2, k = 4, rr = 20 * Math.cos(k * th);
        return new T.Vector3(rr * Math.cos(th), rr * Math.sin(th), 7 * Math.sin(k * th));
    }, 0xff5d8f, 60);

    curveView('toroidal', 'Toroidal coil', function (t, T) {
        var phi = t * PI2, theta = t * PI2 * 9, R = 16, r = 5;
        return new T.Vector3((R + r * Math.cos(theta)) * Math.cos(phi), (R + r * Math.cos(theta)) * Math.sin(phi), r * Math.sin(theta));
    }, 0x9b5de5, 60, 420);
})();
