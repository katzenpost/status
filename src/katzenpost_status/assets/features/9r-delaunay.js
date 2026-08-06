(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Delaunay / Voronoi mesh: a triangulation of random sites (Bowyer-Watson).
    // The Delaunay edges form a natural routable network for the packets.
    function circum(a, b, c) {
        var ax = a.x, ay = a.y, bx = b.x, by = b.y, cx = c.x, cy = c.y;
        var dd = 2 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by));
        if (Math.abs(dd) < 1e-9) return null;
        var ux = ((ax * ax + ay * ay) * (by - cy) + (bx * bx + by * by) * (cy - ay) + (cx * cx + cy * cy) * (ay - by)) / dd;
        var uy = ((ax * ax + ay * ay) * (cx - bx) + (bx * bx + by * by) * (ax - cx) + (cx * cx + cy * cy) * (bx - ax)) / dd;
        var r2 = (ax - ux) * (ax - ux) + (ay - uy) * (ay - uy);
        return { x: ux, y: uy, r2: r2 };
    }
    function delaunay(pts) {
        var st = [{ x: -1e4, y: -1e4 }, { x: 1e4, y: -1e4 }, { x: 0, y: 1e4 }];
        var tris = [{ p: [st[0], st[1], st[2]], c: circum(st[0], st[1], st[2]) }];
        pts.forEach(function (p) {
            var bad = [], i;
            for (i = tris.length - 1; i >= 0; i--) { var cc = tris[i].c; if (cc && (p.x - cc.x) * (p.x - cc.x) + (p.y - cc.y) * (p.y - cc.y) <= cc.r2 * 1.0000001) bad.push(tris.splice(i, 1)[0]); }
            var poly = [];
            bad.forEach(function (t) {
                [[t.p[0], t.p[1]], [t.p[1], t.p[2]], [t.p[2], t.p[0]]].forEach(function (e) {
                    var shared = false;
                    bad.forEach(function (t2) { if (t2 === t) return; [[t2.p[0], t2.p[1]], [t2.p[1], t2.p[2]], [t2.p[2], t2.p[0]]].forEach(function (e2) { if ((e[0] === e2[0] && e[1] === e2[1]) || (e[0] === e2[1] && e[1] === e2[0])) shared = true; }); });
                    if (!shared) poly.push(e);
                });
            });
            poly.forEach(function (e) { tris.push({ p: [e[0], e[1], p], c: circum(e[0], e[1], p) }); });
        });
        return tris.filter(function (t) { return st.indexOf(t.p[0]) < 0 && st.indexOf(t.p[1]) < 0 && st.indexOf(t.p[2]) < 0; });
    }

    G.create({
        id: 'delaunay', name: 'Delaunay mesh', rotateSpeed: 0.28, camZ: 56,
        layout: function (d, THREE) {
            var sites = [], i;
            for (i = 0; i < 30; i++) { var a = Math.random() * Math.PI * 2, r = Math.sqrt(Math.random()) * 22; sites.push({ x: Math.cos(a) * r, y: Math.sin(a) * r }); }
            var tris = delaunay(sites), edges = [], seen = {}, anchors = sites.map(function (s) { return new THREE.Vector3(s.x, s.y, 0); });
            var idx = {}; sites.forEach(function (s, k) { idx[s.x + ',' + s.y] = k; });
            tris.forEach(function (t) {
                [[t.p[0], t.p[1]], [t.p[1], t.p[2]], [t.p[2], t.p[0]]].forEach(function (e) {
                    var ka = idx[e[0].x + ',' + e[0].y], kb = idx[e[1].x + ',' + e[1].y];
                    if (ka == null || kb == null) return;
                    var lo = Math.min(ka, kb), hi = Math.max(ka, kb), key = lo + '_' + hi;
                    if (seen[key]) return; seen[key] = 1;
                    edges.push({ a: anchors[lo], b: anchors[hi], color: 0x4d8bf0 });
                });
            });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
