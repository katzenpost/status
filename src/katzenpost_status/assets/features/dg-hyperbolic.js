(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    // {p,q} regular tiling of the Poincare disk grown by reflecting the central
    // p-gon across its edges (each edge is a geodesic = a circle orthogonal to
    // the unit disk; reflection = inversion in that circle). Coloured by ring.
    function tiling(id, name, p, q, maxPoly, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.12, camZ: camZ || 56, layout: function (d, THREE) {
            var c = Math.cos(Math.PI / q) / Math.sin(Math.PI / p);
            if (c <= 1) { var f = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; return G.anchorLayout(d, THREE, f, [{ a: f[0], b: f[1], color: PAL[0] }]); }
            var R = Math.sqrt((c - 1) / (c + 1)), k;
            function poly0() { var vs = [], a; for (k = 0; k < p; k++) { a = 2 * Math.PI * k / p; vs.push([R * Math.cos(a), R * Math.sin(a)]); } return vs; }
            function geo(A, B) { var ka = (A[0] * A[0] + A[1] * A[1] + 1) / 2, kb = (B[0] * B[0] + B[1] * B[1] + 1) / 2, det = A[0] * B[1] - A[1] * B[0]; if (Math.abs(det) < 1e-9) return null; var Cx = (ka * B[1] - kb * A[1]) / det, Cy = (A[0] * kb - B[0] * ka) / det; return [Cx, Cy, Cx * Cx + Cy * Cy - 1]; }
            function refl(P, g) { var dx = P[0] - g[0], dy = P[1] - g[1], dd = dx * dx + dy * dy || 1e-9, ff = g[2] / dd; return [g[0] + dx * ff, g[1] + dy * ff]; }
            function cent(vs) { var x = 0, y = 0, i; for (i = 0; i < vs.length; i++) { x += vs[i][0]; y += vs[i][1]; } return [x / vs.length, y / vs.length]; }
            function ckey(ct) { return Math.round(ct[0] * 800) + '_' + Math.round(ct[1] * 800); }
            var queue = [{ vs: poly0(), depth: 0 }], seen = {}, polys = [], head = 0;
            seen[ckey(cent(poly0()))] = 1;
            while (head < queue.length && polys.length < maxPoly) {
                var cur = queue[head++]; polys.push(cur);
                if (cur.depth >= 6) continue;
                for (k = 0; k < p; k++) {
                    var A = cur.vs[k], B = cur.vs[(k + 1) % p], g = geo(A, B); if (!g) continue;
                    var nv = cur.vs.map(function (P) { return refl(P, g); }), ct = cent(nv), kk = ckey(ct);
                    if (seen[kk] || ct[0] * ct[0] + ct[1] * ct[1] > 0.9985) continue;
                    seen[kk] = 1; queue.push({ vs: nv, depth: cur.depth + 1 });
                }
            }
            var edges = [], eseen = {}, anchors = [], aseen = {};
            function ak(x, y) { return Math.round(x * 900) + '_' + Math.round(y * 900); }
            polys.forEach(function (pl) {
                var col = PAL[pl.depth % PAL.length], i;
                for (i = 0; i < p; i++) {
                    var A = pl.vs[i], B = pl.vs[(i + 1) % p], a3 = new THREE.Vector3(A[0] * 18, A[1] * 18, 0), b3 = new THREE.Vector3(B[0] * 18, B[1] * 18, 0);
                    var ka = ak(A[0], A[1]), kb = ak(B[0], B[1]), ek = ka < kb ? ka + ':' + kb : kb + ':' + ka;
                    if (!eseen[ek]) { eseen[ek] = 1; edges.push({ a: a3, b: b3, color: col }); }
                    if (!aseen[ka]) { aseen[ka] = 1; anchors.push(a3); }
                }
            });
            if (edges.length < 4) { anchors = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; edges = [{ a: anchors[0], b: anchors[1], color: PAL[0] }]; }
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }

    tiling('hy-tiling-3-7', 'Hyperbolic tiling {3,7}', 3, 7, 160, 56);

    tiling('hy-tiling-7-3', 'Hyperbolic tiling {7,3}', 7, 3, 90, 56);

    tiling('hy-tiling-4-5', 'Hyperbolic tiling {4,5}', 4, 5, 130, 56);

    tiling('hy-tiling-5-4', 'Hyperbolic tiling {5,4}', 5, 4, 110, 56);

    tiling('hy-tiling-3-8', 'Hyperbolic tiling {3,8}', 3, 8, 160, 56);

    tiling('hy-tiling-8-3', 'Hyperbolic tiling {8,3}', 8, 3, 80, 56);

    tiling('hy-tiling-4-6', 'Hyperbolic tiling {4,6}', 4, 6, 130, 56);
})();
