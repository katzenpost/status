(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function cdiv(a, b) { var d = b[0] * b[0] + b[1] * b[1] || 1e-12; return [(a[0] * b[0] + a[1] * b[1]) / d, (a[1] * b[0] - a[0] * b[1]) / d]; }
    function knn(pts, cols, k) {
        var edges = [], seen = {}, i, j, m;
        for (i = 0; i < pts.length; i++) {
            var ds = [];
            for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]);
            ds.sort(function (a, b) { return a[0] - b[0]; });
            for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], key = Math.min(i, jj) + '_' + Math.max(i, jj); if (!seen[key]) { seen[key] = 1; edges.push({ a: pts[i], b: pts[jj], color: cols[i] }); } }
        }
        return edges;
    }
    // Kleinian / Schottky group limit set. A ring of 2n circles is paired
    // opposite-to-opposite; each pairing gives a Mobius generator T(z)=b+k/(z-a)
    // (maps the exterior of circle A into the interior of circle B) plus its
    // inverse. The generators are contractions toward the limit set, so a random
    // walk over them (never immediately undoing the last move) converges onto it.
    // k carries a twist angle -> loxodromic spiral limit sets.
    function schottky(id, name, npair, rfac, twist, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.14, camZ: camZ || 58, layout: function (d, THREE) {
            var M = 2 * npair, R = 10, r = R * Math.sin(Math.PI / M) * rfac, circ = [], i;
            for (i = 0; i < M; i++) { var th = 2 * Math.PI * i / M; circ.push([R * Math.cos(th), R * Math.sin(th)]); }
            var maps = [];   // each: {a,b,k}; partner index is idx^1
            for (i = 0; i < npair; i++) {
                var A = circ[i], B = circ[i + npair], k = [r * r * Math.cos(twist), r * r * Math.sin(twist)];
                maps.push({ a: A, b: B, k: k }); maps.push({ a: B, b: A, k: k });
            }
            var z = [0.13, 0.09], pts = [], cols = [], last = -1, s;
            for (s = 0; s < 60 + 520; s++) {
                var mi; do { mi = (Math.random() * maps.length) | 0; } while (last >= 0 && mi === (last ^ 1));
                var mp = maps[mi], q = cdiv(mp.k, [z[0] - mp.a[0], z[1] - mp.a[1]]);
                z = [mp.b[0] + q[0], mp.b[1] + q[1]]; last = mi;
                if (!isFinite(z[0]) || !isFinite(z[1]) || z[0] * z[0] + z[1] * z[1] > 1e6) { z = [0.13, 0.09]; last = -1; continue; }
                if (s >= 60 && pts.length < 500) { pts.push([z[0], z[1], mi]); }
            }
            if (pts.length < 8) { return G.anchorLayout(d, THREE, [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)], [{ a: new THREE.Vector3(-6, 0, 0), b: new THREE.Vector3(6, 0, 0), color: PAL[0] }]); }
            var mx = 1e-6; pts.forEach(function (p) { mx = Math.max(mx, Math.abs(p[0]), Math.abs(p[1])); });
            var sc = 18 / mx, v = [], cl = [];
            pts.forEach(function (p) { v.push(new THREE.Vector3(p[0] * sc, p[1] * sc, ((p[2] % 5) - 2) * 0.9)); cl.push(PAL[p[2] % PAL.length]); });
            return G.anchorLayout(d, THREE, v, knn(v, cl, 3));
        } });
    }

    schottky('ls-schottky-2', 'Schottky group (2 pairs)', 2, 0.9, 0.0, 56);

    schottky('ls-schottky-2-spiral', 'Loxodromic Schottky (2 pairs)', 2, 0.9, 1.2, 56);

    schottky('ls-schottky-3', 'Schottky group (3 pairs)', 3, 0.92, 0.0, 56);

    schottky('ls-schottky-3-spiral', 'Loxodromic Schottky (3 pairs)', 3, 0.92, 1.0, 56);

    schottky('ls-schottky-4', 'Schottky group (4 pairs)', 4, 0.94, 0.0, 56);

    schottky('ls-schottky-4-spiral', 'Loxodromic Schottky (4 pairs)', 4, 0.94, 0.9, 56);
})();
