(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function cmul(a, b) { return [a[0] * b[0] - a[1] * b[1], a[0] * b[1] + a[1] * b[0]]; }
    function cdiv(a, b) { var d = b[0] * b[0] + b[1] * b[1] || 1e-12; return [(a[0] * b[0] + a[1] * b[1]) / d, (a[1] * b[0] - a[0] * b[1]) / d]; }
    function csub(a, b) { return [a[0] - b[0], a[1] - b[1]]; }
    function cadd(a, b) { return [a[0] + b[0], a[1] + b[1]]; }
    // Powers of a complex polynomial z^n - 1 (roots = n-th roots of unity).
    function polyPow(n) {
        var roots = [], i;
        for (i = 0; i < n; i++) roots.push([Math.cos(2 * Math.PI * i / n), Math.sin(2 * Math.PI * i / n)]);
        function pw(z, e) { var r = [1, 0], k; for (k = 0; k < e; k++) r = cmul(r, z); return r; }
        return {
            roots: roots,
            f: function (z) { return csub(pw(z, n), [1, 0]); },
            df: function (z) { return cmul([n, 0], pw(z, n - 1)); },
            ddf: function (z) { return cmul([n * (n - 1), 0], pw(z, n - 2)); }
        };
    }
    // Iteration steps. a is the (over/under) relaxation factor for Newton.
    function stepNewton(z, fv, dv, ddv, a) { return csub(z, cmul([a, 0], cdiv(fv, dv))); }
    function stepHalley(z, fv, dv, ddv, a) { var num = cmul([2, 0], cmul(fv, dv)); var den = csub(cmul([2, 0], cmul(dv, dv)), cmul(fv, ddv)); return csub(z, cdiv(num, den)); }
    function stepHouse(z, fv, dv, ddv, a) { var q = cdiv(fv, dv); var corr = cadd([1, 0], cdiv(cmul(fv, ddv), cmul([2, 0], cmul(dv, dv)))); return csub(z, cmul(q, corr)); }
    // Local k-nearest-neighbour edges for a coloured point cloud so packets can
    // route and every ball takes a themed colour from its structure.
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
    // Newton-family basins: sample the complex plane, classify each cell by the
    // root it converges to, keep only the fractal basin BOUNDARY as a coloured
    // point cloud (z-relief from the iteration count), and mesh via kNN.
    function basins(id, name, poly, step, a, W, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.16, camZ: camZ || 58, layout: function (d, THREE) {
            var N = 132, ri = new Int8Array(N * N), it = new Uint8Array(N * N), gx, gy, MAXIT = 34;
            for (gx = 0; gx < N; gx++) for (gy = 0; gy < N; gy++) {
                var z = [(gx / (N - 1) * 2 - 1) * W, (gy / (N - 1) * 2 - 1) * W], k, root = -1;
                for (k = 0; k < MAXIT; k++) {
                    var fv = poly.f(z); if (fv[0] * fv[0] + fv[1] * fv[1] < 1e-8) break;
                    var dv = poly.df(z), ddv = poly.ddf(z);
                    var nz = step(z, fv, dv, ddv, a);
                    if (!isFinite(nz[0]) || !isFinite(nz[1]) || nz[0] * nz[0] + nz[1] * nz[1] > 1e6) { k = MAXIT; break; }
                    z = nz;
                }
                var bd = 1e9, bi = -1, r;
                for (r = 0; r < poly.roots.length; r++) { var dx = z[0] - poly.roots[r][0], dy = z[1] - poly.roots[r][1], dd = dx * dx + dy * dy; if (dd < bd) { bd = dd; bi = r; } }
                if (bd > 0.25) bi = -1;
                ri[gx * N + gy] = bi; it[gx * N + gy] = Math.min(MAXIT, k);
            }
            var raw = [];
            for (gx = 1; gx < N - 1; gx++) for (gy = 1; gy < N - 1; gy++) {
                var c = ri[gx * N + gy];
                if (c !== ri[(gx + 1) * N + gy] || c !== ri[(gx - 1) * N + gy] || c !== ri[gx * N + gy + 1] || c !== ri[gx * N + gy - 1]) raw.push([gx, gy, c, it[gx * N + gy]]);
            }
            var pts = [], cols = [], stride = Math.max(1, Math.ceil(raw.length / 470)), i;
            for (i = 0; i < raw.length; i += stride) {
                var e = raw[i], x = (e[0] / (N - 1) * 2 - 1) * 18, y = (e[1] / (N - 1) * 2 - 1) * 18, zz = (e[3] / MAXIT) * 7 - 3.5;
                pts.push(new THREE.Vector3(x, y, zz)); cols.push(PAL[(e[2] < 0 ? 9 : e[2]) % PAL.length]);
            }
            if (pts.length < 6) { pts = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; cols = [PAL[0], PAL[0]]; }
            return G.anchorLayout(d, THREE, pts, knn(pts, cols, 3));
        } });
    }

    basins('nb-halley-cubic', 'Halley basins (z^3-1)', polyPow(3), stepHalley, 1, 1.6, 56);

    basins('nb-householder-cubic', 'Householder basins (z^3-1)', polyPow(3), stepHouse, 1, 1.6, 56);

    basins('nb-newton-quartic', 'Newton basins (z^4-1)', polyPow(4), stepNewton, 1, 1.7, 56);

    basins('nb-halley-quartic', 'Halley basins (z^4-1)', polyPow(4), stepHalley, 1, 1.7, 56);

    basins('nb-newton-quintic', 'Newton basins (z^5-1)', polyPow(5), stepNewton, 1, 1.7, 56);
})();
