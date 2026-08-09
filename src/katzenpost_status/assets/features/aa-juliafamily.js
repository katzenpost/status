(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    // Sample an escape-time fractal and keep boundary cells (escape count within
    // a band), meshed by nearest neighbour so packets ride the boundary.
    function escapeCloud(id, name, iter, x0, x1, y0, y1, lo, hi, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 56,
            layout: function (d, THREE) {
                var N = 240, raw = [], i, j;
                for (i = 0; i < N; i++) for (j = 0; j < N; j++) {
                    var cx = x0 + (x1 - x0) * i / N, cy = y0 + (y1 - y0) * j / N, n = iter(cx, cy);
                    if (n >= lo && n <= hi) raw.push([cx, cy]);
                }
                var pts = [], step = Math.max(1, Math.floor(raw.length / 620));
                for (i = 0; i < raw.length; i += step) pts.push(raw[i]);
                var sx = 42 / Math.max(1e-6, x1 - x0), sy = 42 / Math.max(1e-6, y1 - y0), s = Math.min(sx, sy);
                var mcx = (x0 + x1) / 2, mcy = (y0 + y1) / 2;
                var V = pts.map(function (p) { return new THREE.Vector3((p[0] - mcx) * s, (p[1] - mcy) * s, 0); });
                if (V.length < 4) return G.anchorLayout(d, THREE, V, []);
                return G.anchorLayout(d, THREE, V, knn(V, THREE, 3, color));
            } });
    }
    var MAXIT = 60;
    function mandel(cx, cy) { var x = 0, y = 0, n = 0; while (n < MAXIT && x * x + y * y < 4) { var t = x * x - y * y + cx; y = 2 * x * y + cy; x = t; n++; } return n; }
    function julia(cx, cy, ax, ay) { var x = cx, y = cy, n = 0; while (n < MAXIT && x * x + y * y < 4) { var t = x * x - y * y + ax; y = 2 * x * y + ay; x = t; n++; } return n; }

    escapeCloud('mandelbrot', 'Mandelbrot set', mandel, -2.2, 0.8, -1.3, 1.3, 6, 28, 0x2ec4b6, 56);

    escapeCloud('juliarabbit', 'Julia set (Douady rabbit)', function (x, y) { return julia(x, y, -0.123, 0.745); }, -1.6, 1.6, -1.3, 1.3, 5, 30, 0x4d8bf0, 56);

    escapeCloud('juliadendrite', 'Julia set (dendrite)', function (x, y) { return julia(x, y, 0.0, 1.0); }, -1.8, 1.8, -1.8, 1.8, 6, 34, 0x9b5de5, 56);

    escapeCloud('juliaspiral', 'Julia set (spiral)', function (x, y) { return julia(x, y, -0.8, 0.156); }, -1.7, 1.7, -1.2, 1.2, 5, 30, 0xff8f3f, 56);

    escapeCloud('burningship', 'Burning ship fractal', function (cx, cy) { var x = 0, y = 0, n = 0; while (n < MAXIT && x * x + y * y < 4) { var t = x * x - y * y + cx; y = Math.abs(2 * x * y) + cy; x = t < 0 ? t : t; x = Math.abs(x) * (t < 0 ? 1 : 1); x = t; x = Math.abs(x); x = x + cx - cx; var xx = Math.abs(x); y = y; n++; if (x * x + y * y >= 4) break; } var X = 0, Y = 0; n = 0; while (n < MAXIT && X * X + Y * Y < 4) { var ax = Math.abs(X), ay = Math.abs(Y); var nt = ax * ax - ay * ay + cx; Y = 2 * ax * ay + cy; X = nt; n++; } return n; }, -1.8, -1.7 + 0.9, -0.1, 1.0, 6, 34, 0xff5d8f, 56);

    escapeCloud('tricorn', 'Tricorn (Mandelbar)', function (cx, cy) { var x = 0, y = 0, n = 0; while (n < MAXIT && x * x + y * y < 4) { var t = x * x - y * y + cx; y = -2 * x * y + cy; x = t; n++; } return n; }, -2.0, 1.2, -1.4, 1.4, 6, 28, 0x00d2a0, 56);
})();
