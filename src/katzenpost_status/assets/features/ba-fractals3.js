(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function escapeCloud(id, name, iter, x0, x1, y0, y1, lo, hi, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 56, layout: function (d, THREE) {
            var N = 230, raw = [], i, j; for (i = 0; i < N; i++) for (j = 0; j < N; j++) { var cx = x0 + (x1 - x0) * i / N, cy = y0 + (y1 - y0) * j / N, n = iter(cx, cy); if (n >= lo && n <= hi) raw.push([cx, cy]); }
            var pts = [], step = Math.max(1, Math.floor(raw.length / 620)); for (i = 0; i < raw.length; i += step) pts.push(raw[i]);
            var s = Math.min(42 / Math.max(1e-6, x1 - x0), 42 / Math.max(1e-6, y1 - y0)), mcx = (x0 + x1) / 2, mcy = (y0 + y1) / 2;
            var V = pts.map(function (p) { return new THREE.Vector3((p[0] - mcx) * s, (p[1] - mcy) * s, 0); });
            if (V.length < 4) return G.anchorLayout(d, THREE, V, []);
            return G.anchorLayout(d, THREE, V, knn(V, THREE, 3, color));
        } });
    }
    function cloud(id, name, gen, k, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) { var pts = gen(THREE); if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []); return G.anchorLayout(d, THREE, pts, knn(pts, THREE, k, color)); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.26, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function cmul(a, b) { return [a[0] * b[0] - a[1] * b[1], a[0] * b[1] + a[1] * b[0]]; }
    function cdiv(a, b) { var d = b[0] * b[0] + b[1] * b[1] + 1e-12; return [(a[0] * b[0] + a[1] * b[1]) / d, (a[1] * b[0] - a[0] * b[1]) / d]; }

    escapeCloud('nova', 'Nova fractal', function (cx, cy) { var z = [1, 0], c = [cx, cy], n; for (n = 0; n < 60; n++) { var z2 = cmul(z, z), z3 = cmul(z2, z), num = [z3[0] - 1, z3[1]], den = [3 * z2[0], 3 * z2[1]], q = cdiv(num, den); var nz = [z[0] - q[0] + c[0], z[1] - q[1] + c[1]], dx = nz[0] - z[0], dy = nz[1] - z[1]; z = nz; if (dx * dx + dy * dy < 1e-6) break; } return n; }, -1.5, 1.5, -1.5, 1.5, 4, 26, 0x2ec4b6, 56);

    escapeCloud('magnet', 'Magnet fractal (type I)', function (cx, cy) { var z = [0, 0], c = [cx, cy], n; for (n = 0; n < 60; n++) { var num = [z[0] * z[0] - z[1] * z[1] + c[0] - 1, 2 * z[0] * z[1] + c[1]], den = [2 * z[0] + c[0] - 2, 2 * z[1] + c[1]], q = cdiv(num, den); z = cmul(q, q); var m = z[0] * z[0] + z[1] * z[1]; if (m > 1e6) break; var d1 = z[0] - 1, d2 = z[1]; if (d1 * d1 + d2 * d2 < 1e-6) break; } return n; }, -1, 3, -2, 2, 4, 26, 0x4d8bf0, 56);

    escapeCloud('lambda', 'Lambda fractal', function (cx, cy) { var z = [0.5, 0], c = [cx, cy], n; for (n = 0; n < 60; n++) { var om = [1 - z[0], -z[1]], zz = cmul(z, om); z = cmul(c, zz); if (z[0] * z[0] + z[1] * z[1] > 100) break; } return n; }, -0.5, 4, -2, 2, 5, 28, 0x9b5de5, 56);

    escapeCloud('collatzfractal', 'Collatz fractal', function (cx, cy) { var z = [cx, cy], n; for (n = 0; n < 40; n++) { var pz = [Math.PI * z[0], Math.PI * z[1]]; var cr = Math.cos(pz[0]) * Math.cosh(pz[1]), ci = -Math.sin(pz[0]) * Math.sinh(pz[1]); var a = [2 + 7 * z[0], 7 * z[1]], b = cmul([2 + 5 * z[0], 5 * z[1]], [cr, ci]); z = [0.25 * (a[0] - b[0]), 0.25 * (a[1] - b[1])]; if (z[0] * z[0] + z[1] * z[1] > 1e8) break; } return n; }, -3, 5, -2.5, 2.5, 3, 18, 0xff8f3f, 56);

    ae('pythagorastree', 'Pythagoras tree', function (a, e, T, color) { function sq(x, y, ux, uy, depth) { var vx = -uy, vy = ux; var p = [[x, y], [x + ux, y + uy], [x + ux + vx, y + uy + vy], [x + vx, y + vy]]; for (var i = 0; i < 4; i++) { var q = p[i], r = p[(i + 1) % 4]; e.push({ a: new T.Vector3(q[0], q[1], 0), b: new T.Vector3(r[0], r[1], 0), color: color }); a.push(new T.Vector3(q[0], q[1], 0)); } if (depth <= 0) return; var tx = p[3][0], ty = p[3][1], tx2 = p[2][0], ty2 = p[2][1]; var ang = Math.PI / 4, ca = Math.cos(ang), sa = Math.sin(ang); var lx = ux * ca - uy * sa, ly = ux * sa + uy * ca; var apex = [tx + lx * 0.707, ty + ly * 0.707]; sq(tx, ty, apex[0] - tx, apex[1] - ty, depth - 1); sq(apex[0], apex[1], tx2 - apex[0], ty2 - apex[1], depth - 1); } sq(-5, -22, 10, 0, 9); }, 0x00d2a0, 60);
})();
