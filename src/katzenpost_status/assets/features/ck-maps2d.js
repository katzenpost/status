(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function knn(pts, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function m2(id, name, step, x0, transient, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, T) { var p = x0.slice(), i, P = []; for (i = 0; i < transient; i++) p = step(p); for (i = 0; i < 900; i++) { p = step(p); if (!isFinite(p[0]) || !isFinite(p[1]) || Math.abs(p[0]) > 1e6) break; P.push(new T.Vector3(p[0], p[1], 0)); } fit(P, 18); return G.anchorLayout(d, T, P, knn(P, 2, color)); } }); }

    m2('map2-gingerbread', 'Gingerbread man map', function (p) { return [1 - p[1] + Math.abs(p[0]), p[0]]; }, [-0.1, 0], 100, 0x2ec4b6);

    m2('map2-standard', 'Standard (Chirikov) map', function (p) { var K = 0.971635, np = p[1] + K * Math.sin(p[0]); np = ((np % (2 * PI)) + 2 * PI) % (2 * PI); var nt = ((p[0] + np) % (2 * PI) + 2 * PI) % (2 * PI); return [nt, np]; }, [2, 0.5], 0, 0x4d8bf0);

    m2('map2-hopalong', 'Hopalong (Martin) map', function (p) { var a = -55, b = -1, c = -42; return [p[1] - (p[0] < 0 ? -1 : 1) * Math.sqrt(Math.abs(b * p[0] - c)), a - p[0]]; }, [0, 0], 50, 0x9b5de5);

    m2('map2-hopalong2', 'Hopalong (Martin) map II', function (p) { var a = 0.4, b = 1, c = 0; return [p[1] - (p[0] < 0 ? -1 : 1) * Math.sqrt(Math.abs(b * p[0] - c)), a - p[0]]; }, [0, 0], 50, 0xff5d8f);

    m2('map2-martin', 'Sine Hopalong map', function (p) { var a = PI; return [p[1] - Math.sin(p[0]), a - p[0]]; }, [0, 0], 50, 0xff8f3f);

    m2('map2-chip', 'Chip map (Pickover)', function (p) { var a = -15, b = -19, c = 1; return [p[1] - (p[0] < 0 ? -1 : 1) * Math.cos(Math.atan(Math.abs(b * p[0] - c))) * Math.sin(Math.log(Math.abs(a * p[0] - c) + 1)), a - p[0]]; }, [0, 0], 50, 0x00d2a0);

    m2('map2-quadruptwo', 'Quadruptwo (Pickover)', function (p) { var a = 34, b = 1, c = 5, s = (b * p[0] - c) < 0 ? -1 : 1; return [p[1] - s * Math.sin(Math.log(Math.abs(b * p[0] - c) + 1)) * Math.atan((c - b * p[0]) * (c - b * p[0])), a - p[0]]; }, [0, 0], 50, 0xffd23f);

    m2('map2-duffing', 'Duffing map', function (p) { var a = 2.75, b = 0.2; return [p[1], -b * p[0] + a * p[1] - p[1] * p[1] * p[1]]; }, [0.1, 0], 200, 0xff5d6c);

    m2('map2-gumowskimira', 'Gumowski-Mira map', function (p) { var a = -0.2, b = 0.99; function g(x) { return a * x + 2 * (1 - a) * x * x / (1 + x * x); } var ny = b * p[1] + g(p[0]); return [ny, -p[0] + g(ny)]; }, [4, 0], 300, 0x33ccff);
})();
