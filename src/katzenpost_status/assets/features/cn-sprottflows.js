(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function fl(id, name, step, dt, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 62, stellate: false, layout: function (d, T) { var p = [0.05, 0.05, 0.05], i, P = []; for (i = 0; i < 1500; i++) p = step(p, dt); for (i = 0; i < 5000; i++) { p = step(p, dt); if (!isFinite(p[0]) || !isFinite(p[1]) || !isFinite(p[2]) || Math.abs(p[0]) > 1e3) break; P.push(new T.Vector3(p[0], p[1], p[2])); } fit(P, 18); return G.curveLayout(d, T, P, color); } }); }

    fl('sprotta', 'Sprott A flow', function (p, h) { return [p[0] + h * p[1], p[1] + h * (-p[0] + p[1] * p[2]), p[2] + h * (1 - p[1] * p[1])]; }, 0.02, 0x2ec4b6);

    fl('sprotth', 'Sprott H flow', function (p, h) { return [p[0] + h * (-p[1] + p[2] * p[2]), p[1] + h * (p[0] + 0.5 * p[1]), p[2] + h * (p[0] - p[2])]; }, 0.008, 0x4d8bf0);
})();
