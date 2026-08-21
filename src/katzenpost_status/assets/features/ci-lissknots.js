(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function cv(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, stellate: false, layout: function (d, T) { var P = [], i, n = N || 800; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); fit(P, 18); return G.curveLayout(d, T, P, color); } }); }
    function lk(a, b, c, pa, pb, pc) { return function (t, T) { var u = 2 * PI * t; return new T.Vector3(Math.cos(a * u + pa), Math.cos(b * u + pb), Math.cos(c * u + pc)); }; }

    cv('lk-3-4-7', 'Lissajous knot 3:4:7', lk(3, 4, 7, 0, 1.2, 0.5), 0x2ec4b6, 58, 1200);
})();
