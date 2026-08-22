(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function cv(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, stellate: false, layout: function (d, T) { var P = [], i, n = N || 800; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); fit(P, 18); return G.curveLayout(d, T, P, color); } }); }
    function rou(R, r, k, hh, w) { return function (t, T) { var a = 2 * PI * t, rr = R + r * Math.cos(k * a); return new T.Vector3(rr * Math.cos(a), rr * Math.sin(a), r * Math.sin(k * a) + hh * Math.sin(w * a)); }; }

    cv('rou-5-7', 'Toroidal roulette 5:7', rou(10, 6, 5, 5, 7), 0x2ec4b6, 58, 1600);
})();
