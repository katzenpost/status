(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function cv(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, stellate: false, layout: function (d, T) { var P = [], i, n = N || 800; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); fit(P, 18); return G.curveLayout(d, T, P, color); } }); }
    function rou(R, r, k, hh, w) { return function (t, T) { var a = 2 * PI * t, rr = R + r * Math.cos(k * a); return new T.Vector3(rr * Math.cos(a), rr * Math.sin(a), r * Math.sin(k * a) + hh * Math.sin(w * a)); }; }

    cv('rou-5-7', 'Toroidal roulette 5:7', rou(10, 6, 5, 5, 7), 0x2ec4b6, 58, 1600);

    cv('rou-7-9', 'Toroidal roulette 7:9', rou(11, 5, 7, 4, 9), 0x4d8bf0, 58, 1600);

    cv('rou-3-5', 'Toroidal roulette 3:5', rou(9, 7, 3, 6, 5), 0x9b5de5, 58, 1600);

    cv('rou-9-11', 'Toroidal roulette 9:11', rou(12, 4, 9, 3, 11), 0xff5d8f, 58, 1600);

    cv('rou-4-3', 'Toroidal roulette 4:3', rou(10, 5, 4, 5, 3), 0xff8f3f, 58, 1600);

    cv('rou-6-10', 'Toroidal roulette 6:10', rou(8, 8, 6, 4, 10), 0x00d2a0, 58, 1600);
})();
