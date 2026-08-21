(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function cv(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, stellate: false, layout: function (d, T) { var P = [], i, n = N || 800; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); fit(P, 18); return G.curveLayout(d, T, P, color); } }); }
    function tk(p, q) { return function (t, T) { var a = 2 * PI * t, r = 2 + Math.cos(q * a); return new T.Vector3(r * Math.cos(p * a), r * Math.sin(p * a), -Math.sin(q * a)); }; }

    cv('tk-2-3', 'Torus knot (2,3)', tk(2, 3), 0x2ec4b6, 58, 900);

    cv('tk-2-5', 'Torus knot (2,5)', tk(2, 5), 0x4d8bf0, 58, 900);

    cv('tk-2-7', 'Torus knot (2,7)', tk(2, 7), 0x9b5de5, 58, 900);

    cv('tk-3-4', 'Torus knot (3,4)', tk(3, 4), 0xff5d8f, 58, 900);

    cv('tk-3-5', 'Torus knot (3,5)', tk(3, 5), 0xff8f3f, 58, 900);

    cv('tk-3-7', 'Torus knot (3,7)', tk(3, 7), 0x00d2a0, 58, 900);

    cv('tk-4-5', 'Torus knot (4,5)', tk(4, 5), 0xffd23f, 58, 900);
})();
