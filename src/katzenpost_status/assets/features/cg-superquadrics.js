(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function gridEdges(A, idx, U, Vn, color, wrapU, wrapV) { var E = [], i, j; function add(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < U; i++) for (j = 0; j < Vn; j++) { add(i, j, i + 1, j); add(i, j, i, j + 1); } if (wrapV) for (i = 0; i <= U; i++) add(i, Vn, i, 0); if (wrapU) for (j = 0; j <= Vn; j++) add(U, j, 0, j); return E; }
    function surf(id, name, pfn, U, Vn, color, camZ, wrapU, wrapV) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 60, stellate: false, layout: function (d, T) { var A = [], idx = {}, i, j; for (i = 0; i <= U; i++) for (j = 0; j <= Vn; j++) { idx[i + '_' + j] = A.length; A.push(pfn(i / U, j / Vn, T)); } fit(A, 18); return G.anchorLayout(d, T, A, gridEdges(A, idx, U, Vn, color, wrapU, wrapV)); } }); }
    function sgn(v) { return v < 0 ? -1 : 1; }
    function sp(b, e) { return sgn(b) * Math.pow(Math.abs(b), e); }
    function se(e1, e2) { return function (u, v, T) { var uu = -PI + 2 * PI * u, vv = -PI / 2 + PI * v; return new T.Vector3(sp(Math.cos(vv), e1) * sp(Math.cos(uu), e2), sp(Math.cos(vv), e1) * sp(Math.sin(uu), e2), sp(Math.sin(vv), e1)); }; }
    function st(e1, e2, RR) { return function (u, v, T) { var uu = -PI + 2 * PI * u, vv = -PI + 2 * PI * v; return new T.Vector3((RR + sp(Math.cos(vv), e1)) * sp(Math.cos(uu), e2), (RR + sp(Math.cos(vv), e1)) * sp(Math.sin(uu), e2), sp(Math.sin(vv), e1)); }; }

    surf('sq-cube', 'Superellipsoid cube', se(0.25, 0.25), 50, 28, 0x2ec4b6, 60, true, false);

    surf('sq-octa', 'Superellipsoid octahedron', se(2.5, 2.5), 50, 28, 0x4d8bf0, 60, true, false);

    surf('sq-star', 'Superellipsoid star', se(3, 0.4), 50, 28, 0x9b5de5, 60, true, false);

    surf('sq-pillow', 'Superellipsoid pillow', se(0.3, 2.6), 50, 28, 0xff5d8f, 60, true, false);

    surf('sq-rounded', 'Superellipsoid rounded', se(0.7, 0.7), 50, 28, 0xff8f3f, 60, true, false);

    surf('sq-spiky', 'Superellipsoid spiky', se(0.2, 3), 50, 28, 0x00d2a0, 60, true, false);
})();
