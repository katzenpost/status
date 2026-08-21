(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function gridEdges(A, idx, U, Vn, color, wrapU, wrapV) { var E = [], i, j; function add(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < U; i++) for (j = 0; j < Vn; j++) { add(i, j, i + 1, j); add(i, j, i, j + 1); } if (wrapV) for (i = 0; i <= U; i++) add(i, Vn, i, 0); if (wrapU) for (j = 0; j <= Vn; j++) add(U, j, 0, j); return E; }
    function surf(id, name, pfn, U, Vn, color, camZ, wrapU, wrapV) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 60, stellate: false, layout: function (d, T) { var A = [], idx = {}, i, j; for (i = 0; i <= U; i++) for (j = 0; j <= Vn; j++) { idx[i + '_' + j] = A.length; A.push(pfn(i / U, j / Vn, T)); } fit(A, 18); return G.anchorLayout(d, T, A, gridEdges(A, idx, U, Vn, color, wrapU, wrapV)); } }); }
    function plgndr(l, m, x) { var pmm = 1, i, ll; if (m > 0) { var somx2 = Math.sqrt(Math.max(0, (1 - x) * (1 + x))), fact = 1; for (i = 1; i <= m; i++) { pmm *= -fact * somx2; fact += 2; } } if (l === m) return pmm; var pmmp1 = x * (2 * m + 1) * pmm; if (l === m + 1) return pmmp1; var pll = 0; for (ll = m + 2; ll <= l; ll++) { pll = (x * (2 * ll - 1) * pmmp1 - (ll + m - 1) * pmm) / (ll - m); pmm = pmmp1; pmmp1 = pll; } return pll; }
    function hy(l, m) { return function (u, v, T) { var phi = 2 * PI * u, theta = PI * v, r = Math.abs(plgndr(l, m, Math.cos(theta)) * Math.cos(m * phi)); return new T.Vector3(r * Math.sin(theta) * Math.cos(phi), r * Math.sin(theta) * Math.sin(phi), r * Math.cos(theta)); }; }

    surf('shy-y41', 'Spherical harmonic Y(4,1)', hy(4, 1), 60, 40, 0x2ec4b6, 60, true, false);

    surf('shy-y51', 'Spherical harmonic Y(5,1)', hy(5, 1), 60, 40, 0x4d8bf0, 60, true, false);

    surf('shy-y52', 'Spherical harmonic Y(5,2)', hy(5, 2), 60, 40, 0x9b5de5, 60, true, false);

    surf('shy-y54', 'Spherical harmonic Y(5,4)', hy(5, 4), 60, 40, 0xff5d8f, 60, true, false);

    surf('shy-y62', 'Spherical harmonic Y(6,2)', hy(6, 2), 60, 40, 0xff8f3f, 60, true, false);

    surf('shy-y64', 'Spherical harmonic Y(6,4)', hy(6, 4), 60, 40, 0x00d2a0, 60, true, false);

    surf('shy-y71', 'Spherical harmonic Y(7,1)', hy(7, 1), 60, 40, 0xffd23f, 60, true, false);

    surf('shy-y73', 'Spherical harmonic Y(7,3)', hy(7, 3), 60, 40, 0xff5d6c, 60, true, false);
})();
