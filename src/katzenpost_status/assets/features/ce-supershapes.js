(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function gridEdges(A, idx, U, Vn, color, wrapU, wrapV) { var E = [], i, j; function add(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < U; i++) for (j = 0; j < Vn; j++) { add(i, j, i + 1, j); add(i, j, i, j + 1); } if (wrapV) for (i = 0; i <= U; i++) add(i, Vn, i, 0); if (wrapU) for (j = 0; j <= Vn; j++) add(U, j, 0, j); return E; }
    function surf(id, name, pfn, U, Vn, color, camZ, wrapU, wrapV) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 60, stellate: false, layout: function (d, T) { var A = [], idx = {}, i, j; for (i = 0; i <= U; i++) for (j = 0; j <= Vn; j++) { idx[i + '_' + j] = A.length; A.push(pfn(i / U, j / Vn, T)); } fit(A, 18); return G.anchorLayout(d, T, A, gridEdges(A, idx, U, Vn, color, wrapU, wrapV)); } }); }
    function superr(theta, m, n1, n2, n3) { var t = m * theta / 4, a = Math.pow(Math.abs(Math.cos(t)), n2), b = Math.pow(Math.abs(Math.sin(t)), n3), r = Math.pow(a + b, -1 / n1); if (!isFinite(r)) r = 0; return Math.min(r, 6); }
    function ss(P) { return function (u, v, T) { var th = -PI + 2 * PI * u, ph = -PI / 2 + PI * v, r1 = superr(th, P[0], P[1], P[2], P[3]), r2 = superr(ph, P[4], P[5], P[6], P[7]); return new T.Vector3(r1 * Math.cos(th) * r2 * Math.cos(ph), r1 * Math.sin(th) * r2 * Math.cos(ph), r2 * Math.sin(ph)); }; }

    surf('ss-star6', 'Supershape star', ss([6,0.3,1.7,1.7,6,0.3,1.7,1.7]), 48, 24, 0x2ec4b6, 60, true, false);

    surf('ss-flower5', 'Supershape flower', ss([5,0.4,1.5,1.5,5,0.4,1.5,1.5]), 48, 24, 0x4d8bf0, 60, true, false);

    surf('ss-gear', 'Supershape gear', ss([12,10,10,10,12,10,10,10]), 48, 24, 0x9b5de5, 60, true, false);

    surf('ss-bloom', 'Supershape bloom', ss([3,5,18,18,3,5,18,18]), 48, 24, 0xff5d8f, 60, true, false);

    surf('ss-pinch', 'Supershape pinch', ss([7,2,8,8,2,2,8,8]), 48, 24, 0xff8f3f, 60, true, false);

    surf('ss-cushion', 'Supershape cushion', ss([4,1,1,1,4,1,1,1]), 48, 24, 0x00d2a0, 60, true, false);

    surf('ss-urchin', 'Supershape urchin', ss([10,0.2,1.7,1.7,10,0.2,1.7,1.7]), 48, 24, 0xffd23f, 60, true, false);

    surf('ss-lobed8', 'Supershape lobed', ss([8,1,1,8,8,1,1,8]), 48, 24, 0xff5d6c, 60, true, false);

    surf('ss-shell', 'Supershape shell', ss([2,1,4,8,6,1,1,1]), 48, 24, 0x33ccff, 60, true, false);

    surf('ss-diamond', 'Supershape diamond', ss([4,0.5,0.5,0.5,4,0.5,0.5,0.5]), 48, 24, 0x8a5bff, 60, true, false);
})();
