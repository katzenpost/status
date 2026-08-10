(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 56, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function circle(a, e, T, cx, cy, r, segs, color) { var prev = null, first = null; for (var s = 0; s <= segs; s++) { var t = s / segs * PI2, p = new T.Vector3(cx + Math.cos(t) * r, cy + Math.sin(t) * r, 0); if (s % 3 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } }
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 58, layout: function (d, THREE) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, THREE)); } function ad(a, b, c, e2) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e2]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, THREE, A, E); } }); }
    function gcd(a, b) { while (b) { var t = b; b = a % b; a = t; } return a; }
    var D = 20;

    ae('fordcircles', 'Ford circles', function (a, e, T, color) { var Q = 9, q, p; for (q = 1; q <= Q; q++) for (p = 0; p <= q; p++) { if (gcd(p, q) !== 1) continue; var r = 1 / (2 * q * q), cx = (p / q - 0.5) * 2 * D, cy = -D + r * 2 * D; circle(a, e, T, cx, cy, r * 2 * D, 20, color); } }, 0x2ec4b6, 56);

    ae('poincaregeodesics', 'Poincare geodesics', function (a, e, T, color) { circle(a, e, T, 0, 0, D, 64, color); var i, j, M = 16; for (i = 0; i < M; i++) for (j = i + 2; j < M; j++) { var t1 = i / M * PI2, t2 = j / M * PI2, dt = (t2 - t1) / 2; if (Math.abs(Math.cos(dt)) < 0.08) continue; var cd = 1 / Math.cos(dt), cx = Math.cos((t1 + t2) / 2) * cd * D, cy = Math.sin((t1 + t2) / 2) * cd * D, rr = Math.abs(Math.tan(dt)) * D; if (rr > D * 4) continue; var a1 = Math.atan2(Math.sin(t1) * D - cy, Math.cos(t1) * D - cx), a2 = Math.atan2(Math.sin(t2) * D - cy, Math.cos(t2) * D - cx); var prev = null; for (var s = 0; s <= 16; s++) { var da = a2 - a1; while (da > Math.PI) da -= PI2; while (da < -Math.PI) da += PI2; var ang = a1 + da * s / 16, p = new T.Vector3(cx + Math.cos(ang) * rr, cy + Math.sin(ang) * rr, 0); if (s % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } } }, 0x4d8bf0, 56);

    ae('hyperbolictree', 'Hyperbolic tree', function (a, e, T, color) { function node(x, y, ang, spread, r, depth, parent) { var p = new T.Vector3(x * D, y * D, 0); a.push(p); if (parent) e.push({ a: parent, b: p, color: color }); if (depth <= 0) return; var nb = parent ? 2 : 5, nr = r + (1 - r) * 0.55; for (var i = 0; i < nb; i++) { var ca = ang + (i - (nb - 1) / 2) * spread; node(Math.cos(ca) * nr, Math.sin(ca) * nr, ca, spread * 0.5, nr, depth - 1, p); } } node(0, 0, 0, PI2 / 5, 0.02, 5, null); }, 0x9b5de5, 56);

    ae('steinerchain', 'Steiner chain', function (a, e, T, color) { var R = D, r = D * 0.34, n = 6, cr = (R - r) / 2, cd = (R + r) / 2; circle(a, e, T, 0, 0, R, 60, color); circle(a, e, T, 0, 0, r, 40, color); for (var i = 0; i < n; i++) { var th = i / n * PI2; circle(a, e, T, Math.cos(th) * cd, Math.sin(th) * cd, cr, 30, color); } }, 0xff8f3f, 56);
})();
