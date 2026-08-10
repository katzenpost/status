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
})();
