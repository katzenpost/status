(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.42, camZ: camZ || 58, layout: function (d, THREE) { var P = [], i, n = N || 600; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } }); }
    function tk(id, name, p, q, color) { curve(id, name, function (t, T) { var R = 15, r = 6, a = t * PI2; return new T.Vector3((R + r * Math.cos(q * a)) * Math.cos(p * a), (R + r * Math.cos(q * a)) * Math.sin(p * a), r * Math.sin(q * a)); }, color, 58, 520); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 56, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, THREE)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, THREE, A, E); } }); }

    tk('knot52', '(5,2) torus knot', 5, 2, 0x2ec4b6);

    tk('knot53', '(5,3) torus knot', 5, 3, 0x4d8bf0);

    tk('knot74', '(7,4) torus knot', 7, 4, 0x9b5de5);
})();
