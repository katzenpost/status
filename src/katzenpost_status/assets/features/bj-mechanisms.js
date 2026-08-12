(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var P = [], i, n = N || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } }); }
    function caustic(id, name, k, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 54, layout: function (d, THREE) { var N = 200, R = 20, a = [], e = [], i; function pt(x) { var th = (x % N) / N * PI2; return new THREE.Vector3(Math.cos(th) * R, Math.sin(th) * R, 0); } for (i = 0; i < N; i++) { var p = pt(i), q = pt(i * k); a.push(p); e.push({ a: p, b: q, color: color }); } return G.anchorLayout(d, THREE, a, e); } }); }

    caustic('cardioidcaustic', 'Cardioid caustic', 2, 0x2ec4b6, 54);

    caustic('nephroidcaustic', 'Nephroid caustic', 3, 0x4d8bf0, 54);

    caustic('causticstar', 'Caustic star (x7)', 7, 0x9b5de5, 54);

    curve('maurerrose', 'Maurer rose (n6 d71)', function (t, T) { var k = t * 360, th = k * 71 * Math.PI / 180, r = 20 * Math.sin(6 * th); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 4 * Math.sin(3 * th)); }, 0xff8f3f, 56, 361);

    curve('maurerrose7', 'Maurer rose (n7 d115)', function (t, T) { var k = t * 360, th = k * 115 * Math.PI / 180, r = 20 * Math.sin(7 * th); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 4 * Math.cos(4 * th)); }, 0xff5d8f, 56, 361);
})();
