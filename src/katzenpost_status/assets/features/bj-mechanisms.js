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

    curve('spirograph2', 'Spirograph (dense)', function (t, T) { var R = 16, r = 6.2, dd = 9, u = t * PI2 * 31, k = (R - r) / r; return new T.Vector3((R - r) * Math.cos(u) + dd * Math.cos(k * u), (R - r) * Math.sin(u) - dd * Math.sin(k * u), 0); }, 0x00d2a0, 56, 2400);

    curve('epitrochoid', 'Epitrochoid', function (t, T) { var R = 12, r = 3.3, dd = 6, u = t * PI2 * 10, k = (R + r) / r; return new T.Vector3((R + r) * Math.cos(u) - dd * Math.cos(k * u), (R + r) * Math.sin(u) - dd * Math.sin(k * u), 0); }, 0xffd23f, 56, 1400);

    curve('harmonograph3d', 'Harmonograph (3D)', function (t, T) { var s = t * 60, e1 = Math.exp(-0.008 * s), e2 = Math.exp(-0.006 * s), e3 = Math.exp(-0.01 * s); return new T.Vector3(18 * e1 * Math.sin(2.0 * s + 0.2), 18 * e2 * Math.sin(3.01 * s + 1.2), 14 * e3 * Math.sin(5.0 * s)); }, 0x4d8bf0, 58, 1800);

    curve('lissajous3d', 'Lissajous (3D 5:4:3)', function (t, T) { var u = t * PI2; return new T.Vector3(19 * Math.sin(5 * u + Math.PI / 2), 19 * Math.sin(4 * u), 19 * Math.sin(3 * u + Math.PI / 4)); }, 0x9b5de5, 58, 900);

    G.create({ id: 'anamorphicgrid', name: 'Anamorphic grid', rotateSpeed: 0.28, camZ: 56, layout: function (d, THREE) { var a = [], e = [], M = 16, i, j; function warp(x, y) { var r = 4 + (y + 1) * 8, th = x * Math.PI; return new THREE.Vector3(Math.cos(th) * r, Math.sin(th) * r, 0); } for (i = 0; i <= M; i++) { var prev = null; for (j = 0; j <= M; j++) { var p = warp(i / M * 2 - 1, j / M * 2 - 1); if (j % 2 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: 0xff8f3f }); prev = p; } } for (j = 0; j <= M; j++) { var prev2 = null; for (i = 0; i <= M; i++) { var p2 = warp(i / M * 2 - 1, j / M * 2 - 1); if (prev2) e.push({ a: prev2, b: p2, color: 0xff8f3f }); prev2 = p2; } } return G.anchorLayout(d, THREE, a, e); } });
})();
