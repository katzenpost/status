(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, T) { var P = [], i, n = N || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); return G.curveLayout(d, T, P, color); } }); }
    function liss(a, b, c, pa, pb) { return function (t, T) { var u = t * PI2; return new T.Vector3(19 * Math.sin(a * u + pa), 19 * Math.sin(b * u + pb), 19 * Math.sin(c * u)); }; }
    function rose3d(k, kz) { return function (t, T) { var th = t * PI2 * 2, r = 19 * Math.cos(k * th); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 8 * Math.sin(kz * th)); }; }

    curve('liss-4-5-3', 'Lissajous 4:5:3', liss(4, 5, 3, Math.PI / 2, 0), 0x2ec4b6, 58, 900);

    curve('liss-5-6-4', 'Lissajous 5:6:4', liss(5, 6, 4, 0.4, 1.1), 0x4d8bf0, 58, 1000);

    curve('liss-3-5-7', 'Lissajous 3:5:7', liss(3, 5, 7, 0.2, 0.7), 0x9b5de5, 58, 1000);

    curve('liss-7-5-3', 'Lissajous 7:5:3', liss(7, 5, 3, 1.1, 0.3), 0xff8f3f, 58, 1000);

    curve('liss-4-7-5', 'Lissajous 4:7:5', liss(4, 7, 5, 0.6, 0.2), 0xff5d8f, 58, 1000);

    curve('liss-8-9-7', 'Lissajous 8:9:7', liss(8, 9, 7, 0.5, 0.9), 0x00d2a0, 58, 1400);

    curve('rose3d-3', 'Rose 3D (k=3)', rose3d(3, 6), 0xffd23f, 58, 700);

    curve('rose3d-5', 'Rose 3D (k=5)', rose3d(5, 10), 0x4d8bf0, 58, 800);

    curve('rose3d-7', 'Rose 3D (k=7)', rose3d(7, 7), 0x9b5de5, 58, 900);
})();
