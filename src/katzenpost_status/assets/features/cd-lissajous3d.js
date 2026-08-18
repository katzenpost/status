(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, T) { var P = [], i, n = N || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); return G.curveLayout(d, T, P, color); } }); }
    function liss(a, b, c, pa, pb) { return function (t, T) { var u = t * PI2; return new T.Vector3(19 * Math.sin(a * u + pa), 19 * Math.sin(b * u + pb), 19 * Math.sin(c * u)); }; }
    function rose3d(k, kz) { return function (t, T) { var th = t * PI2 * 2, r = 19 * Math.cos(k * th); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 8 * Math.sin(kz * th)); }; }

    curve('liss-4-5-3', 'Lissajous 4:5:3', liss(4, 5, 3, Math.PI / 2, 0), 0x2ec4b6, 58, 900);
})();
