(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var P = [], i, n = N || 700; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }

    curve('viviani', "Viviani's curve", function (t, T) { var a = 10, u = t * 2 * PI2; return new T.Vector3(a * (1 + Math.cos(u)) - a, a * Math.sin(u), 2 * a * Math.sin(u / 2)); }, 0x2ec4b6, 58, 700);
})();
