(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ptsView(id, name, gen, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 58, layout: function (d, T) { return G.curveLayout(d, T, gen(T), color); } }); }
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, T) { var P = [], i, n = N || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); return G.curveLayout(d, T, P, color); } }); }

    ptsView('cubefill', 'Boustrophedon cube fill', function (T) { var n = 6, s = 34 / n, P = [], x, y, z; for (z = 0; z < n; z++) { var yr = (z % 2 === 0); for (var yy = 0; yy < n; yy++) { y = yr ? yy : n - 1 - yy; var xr = ((z * n + y) % 2 === 0); for (var xx = 0; xx < n; xx++) { x = xr ? xx : n - 1 - xx; P.push(new T.Vector3((x - n / 2) * s, (y - n / 2) * s, (z - n / 2) * s)); } } } return P; }, 0x2ec4b6, 60);

    curve('layerspiral', 'Layered spiral fill', function (t, T) { var th = t * PI2 * 40, r = 2 + (1 - Math.abs(2 * ((t * 6) % 1) - 1)) * 16, z = (t - 0.5) * 34; return new T.Vector3(Math.cos(th) * r, z, Math.sin(th) * r); }, 0x4d8bf0, 60, 2000);

    curve('toruswind', 'Dense torus winding', function (t, T) { var phi = t * PI2 * 3, theta = t * PI2 * 40, R = 15, r = 6; return new T.Vector3((R + r * Math.cos(theta)) * Math.cos(phi), r * Math.sin(theta), (R + r * Math.cos(theta)) * Math.sin(phi)); }, 0x9b5de5, 58, 2400);
})();
