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

    curve('sphereboustro', 'Spherical boustrophedon', function (t, T) { var lat = (t - 0.5) * Math.PI, lon = t * PI2 * 24, R = 18; return new T.Vector3(R * Math.cos(lat) * Math.cos(lon), R * Math.sin(lat), R * Math.cos(lat) * Math.sin(lon)); }, 0xff8f3f, 58, 1800);

    curve('helixtower', 'Helix tower fill', function (t, T) { var th = t * PI2 * 30, R = 14; return new T.Vector3(Math.cos(th) * R, (t - 0.5) * 36, Math.sin(th) * R); }, 0xff5d8f, 58, 1400);

    curve('doublehelix', 'Double helix fill', function (t, T) { var th = t * PI2 * 10, R = 12, s = (t < 0.5) ? 1 : -1, tt = (t < 0.5) ? t * 2 : (t - 0.5) * 2, y = (tt - 0.5) * 34; return new T.Vector3(Math.cos(th) * R * s, y, Math.sin(th) * R * s); }, 0x00d2a0, 58, 1400);

    ptsView('spherefib', 'Fibonacci sphere path', function (T) { var N = 500, GA = PI2 * (1 - 1 / ((1 + Math.sqrt(5)) / 2)), P = [], i; for (i = 0; i < N; i++) { var y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * GA; P.push(new T.Vector3(Math.cos(th) * r * 19, y * 19, Math.sin(th) * r * 19)); } return P; }, 0xffd23f, 58);

    curve('conichelix2', 'Conic helix cascade', function (t, T) { var th = t * PI2 * 12, r = 2 + Math.abs(2 * ((t * 3) % 1) - 1) * 15, y = (t - 0.5) * 34; return new T.Vector3(Math.cos(th) * r, y, Math.sin(th) * r); }, 0x4d8bf0, 58, 1600);

    curve('cylspiral', 'Cylindrical spiral wrap', function (t, T) { var th = t * PI2 * 20, R = 14, y = 18 * Math.sin(t * PI2); return new T.Vector3(Math.cos(th) * R, y, Math.sin(th) * R); }, 0x9b5de5, 58, 1400);
})();
