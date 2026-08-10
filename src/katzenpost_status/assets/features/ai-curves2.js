(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var P = [], i, n = N || 700; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }

    curve('viviani', "Viviani's curve", function (t, T) { var a = 10, u = t * 2 * PI2; return new T.Vector3(a * (1 + Math.cos(u)) - a, a * Math.sin(u), 2 * a * Math.sin(u / 2)); }, 0x2ec4b6, 58, 700);

    curve('sphericalspiral', 'Spherical spiral', function (t, T) { var R = 18, th = t * PI2 * 15, ph = t * Math.PI; return new T.Vector3(R * Math.sin(ph) * Math.cos(th), R * Math.cos(ph), R * Math.sin(ph) * Math.sin(th)); }, 0x4d8bf0, 56, 900);

    curve('conicalhelix', 'Conical helix', function (t, T) { var th = t * PI2 * 6, r = t * 15, h = (t - 0.5) * 32; return new T.Vector3(r * Math.cos(th), h, r * Math.sin(th)); }, 0x9b5de5, 58, 700);

    curve('baseballseam', 'Baseball seam curve', function (t, T) { var R = 18, u = t * PI2, L = 0.62 * Math.sin(2 * u), w = 0.62 * Math.cos(2 * u) * Math.sin(u); return new T.Vector3(R * Math.cos(L) * Math.cos(u), R * Math.sin(L), R * Math.cos(L) * Math.sin(u)); }, 0xff8f3f, 56, 700);

    curve('spirograph', 'Spirograph (hypotrochoid)', function (t, T) { var R = 14, r = 5, dd = 8, u = t * PI2 * 5, k = (R - r) / r; return new T.Vector3((R - r) * Math.cos(u) + dd * Math.cos(k * u), (R - r) * Math.sin(u) - dd * Math.sin(k * u), 0); }, 0xff5d8f, 56, 1200);

    curve('epicycloid', 'Epicycloid', function (t, T) { var R = 12, r = R / 5, u = t * PI2 * 5, k = (R + r) / r; return new T.Vector3((R + r) * Math.cos(u) - r * Math.cos(k * u), (R + r) * Math.sin(u) - r * Math.sin(k * u), 0); }, 0x00d2a0, 56, 900);

    curve('hypocycloid', 'Hypocycloid (astroid)', function (t, T) { var R = 16, r = R / 7, u = t * PI2, k = (R - r) / r; return new T.Vector3((R - r) * Math.cos(u) + r * Math.cos(k * u), (R - r) * Math.sin(u) - r * Math.sin(k * u), 0); }, 0xffd23f, 56, 900);

    G.create({ id: 'cornu', name: 'Cornu spiral (clothoid)', rotateSpeed: 0.3, camZ: 54, layout: function (d, THREE) { var pts = [], N = 500, ds = 0.016, x = 0, y = 0, i; var pos = [], s; x = 0; y = 0; for (i = 0; i <= N; i++) { s = i * ds; x += Math.cos(Math.PI * s * s / 2) * ds; y += Math.sin(Math.PI * s * s / 2) * ds; pos.push([x, y]); } var neg = [[0, 0]]; x = 0; y = 0; for (i = 1; i <= N; i++) { s = i * ds; x -= Math.cos(Math.PI * s * s / 2) * ds; y -= Math.sin(Math.PI * s * s / 2) * ds; neg.push([x, y]); } var all = neg.slice().reverse().concat(pos); var sc = 26; all.forEach(function (p) { pts.push(new THREE.Vector3(p[0] * sc, p[1] * sc, 0)); }); return G.curveLayout(d, THREE, pts, 0x4d8bf0); } });

    curve('lemniscate', 'Lemniscate (figure eight)', function (t, T) { var u = t * PI2, a = 18, dn = 1 + Math.sin(u) * Math.sin(u); return new T.Vector3(a * Math.cos(u) / dn, a * Math.sin(u) * Math.cos(u) / dn, 6 * Math.sin(2 * u)); }, 0xff8f3f, 54, 700);

    ae('villarceau', 'Villarceau circles', function (a, e, T, color) { var M = 9, R = 14, al = Math.asin(6 / R), i, s; for (i = 0; i < M; i++) { var be = i / M * PI2, prev = null, first = null; for (s = 0; s <= 48; s++) { var th = s / 48 * PI2; var x0 = R * Math.cos(th), y0 = R * Math.sin(th) * Math.cos(al), z0 = R * Math.sin(th) * Math.sin(al); var x = x0 * Math.cos(be) - y0 * Math.sin(be), y = x0 * Math.sin(be) + y0 * Math.cos(be); var p = new T.Vector3(x, z0, y); if (s % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } } }, 0x9b5de5, 56);
})();
