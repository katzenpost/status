(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 58, layout: function (d, T) { var P = [], i, n = N || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); return G.curveLayout(d, T, P, color); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function ring(a, e, T, cx, cy, R, segs, color) { var prev = null, first = null; for (var s = 0; s <= segs; s++) { var t = s / segs * PI2, p = new T.Vector3(cx + Math.cos(t) * R, cy + Math.sin(t) * R, 0); if (s % 3 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } }

    ae('epicycledeferent', 'Epicycle & deferent', function (a, e, T, color) { ring(a, e, T, 0, 0, 16, 60, 0x2a4a5a); var prev = null; for (var i = 0; i <= 900; i++) { var t = i / 900 * PI2, x = 16 * Math.cos(t) + 4 * Math.cos(12 * t), y = 16 * Math.sin(t) + 4 * Math.sin(12 * t); var p = new T.Vector3(x, y, 0); if (i % 6 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } }, 0xffd23f, 56);

    curve('rosetteorbit', 'Rosette orbit (precessing)', function (t, T) { var th = t * PI2 * 8, a = 18, ecc = 0.5, r = a * (1 - ecc * ecc) / (1 + ecc * Math.cos(th - t * PI2 * 0.9)); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 0); }, 0x2ec4b6, 56, 1400);

    curve('lissajousorbit', 'Lissajous orbit', function (t, T) { var u = t * PI2; return new T.Vector3(18 * Math.sin(3 * u), 16 * Math.sin(4 * u + 0.6), 8 * Math.sin(5 * u)); }, 0x4d8bf0, 56, 900);

    curve('analemma', 'Analemma (figure-8)', function (t, T) { var d = t * PI2, decl = 20 * Math.sin(d), eot = 9.87 * Math.sin(2 * d) - 7.53 * Math.cos(d) - 1.5 * Math.sin(d); return new T.Vector3(eot * 1.7, decl * 0.9, 0); }, 0x9b5de5, 52, 700);

    ae('threebodyfig8', 'Three-body figure-8', function (a, e, T, color) { var cols = [0x2ec4b6, 0xff8f3f, 0x9b5de5], s; for (s = 0; s < 3; s++) { var prev = null, off = s / 3; for (var i = 0; i <= 300; i++) { var u = (i / 300 + off) * PI2, dn = 1 + Math.sin(u) * Math.sin(u), x = 18 * Math.cos(u) / dn, y = 18 * Math.sin(u) * Math.cos(u) / dn; var p = new T.Vector3(x, y, 0); if (i % 6 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: cols[s] }); prev = p; } } }, 0x2ec4b6, 54);
})();
