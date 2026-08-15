(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.38, camZ: camZ || 58, layout: function (d, T) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, T)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, T, A, E); } }); }
    function ring(a, e, T, cx, cy, cz, R, segs, color) { var prev = null, first = null; for (var s = 0; s <= segs; s++) { var t = s / segs * PI2, p = new T.Vector3(cx + Math.cos(t) * R, cy, cz + Math.sin(t) * R); if (s % 3 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } }

    ae('lightcone', 'Light cone', function (a, e, T, color) { var H = 20, seg = 24, k; for (var s = -1; s <= 1; s += 2) { for (k = 0; k <= 4; k++) { ring(a, e, T, 0, s * k / 4 * H, 0, k / 4 * H, seg, color); } for (k = 0; k < seg; k++) { var th = k / seg * PI2; e.push({ a: new T.Vector3(0, 0, 0), b: new T.Vector3(Math.cos(th) * H, s * H, Math.sin(th) * H), color: 0xffd23f }); } } a.push(new T.Vector3(0, 0, 0)); }, 0x4d8bf0, 58);

    ae('minkowskigrid', 'Minkowski diagram', function (a, e, T, color) { var R = 20, i, N = 10; for (i = -N; i <= N; i++) { var u = i / N * R; e.push({ a: new T.Vector3(u, -R, 0), b: new T.Vector3(u, R, 0), color: color }); a.push(new T.Vector3(u, 0, 0)); e.push({ a: new T.Vector3(-R, u, 0), b: new T.Vector3(R, u, 0), color: color }); } e.push({ a: new T.Vector3(-R, -R, 0), b: new T.Vector3(R, R, 0), color: 0xffd23f }); e.push({ a: new T.Vector3(-R, R, 0), b: new T.Vector3(R, -R, 0), color: 0xffd23f }); }, 0x2a5a6a, 56);

    ae('penrosediagram', 'Penrose diagram', function (a, e, T, color) { var R = 20, N = 8, i; for (i = 0; i <= N; i++) { var t = i / N; e.push({ a: new T.Vector3((t - 0.5) * 2 * R, -R, 0), b: new T.Vector3(0, -R + t * 2 * R, 0), color: color }); } var d = [[-R, 0], [0, R], [R, 0], [0, -R]]; for (i = 0; i < 4; i++) { e.push({ a: new T.Vector3(d[i][0], d[i][1], 0), b: new T.Vector3(d[(i + 1) % 4][0], d[(i + 1) % 4][1], 0), color: 0xffd23f }); a.push(new T.Vector3(d[i][0], d[i][1], 0)); } for (i = 1; i < N; i++) { var s = i / N; e.push({ a: new T.Vector3(-R + s * R, s * R - R + R, 0), b: new T.Vector3(R - s * R, s * R, 0), color: color }); } }, 0x9b5de5, 56);

    surf('blackholefunnel', 'Black-hole funnel', function (u, v, T) { var r = 2 + u * 22, th = v * PI2, z = -30 / Math.sqrt(r); return new T.Vector3(r * Math.cos(th), z, r * Math.sin(th)); }, 40, 50, 0x4d8bf0, 58);

    surf('flammparaboloid', 'Flamm paraboloid', function (u, v, T) { var M = 2, r = 2 * M + u * 22, th = v * PI2, z = 2 * Math.sqrt(2 * M * (r - 2 * M)); return new T.Vector3(r * Math.cos(th), z - 12, r * Math.sin(th)); }, 40, 50, 0x9b5de5, 58);

    ae('worldlines', 'Worldline bundle', function (a, e, T, color) { var cols = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0xff5d8f], k; for (k = 0; k < 5; k++) { var x0 = (k - 2) * 6, prev = null; for (var i = 0; i <= 80; i++) { var t = i / 80, y = (t - 0.5) * 36, x = x0 + 4 * Math.sin(t * 6 + k); var p = new T.Vector3(x, y, 0); if (i % 6 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: cols[k] }); prev = p; } } }, 0x2ec4b6, 56);

    ae('lensinggrid', 'Gravitational lensing', function (a, e, T, color) { var R = 22, N = 14, M = 40; function warp(x, y) { var r = Math.hypot(x, y) + 1e-3, f = 1 + M / (r * r); return [x * f * 0.6, y * f * 0.6]; } var i, j; for (i = 0; i <= N; i++) { var prev = null; for (j = 0; j <= N * 2; j++) { var w = warp((i / N - 0.5) * 2 * R, (j / (N * 2) - 0.5) * 2 * R), p = new T.Vector3(w[0], w[1], 0); if (j % 3 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } } for (j = 0; j <= N; j++) { var prev2 = null; for (i = 0; i <= N * 2; i++) { var w2 = warp((i / (N * 2) - 0.5) * 2 * R, (j / N - 0.5) * 2 * R), p2 = new T.Vector3(w2[0], w2[1], 0); if (prev2) e.push({ a: prev2, b: p2, color: color }); prev2 = p2; } } }, 0x00d2a0, 56);

    surf('desitter', 'de Sitter hyperboloid', function (u, v, T) { var t = (u - 0.5) * 3, th = v * PI2, R = 8 * Math.cosh(t); return new T.Vector3(R * Math.cos(th), t * 8, R * Math.sin(th)); }, 40, 44, 0xffd23f, 58);

    ae('twinparadox', 'Twin paradox', function (a, e, T, color) { var prev = null, i; for (i = 0; i <= 40; i++) { var y = (i / 40 - 0.5) * 36, p = new T.Vector3(-8, y, 0); if (i % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: 0x2ec4b6 }); prev = p; } var A = new T.Vector3(-8, -18, 0), B = new T.Vector3(10, 0, 0), C = new T.Vector3(-8, 18, 0); e.push({ a: A, b: B, color: 0xff8f3f }); e.push({ a: B, b: C, color: 0xff8f3f }); a.push(A); a.push(B); a.push(C); }, 0x4d8bf0, 56);
})();
