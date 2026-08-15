(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 56, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function curve(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 58, layout: function (d, T) { var P = [], i, n = N || 700; for (i = 0; i <= n; i++) P.push(fn(i / n, T)); return G.curveLayout(d, T, P, color); } }); }

    ae('tonnetz', 'Tonnetz (pitch lattice)', function (a, e, T, color) { var R = 4, s = 6, S3 = Math.sqrt(3), i, j; function P(i, j) { return new T.Vector3((i + j * 0.5) * s - R * s, j * S3 / 2 * s - R * s * 0.5, 0); } for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { a.push(P(i, j)); e.push({ a: P(i, j), b: P(i + 1, j), color: color }); e.push({ a: P(i, j), b: P(i, j + 1), color: color }); e.push({ a: P(i + 1, j), b: P(i, j + 1), color: color }); } }, 0x2ec4b6, 56);

    ae('circleoffifths', 'Circle of fifths', function (a, e, T, color) { var R = 18, P = [], i; for (i = 0; i < 12; i++) { var th = i / 12 * PI2 - Math.PI / 2, k = (i * 7) % 12; P[k] = new T.Vector3(Math.cos(th) * R, Math.sin(th) * R, 0); } for (i = 0; i < 12; i++) { a.push(P[i]); e.push({ a: P[i], b: P[(i + 1) % 12], color: color }); e.push({ a: P[i], b: P[(i + 4) % 12], color: 0xff8f3f }); e.push({ a: P[i], b: P[(i + 7) % 12], color: 0x4d8bf0 }); } }, 0xffd23f, 56);

    ae('chromaticcircle', 'Chromatic circle', function (a, e, T, color) { var R = 18, P = [], i; for (i = 0; i < 12; i++) { var th = i / 12 * PI2 - Math.PI / 2; P.push(new T.Vector3(Math.cos(th) * R, Math.sin(th) * R, 0)); } for (i = 0; i < 12; i++) { a.push(P[i]); e.push({ a: P[i], b: P[(i + 1) % 12], color: color }); e.push({ a: P[i], b: P[(i + 6) % 12], color: 0xff5d8f }); } }, 0x9b5de5, 56);

    ae('justintonation', 'Just-intonation lattice', function (a, e, T, color) { var R = 3, s = 7, i, j; function P(i, j) { return new T.Vector3(i * s, j * s * 0.9, (i * 0.3 + j * 0.2) * s * 0.0); } for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { a.push(P(i, j)); if (i < R) e.push({ a: P(i, j), b: P(i + 1, j), color: color }); if (j < R) e.push({ a: P(i, j), b: P(i, j + 1), color: 0x4d8bf0 }); } }, 0x00d2a0, 56);

    curve('harmonicseries', 'Harmonic series spiral', function (t, T) { var n = 1 + t * 15, th = t * PI2 * 4, r = 20 / Math.sqrt(n); return new T.Vector3(Math.cos(th) * r, Math.sin(th) * r, (t - 0.5) * 12); }, 0xff8f3f, 58, 600);

    curve('shepardhelix', 'Shepard tone helix', function (t, T) { var th = t * PI2 * 3, R = 14; return new T.Vector3(Math.cos(th) * R, (t - 0.5) * 34, Math.sin(th) * R); }, 0x4d8bf0, 58, 500);

    curve('overtonerose', 'Overtone rose', function (t, T) { var th = t * PI2, r = 18 * Math.cos(6 * th); return new T.Vector3(r * Math.cos(th), r * Math.sin(th), 5 * Math.sin(12 * th)); }, 0xff5d8f, 56, 700);

    ae('pentatonicwheel', 'Pentatonic wheel', function (a, e, T, color) { var R = 18, P = [], i; for (i = 0; i < 5; i++) { var th = i / 5 * PI2 - Math.PI / 2; P.push(new T.Vector3(Math.cos(th) * R, Math.sin(th) * R, 0)); } for (i = 0; i < 5; i++) { a.push(P[i]); e.push({ a: P[i], b: P[(i + 1) % 5], color: color }); e.push({ a: P[i], b: P[(i + 2) % 5], color: 0xffd23f }); } }, 0x2ec4b6, 54);

    ae('chordtorus', 'Chord torus', function (a, e, T, color) { var Nu = 12, Nv = 4, R = 15, r = 6, idx = {}, i, j; function P(i, j) { var th = i / Nu * PI2, ph = j / Nv * PI2; return new T.Vector3((R + r * Math.cos(ph)) * Math.cos(th), r * Math.sin(ph), (R + r * Math.cos(ph)) * Math.sin(th)); } for (i = 0; i < Nu; i++) for (j = 0; j < Nv; j++) { idx[i + '_' + j] = P(i, j); a.push(idx[i + '_' + j]); } for (i = 0; i < Nu; i++) for (j = 0; j < Nv; j++) { e.push({ a: P(i, j), b: P((i + 1) % Nu, j), color: color }); e.push({ a: P(i, j), b: P(i, (j + 1) % Nv), color: 0x9b5de5 }); } }, 0x4d8bf0, 56);
})();
