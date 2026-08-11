(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 56, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function V(T, x, y, z) { return new T.Vector3(x, y, z || 0); }
    function seg(e, a, p, q, color) { e.push({ a: p, b: q, color: color }); a.push(p); }

    ae('miuraori', 'Miura-ori crease pattern', function (a, e, T, color) { var cols = 10, rows = 8, dx = 4, dy = 4.5, sh = 1.6, i, j; function P(i, j) { return V(T, (i - cols / 2) * dx, (j - rows / 2) * dy + (i % 2 ? sh : 0), 0); } for (i = 0; i <= cols; i++) for (j = 0; j <= rows; j++) { if (i < cols) seg(e, a, P(i, j), P(i + 1, j), color); if (j < rows) seg(e, a, P(i, j), P(i, j + 1), color); } }, 0x2ec4b6, 56);

    ae('waterbomb', 'Waterbomb tessellation', function (a, e, T, color) { var n = 7, s = 6, i, j; function P(x, y) { return V(T, (x - n / 2) * s, (y - n / 2) * s, 0); } for (i = 0; i < n; i++) for (j = 0; j < n; j++) { seg(e, a, P(i, j), P(i + 1, j), color); seg(e, a, P(i, j), P(i, j + 1), color); seg(e, a, P(i, j), P(i + 1, j + 1), color); seg(e, a, P(i + 1, j), P(i, j + 1), color); seg(e, a, P(i, j + 0.5), P(i + 1, j + 0.5), color); seg(e, a, P(i + 0.5, j), P(i + 0.5, j + 1), color); } }, 0x4d8bf0, 58);

    ae('yoshimura', 'Yoshimura diamond pattern', function (a, e, T, color) { var cols = 10, rows = 8, dx = 4, dy = 4, i, j; function P(i, j) { return V(T, (i - cols / 2) * dx + (j % 2 ? dx / 2 : 0), (j - rows / 2) * dy, 0); } for (i = 0; i <= cols; i++) for (j = 0; j <= rows; j++) { if (j < rows) { seg(e, a, P(i, j), P(i, j + 1), color); seg(e, a, P(i, j), P(i - (j % 2 ? 0 : 1), j + 1), color); seg(e, a, P(i, j), P(i + (j % 2 ? 1 : 0), j + 1), color); } } }, 0x9b5de5, 56);

    ae('kresling', 'Kresling twist tower', function (a, e, T, color) { var n = 8, rows = 7, R = 12, H = 34, tw = 0.5, i, r; var rings = []; for (r = 0; r <= rows; r++) { var ring = []; for (i = 0; i < n; i++) { var th = i / n * PI2 + r * tw; ring.push(V(T, Math.cos(th) * R, -H / 2 + H * r / rows, Math.sin(th) * R)); } rings.push(ring); } for (r = 0; r <= rows; r++) for (i = 0; i < n; i++) { seg(e, a, rings[r][i], rings[r][(i + 1) % n], color); if (r < rows) { seg(e, a, rings[r][i], rings[r + 1][i], color); seg(e, a, rings[r][i], rings[r + 1][(i + 1) % n], color); } } }, 0xff8f3f, 58);

    ae('hypar', 'Hypar (concentric-square fold)', function (a, e, T, color) { var N = 12, i, k; function sq(r, z) { return [V(T, -r, -r, z), V(T, r, -r, z), V(T, r, r, z), V(T, -r, r, z)]; } var prev = null; for (i = 0; i <= N; i++) { var r = 3 + i * 1.6, z = (i % 2 ? 5 : -5) * (i / N); var s = sq(r, z); for (k = 0; k < 4; k++) seg(e, a, s[k], s[(k + 1) % 4], color); if (prev) for (k = 0; k < 4; k++) e.push({ a: prev[k], b: s[k], color: color }); prev = s; } }, 0xff5d8f, 56);

    ae('reschtriangle', 'Ron Resch pattern', function (a, e, T, color) { var R = 4, s = 5, S3 = Math.sqrt(3), i, j; function P(i, j) { return V(T, (i + j * 0.5) * s - R * s, j * S3 / 2 * s - R * s, 0); } for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { seg(e, a, P(i, j), P(i + 1, j), color); seg(e, a, P(i, j), P(i, j + 1), color); seg(e, a, P(i + 1, j), P(i, j + 1), color); var cx = (P(i, j).x + P(i + 1, j).x + P(i, j + 1).x) / 3, cy = (P(i, j).y + P(i + 1, j).y + P(i, j + 1).y) / 3; var c = V(T, cx, cy, 0); seg(e, a, c, P(i, j), color); } }, 0x00d2a0, 58);

    ae('flasher', 'Flasher fold (spiral)', function (a, e, T, color) { var arms = 6, turns = 3, i, s; for (s = 0; s < arms; s++) { var off = s / arms * PI2, prev = null; for (i = 0; i <= 120; i++) { var t = i / 120 * turns * PI2, r = 1 + t * 1.0, p = V(T, Math.cos(t + off) * r, Math.sin(t + off) * r, 0); if (i % 5 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } } for (i = 0; i < 30; i++) { var rr = 1 + i * 1.1, prev2 = null; for (s = 0; s <= arms; s++) { var th = s / arms * PI2 + rr * 0.12, p2 = V(T, Math.cos(th) * rr, Math.sin(th) * rr, 0); if (prev2) e.push({ a: prev2, b: p2, color: color }); prev2 = p2; } } }, 0xffd23f, 56);

    ae('curvedcrease', 'Curved crease (concentric)', function (a, e, T, color) { var i, s, N = 40; for (i = 1; i <= 10; i++) { var r = i * 2, prev = null, first = null; for (s = 0; s <= N; s++) { var t = s / N * PI2, p = V(T, Math.cos(t) * r, Math.sin(t) * r, 0); if (s % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } e.push({ a: prev, b: first, color: color }); } for (s = 0; s < 16; s++) { var th = s / 16 * PI2; e.push({ a: V(T, Math.cos(th) * 2, Math.sin(th) * 2, 0), b: V(T, Math.cos(th) * 20, Math.sin(th) * 20, 0), color: color }); } }, 0x4d8bf0, 56);
})();
