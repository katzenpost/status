(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Zero-contour (nodal) lines of a scalar field via marching squares.
    function contour(id, name, f, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.22, camZ: camZ || 54,
            layout: function (d, THREE) {
                var N = 64, S = 44, edges = [], anchors = [], i, j;
                function XY(u, v) { return new THREE.Vector3((u - 0.5) * S, (v - 0.5) * S, 0); }
                for (i = 0; i < N; i++) for (j = 0; j < N; j++) {
                    var u0 = i / N, u1 = (i + 1) / N, v0 = j / N, v1 = (j + 1) / N;
                    var a = f(u0, v0), b = f(u1, v0), c = f(u1, v1), e = f(u0, v1), cr = [];
                    if ((a < 0) !== (b < 0)) cr.push(XY(u0 + (u1 - u0) * (a / (a - b)), v0));
                    if ((b < 0) !== (c < 0)) cr.push(XY(u1, v0 + (v1 - v0) * (b / (b - c))));
                    if ((c < 0) !== (e < 0)) cr.push(XY(u1 + (u0 - u1) * (c / (c - e)), v1));
                    if ((e < 0) !== (a < 0)) cr.push(XY(u0, v1 + (v0 - v1) * (e / (e - a))));
                    if (cr.length >= 2) { edges.push({ a: cr[0], b: cr[1], color: color }); anchors.push(cr[0], cr[1]); if (cr.length === 4) { edges.push({ a: cr[2], b: cr[3], color: color }); anchors.push(cr[2], cr[3]); } }
                }
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }
    // Elementary cellular automaton: stack rows, live cells as small squares.
    function eca(id, name, rule, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 58,
            layout: function (d, THREE) {
                var W = 65, H = 40, row = [], i, r, edges = [], anchors = [], sc = 1.1;
                for (i = 0; i < W; i++) row.push(i === (W >> 1) ? 1 : 0);
                for (r = 0; r < H; r++) {
                    for (i = 0; i < W; i++) if (row[i]) { var x = (i - W / 2) * sc, y = (H / 2 - r) * sc, h = sc / 2; var p = [[x - h, y - h], [x + h, y - h], [x + h, y + h], [x - h, y + h]]; anchors.push(new THREE.Vector3(x, y, 0)); for (var k = 0; k < 4; k++) edges.push({ a: new THREE.Vector3(p[k][0], p[k][1], 0), b: new THREE.Vector3(p[(k + 1) % 4][0], p[(k + 1) % 4][1], 0), color: color }); }
                    var nr = []; for (i = 0; i < W; i++) { var l = row[(i - 1 + W) % W], c = row[i], rr = row[(i + 1) % W]; nr.push(rule(l, c, rr)); } row = nr;
                }
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }
    function ruleFn(num) { return function (l, c, r) { return (num >> ((l << 2) | (c << 1) | r)) & 1; }; }
    function curve(id, name, fn, color, camZ, Nn) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) { var P = [], i, n = Nn || 900; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } }); }
    function surfMesh(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 60, layout: function (d, THREE) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, THREE)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, THREE, A, E); } }); }
    var PI2 = Math.PI * 2;

    contour('interference', 'Two-source interference', function (u, v) { var x = (u - 0.5) * 20, y = (v - 0.5) * 20, r1 = Math.hypot(x + 5, y), r2 = Math.hypot(x - 5, y); return Math.cos(r1 * 2) + Math.cos(r2 * 2); }, 0x2ec4b6, 54);

    contour('chladni2', 'Chladni figure (5,3)', function (u, v) { var n = 5, m = 3; return Math.cos(n * Math.PI * u) * Math.cos(m * Math.PI * v) - Math.cos(m * Math.PI * u) * Math.cos(n * Math.PI * v); }, 0x4d8bf0, 52);

    eca('rule30', 'Rule 30 automaton', ruleFn(30), 0xff8f3f, 58);

    eca('rule90', 'Rule 90 automaton', ruleFn(90), 0x9b5de5, 58);

    eca('rule110', 'Rule 110 automaton', ruleFn(110), 0x00d2a0, 58);

    surfMesh('standingwave', 'Standing wave', function (u, v, T) { var x = (u - 0.5) * 40, y = (v - 0.5) * 40; return new T.Vector3(x, y, 8 * Math.sin(x * 0.4) * Math.sin(y * 0.4)); }, 40, 40, 0xffd23f, 62);
})();
