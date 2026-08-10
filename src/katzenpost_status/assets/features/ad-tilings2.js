(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    // Marching-squares zero contour of a scalar field.
    function contour(id, name, f, color, camZ, thr) {
        G.create({ id: id, name: name, rotateSpeed: 0.22, camZ: camZ || 54,
            layout: function (d, THREE) {
                var N = 80, S = 44, edges = [], anchors = [], i, j, T = thr || 0;
                function XY(u, v) { return new THREE.Vector3((u - 0.5) * S, (v - 0.5) * S, 0); }
                function g(u, v) { return f((u - 0.5) * 20, (v - 0.5) * 20) - T; }
                for (i = 0; i < N; i++) for (j = 0; j < N; j++) {
                    var u0 = i / N, u1 = (i + 1) / N, v0 = j / N, v1 = (j + 1) / N;
                    var a = g(u0, v0), b = g(u1, v0), c = g(u1, v1), e = g(u0, v1), cr = [];
                    if ((a < 0) !== (b < 0)) cr.push(XY(u0 + (u1 - u0) * (a / (a - b)), v0));
                    if ((b < 0) !== (c < 0)) cr.push(XY(u1, v0 + (v1 - v0) * (b / (b - c))));
                    if ((c < 0) !== (e < 0)) cr.push(XY(u1 + (u0 - u1) * (c / (c - e)), v1));
                    if ((e < 0) !== (a < 0)) cr.push(XY(u0, v1 + (v0 - v1) * (e / (e - a))));
                    if (cr.length >= 2) { edges.push({ a: cr[0], b: cr[1], color: color }); anchors.push(cr[0], cr[1]); if (cr.length === 4) { edges.push({ a: cr[2], b: cr[3], color: color }); anchors.push(cr[2], cr[3]); } }
                }
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }
    function quasi(n) { return function (x, y) { var s = 0, k; for (k = 0; k < n; k++) { var th = k * Math.PI / n; s += Math.cos(x * Math.cos(th) + y * Math.sin(th)); } return s; }; }
    function anchorsEdges(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 56, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function seg(e, x1, y1, x2, y2, color) { e.push({ a: new (window.KATZEN.THREE).Vector3(x1, y1, 0), b: new (window.KATZEN.THREE).Vector3(x2, y2, 0), color: color }); }

    contour('quasicrystal5', 'Quasicrystal (5-fold)', quasi(5), 0x2ec4b6, 54);

    contour('quasicrystal7', 'Quasicrystal (7-fold)', quasi(7), 0x4d8bf0, 54);

    contour('quasicrystal9', 'Quasicrystal (9-fold)', quasi(9), 0x9b5de5, 54);

    contour('quasicrystal11', 'Quasicrystal (11-fold)', quasi(11), 0xff8f3f, 54);

    contour('quasicrystal13', 'Quasicrystal (13-fold)', quasi(13), 0xff5d8f, 54);

    anchorsEdges('truchet', 'Truchet tiling (arcs)', function (a, e, T, color) { var R = 6, s = 5, i, j; for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { var cx = i * s, cy = j * s, h = s / 2, flip = ((i * 7 + j * 3 + i * j) & 1); function arc(ccx, ccy, a0) { var prev = null; for (var k = 0; k <= 8; k++) { var t = a0 + k / 8 * Math.PI / 2, p = new T.Vector3(ccx + Math.cos(t) * h, ccy + Math.sin(t) * h, 0); if (k === 0 || k === 8) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } } if (flip) { arc(cx - h, cy - h, 0); arc(cx + h, cy + h, Math.PI); } else { arc(cx + h, cy - h, Math.PI / 2); arc(cx - h, cy + h, -Math.PI / 2); } } }, 0x00d2a0, 56);

    anchorsEdges('truchetdiag', 'Truchet tiling (diagonal)', function (a, e, T, color) { var R = 7, s = 4, i, j; for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { var cx = i * s, cy = j * s, h = s / 2, flip = ((i * 5 + j * 11 + 3) & 1); var p1, p2; if (flip) { p1 = new T.Vector3(cx - h, cy - h, 0); p2 = new T.Vector3(cx + h, cy + h, 0); } else { p1 = new T.Vector3(cx + h, cy - h, 0); p2 = new T.Vector3(cx - h, cy + h, 0); } a.push(p1); a.push(p2); e.push({ a: p1, b: p2, color: color }); } }, 0xffd23f, 56);

    anchorsEdges('islamicstar', 'Islamic star pattern', function (a, e, T, color) { var R = 3, s = 12, i, j; for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) { var cx = i * s, cy = j * s + (i & 1 ? s / 2 : 0), pts = 8, r1 = 5.5, r2 = 2.4, prev = null, first = null; for (var k = 0; k <= pts * 2; k++) { var rr = (k & 1) ? r2 : r1, th = k / (pts * 2) * PI2, p = new T.Vector3(cx + Math.cos(th) * rr, cy + Math.sin(th) * rr, 0); if (k % 2 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } } }, 0xff8f3f, 58);
})();
