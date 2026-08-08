(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, S3 = Math.sqrt(3);

    // Build a periodic tiling from a prototile function that emits polygons over
    // a lattice; edges are deduped, centred and scaled, then routed + stellated.
    function tiling(id, name, buildFn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58,
            layout: function (d, THREE) {
                var edges = [], anchors = [], seen = {};
                function kk(x, y) { return Math.round(x * 6) + '_' + Math.round(y * 6); }
                function edge(x1, y1, x2, y2) { var a = kk(x1, y1) + '|' + kk(x2, y2), b = kk(x2, y2) + '|' + kk(x1, y1); if (seen[a] || seen[b]) return; seen[a] = 1; edges.push({ a: new THREE.Vector3(x1, y1, 0), b: new THREE.Vector3(x2, y2, 0), color: color }); }
                function poly(pts) { for (var i = 0; i < pts.length; i++) { var p = pts[i], q = pts[(i + 1) % pts.length]; edge(p[0], p[1], q[0], q[1]); anchors.push(new THREE.Vector3(p[0], p[1], 0)); } }
                buildFn(poly);
                var mnx = Infinity, mny = Infinity, mxx = -Infinity, mxy = -Infinity;
                anchors.forEach(function (p) { if (p.x < mnx) mnx = p.x; if (p.x > mxx) mxx = p.x; if (p.y < mny) mny = p.y; if (p.y > mxy) mxy = p.y; });
                var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, sc = 42 / Math.max(1e-6, Math.max(mxx - mnx, mxy - mny));
                var allp = anchors.slice(); edges.forEach(function (e) { allp.push(e.a); allp.push(e.b); });
                allp.forEach(function (p) { if (p.__s) return; p.__s = 1; p.x = (p.x - cx) * sc; p.y = (p.y - cy) * sc; });
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }
    function ngon(cx, cy, r, n, rot) { var a = []; for (var i = 0; i < n; i++) { var t = rot + i / n * Math.PI * 2; a.push([cx + Math.cos(t) * r, cy + Math.sin(t) * r]); } return a; }
    var R = 4;   // lattice half-extent

    tiling('hextiling', 'Hexagonal tiling', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * 1.5, cy = j * S3 + (i & 1 ? S3 / 2 : 0); poly(ngon(cx, cy, 1, 6, 0)); } }, 0x2ec4b6, 56);

    tiling('tritiling', 'Triangular tiling', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var x = i + j * 0.5, y = j * S3 / 2; poly([[x, y], [x + 1, y], [x + 0.5, y + S3 / 2]]); poly([[x + 1, y], [x + 1.5, y + S3 / 2], [x + 0.5, y + S3 / 2]]); } }, 0x4d8bf0, 56);

    tiling('sqtiling', 'Square tiling', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) poly([[i, j], [i + 1, j], [i + 1, j + 1], [i, j + 1]]); }, 0x9b5de5, 56);

    tiling('trihex', 'Trihexagonal (kagome)', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * 2 + j, cy = j * S3; poly(ngon(cx, cy, 1, 6, 0)); poly([[cx + 1, cy], [cx + 2, cy], [cx + 1.5, cy + S3 / 2]]); poly([[cx + 0.5, cy + S3 / 2], [cx + 1.5, cy + S3 / 2], [cx + 1, cy + S3]]); } }, 0xff8f3f, 58);

    tiling('truncsq', 'Truncated square (4.8.8)', function (poly) { var s = 1, d = s * (1 + S3); for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * d, cy = j * d; poly(ngon(cx, cy, s * 1.307, 8, Math.PI / 8)); poly(ngon(cx + d / 2, cy + d / 2, s * 0.707, 4, Math.PI / 4)); } }, 0xff5d8f, 58);

    tiling('trunchex', 'Truncated hexagonal (3.12.12)', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * 3 * S3 + (j & 1 ? 3 * S3 / 2 : 0), cy = j * 4.5; poly(ngon(cx, cy, S3 + 0.001, 12, Math.PI / 12)); } }, 0x00d2a0, 58);

    tiling('rhombille', 'Rhombille tiling', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * 1.5, cy = j * S3 + (i & 1 ? S3 / 2 : 0); for (var k = 0; k < 6; k += 2) { var a = k / 6 * Math.PI * 2, b = (k + 1) / 6 * Math.PI * 2; poly([[cx, cy], [cx + Math.cos(a), cy + Math.sin(a)], [cx + Math.cos(a) + Math.cos(b), cy + Math.sin(a) + Math.sin(b)], [cx + Math.cos(b), cy + Math.sin(b)]]); } } }, 0xffd23f, 56);

    tiling('snubsq', 'Snub square tiling', function (poly) { var d = 1 + S3 / 2 * 0 + 1.9319; for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * d, cy = j * d, rot = (i + j) & 1 ? Math.PI / 12 : -Math.PI / 12; poly(ngon(cx, cy, 0.707, 4, rot)); } }, 0x9b5de5, 58);

    tiling('cairo', 'Cairo pentagonal tiling', function (poly) { var pent = [[0, 0], [1, 0], [1.31, 0.95], [0.5, 1.54], [-0.31, 0.95]]; for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * 2.62, cy = j * 2.62; for (var r = 0; r < 4; r++) { var ca = Math.cos(r * Math.PI / 2), sa = Math.sin(r * Math.PI / 2); poly(pent.map(function (p) { return [cx + p[0] * ca - p[1] * sa, cy + p[0] * sa + p[1] * ca]; })); } } }, 0x4d8bf0, 58);

    tiling('rhombitri', 'Rhombitrihexagonal (3.4.6.4)', function (poly) { for (var i = -R; i <= R; i++) for (var j = -R; j <= R; j++) { var cx = i * (2 + S3) + (j & 1 ? (2 + S3) / 2 : 0), cy = j * (2 + S3) * S3 / 2; poly(ngon(cx, cy, 1, 6, 0)); for (var k = 0; k < 6; k++) { var a = k / 6 * Math.PI * 2, ex = cx + Math.cos(a) * (1 + 0.707), ey = cy + Math.sin(a) * (1 + 0.707); poly(ngon(ex, ey, 0.707, 4, a)); } } }, 0xffb454, 60);
})();
