(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // L-system tree: a recursively branching binary tree; packets climb it.
    G.create({
        id: 'ltree', name: 'L-system tree', rotateSpeed: 0.22, camZ: 60,
        layout: function (d, THREE) {
            var edges = [], anchors = [], ang = 26 * Math.PI / 180, ratio = 0.72;
            function grow(x, y, dir, len, depth) {
                var x2 = x + Math.cos(dir) * len, y2 = y + Math.sin(dir) * len;
                edges.push({ a: new THREE.Vector3(x, y, 0), b: new THREE.Vector3(x2, y2, 0), color: 0x2ec4b6 });
                anchors.push(new THREE.Vector3(x2, y2, 0));
                if (depth <= 0) return;
                grow(x2, y2, dir + ang, len * ratio, depth - 1);
                grow(x2, y2, dir - ang, len * ratio, depth - 1);
            }
            anchors.push(new THREE.Vector3(0, -20, 0));
            grow(0, -20, Math.PI / 2, 14, 5);
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });

    // Dragon curve (Heighway): one folded continuous line; packets ride it.
    G.create({
        id: 'dragon', name: 'Dragon curve', rotateSpeed: 0.3, camZ: 58,
        layout: function (d, THREE) {
            var turns = [], i, j;
            for (i = 0; i < 11; i++) { var t = turns.slice(); turns.push(1); for (j = t.length - 1; j >= 0; j--) turns.push(t[j] ? 0 : 1); }
            var dir = 0, x = 0, y = 0, step = 1.15, raw = [[0, 0]];
            for (i = 0; i < turns.length; i++) { x += Math.cos(dir) * step; y += Math.sin(dir) * step; raw.push([x, y]); dir += turns[i] ? Math.PI / 2 : -Math.PI / 2; }
            var cx = 0, cy = 0; raw.forEach(function (p) { cx += p[0]; cy += p[1]; }); cx /= raw.length; cy /= raw.length;
            var pts = raw.map(function (p) { return new THREE.Vector3((p[0] - cx) * 0.55, (p[1] - cy) * 0.55, 0); });
            return G.curveLayout(d, THREE, pts, 0xff8f3f);
        }
    });

    // Koch snowflake: the Koch curve applied to a triangle; a closed fractal
    // boundary the packets trace.
    G.create({
        id: 'koch', name: 'Koch snowflake', rotateSpeed: 0.28, camZ: 56,
        layout: function (d, THREE) {
            var R = 20, pts = [], i;
            for (i = 0; i < 3; i++) { var a = Math.PI / 2 + i * Math.PI * 2 / 3; pts.push({ x: Math.cos(a) * R, y: Math.sin(a) * R }); }
            pts.push(pts[0]);
            for (var it = 0; it < 4; it++) {
                var out = [];
                for (i = 0; i < pts.length - 1; i++) {
                    var A = pts[i], B = pts[i + 1], dx = B.x - A.x, dy = B.y - A.y;
                    var p1 = { x: A.x + dx / 3, y: A.y + dy / 3 }, p3 = { x: A.x + 2 * dx / 3, y: A.y + 2 * dy / 3 };
                    var ang = Math.atan2(dy, dx) - Math.PI / 3, len = Math.sqrt(dx * dx + dy * dy) / 3;
                    var p2 = { x: p1.x + Math.cos(ang) * len, y: p1.y + Math.sin(ang) * len };
                    out.push(A, p1, p2, p3);
                }
                out.push(pts[pts.length - 1]); pts = out;
            }
            var v = pts.map(function (p) { return new THREE.Vector3(p.x, p.y, 0); });
            return G.curveLayout(d, THREE, v, 0x4d8bf0);
        }
    });

    // Menger sponge: a cube with its fractal holes; packets route the lattice.
    G.create({
        id: 'menger', name: 'Menger sponge', rotateSpeed: 0.35, camZ: 60,
        layout: function (d, THREE) {
            var D = 2, N = 9, s = 3.6, off = (N - 1) / 2, anchors = [], edges = [], x, y, z;
            function survives(a, b, c) { for (var l = 0; l < D; l++) { var m = 0; if (a % 3 === 1) m++; if (b % 3 === 1) m++; if (c % 3 === 1) m++; if (m >= 2) return false; a = (a / 3) | 0; b = (b / 3) | 0; c = (c / 3) | 0; } return true; }
            var corners = [[-1, -1, -1], [1, -1, -1], [1, 1, -1], [-1, 1, -1], [-1, -1, 1], [1, -1, 1], [1, 1, 1], [-1, 1, 1]];
            var wire = [[0, 1], [1, 2], [2, 3], [3, 0], [4, 5], [5, 6], [6, 7], [7, 4], [0, 4], [1, 5], [2, 6], [3, 7]];
            for (x = 0; x < N; x++) for (y = 0; y < N; y++) for (z = 0; z < N; z++) {
                if (!survives(x, y, z)) continue;
                var cx = (x - off) * s, cy = (y - off) * s, cz = (z - off) * s, h = s / 2;
                var vs = corners.map(function (c) { return new THREE.Vector3(cx + c[0] * h, cy + c[1] * h, cz + c[2] * h); });
                anchors.push(new THREE.Vector3(cx, cy, cz));
                wire.forEach(function (w) { edges.push({ a: vs[w[0]], b: vs[w[1]], color: 0x9b5de5 }); });
            }
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
