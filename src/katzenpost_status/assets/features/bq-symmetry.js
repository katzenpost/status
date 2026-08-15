(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    // Asymmetric motif in unit-cell coords (segments) so symmetry is visible.
    var MOTIF = [[[0.30, 0.30], [0.30, 0.72]], [[0.30, 0.72], [0.52, 0.72]], [[0.30, 0.52], [0.46, 0.52]], [[0.30, 0.30], [0.62, 0.40]]];
    function wallpaper(id, name, ops, lat, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.25, camZ: camZ || 58, layout: function (d, T) {
            var edges = [], anchors = [], R = 3, i, j, cell = 9;
            function xf(op, p) { return [op[0] * p[0] + op[1] * p[1] + op[4], op[2] * p[0] + op[3] * p[1] + op[5]]; }
            for (i = -R; i <= R; i++) for (j = -R; j <= R; j++) {
                var ox = (i * lat[0] + j * lat[2]) * cell, oy = (i * lat[1] + j * lat[3]) * cell;
                ops.forEach(function (op) {
                    MOTIF.forEach(function (seg) {
                        var A = xf(op, seg[0]), B = xf(op, seg[1]);
                        var pa = new T.Vector3(A[0] * cell + ox - R * cell, A[1] * cell + oy - R * cell, 0);
                        var pb = new T.Vector3(B[0] * cell + ox - R * cell, B[1] * cell + oy - R * cell, 0);
                        edges.push({ a: pa, b: pb, color: color }); anchors.push(pa);
                    });
                });
            }
            return G.anchorLayout(d, T, anchors, edges);
        } });
    }
    var I = [1, 0, 0, 1, 0, 0], MX = [-1, 0, 0, 1, 1, 0], MY = [1, 0, 0, -1, 0, 1], R180 = [-1, 0, 0, -1, 1, 1];
    var R90 = [0, -1, 1, 0, 1, 0], R270 = [0, 1, -1, 0, 0, 1], GX = [-1, 0, 0, 1, 1, 0.5];
    var SQ = [1, 0, 0, 1], HEX = [1, 0, 0.5, Math.sqrt(3) / 2];

    wallpaper('wp-p1', 'Wallpaper p1', [I], SQ, 0x2ec4b6, 58);

    wallpaper('wp-p2', 'Wallpaper p2', [I, R180], SQ, 0x4d8bf0, 58);

    wallpaper('wp-pm', 'Wallpaper pm', [I, MX], SQ, 0x9b5de5, 58);

    wallpaper('wp-pg', 'Wallpaper pg', [I, GX], SQ, 0xff8f3f, 58);

    wallpaper('wp-cm', 'Wallpaper cm', [I, MX, [1, 0, 0, 1, 0.5, 0.5], [-1, 0, 0, 1, 1.5, 0.5]], SQ, 0xff5d8f, 58);

    wallpaper('wp-pmm', 'Wallpaper pmm', [I, MX, MY, R180], SQ, 0x00d2a0, 58);

    wallpaper('wp-pmg', 'Wallpaper pmg', [I, R180, GX, [1, 0, 0, -1, 0, 0.5]], SQ, 0xffd23f, 58);
})();
