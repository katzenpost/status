(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function cellsView(id, name, gen, color, camZ, sc) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 60, layout: function (d, THREE) {
            var cells = gen(), s = sc || 1.0, edges = [], anchors = [], mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9;
            cells.forEach(function (c) { if (c[0] < mnx) mnx = c[0]; if (c[0] > mxx) mxx = c[0]; if (c[1] < mny) mny = c[1]; if (c[1] > mxy) mxy = c[1]; });
            var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2;
            cells.forEach(function (c) { var x = (c[0] - cx) * s, y = (c[1] - cy) * s, h = s / 2; var p = [[x - h, y - h], [x + h, y - h], [x + h, y + h], [x - h, y + h]]; anchors.push(new THREE.Vector3(x, y, 0)); for (var k = 0; k < 4; k++) edges.push({ a: new THREE.Vector3(p[k][0], p[k][1], 0), b: new THREE.Vector3(p[(k + 1) % 4][0], p[(k + 1) % 4][1], 0), color: color }); });
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }
    // Generic life-like B/S automaton -> live cells after `steps`.
    function lifeCells(W, steps, dens, birth, surv) {
        var g = [], i, j, s; for (i = 0; i < W; i++) { g[i] = []; for (j = 0; j < W; j++) g[i][j] = Math.random() < dens ? 1 : 0; }
        for (s = 0; s < steps; s++) { var n = []; for (i = 0; i < W; i++) { n[i] = []; for (j = 0; j < W; j++) { var cnt = 0, a, b; for (a = -1; a <= 1; a++) for (b = -1; b <= 1; b++) if (a || b) cnt += g[(i + a + W) % W][(j + b + W) % W]; n[i][j] = g[i][j] ? (surv.indexOf(cnt) >= 0 ? 1 : 0) : (birth.indexOf(cnt) >= 0 ? 1 : 0); } } g = n; }
        var out = []; for (i = 0; i < W; i++) for (j = 0; j < W; j++) if (g[i][j]) out.push([i, j]); return out;
    }

    cellsView('rule110', 'Rule 110 automaton', function () { var W = 74, H = 46, row = [], i, r, out = []; for (i = 0; i < W; i++) row.push(i === W - 8 ? 1 : (Math.random() < 0.08 ? 1 : 0)); for (r = 0; r < H; r++) { for (i = 0; i < W; i++) if (row[i]) out.push([i, H - r]); var nr = []; for (i = 0; i < W; i++) { var l = row[(i - 1 + W) % W], c = row[i], rr = row[(i + 1) % W]; nr.push((110 >> ((l << 2) | (c << 1) | rr)) & 1); } row = nr; } return out; }, 0x2ec4b6, 60);

    cellsView('ising', 'Ising model', function () { var W = 60, g = [], i, j, s, beta = 0.62; for (i = 0; i < W; i++) { g[i] = []; for (j = 0; j < W; j++) g[i][j] = Math.random() < 0.5 ? 1 : -1; } for (s = 0; s < 60; s++) for (i = 0; i < W; i++) for (j = 0; j < W; j++) { var nb = g[(i + 1) % W][j] + g[(i - 1 + W) % W][j] + g[i][(j + 1) % W] + g[i][(j - 1 + W) % W]; var dE = 2 * g[i][j] * nb; if (dE <= 0 || Math.random() < Math.exp(-beta * dE)) g[i][j] = -g[i][j]; } var out = []; for (i = 0; i < W; i++) for (j = 0; j < W; j++) if (g[i][j] > 0) out.push([i, j]); return out; }, 0x4d8bf0, 60);

    cellsView('margolus', 'Margolus block CA', function () { var W = 60, g = [], i, j, s; for (i = 0; i < W; i++) { g[i] = []; for (j = 0; j < W; j++) g[i][j] = (Math.abs(i - W / 2) < 12 && Math.abs(j - W / 2) < 12 && Math.random() < 0.4) ? 1 : 0; } for (s = 0; s < 30; s++) { var off = s & 1; for (i = off; i < W - 1; i += 2) for (j = off; j < W - 1; j += 2) { var a = g[i][j], b = g[i + 1][j], c = g[i][j + 1], dd = g[i + 1][j + 1], sum = a + b + c + dd; if (sum === 1 || sum === 2) { g[i][j] = dd; g[i + 1][j + 1] = a; g[i + 1][j] = c; g[i][j + 1] = b; } } } var out = []; for (i = 0; i < W; i++) for (j = 0; j < W; j++) if (g[i][j]) out.push([i, j]); return out; }, 0x9b5de5, 60);
})();
