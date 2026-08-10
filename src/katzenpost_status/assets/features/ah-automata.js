(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Draw a set of grid cells [x,y] as small squares; routed + stellated.
    function cellsView(id, name, gen, color, camZ, sc) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 60, layout: function (d, THREE) {
            var cells = gen(), s = sc || 1.1, edges = [], anchors = [], i, mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9;
            cells.forEach(function (c) { if (c[0] < mnx) mnx = c[0]; if (c[0] > mxx) mxx = c[0]; if (c[1] < mny) mny = c[1]; if (c[1] > mxy) mxy = c[1]; });
            var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2;
            cells.forEach(function (c) { var x = (c[0] - cx) * s, y = (c[1] - cy) * s, h = s / 2; var p = [[x - h, y - h], [x + h, y - h], [x + h, y + h], [x - h, y + h]]; anchors.push(new THREE.Vector3(x, y, 0)); for (var k = 0; k < 4; k++) edges.push({ a: new THREE.Vector3(p[k][0], p[k][1], 0), b: new THREE.Vector3(p[(k + 1) % 4][0], p[(k + 1) % 4][1], 0), color: color }); });
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }
    function keyOf(x, y) { return x + ',' + y; }

    cellsView('langtonsant', "Langton's ant", function () { var grid = {}, x = 0, y = 0, dir = 0, dx = [0, 1, 0, -1], dy = [1, 0, -1, 0], i; for (i = 0; i < 11200; i++) { var k = keyOf(x, y); if (grid[k]) { dir = (dir + 3) % 4; delete grid[k]; } else { dir = (dir + 1) % 4; grid[k] = 1; } x += dx[dir]; y += dy[dir]; } var out = []; for (var kk in grid) { var p = kk.split(','); out.push([+p[0], +p[1]]); } return out; }, 0x2ec4b6, 60, 0.7);

    cellsView('turmite', 'Turmite', function () { var grid = {}, x = 0, y = 0, dir = 0, dx = [0, 1, 0, -1], dy = [1, 0, -1, 0], i; for (i = 0; i < 8200; i++) { var k = keyOf(x, y), st = grid[k] || 0; if (st === 0) { dir = (dir + 1) % 4; grid[k] = 1; } else if (st === 1) { dir = (dir + 1) % 4; grid[k] = 2; } else { dir = (dir + 3) % 4; grid[k] = 0; } x += dx[dir]; y += dy[dir]; } var out = []; for (var kk in grid) { if (!grid[kk]) continue; var p = kk.split(','); out.push([+p[0], +p[1]]); } return out; }, 0x4d8bf0, 60, 0.8);

    cellsView('sandpile', 'Abelian sandpile', function () { var H = 63, g = new Int16Array(H * H), c = (H >> 1); g[c * H + c] = 2400; var changed = true, x, y; while (changed) { changed = false; for (x = 1; x < H - 1; x++) for (y = 1; y < H - 1; y++) { var idx = x * H + y; if (g[idx] >= 4) { var q = (g[idx] / 4) | 0; g[idx] -= q * 4; g[idx - H] += q; g[idx + H] += q; g[idx - 1] += q; g[idx + 1] += q; changed = true; } } } var out = []; for (x = 0; x < H; x++) for (y = 0; y < H; y++) if (g[x * H + y] > 0) out.push([x - c, y - c]); return out; }, 0x9b5de5, 62, 1.0);
})();
