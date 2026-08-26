(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    // Cells [x,y,order] -> centred small squares, coloured by growth order.
    function clusterView(id, name, gen, camZ, sc) {
        G.create({ id: id, name: name, rotateSpeed: 0.22, camZ: camZ || 60, layout: function (d, THREE) {
            var cells = gen(), s = sc || 0.9, i, mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9, tot = cells.length || 1;
            cells.forEach(function (c) { if (c[0] < mnx) mnx = c[0]; if (c[0] > mxx) mxx = c[0]; if (c[1] < mny) mny = c[1]; if (c[1] > mxy) mxy = c[1]; });
            var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, span = Math.max(mxx - mnx, mxy - mny) || 1, sc2 = Math.min(s, 34 / span);
            var edges = [], anchors = [];
            var stride = Math.max(1, Math.ceil(cells.length / 340));
            for (i = 0; i < cells.length; i += stride) {
                var c = cells[i], x = (c[0] - cx) * sc2, y = (c[1] - cy) * sc2, h = sc2 / 2, col = PAL[Math.min(PAL.length - 1, ((c[2] / tot) * PAL.length) | 0)];
                var p = [[x - h, y - h], [x + h, y - h], [x + h, y + h], [x - h, y + h]];
                anchors.push(new THREE.Vector3(x, y, 0));
                for (var kk = 0; kk < 4; kk++) edges.push({ a: new THREE.Vector3(p[kk][0], p[kk][1], 0), b: new THREE.Vector3(p[(kk + 1) % 4][0], p[(kk + 1) % 4][1], 0), color: col });
            }
            if (!edges.length) { anchors = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; edges = [{ a: anchors[0], b: anchors[1], color: PAL[0] }]; }
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }
    // Edge list [[x1,y1,x2,y2,band],...] on a grid -> centred line segments (trees, mazes).
    function graphView(id, name, gen, camZ, sc) {
        G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 60, layout: function (d, THREE) {
            var segs = gen(), s = sc || 1.0, i, mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9;
            segs.forEach(function (e) { mnx = Math.min(mnx, e[0], e[2]); mxx = Math.max(mxx, e[0], e[2]); mny = Math.min(mny, e[1], e[3]); mxy = Math.max(mxy, e[1], e[3]); });
            var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, span = Math.max(mxx - mnx, mxy - mny) || 1, sc2 = Math.min(s, 34 / span);
            var edges = [], anchors = [], seen = {};
            segs.forEach(function (e) {
                var a = new THREE.Vector3((e[0] - cx) * sc2, (e[1] - cy) * sc2, 0), b = new THREE.Vector3((e[2] - cx) * sc2, (e[3] - cy) * sc2, 0);
                edges.push({ a: a, b: b, color: PAL[(e[4] || 0) % PAL.length] });
                var ka = e[0] + ',' + e[1], kb = e[2] + ',' + e[3];
                if (!seen[ka]) { seen[ka] = 1; anchors.push(a); } if (!seen[kb]) { seen[kb] = 1; anchors.push(b); }
            });
            if (!edges.length) { anchors = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; edges = [{ a: anchors[0], b: anchors[1], color: PAL[0] }]; }
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }
    // Height profile h[x] -> a rough interface curve (deposition / KPZ classes).
    function profileView(id, name, gen, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.16, camZ: camZ || 58, layout: function (d, THREE) {
            var h = gen(), W = h.length, i, mn = 1e9, mx = -1e9;
            for (i = 0; i < W; i++) { if (h[i] < mn) mn = h[i]; if (h[i] > mx) mx = h[i]; }
            var rng = (mx - mn) || 1, pts = [];
            for (i = 0; i < W; i++) pts.push(new THREE.Vector3((i / (W - 1) * 2 - 1) * 18, ((h[i] - mn) / rng) * 16 - 8, 0));
            return G.curveLayout(d, THREE, pts, color);
        } });
    }
    function key(x, y) { return x + ',' + y; }

    clusterView('gr-eden', 'Eden growth cluster', function () { var grid = {}, front = [[0, 0]], out = [[0, 0, 0]], n = 0; grid[key(0, 0)] = 1; while (out.length < 900 && front.length) { var i = (Math.random() * front.length) | 0, c = front[i], nb = [[c[0] + 1, c[1]], [c[0] - 1, c[1]], [c[0], c[1] + 1], [c[0], c[1] - 1]], open = []; nb.forEach(function (q) { if (!grid[key(q[0], q[1])]) open.push(q); }); if (!open.length) { front.splice(i, 1); continue; } var q = open[(Math.random() * open.length) | 0]; grid[key(q[0], q[1])] = 1; front.push(q); out.push([q[0], q[1], ++n]); } return out; }, 60, 0.9);

    clusterView('gr-invasion', 'Invasion percolation', function () { var R = 40, thr = {}, inv = {}, out = [], bnd = [[0, 0]], n = 0; function T(x, y) { var k = key(x, y); if (thr[k] == null) thr[k] = Math.random(); return thr[k]; } inv[key(0, 0)] = 1; out.push([0, 0, 0]); while (out.length < 760) { var bi = 0, bv = 2, i; for (i = 0; i < bnd.length; i++) { var v = T(bnd[i][0], bnd[i][1]); if (v < bv) { bv = v; bi = i; } } var c = bnd.splice(bi, 1)[0]; inv[key(c[0], c[1])] = 1; out.push([c[0], c[1], ++n]); var nb = [[c[0] + 1, c[1]], [c[0] - 1, c[1]], [c[0], c[1] + 1], [c[0], c[1] - 1]]; nb.forEach(function (q) { if (Math.abs(q[0]) > R || Math.abs(q[1]) > R) return; var k = key(q[0], q[1]); if (!inv[k]) { var dup = false, j; for (j = 0; j < bnd.length; j++) if (bnd[j][0] === q[0] && bnd[j][1] === q[1]) { dup = true; break; } if (!dup) bnd.push(q); } }); if (!bnd.length) break; } return out; }, 60, 0.9);

    clusterView('gr-percolation', 'Percolation cluster (critical)', function () { var W = 62, p = 0.5927, occ = new Uint8Array(W * W), i, x, y; for (i = 0; i < W * W; i++) occ[i] = Math.random() < p ? 1 : 0; var seen = new Uint8Array(W * W), best = [], out; for (x = 0; x < W; x++) for (y = 0; y < W; y++) { var st = x * W + y; if (!occ[st] || seen[st]) continue; var q = [st], head = 0, comp = []; seen[st] = 1; while (head < q.length) { var u = q[head++], ux = (u / W) | 0, uy = u % W; comp.push([ux - (W >> 1), uy - (W >> 1)]); [[1, 0], [-1, 0], [0, 1], [0, -1]].forEach(function (o) { var nx = ux + o[0], ny = uy + o[1]; if (nx < 0 || ny < 0 || nx >= W || ny >= W) return; var v = nx * W + ny; if (occ[v] && !seen[v]) { seen[v] = 1; q.push(v); } }); } if (comp.length > best.length) best = comp; } out = []; best.forEach(function (c, i) { out.push([c[0], c[1], i]); }); return out; }, 60, 0.85);
})();
