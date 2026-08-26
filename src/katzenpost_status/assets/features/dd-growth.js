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

    clusterView('gr-snowflake', 'Reiter snowflake (hex)', function () { var R = 34, s = {}, rec = {}, alpha = 1.0, beta = 0.4, gamma = 0.001, i, step; function inb(x, y) { return Math.abs(x) <= R && Math.abs(y) <= R && Math.abs(x + y) <= R; } var cells = []; for (var x = -R; x <= R; x++) for (var y = -R; y <= R; y++) if (inb(x, y)) { s[key(x, y)] = beta; cells.push([x, y]); } s[key(0, 0)] = 1; var NB = [[1, 0], [-1, 0], [0, 1], [0, -1], [1, -1], [-1, 1]]; for (step = 0; step < 90; step++) { var recv = {}, u = {}; cells.forEach(function (c) { var k = key(c[0], c[1]), r = s[k] >= 1; if (!r) { NB.forEach(function (o) { if (s[key(c[0] + o[0], c[1] + o[1])] >= 1) r = true; }); } recv[k] = r; }); cells.forEach(function (c) { var k = key(c[0], c[1]); u[k] = recv[k] ? 0 : s[k]; }); var ns = {}; cells.forEach(function (c) { var k = key(c[0], c[1]), sum = u[k], cnt = 1; NB.forEach(function (o) { var nk = key(c[0] + o[0], c[1] + o[1]); if (u[nk] != null) { sum += u[nk]; } cnt++; }); var diff = u[k] + (beta * 0) ; var lap = 0; NB.forEach(function (o) { var nk = key(c[0] + o[0], c[1] + o[1]); lap += (u[nk] != null ? u[nk] : u[k]) - u[k]; }); var val = (recv[k] ? s[k] + gamma : 0) + u[k] + 0.5 * lap * 0.5; ns[k] = val; }); cells.forEach(function (c) { s[key(c[0], c[1])] = ns[key(c[0], c[1])]; }); } var out = [], n = 0; cells.forEach(function (c) { if (s[key(c[0], c[1])] >= 1) out.push([c[0] + c[1] * 0.5, c[1] * 0.87, n++]); }); return out; }, 62, 1.0);

    graphView('gr-lerw', 'Loop-erased random walk', function () { var W = 42, x = -W / 2 | 0, y = 0, path = [[x, y]], idx = {}, band = 0; idx[key(x, y)] = 0; var steps = 0; while (x < W / 2 && steps < 40000) { steps++; var d = (Math.random() * 4) | 0, dx = [1, -1, 0, 0][d], dy = [0, 0, 1, -1][d]; x += dx; y += dy; if (y < -W / 2 || y > W / 2) { x -= dx; y -= dy; continue; } var k = key(x, y); if (idx[k] != null) { path.length = idx[k] + 1; var kk; for (kk in idx) if (idx[kk] > idx[k]) delete idx[kk]; } else { idx[k] = path.length; path.push([x, y]); } } var segs = [], i; for (i = 0; i + 1 < path.length; i++) segs.push([path[i][0], path[i][1], path[i + 1][0], path[i + 1][1], (i / 20) | 0]); return segs; }, 60, 1.2);

    graphView('gr-maze', 'Recursive backtracker maze', function () { var W = 26, vis = {}, stack = [[0, 0]], segs = []; vis[key(0, 0)] = 1; while (stack.length) { var c = stack[stack.length - 1], nb = [[c[0] + 1, c[1]], [c[0] - 1, c[1]], [c[0], c[1] + 1], [c[0], c[1] - 1]], open = []; nb.forEach(function (q) { if (q[0] >= 0 && q[1] >= 0 && q[0] < W && q[1] < W && !vis[key(q[0], q[1])]) open.push(q); }); if (!open.length) { stack.pop(); continue; } var q = open[(Math.random() * open.length) | 0]; vis[key(q[0], q[1])] = 1; segs.push([c[0], c[1], q[0], q[1], (segs.length / 40) | 0]); stack.push(q); } return segs; }, 60, 1.3);

    graphView('gr-spanningtree', 'Random minimal spanning tree', function () { var W = 24, inT = {}, segs = [], edges = [], x, y; function push(a, b) { edges.push([a, b, Math.random()]); } inT[key(0, 0)] = 1; function addFrontier(cx, cy) { [[cx + 1, cy], [cx - 1, cy], [cx, cy + 1], [cx, cy - 1]].forEach(function (q) { if (q[0] >= 0 && q[1] >= 0 && q[0] < W && q[1] < W && !inT[key(q[0], q[1])]) push([cx, cy], q); }); } addFrontier(0, 0); while (edges.length) { var bi = 0, bv = 2, i; for (i = 0; i < edges.length; i++) if (edges[i][2] < bv) { bv = edges[i][2]; bi = i; } var e = edges.splice(bi, 1)[0], a = e[0], b = e[1]; if (inT[key(b[0], b[1])]) continue; inT[key(b[0], b[1])] = 1; segs.push([a[0], a[1], b[0], b[1], (segs.length / 40) | 0]); addFrontier(b[0], b[1]); edges = edges.filter(function (ee) { return !inT[key(ee[1][0], ee[1][1])]; }); } return segs; }, 60, 1.4);

    graphView('gr-differential', 'Differential growth curve', function () { var n = 90, pts = [], i, R = 6; for (i = 0; i < n; i++) { var a = 2 * Math.PI * i / n; pts.push([Math.cos(a) * R, Math.sin(a) * R]); } var rep = 2.4, seg = 1.6, step; for (step = 0; step < 120 && pts.length < 320; step++) { var np = pts.map(function (p) { return [p[0], p[1]]; }), N = pts.length, i2, j; for (i2 = 0; i2 < N; i2++) { var fx = 0, fy = 0; for (j = 0; j < N; j++) { if (j === i2) continue; var dx = pts[i2][0] - pts[j][0], dy = pts[i2][1] - pts[j][1], dd = Math.sqrt(dx * dx + dy * dy) || 1e-3; if (dd < rep) { fx += dx / dd * (rep - dd) * 0.5; fy += dy / dd * (rep - dd) * 0.5; } } var pa = pts[(i2 - 1 + N) % N], pb = pts[(i2 + 1) % N]; fx += (pa[0] + pb[0] - 2 * pts[i2][0]) * 0.25; fy += (pa[1] + pb[1] - 2 * pts[i2][1]) * 0.25; np[i2][0] += fx; np[i2][1] += fy; } pts = np; var grown = [pts[0]]; for (i2 = 1; i2 <= pts.length; i2++) { var a2 = pts[i2 % pts.length], b2 = pts[i2 - 1], dx2 = a2[0] - b2[0], dy2 = a2[1] - b2[1]; if (Math.sqrt(dx2 * dx2 + dy2 * dy2) > seg && pts.length + grown.length < 320) grown.push([(a2[0] + b2[0]) / 2, (a2[1] + b2[1]) / 2]); if (i2 < pts.length) grown.push(pts[i2]); } pts = grown; } var segs = [], N2 = pts.length; for (i = 0; i < N2; i++) { var a = pts[i], b = pts[(i + 1) % N2]; segs.push([a[0], a[1], b[0], b[1], (i / 24) | 0]); } return segs; }, 58, 1.0);
})();
