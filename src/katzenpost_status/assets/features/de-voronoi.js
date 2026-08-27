(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function knn(pts, cols, k) {
        var edges = [], seen = {}, i, j, m;
        for (i = 0; i < pts.length; i++) {
            var ds = [];
            for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]);
            ds.sort(function (a, b) { return a[0] - b[0]; });
            for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], key = Math.min(i, jj) + '_' + Math.max(i, jj); if (!seen[key]) { seen[key] = 1; edges.push({ a: pts[i], b: pts[jj], color: cols[i % cols.length] }); } }
        }
        return edges;
    }
    // A set of 3D sites -> Delaunay-like dual graph via kNN, coloured by index band.
    function sitesView(id, name, gen, k, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 58, layout: function (d, THREE) {
            var pts = gen(THREE), cols = pts.map(function (p, i) { return PAL[(i * 7 % PAL.length)]; });
            if (pts.length < 4) { pts = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; cols = [PAL[0], PAL[0]]; }
            return G.anchorLayout(d, THREE, pts, knn(pts, cols, k || 5));
        } });
    }
    // True Voronoi diagram by rasterising: a grid cell whose nearest site differs
    // from a 4-neighbour is a cell wall. metric 1 = Manhattan, wrap = toroidal.
    function voronoiRaster(id, name, sites, metric, wrap, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.14, camZ: camZ || 58, layout: function (d, THREE) {
            var N = 120, own = new Int16Array(N * N), gx, gy, s, S = sites.length;
            function dist(ax, ay, bx, by) { var dx = Math.abs(ax - bx), dy = Math.abs(ay - by); if (wrap) { dx = Math.min(dx, 2 - dx); dy = Math.min(dy, 2 - dy); } return metric === 1 ? dx + dy : dx * dx + dy * dy; }
            for (gx = 0; gx < N; gx++) for (gy = 0; gy < N; gy++) {
                var px = gx / (N - 1) * 2 - 1, py = gy / (N - 1) * 2 - 1, bd = 1e9, bi = 0;
                for (s = 0; s < S; s++) { var dd = dist(px, py, sites[s][0], sites[s][1]); if (dd < bd) { bd = dd; bi = s; } }
                own[gx * N + gy] = bi;
            }
            var raw = [];
            for (gx = 1; gx < N - 1; gx++) for (gy = 1; gy < N - 1; gy++) {
                var c = own[gx * N + gy];
                if (c !== own[(gx + 1) * N + gy] || c !== own[gx * N + gy + 1]) raw.push([gx, gy, c]);
            }
            var stride = Math.max(1, Math.ceil(raw.length / 490)), pts = [], cols = [], i;
            for (i = 0; i < raw.length; i += stride) { var e = raw[i]; pts.push(new THREE.Vector3((e[0] / (N - 1) * 2 - 1) * 18, (e[1] / (N - 1) * 2 - 1) * 18, 0)); cols.push(PAL[e[2] % PAL.length]); }
            if (pts.length < 8) { pts = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; cols = [PAL[0], PAL[0]]; }
            return G.anchorLayout(d, THREE, pts, knn(pts, cols, 3));
        } });
    }
    function randSites(n) { var s = [], i; for (i = 0; i < n; i++) s.push([Math.random() * 2 - 1, Math.random() * 2 - 1]); return s; }
    function fibSphere(n, THREE) { var pts = [], i, ga = Math.PI * (3 - Math.sqrt(5)); for (i = 0; i < n; i++) { var y = 1 - 2 * (i + 0.5) / n, r = Math.sqrt(1 - y * y), th = ga * i; pts.push(new THREE.Vector3(Math.cos(th) * r * 17, y * 17, Math.sin(th) * r * 17)); } return pts; }
    function relaxSphere(n, iters, THREE) {
        var pts = [], i, j, s;
        for (i = 0; i < n; i++) { var u = Math.random() * 2 - 1, th = Math.random() * 2 * Math.PI, r = Math.sqrt(1 - u * u); pts.push(new THREE.Vector3(Math.cos(th) * r, u, Math.sin(th) * r)); }
        for (s = 0; s < iters; s++) { var f = []; for (i = 0; i < n; i++) f.push(new THREE.Vector3(0, 0, 0)); for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) { var dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y, dz = pts[i].z - pts[j].z, dd = dx * dx + dy * dy + dz * dz + 1e-4, w = 0.006 / dd; f[i].x += dx * w; f[i].y += dy * w; f[i].z += dz * w; f[j].x -= dx * w; f[j].y -= dy * w; f[j].z -= dz * w; } for (i = 0; i < n; i++) { pts[i].x += f[i].x; pts[i].y += f[i].y; pts[i].z += f[i].z; var L = Math.sqrt(pts[i].x * pts[i].x + pts[i].y * pts[i].y + pts[i].z * pts[i].z) || 1; pts[i].x /= L; pts[i].y /= L; pts[i].z /= L; } }
        return pts.map(function (p) { return new THREE.Vector3(p.x * 17, p.y * 17, p.z * 17); });
    }

    sitesView('vr-delaunay-sphere', 'Delaunay graph on a sphere', function (T) { return fibSphere(150, T); }, 6, 56);
})();
