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

    sitesView('vr-lloyd-sphere', 'Lloyd relaxation on a sphere', function (T) { return relaxSphere(140, 60, T); }, 6, 56);

    sitesView('vr-delaunay-torus', 'Delaunay graph on a torus', function (T) { var pts = [], i, N = 150; for (i = 0; i < N; i++) { var u = Math.random() * 2 * Math.PI, v = Math.random() * 2 * Math.PI, R = 12, r = 5.2; pts.push(new T.Vector3((R + r * Math.cos(v)) * Math.cos(u), (R + r * Math.cos(v)) * Math.sin(u), r * Math.sin(v))); } return pts; }, 5, 60);

    sitesView('vr-poisson-sphere', 'Poisson-disk on a sphere', function (T) { var uv = [], tries = 0, minC = Math.cos(0.32); while (uv.length < 150 && tries < 30000) { tries++; var u = Math.random() * 2 - 1, th = Math.random() * 2 * Math.PI, r = Math.sqrt(1 - u * u), x = Math.cos(th) * r, y = u, z = Math.sin(th) * r, ok = true, i; for (i = 0; i < uv.length; i++) { if (uv[i][0] * x + uv[i][1] * y + uv[i][2] * z > minC) { ok = false; break; } } if (ok) uv.push([x, y, z]); } return uv.map(function (q) { return new T.Vector3(q[0] * 17, q[1] * 17, q[2] * 17); }); }, 6, 56);

    sitesView('vr-poisson-disk', 'Poisson-disk sampling (Bridson)', function (T) { var rad = 0.13, k = 20, grid = {}, active = [], pts = [], cs = rad / Math.SQRT2; function gk(x, y) { return Math.floor(x / cs) + ',' + Math.floor(y / cs); } function add(x, y) { pts.push([x, y]); active.push([x, y]); grid[gk(x, y)] = [x, y]; } add(0, 0); var guard = 0; while (active.length && pts.length < 300 && guard++ < 60000) { var ai = (Math.random() * active.length) | 0, p = active[ai], found = false, t; for (t = 0; t < k; t++) { var ang = Math.random() * 2 * Math.PI, rr = rad * (1 + Math.random()), nx = p[0] + Math.cos(ang) * rr, ny = p[1] + Math.sin(ang) * rr; if (nx < -1 || nx > 1 || ny < -1 || ny > 1) continue; var ok = true, gxx, gyy; for (gxx = -2; gxx <= 2; gxx++) for (gyy = -2; gyy <= 2; gyy++) { var g = grid[(Math.floor(nx / cs) + gxx) + ',' + (Math.floor(ny / cs) + gyy)]; if (g) { var dx = g[0] - nx, dy = g[1] - ny; if (dx * dx + dy * dy < rad * rad) { ok = false; } } } if (ok) { add(nx, ny); found = true; break; } } if (!found) active.splice(ai, 1); } return pts.map(function (q) { return new T.Vector3(q[0] * 18, q[1] * 18, 0); }); }, 4, 56);

    sitesView('vr-cvt', 'Centroidal Voronoi tessellation', function (T) { var n = 90, sites = randSites(n), M = 46, it, i, gx, gy; for (it = 0; it < 7; it++) { var sx = new Float32Array(n), sy = new Float32Array(n), cnt = new Int32Array(n); for (gx = 0; gx < M; gx++) for (gy = 0; gy < M; gy++) { var px = gx / (M - 1) * 2 - 1, py = gy / (M - 1) * 2 - 1, bd = 1e9, bi = 0; for (i = 0; i < n; i++) { var dx = px - sites[i][0], dy = py - sites[i][1], dd = dx * dx + dy * dy; if (dd < bd) { bd = dd; bi = i; } } sx[bi] += px; sy[bi] += py; cnt[bi]++; } for (i = 0; i < n; i++) if (cnt[i]) { sites[i][0] = sx[i] / cnt[i]; sites[i][1] = sy[i] / cnt[i]; } } return sites.map(function (q) { return new T.Vector3(q[0] * 18, q[1] * 18, 0); }); }, 4, 56);

    sitesView('vr-jittered', 'Jittered grid sites', function (T) { var g = 11, pts = [], i, j; for (i = 0; i < g; i++) for (j = 0; j < g; j++) { var x = (i + 0.5 + (Math.random() - 0.5) * 0.8) / g * 2 - 1, y = (j + 0.5 + (Math.random() - 0.5) * 0.8) / g * 2 - 1; pts.push(new T.Vector3(x * 18, y * 18, 0)); } return pts; }, 4, 56);
})();
