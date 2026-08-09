(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    // Iterate a 2D map to its attractor, sample points, mesh by nearest neighbour.
    function mapAttractor(id, name, step, x0, y0, color, camZ, keepEvery, iters) {
        G.create({ id: id, name: name, rotateSpeed: 0.26, camZ: camZ || 56,
            layout: function (d, THREE) {
                var x = x0, y = y0, raw = [], i, ke = keepEvery || 6, IT = iters || 5000;
                for (i = 0; i < IT; i++) { var p = step(x, y); x = p[0]; y = p[1]; if (!isFinite(x) || !isFinite(y)) break; if (i > 60 && i % ke === 0 && raw.length < 720) raw.push([x, y]); }
                if (raw.length < 4) return G.anchorLayout(d, THREE, [], []);
                var mnx = Infinity, mny = Infinity, mxx = -Infinity, mxy = -Infinity;
                raw.forEach(function (p) { if (p[0] < mnx) mnx = p[0]; if (p[0] > mxx) mxx = p[0]; if (p[1] < mny) mny = p[1]; if (p[1] > mxy) mxy = p[1]; });
                var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, s = 42 / Math.max(1e-6, Math.max(mxx - mnx, mxy - mny));
                var V = raw.map(function (p) { return new THREE.Vector3((p[0] - cx) * s, (p[1] - cy) * s, 0); });
                return G.anchorLayout(d, THREE, V, knn(V, THREE, 2, color));
            } });
    }

    mapAttractor('henon', 'Henon map', function (x, y) { return [1 - 1.4 * x * x + y, 0.3 * x]; }, 0.1, 0.1, 0x2ec4b6, 56, 4, 3000);

    mapAttractor('ikeda', 'Ikeda map', function (x, y) { var t = 0.4 - 6 / (1 + x * x + y * y), u = 0.9; return [1 + u * (x * Math.cos(t) - y * Math.sin(t)), u * (x * Math.sin(t) + y * Math.cos(t))]; }, 0.1, 0.1, 0x4d8bf0, 56, 5, 4000);

    mapAttractor('clifford', 'Clifford attractor map', function (x, y) { var a = -1.4, b = 1.6, c = 1.0, d = 0.7; return [Math.sin(a * y) + c * Math.cos(a * x), Math.sin(b * x) + d * Math.cos(b * y)]; }, 0.1, 0.1, 0x9b5de5, 56, 7, 6000);

    mapAttractor('dejong', 'De Jong attractor map', function (x, y) { var a = 1.4, b = -2.3, c = 2.4, d = -2.1; return [Math.sin(a * y) - Math.cos(b * x), Math.sin(c * x) - Math.cos(d * y)]; }, 0.1, 0.1, 0xff8f3f, 56, 7, 6000);

    mapAttractor('tinkerbell', 'Tinkerbell map', function (x, y) { var a = 0.9, b = -0.6013, c = 2.0, d = 0.5; return [x * x - y * y + a * x + b * y, 2 * x * y + c * x + d * y]; }, -0.72, -0.64, 0xff5d8f, 56, 4, 4000);

    mapAttractor('lozi', 'Lozi map', function (x, y) { var a = 1.7, b = 0.5; return [1 - a * Math.abs(x) + y, b * x]; }, 0.1, 0.1, 0x00d2a0, 56, 4, 3000);
})();
