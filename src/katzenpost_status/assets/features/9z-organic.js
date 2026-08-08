(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, PHI = (1 + Math.sqrt(5)) / 2, GA = PI2 * (1 - 1 / PHI);

    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function cloud(id, name, gen, k, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 58, layout: function (d, THREE) { var pts = gen(THREE); if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []); return G.anchorLayout(d, THREE, pts, knn(pts, THREE, k, color)); } }); }
    function rand(n) { return (Math.random() * 2 - 1) * n; }
    // Stochastic 3D branch structure.
    function tree(id, name, cfg, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 60, layout: function (d, THREE) {
            var a = [], e = [];
            function grow(pos, dir, len, depth) {
                var end = pos.clone().add(dir.clone().multiplyScalar(len));
                e.push({ a: pos, b: end, color: color }); a.push(end);
                if (depth <= 0) return;
                for (var b = 0; b < cfg.branches; b++) {
                    var nd = dir.clone();
                    nd.x += rand(cfg.spread); nd.y += rand(cfg.spread); nd.z += rand(cfg.spread);
                    nd.y += cfg.up; nd.normalize();
                    grow(end, nd, len * cfg.ratio, depth - 1);
                }
            }
            a.push(new THREE.Vector3(0, cfg.y0, 0));
            grow(new THREE.Vector3(0, cfg.y0, 0), new THREE.Vector3(0, cfg.up > 0 ? 1 : (cfg.up < 0 ? -1 : 0.3), 0.0).normalize(), cfg.len, cfg.depth);
            return G.anchorLayout(d, THREE, a, e);
        } });
    }
    function anchorsEdges(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }

    G.create({ id: 'nautilus', name: 'Nautilus shell', rotateSpeed: 0.35, camZ: 58, layout: function (d, THREE) { var P = [], i, N = 900, turns = 4; for (i = 0; i <= N; i++) { var t = i / N * turns * PI2, r = 1.2 * Math.exp(0.19 * t), tube = 0.32 * r; var cx = Math.cos(t) * r, cy = Math.sin(t) * r, phi = i / N * PI2 * 26; P.push(new THREE.Vector3(cx + Math.cos(phi) * tube, cy + Math.sin(phi) * tube * 0.6, Math.sin(phi) * tube)); } var s = 0.6; P.forEach(function (p) { p.multiplyScalar(s); }); return G.curveLayout(d, THREE, P, 0xffb454); } });
})();
