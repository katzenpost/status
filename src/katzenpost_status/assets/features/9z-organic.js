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

    anchorsEdges('dna', 'DNA double helix', function (a, e, T, color) { var N = 120, R = 8, H = 46; var s1 = [], s2 = []; for (var i = 0; i <= N; i++) { var t = i / N, th = t * PI2 * 4, y = (t - 0.5) * H; var p1 = new T.Vector3(Math.cos(th) * R, y, Math.sin(th) * R), p2 = new T.Vector3(Math.cos(th + Math.PI) * R, y, Math.sin(th + Math.PI) * R); s1.push(p1); s2.push(p2); a.push(p1); a.push(p2); if (i > 0) { e.push({ a: s1[i - 1], b: p1, color: 0x4d8bf0 }); e.push({ a: s2[i - 1], b: p2, color: 0xff8f3f }); } if (i % 5 === 0) e.push({ a: p1, b: p2, color: 0x9fb3c2 }); } }, 0x4d8bf0, 60);

    cloud('romanesco', 'Romanesco fractal', function (T) { var pts = [], M = 13, i, j; for (i = 0; i < M; i++) { var r = Math.sqrt(i) * 4.4, th = i * GA, cx = Math.cos(th) * r, cz = Math.sin(th) * r, cy = 18 - Math.sqrt(i) * 5; for (j = 0; j < 22; j++) { var rr = Math.sqrt(j) * 1.0, ph = j * GA; pts.push(new T.Vector3(cx + Math.cos(ph) * rr, cy + j * 0.28, cz + Math.sin(ph) * rr)); } } return pts; }, 3, 0x2ec4b6, 60);

    tree('coral', 'Coral (3D L-system)', { branches: 3, spread: 0.55, up: 0.5, ratio: 0.74, len: 9, depth: 6, y0: -20 }, 0xff5d8f, 62);

    tree('dendrite', 'Neuron dendrite', { branches: 3, spread: 1.0, up: 0.0, ratio: 0.72, len: 8, depth: 6, y0: 0 }, 0x9b5de5, 60);

    G.create({ id: 'lichtenberg', name: 'Lichtenberg figure', rotateSpeed: 0.2, camZ: 58, layout: function (d, THREE) { var a = [], e = []; function grow(pos, dir, len, depth) { var end = pos.clone(); end.x += dir.x * len; end.y += dir.y * len; end.z += rand(0.6); e.push({ a: pos, b: end, color: 0x4d8bf0 }); a.push(end); if (depth <= 0) return; var nb = 1 + (Math.random() < 0.55 ? 1 : 0); for (var b = 0; b < nb; b++) { var ang = Math.atan2(dir.y, dir.x) + rand(0.9); var nd = new THREE.Vector3(Math.cos(ang), Math.sin(ang), 0); grow(end, nd, len * 0.82, depth - 1); } } a.push(new THREE.Vector3(0, -22, 0)); for (var s = 0; s < 6; s++) { var ang = -Math.PI / 2 + rand(0.5) + s * 0.0; grow(new THREE.Vector3(0, -22, 0), new THREE.Vector3(Math.cos(-Math.PI / 2 + (s - 2.5) * 0.4), Math.sin(-Math.PI / 2 + (s - 2.5) * 0.4) * -1, 0), 7, 7); } return G.anchorLayout(d, THREE, a, e); } });

    cloud('dla', 'Diffusion-limited aggregation', function (T) { var pts = [new T.Vector3(0, 0, 0)]; for (var i = 0; i < 460; i++) { var base = pts[(Math.random() * pts.length) | 0], a1 = Math.random() * PI2, a2 = Math.acos(rand(1)); pts.push(new T.Vector3(base.x + Math.sin(a2) * Math.cos(a1) * 1.4, base.y + Math.sin(a2) * Math.sin(a1) * 1.4, base.z + Math.cos(a2) * 1.4)); } return pts; }, 2, 0xffd23f, 56);
})();
