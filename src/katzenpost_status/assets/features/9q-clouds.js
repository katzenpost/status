(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Connect a point cloud into a graph: each point links to its k nearest
    // neighbours, so packets can still route "along" an edge-less fractal.
    function knnEdges(pts, THREE, k, color) {
        var edges = [], seen = {}, i, j, m;
        for (i = 0; i < pts.length; i++) {
            var ds = [];
            for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]);
            ds.sort(function (a, b) { return a[0] - b[0]; });
            for (m = 0; m < k && m < ds.length; m++) {
                var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b;
                if (!seen[key]) { seen[key] = 1; edges.push({ a: pts[i], b: pts[jj], color: color }); }
            }
        }
        return edges;
    }
    function center(pts) {
        var c = pts[0].clone().multiplyScalar(0); pts.forEach(function (p) { c.add(p); }); c.multiplyScalar(1 / pts.length);
        pts.forEach(function (p) { p.sub(c); });
    }

    // Barnsley fern: the classic affine IFS, connected into a routable mesh.
    G.create({
        id: 'fern', name: 'Barnsley fern', rotateSpeed: 0.18, camZ: 60,
        layout: function (d, THREE) {
            var x = 0, y = 0, pts = [], i, keep = 3;
            for (i = 0; i < 6000; i++) {
                var r = Math.random(), nx, ny;
                if (r < 0.01) { nx = 0; ny = 0.16 * y; }
                else if (r < 0.86) { nx = 0.85 * x + 0.04 * y; ny = -0.04 * x + 0.85 * y + 1.6; }
                else if (r < 0.93) { nx = 0.2 * x - 0.26 * y; ny = 0.23 * x + 0.22 * y + 1.6; }
                else { nx = -0.15 * x + 0.28 * y; ny = 0.26 * x + 0.24 * y + 0.44; }
                x = nx; y = ny;
                if (i > 60 && i % keep === 0 && pts.length < 460) pts.push(new THREE.Vector3(x * 6.5, y * 5.2, (Math.random() - 0.5) * 1.2));
            }
            center(pts);
            return G.anchorLayout(d, THREE, pts, knnEdges(pts, THREE, 2, 0x00d2a0));
        }
    });

    // Mandelbulb (power 8): a boundary-shell point cloud, meshed for routing.
    G.create({
        id: 'mandelbulb', name: 'Mandelbulb', rotateSpeed: 0.3, camZ: 54,
        layout: function (d, THREE) {
            function bulb(vx, vy, vz, cx, cy, cz) {
                var r = Math.sqrt(vx * vx + vy * vy + vz * vz);
                if (r < 1e-9) return [cx, cy, cz];
                var theta = 8 * Math.acos(vz / r), phi = 8 * Math.atan2(vy, vx), rp = Math.pow(r, 8);
                return [rp * Math.sin(theta) * Math.cos(phi) + cx, rp * Math.sin(theta) * Math.sin(phi) + cy, rp * Math.cos(theta) + cz];
            }
            var pts = [], tries = 0;
            while (pts.length < 420 && tries < 40000) {
                tries++;
                var cx = (Math.random() * 2 - 1) * 1.25, cy = (Math.random() * 2 - 1) * 1.25, cz = (Math.random() * 2 - 1) * 1.25;
                var vx = cx, vy = cy, vz = cz, n = 0, esc = false;
                for (; n < 12; n++) { var q = bulb(vx, vy, vz, cx, cy, cz); vx = q[0]; vy = q[1]; vz = q[2]; if (vx * vx + vy * vy + vz * vz > 4) { esc = true; break; } }
                if (esc && n >= 3) pts.push(new THREE.Vector3(cx * 16, cz * 16, cy * 16));   // shell points
            }
            if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []);
            return G.anchorLayout(d, THREE, pts, knnEdges(pts, THREE, 3, 0x9b5de5));
        }
    });
})();
