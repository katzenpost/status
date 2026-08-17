(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function cloud(id, name, gen, k, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 56, layout: function (d, THREE) { var pts = gen(THREE); if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []); return G.anchorLayout(d, THREE, pts, knn(pts, THREE, k, color)); } }); }
    // 3D escape-time shell: keep boundary voxels (escaped in a mid band).
    function shell3d(step, R, sc) {
        return function (THREE) { var N = 34, pts = [], i, j, l; for (i = 0; i <= N && pts.length < 560; i++) for (j = 0; j <= N && pts.length < 560; j++) for (l = 0; l <= N && pts.length < 560; l++) { var x = -R + 2 * R * i / N, y = -R + 2 * R * j / N, z = -R + 2 * R * l / N; var n = step(x, y, z); if (n >= 3 && n <= 9) pts.push(new THREE.Vector3(x * sc, y * sc, z * sc)); } return pts; };
    }
    function mbulb(power) { return function (cx, cy, cz) { var vx = cx, vy = cy, vz = cz, n = 0; for (; n < 12; n++) { var r = Math.sqrt(vx * vx + vy * vy + vz * vz); if (r > 2) break; if (r < 1e-9) r = 1e-9; var th = power * Math.acos(vz / r), ph = power * Math.atan2(vy, vx), rp = Math.pow(r, power); vx = rp * Math.sin(th) * Math.cos(ph) + cx; vy = rp * Math.sin(th) * Math.sin(ph) + cy; vz = rp * Math.cos(th) + cz; } return n; }; }
    // Chaos-game IFS point set from affine/scaling maps.
    function ifs(maps, iters) { return function (THREE) { var p = [0.1, 0.1, 0.1], pts = [], i; for (i = 0; i < iters; i++) { var m = maps[(Math.random() * maps.length) | 0]; p = m(p); if (i > 30 && pts.length < 560) pts.push(new THREE.Vector3(p[0], p[1], p[2])); } var mx = 0; pts.forEach(function (v) { mx = Math.max(mx, Math.abs(v.x), Math.abs(v.y), Math.abs(v.z)); }); var s = 20 / (mx || 1); pts.forEach(function (v) { v.multiplyScalar(s); }); return pts; }; }

    cloud('quaternionjulia', 'Quaternion Julia', shell3d(function (x, y, z) { var qx = x, qy = y, qz = z, qw = 0, cx = -0.2, cy = 0.6, cz = 0.2, cw = 0.2, n = 0; for (; n < 12; n++) { var nx = qx * qx - qy * qy - qz * qz - qw * qw + cx; var ny = 2 * qx * qy + cy; var nz = 2 * qx * qz + cz; var nw = 2 * qx * qw + cw; qx = nx; qy = ny; qz = nz; qw = nw; if (qx * qx + qy * qy + qz * qz + qw * qw > 4) break; } return n; }, 1.3, 12), 3, 0x2ec4b6, 54);

    cloud('mandelbulb3', 'Mandelbulb (power 3)', shell3d(mbulb(3), 1.25, 15), 3, 0x4d8bf0, 54);

    cloud('mandelbulb4', 'Mandelbulb (power 4)', shell3d(mbulb(4), 1.25, 15), 3, 0x9b5de5, 54);

    cloud('mandelbulb5', 'Mandelbulb (power 5)', shell3d(mbulb(5), 1.25, 15), 3, 0xff8f3f, 54);

    cloud('mandelbulb6', 'Mandelbulb (power 6)', shell3d(mbulb(6), 1.25, 15), 3, 0xff5d8f, 54);

    cloud('mandelbox', 'Mandelbox', shell3d(function (cx, cy, cz) { var x = cx, y = cy, z = cz, s = 2, n = 0; for (; n < 11; n++) { function bf(v) { return v > 1 ? 2 - v : (v < -1 ? -2 - v : v); } x = bf(x); y = bf(y); z = bf(z); var r2 = x * x + y * y + z * z; var m = r2 < 0.25 ? 4 : (r2 < 1 ? 1 / r2 : 1); x = x * m * s + cx; y = y * m * s + cy; z = z * m * s + cz; if (x * x + y * y + z * z > 16) break; } return n; }, 3.2, 6), 3, 0x00d2a0, 54);
})();
