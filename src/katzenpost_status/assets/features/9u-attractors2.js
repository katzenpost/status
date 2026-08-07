(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Integrate a 3D flow and lay nodes/packets along the trajectory (z up).
    function attractor(id, name, step, x0, dt, iters, scale, center, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 66,
            layout: function (d, THREE) {
                var p = x0.slice(), pts = [], i, q;
                for (i = 0; i < 500; i++) { p = step(p, dt); }
                for (i = 0; i < iters; i++) {
                    p = step(p, dt);
                    if (!isFinite(p[0]) || !isFinite(p[1]) || !isFinite(p[2])) break;
                    q = new THREE.Vector3((p[0] - center[0]) * scale, (p[2] - center[2]) * scale, (p[1] - center[1]) * scale);
                    if (q.length() < 200) pts.push(q);
                }
                if (pts.length < 4) pts = [new THREE.Vector3(-5, 0, 0), new THREE.Vector3(5, 0, 0)];
                return G.curveLayout(d, THREE, pts, color);
            } });
    }

    attractor('chen', 'Chen attractor', function (p, dt) { var a = 35, b = 3, c = 28, x = p[0], y = p[1], z = p[2]; return [x + dt * a * (y - x), y + dt * ((c - a) * x - x * z + c * y), z + dt * (x * y - b * z)]; }, [-0.1, 0.5, -0.6], 0.004, 3600, 0.62, [0, 0, 24], 0x2ec4b6, 70);
})();
