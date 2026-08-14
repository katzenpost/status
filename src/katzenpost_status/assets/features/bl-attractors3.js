(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function attractor(id, name, step, x0, dt, iters, scale, center, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 66, layout: function (d, THREE) {
            var p = x0.slice(), pts = [], i, q;
            for (i = 0; i < 600; i++) p = step(p, dt);
            for (i = 0; i < iters; i++) { p = step(p, dt); if (!isFinite(p[0]) || !isFinite(p[1]) || !isFinite(p[2])) break; q = new THREE.Vector3((p[0] - center[0]) * scale, (p[2] - center[2]) * scale, (p[1] - center[1]) * scale); if (q.length() < 220) pts.push(q); }
            if (pts.length < 4) pts = [new THREE.Vector3(-5, 0, 0), new THREE.Vector3(5, 0, 0)];
            return G.curveLayout(d, THREE, pts, color);
        } });
    }

    attractor('rikitake', 'Rikitake dynamo', function (p, dt) { var m = 2, a = 5, x = p[0], y = p[1], z = p[2]; return [x + dt * (-m * x + z * y), y + dt * (-m * y + (z - a) * x), z + dt * (1 - x * y)]; }, [0.1, 0.1, 0.1], 0.01, 5000, 3.2, [0, 0, 2], 0x2ec4b6, 62);
})();
