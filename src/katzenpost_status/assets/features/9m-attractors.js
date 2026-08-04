(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Integrate a strange attractor and lay nodes/packets along its trajectory
    // (z is mapped to the vertical so it stands upright).
    function attractor(id, name, step, x0, dt, iters, scale, center, color, camZ) {
        G.create({
            id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 68,
            layout: function (d, THREE) {
                var p = x0.slice(), pts = [], i;
                for (i = 0; i < 400; i++) p = step(p, dt);   // settle onto the attractor
                for (i = 0; i < iters; i++) {
                    p = step(p, dt);
                    pts.push(new THREE.Vector3((p[0] - center[0]) * scale, (p[2] - center[2]) * scale, (p[1] - center[1]) * scale));
                }
                return G.curveLayout(d, THREE, pts, color);
            }
        });
    }

    attractor('lorenz', 'Lorenz attractor', function (p, dt) {
        var s = 10, r = 28, b = 8 / 3;
        return [p[0] + dt * s * (p[1] - p[0]), p[1] + dt * (p[0] * (r - p[2]) - p[1]), p[2] + dt * (p[0] * p[1] - b * p[2])];
    }, [0.1, 0, 0], 0.006, 3200, 0.85, [0, 0, 25], 0x2ec4b6, 74);

    attractor('rossler', 'Rossler attractor', function (p, dt) {
        var a = 0.2, b = 0.2, c = 5.7;
        return [p[0] + dt * (-p[1] - p[2]), p[1] + dt * (p[0] + a * p[1]), p[2] + dt * (b + p[2] * (p[0] - c))];
    }, [0.1, 0, 0], 0.03, 3400, 1.3, [0, 0, 6], 0x4d8bf0, 72);
})();
