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

    attractor('thomas', 'Thomas attractor', function (p, dt) {
        var b = 0.208;
        return [p[0] + dt * (Math.sin(p[1]) - b * p[0]), p[1] + dt * (Math.sin(p[2]) - b * p[1]), p[2] + dt * (Math.sin(p[0]) - b * p[2])];
    }, [1.1, 1.1, -0.1], 0.06, 4000, 5.0, [0, 0, 0], 0x9b5de5, 66);

    attractor('halvorsen', 'Halvorsen attractor', function (p, dt) {
        var a = 1.89, x = p[0], y = p[1], z = p[2];
        return [x + dt * (-a * x - 4 * y - 4 * z - y * y), y + dt * (-a * y - 4 * z - 4 * x - z * z), z + dt * (-a * z - 4 * x - 4 * y - x * x)];
    }, [-1.48, -1.51, 2.04], 0.007, 4000, 3.2, [-2.7, -2.7, -2.7], 0x00d2a0, 60);

    attractor('aizawa', 'Aizawa attractor', function (p, dt) {
        var a = 0.95, b = 0.7, c = 0.6, e = 0.25, f = 0.1, dd = 3.5, x = p[0], y = p[1], z = p[2];
        return [x + dt * ((z - b) * x - dd * y), y + dt * (dd * x + (z - b) * y), z + dt * (c + a * z - z * z * z / 3 - (x * x + y * y) * (1 + e * z) + f * z * x * x * x)];
    }, [0.1, 0, 0], 0.01, 4200, 15, [0, 0, 0.6], 0xff8f3f, 46);
})();
