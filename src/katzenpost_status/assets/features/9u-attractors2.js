(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Integrate a 3D flow and lay nodes/packets along the trajectory (z up).
    // mapFn(p)->[X,Y,Z] optionally re-embeds the state (e.g. for a forced
    // oscillator whose raw 3rd coord grows without bound).
    function attractor(id, name, step, x0, dt, iters, scale, center, color, camZ, mapFn) {
        G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 66,
            layout: function (d, THREE) {
                var p = x0.slice(), pts = [], i, q, m;
                for (i = 0; i < 500; i++) { p = step(p, dt); }
                for (i = 0; i < iters; i++) {
                    p = step(p, dt);
                    if (!isFinite(p[0]) || !isFinite(p[1]) || !isFinite(p[2])) break;
                    m = mapFn ? mapFn(p) : [p[0], p[2], p[1]];
                    q = new THREE.Vector3((m[0] - center[0]) * scale, (m[1] - center[2]) * scale, (m[2] - center[1]) * scale);
                    if (q.length() < 200) pts.push(q);
                }
                if (pts.length < 4) pts = [new THREE.Vector3(-5, 0, 0), new THREE.Vector3(5, 0, 0)];
                return G.curveLayout(d, THREE, pts, color);
            } });
    }

    attractor('chen', 'Chen attractor', function (p, dt) { var a = 35, b = 3, c = 28, x = p[0], y = p[1], z = p[2]; return [x + dt * a * (y - x), y + dt * ((c - a) * x - x * z + c * y), z + dt * (x * y - b * z)]; }, [-10, 0, 37], 0.002, 6000, 0.55, [0, 0, 22], 0x2ec4b6, 70);

    attractor('chua', 'Chua attractor', function (p, dt) { var al = 15.6, be = 28, m0 = -1.143, m1 = -0.714, x = p[0], y = p[1], z = p[2]; var f = m1 * x + 0.5 * (m0 - m1) * (Math.abs(x + 1) - Math.abs(x - 1)); return [x + dt * al * (y - x - f), y + dt * (x - y + z), z + dt * (-be * y)]; }, [0.7, 0, 0], 0.02, 4200, 3.4, [0, 0, 0], 0x9b5de5, 60);

    attractor('dadras', 'Dadras attractor', function (p, dt) { var a = 3, b = 2.7, c = 1.7, dd = 2, e = 9, x = p[0], y = p[1], z = p[2]; return [x + dt * (y - a * x + b * y * z), y + dt * (c * y - x * z + z), z + dt * (dd * x * y - e * z)]; }, [1.1, 2.1, -2], 0.01, 4000, 3.0, [0, 0, 0], 0x4d8bf0, 62);

    attractor('rabinovich', 'Rabinovich-Fabrikant', function (p, dt) { var g = 0.87, a = 1.1, x = p[0], y = p[1], z = p[2]; return [x + dt * (y * (z - 1 + x * x) + g * x), y + dt * (x * (3 * z + 1 - x * x) + g * y), z + dt * (-2 * z * (a + x * y))]; }, [-1, 0, 0.5], 0.004, 4200, 9.0, [0, 0, 0.6], 0xff8f3f, 58);

    attractor('nosehoover', 'Nose-Hoover attractor', function (p, dt) { var a = 1.5, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * (-x + y * z), z + dt * (a - y * y)]; }, [0.1, 0.1, 0], 0.02, 4200, 5.5, [0, 0, 0], 0x00d2a0, 60);

    attractor('fourwing', 'Four-wing attractor', function (p, dt) { var a = 0.2, b = 0.01, c = -0.4, x = p[0], y = p[1], z = p[2]; return [x + dt * (a * x + y * z), y + dt * (b * x + c * y - x * z), z + dt * (-z - x * y)]; }, [1, -1, 1], 0.02, 4400, 6.5, [0, 0, 0], 0xff5d8f, 58);

    attractor('sprottb', 'Sprott-B attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (y * z), y + dt * (x - y), z + dt * (1 - x * y)]; }, [0.5, 0.5, 0.5], 0.02, 4200, 6.5, [0, 0, 0], 0xffd23f, 60);

    attractor('lorenz84', 'Lorenz-84 attractor', function (p, dt) { var a = 0.25, b = 4, F = 8, GG = 1, x = p[0], y = p[1], z = p[2]; return [x + dt * (-y * y - z * z - a * x + a * F), y + dt * (x * y - b * x * z - y + GG), z + dt * (b * x * y + x * z - z)]; }, [1, 0, 0], 0.03, 4200, 7.5, [3, 0, 0], 0x2ec4b6, 60);

    attractor('sprottf', 'Sprott-Linz F attractor', function (p, dt) { var a = 0.5, x = p[0], y = p[1], z = p[2]; return [x + dt * (y + z), y + dt * (-x + a * y), z + dt * (x * x - z)]; }, [0.1, 0, 0], 0.02, 4400, 7.0, [0, 0, 1.5], 0x9b5de5, 60);

    // Duffing is forced: its 3rd coord is an ever-growing phase, so re-embed it
    // as (x, y, sin phase) - a bounded 3D coil of the phase portrait.
    attractor('duffing', 'Duffing oscillator', function (p, dt) { var de = 0.3, ga = 0.5, w = 1.2, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * (-de * y + x - x * x * x + ga * Math.cos(z)), z + dt * w]; }, [0.1, 0, 0], 0.02, 4400, 13.0, [0, 0, 0], 0xff8f3f, 56, function (p) { return [p[0], p[1], Math.sin(p[2]) * 1.4]; });
})();
