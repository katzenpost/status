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

    attractor('newtonleipnik', 'Newton-Leipnik attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (-0.4 * x + y + 10 * y * z), y + dt * (-x - 0.4 * y + 5 * x * z), z + dt * (0.175 * z - 5 * x * y)]; }, [0.349, 0, -0.16], 0.008, 5000, 22, [0, 0, 0], 0x4d8bf0, 56);

    attractor('rucklidge', 'Rucklidge attractor', function (p, dt) { var k = 2, a = 6.7, x = p[0], y = p[1], z = p[2]; return [x + dt * (-k * x + a * y - y * z), y + dt * x, z + dt * (-z + y * y)]; }, [0.1, 0, 0], 0.01, 5000, 2.6, [0, 0, 6], 0x9b5de5, 60);

    attractor('sprottc', 'Sprott-C attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (y * z), y + dt * (x - y), z + dt * (1 - x * x)]; }, [0.1, 0.2, 0.3], 0.02, 4600, 7, [0, 0, 0], 0xff8f3f, 58);

    attractor('sprottd', 'Sprott-D attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (-y), y + dt * (x + z), z + dt * (x * z + 3 * y * y)]; }, [0.1, 0.1, 0.1], 0.02, 4600, 6, [0, 0, 0], 0xff5d8f, 58);

    attractor('sprotte', 'Sprott-E attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (y * z), y + dt * (x * x - y), z + dt * (1 - 4 * x)]; }, [0.1, 0.1, 0.1], 0.02, 4600, 7, [0.25, 0, 0], 0x00d2a0, 58);

    attractor('sprottg', 'Sprott-G attractor', function (p, dt) { var x = p[0], y = p[1], z = p[2]; return [x + dt * (0.4 * x + z), y + dt * (x * z - y), z + dt * (-x + y)]; }, [0.1, 0.1, 0.1], 0.02, 4800, 7, [0, 0, 0], 0xffd23f, 58);

    attractor('hindmarshrose', 'Hindmarsh-Rose neuron', function (p, dt) { var x = p[0], y = p[1], z = p[2], I = 3.2; return [x + dt * (y - x * x * x + 3 * x * x - z + I), y + dt * (1 - 5 * x * x - y), z + dt * (0.006 * (4 * (x + 1.6) - z))]; }, [-1, -5, 3], 0.05, 5000, 7, [0, -3, 3], 0x4d8bf0, 56);
})();
