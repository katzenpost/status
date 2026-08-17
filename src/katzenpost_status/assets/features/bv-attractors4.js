(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function attractor(id, name, step, x0, dt, iters, scale, center, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 64, layout: function (d, THREE) {
            var p = x0.slice(), pts = [], i, q;
            for (i = 0; i < 700; i++) p = step(p, dt);
            for (i = 0; i < iters; i++) { p = step(p, dt); if (!isFinite(p[0]) || !isFinite(p[1]) || !isFinite(p[2])) break; q = new THREE.Vector3((p[0] - center[0]) * scale, (p[2] - center[2]) * scale, (p[1] - center[1]) * scale); if (q.length() < 220) pts.push(q); }
            if (pts.length < 4) pts = [new THREE.Vector3(-5, 0, 0), new THREE.Vector3(5, 0, 0)];
            return G.curveLayout(d, THREE, pts, color);
        } });
    }

    attractor('arneodo', 'Arneodo attractor', function (p, dt) { var a = -5.5, b = 3.5, c = -1, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (-a * x - b * y - z + c * x * x * x)]; }, [0.1, 0, 0], 0.02, 5000, 4, [0, 0, 0], 0x2ec4b6, 60);

    attractor('coullet', 'Coullet attractor', function (p, dt) { var a = 0.8, b = -1.1, c = -0.45, d = -1, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (a * x + b * y + c * z + d * x * x * x)]; }, [0.1, 0, 0], 0.03, 5000, 10, [0, 0, 0], 0x4d8bf0, 58);

    attractor('genesiotesi', 'Genesio-Tesi attractor', function (p, dt) { var a = 0.44, b = 1.1, c = 1, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (-c * x - b * y - a * z + x * x)]; }, [0.1, 0, 0], 0.02, 5000, 12, [0.5, 0, 0], 0x9b5de5, 58);

    attractor('shimizumorioka', 'Shimizu-Morioka attractor', function (p, dt) { var a = 0.75, b = 0.45, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * (x * (1 - z) - a * y), z + dt * (-b * z + x * x)]; }, [0.1, 0.1, 0.1], 0.02, 5000, 13, [0, 0, 1], 0xff8f3f, 58);

    attractor('windmi', 'WINDMI attractor', function (p, dt) { var a = 0.7, b = 2.5, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (-a * z - y + b - Math.exp(x))]; }, [0, 0.8, 0], 0.03, 5000, 6, [0, 0, 0], 0xff5d8f, 58);

    attractor('moorespiegel', 'Moore-Spiegel attractor', function (p, dt) { var t = 6, r = 20, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (-z - (t - r + r * x * x) * y - t * x)]; }, [0.1, 0, 0], 0.01, 5000, 4, [0, 0, 0], 0x00d2a0, 58);

    attractor('sprottjerk', 'Sprott jerk attractor', function (p, dt) { var a = 2.017, x = p[0], y = p[1], z = p[2]; return [x + dt * y, y + dt * z, z + dt * (-a * z + y * y - x)]; }, [0.1, 0, 0], 0.03, 5000, 6, [0, 0, 0], 0xffd23f, 58);

    attractor('burkeshaw', 'Burke-Shaw attractor', function (p, dt) { var s = 10, v = 4.272, x = p[0], y = p[1], z = p[2]; return [x + dt * (-s * (x + y)), y + dt * (-y - s * x * z), z + dt * (s * x * y + v)]; }, [0.6, 0, 0], 0.01, 5000, 8, [0, 0, 0], 0x4d8bf0, 58);
})();
