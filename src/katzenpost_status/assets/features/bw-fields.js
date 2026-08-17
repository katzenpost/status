(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    // Integrate streamlines of a 3D vector field from a grid of seeds.
    function field(id, name, vfn, color, camZ, seedsPerAxis, span, steps, dt) {
        G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 60, layout: function (d, THREE) {
            var a = [], e = [], S = span || 16, n = seedsPerAxis || 4, i, j, l, st = steps || 60, h = dt || 0.15;
            for (i = 0; i < n; i++) for (j = 0; j < n; j++) for (l = 0; l < n; l++) {
                var x = -S + 2 * S * (i + 0.5) / n, y = -S + 2 * S * (j + 0.5) / n, z = -S + 2 * S * (l + 0.5) / n, prev = null, k;
                for (k = 0; k < st; k++) {
                    var v = vfn(x / S, y / S, z / S); var m = Math.sqrt(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]) || 1;
                    x += v[0] / m * h * S; y += v[1] / m * h * S; z += v[2] / m * h * S;
                    if (Math.abs(x) > S * 2.2 || Math.abs(y) > S * 2.2 || Math.abs(z) > S * 2.2) break;
                    var p = new THREE.Vector3(x, y, z); if (k % 5 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p;
                }
            }
            return G.anchorLayout(d, THREE, a, e);
        } });
    }

    field('field-source', 'Source-sink field', function (x, y, z) { return [x, y, z]; }, 0x2ec4b6, 58, 4, 16, 40, 0.2);

    field('field-vortex', 'Vortex field', function (x, y, z) { return [-y, x, z * 0.15]; }, 0x4d8bf0, 58, 4, 16, 70, 0.14);
})();
