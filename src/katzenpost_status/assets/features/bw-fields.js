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

    field('field-saddle', 'Saddle field', function (x, y, z) { return [x, -y, z * 0.3]; }, 0x9b5de5, 58, 4, 16, 40, 0.18);

    field('field-dipole', 'Dipole field', function (x, y, z) { var r = Math.sqrt(x * x + y * y + z * z) + 0.05, r5 = Math.pow(r, 5); return [3 * z * x / r5, 3 * z * y / r5, (3 * z * z - r * r) / r5]; }, 0xff8f3f, 56, 5, 14, 70, 0.12);

    field('field-abc', 'ABC flow', function (x, y, z) { var A = 1, B = 0.7, C = 0.43, X = x * 3, Y = y * 3, Z = z * 3; return [A * Math.sin(Z) + C * Math.cos(Y), B * Math.sin(X) + A * Math.cos(Z), C * Math.sin(Y) + B * Math.cos(X)]; }, 0xff5d8f, 58, 5, 16, 90, 0.12);

    field('field-shear', 'Shear flow', function (x, y, z) { return [y, 0.15 * z, -0.15 * y]; }, 0x00d2a0, 58, 5, 16, 50, 0.16);

    field('field-spiralsink', 'Spiral sink', function (x, y, z) { return [-x - y, x - y, -z * 0.4]; }, 0xffd23f, 58, 4, 16, 80, 0.14);

    field('field-quadrupole', 'Quadrupole field', function (x, y, z) { return [x * (x * x - 3 * y * y), y * (y * y - 3 * x * x), z * 0.4]; }, 0x4d8bf0, 58, 5, 14, 40, 0.12);

    field('field-roberts', 'Roberts cell flow', function (x, y, z) { var X = x * 3, Y = y * 3; return [Math.sin(X) * Math.cos(Y), -Math.cos(X) * Math.sin(Y), Math.sin(X) * Math.sin(Y) * 0.6]; }, 0x9b5de5, 58, 5, 16, 80, 0.12);
})();
