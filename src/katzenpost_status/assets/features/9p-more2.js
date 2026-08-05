(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // 64-tetrahedron grid (isotropic vector matrix): the FCC lattice, whose
    // nearest-neighbour bonds tile space with tetrahedra and octahedra.
    G.create({
        id: 'ivm64', name: '64-tetrahedron grid', rotateSpeed: 0.4, camZ: 62,
        layout: function (d, THREE) {
            var S = 6, pts = [], x, y, z, i, j;
            for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) {
                if (((x + y + z) & 1) === 0 && x * x + y * y + z * z <= 6) pts.push(new THREE.Vector3(x * S, y * S, z * S));
            }
            var edges = [], nn = Math.SQRT2 * S;
            for (i = 0; i < pts.length; i++) for (j = i + 1; j < pts.length; j++) if (Math.abs(pts[i].distanceTo(pts[j]) - nn) < 0.4 * S) edges.push({ a: pts[i], b: pts[j], color: 0xffb454 });
            return G.anchorLayout(d, THREE, pts, edges);
        }
    });
})();
