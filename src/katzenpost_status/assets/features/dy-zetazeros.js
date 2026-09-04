(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var ZEROS = [14.134725, 21.022040, 25.010858, 30.424876, 32.935062,
        37.586178, 40.918719, 43.327073, 48.005151, 49.773832,
        52.970321, 56.446248, 59.347044, 60.831779, 65.112544,
        67.079811, 69.546402, 72.067158, 75.704691, 77.144840,
        79.337375, 82.910381, 84.735493, 87.425275, 88.809111,
        92.491899, 94.651344, 95.870634, 98.831194, 101.317851];

    G.create({
        id: 'zeta-zeros', name: 'Riemann zeta zeros', rotateSpeed: 0.35, camZ: 60,
        layout: function (d, THREE) {
            var maxg = ZEROS[ZEROS.length - 1], R = 7, step = 0.62;
            var A = [], B = [], anchors = [], edges = [], i;
            for (i = 0; i < ZEROS.length; i++) {
                var g = ZEROS[i], y = g / maxg * 36 - 18, a = i * step;
                var pa = new THREE.Vector3(R * Math.cos(a), y, R * Math.sin(a));
                var pb = new THREE.Vector3(R * Math.cos(a + Math.PI), y, R * Math.sin(a + Math.PI));
                A.push(pa); B.push(pb);
                anchors.push(pa); anchors.push(pb);
            }
            for (i = 0; i + 1 < A.length; i++) {
                edges.push({ a: A[i], b: A[i + 1], color: 0x4d8bf0 });
                edges.push({ a: B[i], b: B[i + 1], color: 0x9b5de5 });
            }
            for (i = 0; i < A.length; i++) edges.push({ a: A[i], b: B[i], color: 0x2ec4b6 });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
