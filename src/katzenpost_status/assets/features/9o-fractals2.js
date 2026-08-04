(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // L-system tree: a recursively branching binary tree; packets climb it.
    G.create({
        id: 'ltree', name: 'L-system tree', rotateSpeed: 0.22, camZ: 60,
        layout: function (d, THREE) {
            var edges = [], anchors = [], ang = 26 * Math.PI / 180, ratio = 0.72;
            function grow(x, y, dir, len, depth) {
                var x2 = x + Math.cos(dir) * len, y2 = y + Math.sin(dir) * len;
                edges.push({ a: new THREE.Vector3(x, y, 0), b: new THREE.Vector3(x2, y2, 0), color: 0x2ec4b6 });
                anchors.push(new THREE.Vector3(x2, y2, 0));
                if (depth <= 0) return;
                grow(x2, y2, dir + ang, len * ratio, depth - 1);
                grow(x2, y2, dir - ang, len * ratio, depth - 1);
            }
            anchors.push(new THREE.Vector3(0, -20, 0));
            grow(0, -20, Math.PI / 2, 14, 5);
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
