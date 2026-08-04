(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // Tree of Life (Kabbalah): 10 sephirot joined by the 22 paths. A natural
    // graph -- packets route the pipeline along the paths.
    G.create({
        id: 'treeoflife', name: 'Tree of Life', rotateSpeed: 0.3, camZ: 62,
        layout: function (d, THREE) {
            var S = 5.2, P = [[0, 4], [1.2, 3], [-1.2, 3], [1.2, 1.4], [-1.2, 1.4], [0, 0.6], [1.2, -0.6], [-1.2, -0.6], [0, -1.6], [0, -3]];
            var anchors = P.map(function (p) { return new THREE.Vector3(p[0] * S, p[1] * S, 0); });
            var pairs = [[0, 1], [0, 2], [0, 5], [1, 2], [1, 3], [1, 5], [2, 4], [2, 5], [3, 4], [3, 5], [3, 6], [4, 5], [4, 7], [5, 6], [5, 7], [5, 8], [6, 7], [6, 8], [6, 9], [7, 8], [7, 9], [8, 9]];
            var edges = pairs.map(function (pr) { return { a: anchors[pr[0]], b: anchors[pr[1]], color: 0xffd23f }; });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
