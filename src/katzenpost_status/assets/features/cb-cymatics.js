(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function contour(id, name, f, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 54, layout: function (d, THREE) {
            var N = 72, S = 44, edges = [], anchors = [], i, j;
            function XY(u, v) { return new THREE.Vector3((u - 0.5) * S, (v - 0.5) * S, 0); }
            for (i = 0; i < N; i++) for (j = 0; j < N; j++) {
                var u0 = i / N, u1 = (i + 1) / N, v0 = j / N, v1 = (j + 1) / N;
                var a = f(u0, v0), b = f(u1, v0), c = f(u1, v1), e = f(u0, v1), cr = [];
                if ((a < 0) !== (b < 0)) cr.push(XY(u0 + (u1 - u0) * (a / (a - b)), v0));
                if ((b < 0) !== (c < 0)) cr.push(XY(u1, v0 + (v1 - v0) * (b / (b - c))));
                if ((c < 0) !== (e < 0)) cr.push(XY(u1 + (u0 - u1) * (c / (c - e)), v1));
                if ((e < 0) !== (a < 0)) cr.push(XY(u0, v1 + (v0 - v1) * (e / (e - a))));
                if (cr.length >= 2) { edges.push({ a: cr[0], b: cr[1], color: color }); anchors.push(cr[0], cr[1]); if (cr.length === 4) { edges.push({ a: cr[2], b: cr[3], color: color }); anchors.push(cr[2], cr[3]); } }
            }
            return G.anchorLayout(d, THREE, anchors, edges);
        } });
    }
    function chl(n, m) { return function (u, v) { var P = Math.PI; return Math.cos(n * P * u) * Math.cos(m * P * v) - Math.cos(m * P * u) * Math.cos(n * P * v); }; }

    contour('cym-1-2', 'Chladni (1,2)', chl(1, 2), 0x2ec4b6, 54);
})();
