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

    // Dragon curve (Heighway): one folded continuous line; packets ride it.
    G.create({
        id: 'dragon', name: 'Dragon curve', rotateSpeed: 0.3, camZ: 58,
        layout: function (d, THREE) {
            var turns = [], i, j;
            for (i = 0; i < 11; i++) { var t = turns.slice(); turns.push(1); for (j = t.length - 1; j >= 0; j--) turns.push(t[j] ? 0 : 1); }
            var dir = 0, x = 0, y = 0, step = 1.15, raw = [[0, 0]];
            for (i = 0; i < turns.length; i++) { x += Math.cos(dir) * step; y += Math.sin(dir) * step; raw.push([x, y]); dir += turns[i] ? Math.PI / 2 : -Math.PI / 2; }
            var cx = 0, cy = 0; raw.forEach(function (p) { cx += p[0]; cy += p[1]; }); cx /= raw.length; cy /= raw.length;
            var pts = raw.map(function (p) { return new THREE.Vector3((p[0] - cx) * 0.55, (p[1] - cy) * 0.55, 0); });
            return G.curveLayout(d, THREE, pts, 0xff8f3f);
        }
    });
})();
