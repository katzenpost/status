(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    // Metatron's Cube: 13 vertices (centre + two hexagons) fully connected.
    // Nodes sit on the vertices; packets flow the gateway->mix->service pipeline
    // along the drawn lines.
    window.KATZEN_GEO3D.create({
        id: 'metatron', name: 'Metatron cube', rotateSpeed: 0.45, camZ: 64,
        layout: function (d, THREE) {
            var R = 15, anchors = [new THREE.Vector3(0, 0, 0)], k, a;
            for (k = 0; k < 6; k++) { a = k * Math.PI / 3; anchors.push(new THREE.Vector3(Math.cos(a) * R, Math.sin(a) * R, 0)); }
            for (k = 0; k < 6; k++) { a = k * Math.PI / 3 + Math.PI / 6; anchors.push(new THREE.Vector3(Math.cos(a) * 2 * R, Math.sin(a) * 2 * R, 0)); }
            var order = (d.nodes || []).slice().sort(function (x, y) { return (x.type + x.name).localeCompare(y.type + y.name); });
            var nodes = [], nodePos = {};
            order.forEach(function (n, i) {
                var p = anchors[i % anchors.length].clone();
                if (i >= anchors.length) p.z += Math.floor(i / anchors.length) * 2.4;   // stack wrapped nodes in depth
                nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
            });
            var edges = [];
            for (var i2 = 0; i2 < anchors.length; i2++) for (var j = i2 + 1; j < anchors.length; j++) edges.push({ a: anchors[i2], b: anchors[j], color: 0x6c7bd6 });
            var cols = window.KATZEN_GEO3D.columns(d);
            function spawn() {
                if (cols.length < 2) return null;
                var path = [];
                for (var ci = 0; ci < cols.length; ci++) { var c = cols[ci], nm = c[(Math.random() * c.length) | 0].name; if (nodePos[nm]) path.push(nodePos[nm]); }
                return path;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        }
    });
})();
