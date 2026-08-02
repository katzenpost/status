(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    // Merkaba (star tetrahedron): two interlocking tetrahedra. Gateways on the
    // up-tetra points, services on the down-tetra, mix layers on the edge
    // midpoints; packets flow the pipeline along the star's edges.
    window.KATZEN_GEO3D.create({
        id: 'merkaba', name: 'Merkaba', rotateSpeed: 0.6, camZ: 60,
        layout: function (d, THREE) {
            var S = 16;
            function V(x, y, z) { return new THREE.Vector3(x * S, y * S, z * S); }
            var up = [V(1, 1, 1), V(1, -1, -1), V(-1, 1, -1), V(-1, -1, 1)];
            var dn = [V(-1, -1, -1), V(-1, 1, 1), V(1, -1, 1), V(1, 1, -1)];
            function tetEdges(t, col, out, mids) {
                for (var i = 0; i < 4; i++) for (var j = i + 1; j < 4; j++) {
                    out.push({ a: t[i], b: t[j], color: col });
                    if (mids) mids.push(t[i].clone().add(t[j]).multiplyScalar(0.5));
                }
            }
            var edges = [], mids = [];
            tetEdges(up, 0x2ec4b6, edges, mids);
            tetEdges(dn, 0xff8f3f, edges, mids);   // 12 edge midpoints total

            var byType = {}; (d.nodes || []).forEach(function (n) { (byType[n.type] || (byType[n.type] = [])).push(n); });
            var nodes = [], nodePos = {}, mi = 0;
            function place(list, anchors) {
                (list || []).forEach(function (n, i) {
                    var p = anchors[i % anchors.length].clone();
                    if (i >= anchors.length) p.multiplyScalar(0.82);
                    nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
                });
            }
            place(byType.gateway, up);
            place(byType.service, dn);
            // mixes + storage + dir-auth on the edge midpoints
            var rest = (byType.mix || []).concat(byType.storage || []).concat(byType.dirauth || []).concat(byType.out || []);
            rest.forEach(function (n) { var p = mids[mi % mids.length].clone(); mi++; nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p; });

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
