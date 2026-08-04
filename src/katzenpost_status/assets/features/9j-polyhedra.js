(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function byTN(a, b) { return (a.type + a.name).localeCompare(b.type + b.name); }
    function spawnFn(cols, nodePos) {
        return function () {
            if (cols.length < 2) return null;
            var path = [];
            for (var ci = 0; ci < cols.length; ci++) { var c = cols[ci], nm = c[(Math.random() * c.length) | 0].name; if (nodePos[nm]) path.push(nodePos[nm]); }
            return path;
        };
    }
    function placeOnVerts(d, THREE, verts, edges, color) {
        var order = (d.nodes || []).slice().sort(byTN), nodes = [], nodePos = {};
        order.forEach(function (n, i) {
            var p = verts.length ? verts[i % verts.length].clone() : new THREE.Vector3();
            if (i >= verts.length) p.multiplyScalar(0.66);   // inner shell for wrapped nodes
            nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
        });
        return { nodes: nodes, edges: edges.map(function (e) { return { a: e.a, b: e.b, color: color }; }), spawn: spawnFn(G.columns(d), nodePos) };
    }
    function fromGeo(g, THREE) {
        var pos = g.attributes.position, verts = [], seen = {}, i;
        for (i = 0; i < pos.count; i++) {
            var v = new THREE.Vector3().fromBufferAttribute(pos, i);
            var key = Math.round(v.x * 50) + ',' + Math.round(v.y * 50) + ',' + Math.round(v.z * 50);
            if (!seen[key]) { seen[key] = true; verts.push(v); }
        }
        var eg = new THREE.EdgesGeometry(g, 1), ep = eg.attributes.position, edges = [];
        for (i = 0; i < ep.count; i += 2) edges.push({ a: new THREE.Vector3().fromBufferAttribute(ep, i), b: new THREE.Vector3().fromBufferAttribute(ep, i + 1) });
        eg.dispose();
        return { verts: verts, edges: edges };
    }
    function polyView(id, name, make, color, camZ) {
        G.create({
            id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56,
            layout: function (d, THREE) { var g = make(THREE); var pe = fromGeo(g, THREE); g.dispose(); return placeOnVerts(d, THREE, pe.verts, pe.edges, color); }
        });
    }
    polyView('octahedron', 'Octahedron', function (T) { return new T.OctahedronGeometry(18); }, 0x00d2a0, 52);
    polyView('icosahedron', 'Icosahedron', function (T) { return new T.IcosahedronGeometry(18); }, 0x4d8bf0, 54);
    polyView('dodecahedron', 'Dodecahedron', function (T) { return new T.DodecahedronGeometry(18); }, 0x9b5de5, 56);
    polyView('tetrahedron', 'Tetrahedron', function (T) { return new T.TetrahedronGeometry(19); }, 0x2ec4b6, 52);
    polyView('geodesic', 'Geodesic sphere', function (T) { return new T.IcosahedronGeometry(18, 1); }, 0x00d2a0, 54);

    // Cuboctahedron (Vector Equilibrium): 12 vertices = permutations of (+-1,+-1,0)
    G.create({
        id: 'cuboctahedron', name: 'Vector equilibrium', rotateSpeed: 0.5, camZ: 54,
        layout: function (d, THREE) {
            var S = 13, base = [[1, 1, 0], [1, -1, 0], [-1, 1, 0], [-1, -1, 0], [1, 0, 1], [1, 0, -1], [-1, 0, 1], [-1, 0, -1], [0, 1, 1], [0, 1, -1], [0, -1, 1], [0, -1, -1]];
            var verts = base.map(function (b) { return new THREE.Vector3(b[0] * S, b[1] * S, b[2] * S); });
            var edgeLen = Math.sqrt(2) * S, edges = [];
            for (var i = 0; i < verts.length; i++) for (var j = i + 1; j < verts.length; j++) if (Math.abs(verts[i].distanceTo(verts[j]) - edgeLen) < 0.5) edges.push({ a: verts[i], b: verts[j] });
            return placeOnVerts(d, THREE, verts, edges, 0xffb454);
        }
    });
})();
