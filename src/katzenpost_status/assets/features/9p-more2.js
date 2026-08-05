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

    function uniqueVerts(geo, THREE) {
        var pos = geo.attributes.position, seen = {}, out = [], i;
        for (i = 0; i < pos.count; i++) {
            var v = new THREE.Vector3().fromBufferAttribute(pos, i), k = Math.round(v.x * 40) + ',' + Math.round(v.y * 40) + ',' + Math.round(v.z * 40);
            if (!seen[k]) { seen[k] = 1; out.push(v); }
        }
        return out;
    }
    function geoEdges(geo, THREE, color) {
        var eg = new THREE.EdgesGeometry(geo, 1), ep = eg.attributes.position, edges = [], i;
        for (i = 0; i < ep.count; i += 2) edges.push({ a: new THREE.Vector3().fromBufferAttribute(ep, i), b: new THREE.Vector3().fromBufferAttribute(ep, i + 1), color: color });
        eg.dispose();
        return edges;
    }

    // Stellated dodecahedron: a dodecahedron spiked along its dual directions.
    G.create({
        id: 'stellateddodec', name: 'Stellated dodecahedron', rotateSpeed: 0.42, camZ: 66,
        layout: function (d, THREE) {
            var dg = new THREE.DodecahedronGeometry(15), dv = uniqueVerts(dg, THREE), edges = geoEdges(dg, THREE, 0x9b5de5); dg.dispose();
            var ig = new THREE.IcosahedronGeometry(1), iv = uniqueVerts(ig, THREE); ig.dispose();
            var anchors = dv.slice();
            iv.forEach(function (dir) {
                var sp = dir.clone().normalize().multiplyScalar(26); anchors.push(sp);
                var d5 = dv.map(function (v, i) { return [v.distanceTo(sp), i]; }).sort(function (a, b) { return a[0] - b[0]; }).slice(0, 5);
                d5.forEach(function (pr) { edges.push({ a: sp, b: dv[pr[1]], color: 0xffd23f }); });
            });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
