(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, THREE = K.THREE;

    function geoVE(g, rot) {
        var m = new THREE.Matrix4().makeRotationFromEuler(new THREE.Euler(rot[0], rot[1], rot[2]));
        var pos = g.attributes.position, seen = {}, verts = [], i;
        for (i = 0; i < pos.count; i++) { var v = new THREE.Vector3().fromBufferAttribute(pos, i).applyMatrix4(m); var k = Math.round(v.x * 30) + ',' + Math.round(v.y * 30) + ',' + Math.round(v.z * 30); if (!seen[k]) { seen[k] = 1; verts.push(v); } }
        var eg = new THREE.EdgesGeometry(g, 1), ep = eg.attributes.position, edges = [];
        for (i = 0; i < ep.count; i += 2) edges.push([new THREE.Vector3().fromBufferAttribute(ep, i).applyMatrix4(m), new THREE.Vector3().fromBufferAttribute(ep, i + 1).applyMatrix4(m)]);
        eg.dispose();
        return { verts: verts, edges: edges };
    }
    function compound(id, name, parts, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) {
            var anchors = [], edges = [];
            parts.forEach(function (p, idx) { var g = p.geo(T); var ve = geoVE(g, p.rot || [0, 0, 0]); g.dispose(); ve.verts.forEach(function (v) { anchors.push(v); }); var col = p.color != null ? p.color : color; ve.edges.forEach(function (e) { edges.push({ a: e[0], b: e[1], color: col }); }); });
            return G.anchorLayout(d, T, anchors, edges);
        } });
    }
    function spiked(id, name, geoFn, spikeGeoFn, spikeR, color, spikeCol, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56, layout: function (d, T) {
            var g = geoFn(T), ve = geoVE(g, [0, 0, 0]); g.dispose();
            var anchors = ve.verts.slice(), edges = ve.edges.map(function (e) { return { a: e[0], b: e[1], color: color }; });
            var sg = spikeGeoFn(T), sv = geoVE(sg, [0, 0, 0]); sg.dispose();
            sv.verts.forEach(function (dir) { var sp = dir.clone().normalize().multiplyScalar(spikeR); anchors.push(sp); var d5 = ve.verts.map(function (v, i) { return [v.distanceTo(sp), i]; }).sort(function (a, b) { return a[0] - b[0]; }).slice(0, 5); d5.forEach(function (pr) { edges.push({ a: sp, b: ve.verts[pr[1]], color: spikeCol }); }); });
            return G.anchorLayout(d, T, anchors, edges);
        } });
    }
    var B = function (T) { return new T.BoxGeometry(16, 16, 16); };
    var OCT = function (T) { return new T.OctahedronGeometry(13); };
    var ICO = function (T) { return new T.IcosahedronGeometry(13); };
    var DOD = function (T) { return new T.DodecahedronGeometry(13); };
    var TET = function (T) { return new T.TetrahedronGeometry(15); };

    compound('compound2cubes', 'Compound of two cubes', [{ geo: B, rot: [0, 0, 0], color: 0x2ec4b6 }, { geo: B, rot: [0.62, 0.62, 0], color: 0xff8f3f }], 0x2ec4b6, 54);

    compound('compound3cubes', 'Compound of three cubes', [{ geo: B, rot: [0, 0, 0], color: 0x2ec4b6 }, { geo: B, rot: [0, 0, 1.047], color: 0x9b5de5 }, { geo: B, rot: [1.047, 0, 0], color: 0xff8f3f }], 0x2ec4b6, 54);

    compound('stellaoctangula2', 'Stella octangula (2 tetrahedra)', [{ geo: TET, rot: [0, 0, 0], color: 0x4d8bf0 }, { geo: TET, rot: [Math.PI, 0, 0], color: 0xffd23f }], 0x4d8bf0, 54);

    compound('cubeoctacompound', 'Cube + octahedron compound', [{ geo: B, rot: [0, 0, 0], color: 0x2ec4b6 }, { geo: function (T) { return new T.OctahedronGeometry(16); }, rot: [0, 0, 0], color: 0xff5d8f }], 0x2ec4b6, 54);

    compound('dodecaicosacompound', 'Dodecahedron + icosahedron', [{ geo: DOD, rot: [0, 0, 0], color: 0x9b5de5 }, { geo: ICO, rot: [0, 0, 0], color: 0x00d2a0 }], 0x9b5de5, 54);

    compound('compound5tetra', 'Compound of five tetrahedra', [0, 1, 2, 3, 4].map(function (k) { return { geo: TET, rot: [0.6, k * 1.2566, 0.3 * k], color: [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0xff5d8f][k] }; }), 0x2ec4b6, 56);

    compound('compound5cubes', 'Compound of five cubes', [0, 1, 2, 3, 4].map(function (k) { return { geo: B, rot: [0.3, k * 1.2566, 0], color: [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0xffd23f][k] }; }), 0x2ec4b6, 58);

    spiked('greatstellateddodeca', 'Great stellated dodecahedron', ICO, DOD, 30, 0x9b5de5, 0xffd23f, 62);

    spiked('smallstellateddodeca', 'Small stellated dodecahedron', DOD, ICO, 26, 0x4d8bf0, 0xff8f3f, 60);
})();
