(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PHI = (1 + Math.sqrt(5)) / 2, P2 = PHI * PHI, P3 = PHI * PHI * PHI;

    function permsAll(v) { var idx = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]], out = [], seen = {}; idx.forEach(function (P) { var w = [v[P[0]], v[P[1]], v[P[2]]], k = w.join(','); if (!seen[k]) { seen[k] = 1; out.push(w); } }); return out; }
    function permsEven(v) { return [[v[0], v[1], v[2]], [v[1], v[2], v[0]], [v[2], v[0], v[1]]]; }
    function signAll(v) { var idx = [], i; for (i = 0; i < 3; i++) if (Math.abs(v[i]) > 1e-9) idx.push(i); var out = []; for (var t = 0; t < (1 << idx.length); t++) { var w = v.slice(); for (var b = 0; b < idx.length; b++) if (t & (1 << b)) w[idx[b]] = -w[idx[b]]; out.push(w); } return out; }
    function expand(seeds, even) { var out = [], seen = {}; seeds.forEach(function (v) { (even ? permsEven(v) : permsAll(v)).forEach(function (p) { signAll(p).forEach(function (s) { var k = s.map(function (x) { return Math.round(x * 1000); }).join(','); if (!seen[k]) { seen[k] = 1; out.push(s); } }); }); }); return out; }
    function minEdges3(V, P, color) { var md = Infinity, i, j; function d2(a, b) { var x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2]; return x * x + y * y + z * z; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * 0.06) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function solid(id, name, vertsFn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56, layout: function (d, THREE) { var V = vertsFn(), mx = 0; V.forEach(function (v) { mx = Math.max(mx, Math.abs(v[0]), Math.abs(v[1]), Math.abs(v[2])); }); var sc = 22 / (mx || 1); var P = V.map(function (v) { return new THREE.Vector3(v[0] * sc, v[1] * sc, v[2] * sc); }); return G.anchorLayout(d, THREE, P, minEdges3(V, P, color)); } }); }
    var RT2 = Math.SQRT2;

    solid('truncatedoctahedron', 'Truncated octahedron', function () { return expand([[0, 1, 2]], false); }, 0x2ec4b6, 54);

    solid('truncatedcube', 'Truncated cube', function () { var x = RT2 - 1; return expand([[x, 1, 1]], false); }, 0x4d8bf0, 54);

    solid('rhombicuboctahedron', 'Rhombicuboctahedron', function () { return expand([[1, 1, 1 + RT2]], false); }, 0x9b5de5, 54);

    solid('truncatedcuboctahedron', 'Truncated cuboctahedron', function () { return expand([[1, 1 + RT2, 1 + 2 * RT2]], false); }, 0xff8f3f, 56);

    solid('icosidodecahedron', 'Icosidodecahedron', function () { return expand([[0, 0, PHI]], false).concat(expand([[0.5, PHI / 2, P2 / 2]], true)); }, 0xff5d8f, 54);

    solid('truncatedicosahedron', 'Truncated icosahedron (C60)', function () { return expand([[0, 1, 3 * PHI]], true).concat(expand([[1, 2 + PHI, 2 * PHI]], true)).concat(expand([[PHI, 2, 2 * PHI + 1]], true)); }, 0x00d2a0, 54);

    solid('truncateddodecahedron', 'Truncated dodecahedron', function () { return expand([[0, 1 / PHI, 2 + PHI]], true).concat(expand([[1 / PHI, PHI, 2 * PHI]], true)).concat(expand([[PHI, 2, PHI + 1]], true)); }, 0xffd23f, 54);

    solid('rhombicosidodecahedron', 'Rhombicosidodecahedron', function () { return expand([[1, 1, P3]], true).concat(expand([[P2, PHI, 2 * PHI]], true)).concat(expand([[2 + PHI, 0, P2]], true)); }, 0x4d8bf0, 54);
})();
