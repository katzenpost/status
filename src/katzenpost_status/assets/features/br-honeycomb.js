(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function minEdges3(V, P, color, tolf) { var md = Infinity, i, j; function d2(a, b) { var x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2]; return x * x + y * y + z * z; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tolf || 0.08)) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function lattice(id, name, ptsFn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 58, layout: function (d, T) { var V = ptsFn(), P = V.map(function (v) { return new T.Vector3(v[0], v[1], v[2]); }); return G.anchorLayout(d, T, P, minEdges3(V, P, color)); } }); }
    var S = 7;

    lattice('cubichoneycomb', 'Cubic honeycomb', function () { var V = [], x, y, z; for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) V.push([x * S, y * S, z * S]); return V; }, 0x2ec4b6, 58);

    lattice('bcchoneycomb', 'BCC honeycomb', function () { var V = [], x, y, z; for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) { V.push([x * S, y * S, z * S]); if (x < 2 && y < 2 && z < 2) V.push([(x + 0.5) * S, (y + 0.5) * S, (z + 0.5) * S]); } return V; }, 0x4d8bf0, 58);

    lattice('diamondlattice', 'Diamond lattice', function () { var V = [], x, y, z; for (x = -1; x <= 1; x++) for (y = -1; y <= 1; y++) for (z = -1; z <= 1; z++) { if (((x + y + z) & 1) === 0) { V.push([x * S, y * S, z * S]); V.push([(x + 0.25) * S, (y + 0.25) * S, (z + 0.25) * S]); } } return V; }, 0x9b5de5, 56);

    lattice('hcplattice', 'HCP lattice', function () { var V = [], i, j, k, S3 = Math.sqrt(3); for (k = -1; k <= 1; k++) for (i = -2; i <= 2; i++) for (j = -2; j <= 2; j++) { var off = (k & 1) ? 0.5 : 0; V.push([(i + off + (j % 2 ? 0.5 : 0)) * S, j * S3 / 2 * S / 1 * 0.5 * 1.0, k * S * 0.82]); } return V; }, 0xff8f3f, 58);

    lattice('octettruss', 'Octet truss (FCC)', function () { var V = [], x, y, z; for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) if (((x + y + z) & 1) === 0 && x * x + y * y + z * z <= 8) V.push([x * S * 0.7, y * S * 0.7, z * S * 0.7]); return V; }, 0xff5d8f, 58);

    lattice('pyrochlore', 'Pyrochlore lattice', function () { var V = [], seen = {}, x, y, z; var basis = [[0, 0, 0], [0.25, 0.25, 0], [0.25, 0, 0.25], [0, 0.25, 0.25]]; for (x = -1; x <= 1; x++) for (y = -1; y <= 1; y++) for (z = -1; z <= 1; z++) basis.forEach(function (b) { V.push([(x + b[0]) * S * 1.6, (y + b[1]) * S * 1.6, (z + b[2]) * S * 1.6]); }); return V; }, 0x00d2a0, 58);
})();
