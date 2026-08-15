(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function minEdges3(V, P, color, tolf) { var md = Infinity, i, j; function d2(a, b) { var x = a[0] - b[0], y = a[1] - b[1], z = a[2] - b[2]; return x * x + y * y + z * z; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tolf || 0.08)) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function lattice(id, name, ptsFn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 58, layout: function (d, T) { var V = ptsFn(), P = V.map(function (v) { return new T.Vector3(v[0], v[1], v[2]); }); return G.anchorLayout(d, T, P, minEdges3(V, P, color)); } }); }
    var S = 7;

    lattice('cubichoneycomb', 'Cubic honeycomb', function () { var V = [], x, y, z; for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) V.push([x * S, y * S, z * S]); return V; }, 0x2ec4b6, 58);
})();
