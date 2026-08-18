(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    function dot(a, b) { var s = 0, i; for (i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
    function projMatrix(n) { function seed(f, p) { var v = [], i; for (i = 0; i < n; i++) v.push(Math.cos(i * f + p)); return v; } function nrm(v) { var m = Math.sqrt(dot(v, v)) || 1, i; for (i = 0; i < v.length; i++) v[i] /= m; return v; } function sub(v, u, k) { var i; for (i = 0; i < v.length; i++) v[i] -= k * u[i]; return v; } var a = nrm(seed(1.3, 0.2)), b = nrm(sub(seed(2.1, 1.1), a, dot(seed(2.1, 1.1), a))), c = seed(0.7, 2.7); c = nrm(sub(sub(c, a, dot(c, a)), b, dot(c, b))); return [a, b, c]; }
    function projectND(V, THREE) { var n = V[0].length, M = projMatrix(n), P = V.map(function (v) { return new THREE.Vector3(dot(v, M[0]), dot(v, M[1]), dot(v, M[2])); }); var mx = 0; P.forEach(function (p) { mx = Math.max(mx, Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)); }); var s = 24 / (mx || 1); P.forEach(function (p) { p.multiplyScalar(s); }); return P; }
    function minEdges(V, P, color, tol) { var md = Infinity, i, j; function d2(a, b) { var s = 0, k; for (k = 0; k < a.length; k++) { var t = a[k] - b[k]; s += t * t; } return s; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tol || 0.06)) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function polyN(id, name, vertsFn, color, camZ, tol) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) { var V = vertsFn(), P = projectND(V, T); return G.anchorLayout(d, T, P, minEdges(V, P, color, tol)); } }); }
    function hypercube(n) { var V = [], t, i; for (t = 0; t < (1 << n); t++) { var v = []; for (i = 0; i < n; i++) v.push((t & (1 << i)) ? 1 : -1); V.push(v); } return V; }
    function demicube(n) { return hypercube(n).filter(function (v) { var s = 0; v.forEach(function (x) { if (x > 0) s++; }); return s % 2 === 0; }); }
    function orthoplex(n) { var V = [], i, s; for (i = 0; i < n; i++) for (s = -1; s <= 1; s += 2) { var v = []; for (var k = 0; k < n; k++) v.push(k === i ? s : 0); V.push(v); } return V; }
    function simplex(n) { var V = [], i, k; for (i = 0; i < n + 1; i++) { var v = []; for (k = 0; k < n + 1; k++) v.push(k === i ? 1 : 0); V.push(v); } return V; }

    polyN('hept7cube', 'Hepteract (7-cube)', function () { return hypercube(7); }, 0x2ec4b6, 54);

    polyN('oct8cube', 'Octeract (8-cube)', function () { return hypercube(8); }, 0x4d8bf0, 54);

    polyN('seven-orthoplex', '7-orthoplex', function () { return orthoplex(7); }, 0x9b5de5, 54);

    polyN('eight-orthoplex', '8-orthoplex', function () { return orthoplex(8); }, 0xff8f3f, 54);

    polyN('seven-simplex', '7-simplex', function () { return simplex(7); }, 0xff5d8f, 54);

    polyN('eight-simplex', '8-simplex', function () { return simplex(8); }, 0x00d2a0, 54);
})();
