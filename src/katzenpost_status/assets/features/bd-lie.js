(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function dot(a, b) { var s = 0, i; for (i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
    function projMatrix(n) { function seed(f, p) { var v = [], i; for (i = 0; i < n; i++) v.push(Math.cos(i * f + p)); return v; } function nrm(v) { var m = Math.sqrt(dot(v, v)) || 1, i; for (i = 0; i < v.length; i++) v[i] /= m; return v; } function sub(v, u, k) { var i; for (i = 0; i < v.length; i++) v[i] -= k * u[i]; return v; } var a = nrm(seed(1.3, 0.2)), b = nrm(sub(seed(2.1, 1.1), a, dot(seed(2.1, 1.1), a))), c = seed(0.7, 2.7); c = nrm(sub(sub(c, a, dot(c, a)), b, dot(c, b))); return [a, b, c]; }
    function projectND(V, THREE) { var n = V[0].length, M = projMatrix(n), P = V.map(function (v) { return new THREE.Vector3(dot(v, M[0]), dot(v, M[1]), dot(v, M[2])); }); var mx = 0; P.forEach(function (p) { mx = Math.max(mx, Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)); }); var s = 24 / (mx || 1); P.forEach(function (p) { p.multiplyScalar(s); }); return P; }
    function minEdges(V, P, color, tol) { var md = Infinity, i, j; function d2(a, b) { var s = 0, k; for (k = 0; k < a.length; k++) { var t = a[k] - b[k]; s += t * t; } return s; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tol || 0.06)) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function rootView(id, name, vertsFn, color, camZ, tol) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) { var V = vertsFn(), P = projectND(V, T); return G.anchorLayout(d, T, P, minEdges(V, P, color, tol)); } }); }
    function lattice(id, name, vertsFn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.45, camZ: camZ || 56, layout: function (d, T) { var V = vertsFn(), P = V.map(function (v) { return new T.Vector3(v[0], v[1], v[2]); }); return G.anchorLayout(d, T, P, minEdges(V, P, color)); } }); }
    function An(n) { var V = [], i, j; for (i = 0; i <= n; i++) for (j = 0; j <= n; j++) if (i !== j) { var v = []; for (var k = 0; k <= n; k++) v.push(k === i ? 1 : (k === j ? -1 : 0)); V.push(v); } return V; }
    function Bn(n) { var V = [], i, j, s, s2; for (i = 0; i < n; i++) for (s = -1; s <= 1; s += 2) { var v = []; for (var k = 0; k < n; k++) v.push(k === i ? s : 0); V.push(v); } for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) for (s = -1; s <= 1; s += 2) for (s2 = -1; s2 <= 1; s2 += 2) { var w = []; for (k = 0; k < n; k++) w.push(k === i ? s : (k === j ? s2 : 0)); V.push(w); } return V; }
    function Cn(n) { var V = [], i, j, s, s2, k; for (i = 0; i < n; i++) for (s = -1; s <= 1; s += 2) { var v = []; for (k = 0; k < n; k++) v.push(k === i ? 2 * s : 0); V.push(v); } for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) for (s = -1; s <= 1; s += 2) for (s2 = -1; s2 <= 1; s2 += 2) { var w = []; for (k = 0; k < n; k++) w.push(k === i ? s : (k === j ? s2 : 0)); V.push(w); } return V; }
    function Dn(n) { var V = [], i, j, s, s2, k; for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) for (s = -1; s <= 1; s += 2) for (s2 = -1; s2 <= 1; s2 += 2) { var w = []; for (k = 0; k < n; k++) w.push(k === i ? s : (k === j ? s2 : 0)); V.push(w); } return V; }

    rootView('g2root', 'G2 root system', function () { var V = [], i; for (i = 0; i < 6; i++) { var a = i * Math.PI / 3; V.push([Math.cos(a), Math.sin(a)]); } for (i = 0; i < 6; i++) { var b = i * Math.PI / 3 + Math.PI / 6; V.push([Math.cos(b) * Math.sqrt(3), Math.sin(b) * Math.sqrt(3)]); } return V; }, 0x2ec4b6, 52);

    rootView('a3root', 'A3 root system', function () { return An(3); }, 0x4d8bf0, 54);

    rootView('a4root', 'A4 root system', function () { return An(4); }, 0x9b5de5, 54);

    rootView('b3root', 'B3 root system', function () { return Bn(3); }, 0xff8f3f, 54);

    rootView('b4root', 'B4 root system', function () { return Bn(4); }, 0xff5d8f, 54);
})();
