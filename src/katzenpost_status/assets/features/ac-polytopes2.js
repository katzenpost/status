(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function dot(a, b) { var s = 0, i; for (i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
    // Deterministic orthonormal 3xN projection (Gram-Schmidt on 3 seed vectors).
    function projMatrix(n) {
        function seed(o) { var v = [], i; for (i = 0; i < n; i++) v.push(Math.cos(i * o.f + o.p)); return v; }
        var a = seed({ f: 1.3, p: 0.2 }), b = seed({ f: 2.1, p: 1.1 }), c = seed({ f: 0.7, p: 2.7 });
        function norm(v) { var m = Math.sqrt(dot(v, v)) || 1, i; for (i = 0; i < v.length; i++) v[i] /= m; return v; }
        function sub(v, u, k) { var i; for (i = 0; i < v.length; i++) v[i] -= k * u[i]; return v; }
        a = norm(a); b = norm(sub(b, a, dot(b, a))); c = norm(sub(sub(c, a, dot(c, a)), b, dot(c, b)));
        return [a, b, c];
    }
    function projectND(V, THREE) {
        var n = V[0].length, M = projMatrix(n), P = V.map(function (v) { return new THREE.Vector3(dot(v, M[0]), dot(v, M[1]), dot(v, M[2])); });
        var mx = 0; P.forEach(function (p) { mx = Math.max(mx, Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)); });
        var s = 24 / (mx || 1); P.forEach(function (p) { p.multiplyScalar(s); });
        return P;
    }
    function minEdges(V, P, color, tol) {
        var md = Infinity, i, j; function d2(a, b) { var s = 0, k; for (k = 0; k < a.length; k++) { var t = a[k] - b[k]; s += t * t; } return s; }
        for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; }
        var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tol || 0.06)) E.push({ a: P[i], b: P[j], color: color }); return E;
    }
    function polyN(id, name, vertsFn, color, camZ, tol) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56, layout: function (d, THREE) { var V = vertsFn(), P = projectND(V, THREE); return G.anchorLayout(d, THREE, P, minEdges(V, P, color, tol)); } });
    }
    function hypercube(n) { var V = [], t, i; for (t = 0; t < (1 << n); t++) { var v = []; for (i = 0; i < n; i++) v.push((t & (1 << i)) ? 1 : -1); V.push(v); } return V; }
    function orthoplex(n) { var V = [], i, s; for (i = 0; i < n; i++) for (s = -1; s <= 1; s += 2) { var v = []; for (var k = 0; k < n; k++) v.push(k === i ? s : 0); V.push(v); } return V; }
    function simplex(n) { var V = [], i, k; for (i = 0; i < n + 1; i++) { var v = []; for (k = 0; k < n + 1; k++) v.push(k === i ? 1 : 0); V.push(v); } return V; }
    function permSign(nonzeros, n) {
        // all placements of the given nonzero values into n slots (distinct positions), all sign combos
        var out = [], seen = {}, m = nonzeros.length;
        function place(slotVals, used, depth) {
            if (depth === m) { var v = []; for (var i = 0; i < n; i++) v.push(slotVals[i] || 0); var signs = []; expandSigns(v, 0, signs); return; }
        }
        // simpler: choose positions by recursion
        function choose(pos, idx, vec) {
            if (idx === m) { expandSigns(vec.slice(), 0); return; }
            for (var p = 0; p < n; p++) if (vec[p] === undefined || vec[p] === 0) { if (vec[p] === 0 && idx > 0) { } var nv = vec.slice(); nv[p] = nonzeros[idx]; choose(pos, idx + 1, nv); }
        }
        function expandSigns(vec, i) {
            if (i === n) { var key = vec.map(function (x) { return Math.round(x * 100); }).join(','); if (!seen[key]) { seen[key] = 1; out.push(vec.slice()); } return; }
            if (Math.abs(vec[i]) > 1e-9) { var a = vec.slice(); a[i] = Math.abs(vec[i]); expandSigns(a, i + 1); var b = vec.slice(); b[i] = -Math.abs(vec[i]); expandSigns(b, i + 1); } else expandSigns(vec, i + 1);
        }
        var base = []; for (var q = 0; q < n; q++) base.push(0);
        choose(0, 0, base);
        return out;
    }

    polyN('hexeract', 'Hexeract (6-cube)', function () { return hypercube(6); }, 0x2ec4b6, 56);

    polyN('hepteract', 'Hepteract (7-cube)', function () { return hypercube(7); }, 0x4d8bf0, 56);

    polyN('fiveorthoplex', '5-orthoplex', function () { return orthoplex(5); }, 0x9b5de5, 54);

    polyN('sixorthoplex', '6-orthoplex', function () { return orthoplex(6); }, 0xff8f3f, 54);

    polyN('fivesimplex', '5-simplex', function () { return simplex(5); }, 0xff5d8f, 54);

    polyN('sixsimplex', '6-simplex', function () { return simplex(6); }, 0x00d2a0, 54);
})();
