(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, THREE = K.THREE, RT2 = Math.SQRT2;

    function project4(V, THREE) { var A = 0.62, B = 0.34, dist = 4, out = []; V.forEach(function (v) { var x = v[0], y = v[1], z = v[2], w = v[3]; var x1 = x * Math.cos(A) - w * Math.sin(A), w1 = x * Math.sin(A) + w * Math.cos(A); var y1 = y * Math.cos(B) - w1 * Math.sin(B), w2 = y * Math.sin(B) + w1 * Math.cos(B); var s = dist / (dist - w2); out.push(new THREE.Vector3(x1 * s, y1 * s, z * s)); }); var mx = 0; out.forEach(function (p) { mx = Math.max(mx, Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)); }); var sc = 25 / (mx || 1); out.forEach(function (p) { p.multiplyScalar(sc); }); return out; }
    function minEdges(V, P, color, tol) { var md = Infinity, i, j; function d2(a, b) { var s = 0, k; for (k = 0; k < 4; k++) { var t = a[k] - b[k]; s += t * t; } return s; } for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) { var dd = d2(V[i], V[j]); if (dd < md && dd > 1e-6) md = dd; } var E = []; for (i = 0; i < V.length; i++) for (j = i + 1; j < V.length; j++) if (Math.abs(d2(V[i], V[j]) - md) < md * (tol || 0.06)) E.push({ a: P[i], b: P[j], color: color }); return E; }
    function poly4(id, name, vertsFn, color, camZ, tol) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) { var V = vertsFn(), P = project4(V, T); return G.anchorLayout(d, T, P, minEdges(V, P, color, tol)); } }); }
    function permSign4(nonzeros) { var out = [], seen = {}, base = [0, 0, 0, 0]; function choose(idx, vec) { if (idx === nonzeros.length) { esign(vec, 0); return; } for (var p = 0; p < 4; p++) if (vec[p] === 0) { var nv = vec.slice(); nv[p] = nonzeros[idx]; choose(idx + 1, nv); } } function esign(vec, i) { if (i === 4) { var key = vec.map(function (x) { return Math.round(x * 100); }).join(','); if (!seen[key]) { seen[key] = 1; out.push(vec.slice()); } return; } if (Math.abs(vec[i]) > 1e-9) { var a = vec.slice(); a[i] = Math.abs(vec[i]); esign(a, i + 1); var b = vec.slice(); b[i] = -Math.abs(vec[i]); esign(b, i + 1); } else esign(vec, i + 1); } choose(0, base); return out; }
    // Prism = 3D polyhedron x segment, lifted to w = +-1.
    function prism(id, name, geoFn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) {
            var g = geoFn(T), pos = g.attributes.position, seen = {}, V3 = [], map = {}, i;
            for (i = 0; i < pos.count; i++) { var v = new T.Vector3().fromBufferAttribute(pos, i), k = Math.round(v.x * 40) + ',' + Math.round(v.y * 40) + ',' + Math.round(v.z * 40); if (seen[k] == null) { seen[k] = V3.length; V3.push([v.x, v.y, v.z]); } map[i] = seen[k]; }
            var eg = new T.EdgesGeometry(g, 1), ep = eg.attributes.position, pedges = [], eseen = {};
            function vkey(x, y, z) { return Math.round(x * 40) + ',' + Math.round(y * 40) + ',' + Math.round(z * 40); }
            for (i = 0; i < ep.count; i += 2) { var a = new T.Vector3().fromBufferAttribute(ep, i), b = new T.Vector3().fromBufferAttribute(ep, i + 1); var ia = seen[vkey(a.x, a.y, a.z)], ib = seen[vkey(b.x, b.y, b.z)]; if (ia != null && ib != null) { var ek = Math.min(ia, ib) + '_' + Math.max(ia, ib); if (!eseen[ek]) { eseen[ek] = 1; pedges.push([ia, ib]); } } }
            eg.dispose(); g.dispose();
            var n = V3.length, V = [], h = 2.2; for (i = 0; i < n; i++) V.push([V3[i][0], V3[i][1], V3[i][2], -h]); for (i = 0; i < n; i++) V.push([V3[i][0], V3[i][1], V3[i][2], h]);
            var P = project4(V, T), edges = [];
            pedges.forEach(function (e) { edges.push({ a: P[e[0]], b: P[e[1]], color: color }); edges.push({ a: P[e[0] + n], b: P[e[1] + n], color: color }); });
            for (i = 0; i < n; i++) edges.push({ a: P[i], b: P[i + n], color: color });
            return G.anchorLayout(d, T, P, edges);
        } });
    }
    function duoprism(id, name, m, n, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) { var V = [], idx = {}, i, j; for (i = 0; i < m; i++) for (j = 0; j < n; j++) { var a = i / m * Math.PI * 2, b = j / n * Math.PI * 2; idx[i + '_' + j] = V.length; V.push([Math.cos(a), Math.sin(a), Math.cos(b), Math.sin(b)]); } var P = project4(V, T), edges = []; for (i = 0; i < m; i++) for (j = 0; j < n; j++) { edges.push({ a: P[idx[i + '_' + j]], b: P[idx[((i + 1) % m) + '_' + j]], color: color }); edges.push({ a: P[idx[i + '_' + j]], b: P[idx[i + '_' + ((j + 1) % n)]], color: color }); } return G.anchorLayout(d, T, P, edges); } }); }

    prism('tetraprism', 'Tetrahedral prism', function (T) { return new T.TetrahedronGeometry(1.6); }, 0x2ec4b6, 54);

    prism('octaprism', 'Octahedral prism', function (T) { return new T.OctahedronGeometry(1.6); }, 0x4d8bf0, 54);

    prism('icosaprism', 'Icosahedral prism', function (T) { return new T.IcosahedronGeometry(1.6); }, 0x9b5de5, 54);

    prism('dodecaprism', 'Dodecahedral prism', function (T) { return new T.DodecahedronGeometry(1.6); }, 0xff8f3f, 54);

    poly4('truncatedtesseract', 'Truncated tesseract', function () { var q = 1 + RT2; return permSign4([1, q, q, q]); }, 0xff5d8f, 54);

    poly4('cantellatedtesseract', 'Cantellated tesseract', function () { var q = 1 + RT2; return permSign4([1, 1, q, q]); }, 0x00d2a0, 54);
})();
