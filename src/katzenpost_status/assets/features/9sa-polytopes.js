(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PHI = (1 + Math.sqrt(5)) / 2;

    // Project 4D vertices to 3D (fixed rotation in the x-w and y-w planes, then
    // a perspective divide) and scale to a comfortable size.
    function project4(verts4, THREE) {
        var A = 0.62, B = 0.34, dist = 4, out = [];
        verts4.forEach(function (v) {
            var x = v[0], y = v[1], z = v[2], w = v[3];
            var x1 = x * Math.cos(A) - w * Math.sin(A), w1 = x * Math.sin(A) + w * Math.cos(A);
            var y1 = y * Math.cos(B) - w1 * Math.sin(B), w2 = y * Math.sin(B) + w1 * Math.cos(B);
            var s = dist / (dist - w2);
            out.push(new THREE.Vector3(x1 * s, y1 * s, z * s));
        });
        var mx = 0; out.forEach(function (p) { mx = Math.max(mx, Math.abs(p.x), Math.abs(p.y), Math.abs(p.z)); });
        var sc = 26 / (mx || 1); out.forEach(function (p) { p.multiplyScalar(sc); });
        return out;
    }
    function minEdges(verts4, proj, color) {
        var md = Infinity, i, j;
        function d2(a, b) { var s = 0, k; for (k = 0; k < 4; k++) { var t = a[k] - b[k]; s += t * t; } return s; }
        for (i = 0; i < verts4.length; i++) for (j = i + 1; j < verts4.length; j++) { var dd = d2(verts4[i], verts4[j]); if (dd < md && dd > 1e-6) md = dd; }
        var edges = [];
        for (i = 0; i < verts4.length; i++) for (j = i + 1; j < verts4.length; j++) if (Math.abs(d2(verts4[i], verts4[j]) - md) < md * 0.08) edges.push({ a: proj[i], b: proj[j], color: color });
        return edges;
    }
    function poly4(id, name, vertsFn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56, layout: function (d, THREE) { var V = vertsFn(), P = project4(V, THREE); return G.anchorLayout(d, THREE, P, minEdges(V, P, color)); } });
    }
    function signs(base, n) { var out = [], t; for (t = 0; t < (1 << n); t++) { var v = base.slice(), k, b = 0; for (k = 0; k < base.length; k++) if (base[k] !== 0) { if (t & (1 << b)) v[k] = -v[k]; b++; } out.push(v); } return out; }
    // duoprism: cartesian product of two regular polygons -> a 4-polytope.
    function duoprism(id, name, m, n, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 56, layout: function (d, THREE) {
            var V = [], idx = {}, i, j;
            for (i = 0; i < m; i++) for (j = 0; j < n; j++) { var a = i / m * Math.PI * 2, b = j / n * Math.PI * 2; idx[i + '_' + j] = V.length; V.push([Math.cos(a), Math.sin(a), Math.cos(b), Math.sin(b)]); }
            var P = project4(V, THREE), edges = [];
            for (i = 0; i < m; i++) for (j = 0; j < n; j++) { edges.push({ a: P[idx[i + '_' + j]], b: P[idx[((i + 1) % m) + '_' + j]], color: color }); edges.push({ a: P[idx[i + '_' + j]], b: P[idx[i + '_' + ((j + 1) % n)]], color: color }); }
            return G.anchorLayout(d, THREE, P, edges);
        } });
    }

    poly4('tesseract', 'Tesseract (8-cell)', function () { var V = [], a, b, c, e; for (a = -1; a <= 1; a += 2) for (b = -1; b <= 1; b += 2) for (c = -1; c <= 1; c += 2) for (e = -1; e <= 1; e += 2) V.push([a, b, c, e]); return V; }, 0x2ec4b6, 56);

    poly4('sixteencell', '16-cell', function () { var V = [], i, s; for (i = 0; i < 4; i++) for (s = -1; s <= 1; s += 2) { var v = [0, 0, 0, 0]; v[i] = s; V.push(v); } return V; }, 0x4d8bf0, 54);

    poly4('twentyfourcell', '24-cell', function () { var V = [], i, j, si, sj; for (i = 0; i < 4; i++) for (j = i + 1; j < 4; j++) for (si = -1; si <= 1; si += 2) for (sj = -1; sj <= 1; sj += 2) { var v = [0, 0, 0, 0]; v[i] = si; v[j] = sj; V.push(v); } return V; }, 0x9b5de5, 56);

    poly4('fivecell', '5-cell (pentachoron)', function () { var q = 1 / Math.sqrt(5); return [[1, 1, 1, -q], [1, -1, -1, -q], [-1, 1, -1, -q], [-1, -1, 1, -q], [0, 0, 0, 4 * q]]; }, 0xff8f3f, 54);

    poly4('sixhundredcell', '600-cell', function () {
        var V = [], i, s;
        V = V.concat(signs([0.5, 0.5, 0.5, 0.5], 4));
        for (i = 0; i < 4; i++) for (s = -1; s <= 1; s += 2) { var v = [0, 0, 0, 0]; v[i] = s; V.push(v); }
        var EV = [[0, 1, 2, 3], [0, 2, 3, 1], [0, 3, 1, 2], [1, 0, 3, 2], [1, 2, 0, 3], [1, 3, 2, 0], [2, 0, 1, 3], [2, 1, 3, 0], [2, 3, 0, 1], [3, 0, 2, 1], [3, 1, 0, 2], [3, 2, 1, 0]];
        var vals = [PHI / 2, 0.5, 1 / (2 * PHI)];
        EV.forEach(function (P) { for (var sg = 0; sg < 8; sg++) { var v = [0, 0, 0, 0]; v[P[0]] = (sg & 1 ? -1 : 1) * vals[0]; v[P[1]] = (sg & 2 ? -1 : 1) * vals[1]; v[P[2]] = (sg & 4 ? -1 : 1) * vals[2]; v[P[3]] = 0; V.push(v); } });
        return V;
    }, 0x00d2a0, 54);

    duoprism('duoprism33', 'Triangular duoprism (3-3)', 3, 3, 0xffd23f, 54);

    duoprism('duoprism55', 'Pentagonal duoprism (5-5)', 5, 5, 0xff5d8f, 54);

    duoprism('duoprism88', 'Octagonal duoprism (8-8)', 8, 8, 0x4d8bf0, 54);
})();
