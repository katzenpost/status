(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, D = 20;

    function build(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 56, layout: function (d, THREE) { var v = [], e = []; fn(v, e, THREE, color); return G.anchorLayout(d, THREE, v, e); } }); }
    // Cubic graph from LCF notation on a circle.
    function lcf(id, name, code, reps, color) {
        build(id, name, function (v, e, T, col) {
            var seq = [], i, r; for (r = 0; r < reps; r++) for (i = 0; i < code.length; i++) seq.push(code[i]); var n = seq.length;
            var P = []; for (i = 0; i < n; i++) { var th = i / n * PI2 - Math.PI / 2; P.push(new T.Vector3(Math.cos(th) * D, Math.sin(th) * D, 0)); v.push(P[i]); }
            var seen = {};
            function edge(a, b) { var k = Math.min(a, b) + '_' + Math.max(a, b); if (seen[k]) return; seen[k] = 1; e.push({ a: P[a], b: P[b], color: col }); }
            for (i = 0; i < n; i++) { edge(i, (i + 1) % n); edge(i, (((i + seq[i]) % n) + n) % n); }
        }, color);
    }

    build('petersen', 'Petersen graph', function (v, e, T, col) { var O = [], I = [], i; for (i = 0; i < 5; i++) { var th = i / 5 * PI2 - Math.PI / 2; O.push(new T.Vector3(Math.cos(th) * D, Math.sin(th) * D, 0)); I.push(new T.Vector3(Math.cos(th) * D * 0.5, Math.sin(th) * D * 0.5, 0)); v.push(O[i]); v.push(I[i]); } for (i = 0; i < 5; i++) { e.push({ a: O[i], b: O[(i + 1) % 5], color: col }); e.push({ a: I[i], b: I[(i + 2) % 5], color: col }); e.push({ a: O[i], b: I[i], color: col }); } }, 0x2ec4b6, 54);

    build('completek12', 'Complete graph K12', function (v, e, T, col) { var P = [], i, j, n = 12; for (i = 0; i < n; i++) { var th = i / n * PI2; P.push(new T.Vector3(Math.cos(th) * D, Math.sin(th) * D, 0)); v.push(P[i]); } for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) e.push({ a: P[i], b: P[j], color: col }); }, 0x4d8bf0, 56);

    build('bipartite', 'Complete bipartite K(6,6)', function (v, e, T, col) { var A = [], B = [], i, j, n = 6; for (i = 0; i < n; i++) { A.push(new T.Vector3(-D * 0.7, (i - (n - 1) / 2) * 6, 0)); B.push(new T.Vector3(D * 0.7, (i - (n - 1) / 2) * 6, 0)); v.push(A[i]); v.push(B[i]); } for (i = 0; i < n; i++) for (j = 0; j < n; j++) e.push({ a: A[i], b: B[j], color: col }); }, 0x9b5de5, 56);

    build('permutohedron', 'Permutohedron (S4)', function (v, e, T, col) { var perms = [], base = [1, 2, 3, 4]; function permute(arr, m) { if (!arr.length) perms.push(m); else for (var i = 0; i < arr.length; i++) permute(arr.slice(0, i).concat(arr.slice(i + 1)), m.concat(arr[i])); } permute(base, []); var b1 = [1, -1, 0, 0], b2 = [1, 1, -2, 0], b3 = [1, 1, 1, -3]; function nrm(a) { var m = Math.sqrt(a[0] * a[0] + a[1] * a[1] + a[2] * a[2] + a[3] * a[3]); return a.map(function (x) { return x / m; }); } b1 = nrm(b1); b2 = nrm(b2); b3 = nrm(b3); function dot(a, b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3]; } var P = perms.map(function (p) { var c = [p[0] - 2.5, p[1] - 2.5, p[2] - 2.5, p[3] - 2.5]; return new T.Vector3(dot(c, b1) * 9, dot(c, b2) * 9, dot(c, b3) * 9); }); P.forEach(function (p) { v.push(p); }); for (var i = 0; i < perms.length; i++) for (var j = i + 1; j < perms.length; j++) { var adj = false; for (var k = 0; k < 3; k++) { var s = perms[i].slice(), t = s[k]; s[k] = s[k + 1]; s[k + 1] = t; if (s.join('') === perms[j].join('')) adj = true; } if (adj) e.push({ a: P[i], b: P[j], color: col }); } }, 0xff8f3f, 52);

    lcf('heawood', 'Heawood graph', [5, -5], 7, 0xff5d8f);

    lcf('mobiuskantor', 'Mobius-Kantor graph', [5, -5], 8, 0x00d2a0);

    lcf('pappus', 'Pappus graph', [5, 7, -7, 7, -7, -5], 3, 0xffd23f);

    lcf('desargues', 'Desargues graph', [5, -5, 9, -9], 5, 0x4d8bf0);

    lcf('nauru', 'Nauru graph', [5, -9, 7, -7, 9, -5], 4, 0x9b5de5);
})();
