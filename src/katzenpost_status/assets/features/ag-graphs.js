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
})();
