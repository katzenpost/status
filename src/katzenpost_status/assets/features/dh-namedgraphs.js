(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function emit(d, THREE, pos, eList) {
        var edges = [], seen = {}, i;
        for (i = 0; i < eList.length; i++) { var e = eList[i], a = Math.min(e[0], e[1]), b = Math.max(e[0], e[1]), key = a + '_' + b; if (a === b || seen[key]) continue; seen[key] = 1; edges.push({ a: pos[e[0]], b: pos[e[1]], color: PAL[(e[2] || 0) % PAL.length] }); }
        if (edges.length < 3) { pos = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; edges = [{ a: pos[0], b: pos[1], color: PAL[0] }]; }
        return G.anchorLayout(d, THREE, pos, edges);
    }
    function fibSphere(n, r, THREE) { var pts = [], i, ga = Math.PI * (3 - Math.sqrt(5)); for (i = 0; i < n; i++) { var y = 1 - 2 * (i + 0.5) / n, rr = Math.sqrt(1 - y * y), th = ga * i; pts.push(new THREE.Vector3(Math.cos(th) * rr * r, y * r, Math.sin(th) * rr * r)); } return pts; }
    // Generalized Petersen GP(n,k): outer n-cycle, inner {n/k star}, spokes.
    function gp(id, name, n, k, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) {
            var pos = [], e = [], i;
            for (i = 0; i < n; i++) { var a = 2 * Math.PI * i / n; pos.push(new THREE.Vector3(17 * Math.cos(a), 17 * Math.sin(a), 3)); }
            for (i = 0; i < n; i++) { var a2 = 2 * Math.PI * i / n; pos.push(new THREE.Vector3(9 * Math.cos(a2), 9 * Math.sin(a2), -3)); }
            for (i = 0; i < n; i++) { e.push([i, (i + 1) % n, 0]); e.push([i, n + i, 1]); e.push([n + i, n + (i + k) % n, 2]); }
            return emit(d, THREE, pos, e);
        } });
    }
    function combos(n, k) { var out = []; (function rec(start, cur) { if (cur.length === k) { out.push(cur.slice()); return; } for (var i = start; i < n; i++) { cur.push(i); rec(i + 1, cur); cur.pop(); } })(0, []); return out; }
    // Kneser graph K(n,k): k-subsets adjacent when disjoint.
    function kneser(id, name, n, k, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) {
            var S = combos(n, k), pos = fibSphere(S.length, 17, THREE), e = [], i, j, a, b, dj;
            for (i = 0; i < S.length; i++) for (j = i + 1; j < S.length; j++) { dj = true; for (a = 0; a < k; a++) for (b = 0; b < k; b++) if (S[i][a] === S[j][b]) dj = false; if (dj) e.push([i, j, (S[i][0]) % PAL.length]); }
            return emit(d, THREE, pos, e);
        } });
    }
    // de Bruijn graph B(m,n): length-n base-m strings; edge on shift-and-append.
    function debruijn(id, name, m, n, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 58, layout: function (d, THREE) {
            var M = Math.pow(m, n), pw = Math.pow(m, n - 1), pos = [], e = [], i, x;
            for (i = 0; i < M; i++) { var a = 2 * Math.PI * i / M; pos.push(new THREE.Vector3(17 * Math.cos(a), 17 * Math.sin(a), 4 * Math.sin(3 * a))); }
            for (i = 0; i < M; i++) for (x = 0; x < m; x++) { var to = (i % pw) * m + x; e.push([i, to, x]); }
            return emit(d, THREE, pos, e);
        } });
    }
    // Cayley graph of A4 (right multiplication by two 3-cycles).
    function cayleyA4(id, name, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, THREE) {
            var gens = [[1, 2, 0, 3], [0, 2, 3, 1]], id0 = [0, 1, 2, 3];
            function mul(a, b) { return [a[b[0]], a[b[1]], a[b[2]], a[b[3]]]; }
            function key(p) { return p.join(''); }
            var order = [id0], idx = {}; idx[key(id0)] = 0;
            var head = 0, e = [];
            while (head < order.length) { var g = order[head++]; for (var s = 0; s < gens.length; s++) { var h = mul(g, gens[s]), kk = key(h); if (idx[kk] == null) { idx[kk] = order.length; order.push(h); } e.push([idx[key(g)], idx[kk], s]); } }
            var pos = fibSphere(order.length, 16, THREE);
            return emit(d, THREE, pos, e);
        } });
    }

    gp('ng-genpetersen-7-2', 'Generalized Petersen GP(7,2)', 7, 2, 58);

    gp('ng-genpetersen-9-2', 'Generalized Petersen GP(9,2)', 9, 2, 58);

    gp('ng-genpetersen-11-2', 'Generalized Petersen GP(11,2)', 11, 2, 58);
})();
