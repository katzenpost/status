(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, PHI = (1 + Math.sqrt(5)) / 2, GA = PI2 * (1 - 1 / PHI);

    function sieve(N) { var p = []; for (var i = 0; i <= N; i++) p.push(i > 1); for (i = 2; i * i <= N; i++) if (p[i]) for (var j = i * i; j <= N; j += i) p[j] = false; return p; }
    function constellation(id, name, ptsOfN, N, primesOnly, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 58,
            layout: function (d, THREE) {
                var pr = sieve(N), seq = [], n;
                for (n = 1; n <= N; n++) if (!primesOnly || pr[n]) seq.push(ptsOfN(n));
                var edges = [], anchors = [], prev = null;
                seq.forEach(function (p, i) { var v = new THREE.Vector3(p[0], p[1], p[2] || 0); anchors.push(v); if (prev) edges.push({ a: prev, b: v, color: color }); prev = v; });
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }
    function anchorsEdges(id, name, fn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } });
    }
    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }

    constellation('ulam', 'Ulam prime spiral', function (n) { var k = Math.ceil((Math.sqrt(n) - 1) / 2), t = 2 * k + 1, m = t * t, tt = t - 1, x, y; if (n >= m - tt) { x = k - (m - n); y = -k; } else { m -= tt; if (n >= m - tt) { x = -k; y = -k + (m - n); } else { m -= tt; if (n >= m - tt) { x = -k + (m - n); y = k; } else { x = k; y = k - (m - n - tt); } } } return [x * 1.4, y * 1.4, 0]; }, 900, true, 0x2ec4b6, 60);
})();
