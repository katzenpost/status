(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, PHI = (1 + Math.sqrt(5)) / 2, GA = PI2 * (1 - 1 / PHI);

    function sieve(N) { var p = []; for (var i = 0; i <= N; i++) p.push(i > 1); for (i = 2; i * i <= N; i++) if (p[i]) for (var j = i * i; j <= N; j += i) p[j] = false; return p; }
    // Plot a number sequence as points and connect NEAREST neighbours (not the
    // numeric successor), which reveals the spiral arms instead of a tangle.
    function constellation(id, name, ptsOfN, N, primesOnly, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 58,
            layout: function (d, THREE) {
                var pr = sieve(N), pts = [], n;
                for (n = 1; n <= N; n++) if (!primesOnly || pr[n]) { var p = ptsOfN(n); pts.push(new THREE.Vector3(p[0], p[1], p[2] || 0)); }
                return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 2, color));
            } });
    }
    function anchorsEdges(id, name, fn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } });
    }
    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }

    constellation('ulam', 'Ulam prime spiral', function (n) { var k = Math.ceil((Math.sqrt(n) - 1) / 2), t = 2 * k + 1, m = t * t, tt = t - 1, x, y; if (n >= m - tt) { x = k - (m - n); y = -k; } else { m -= tt; if (n >= m - tt) { x = -k; y = -k + (m - n); } else { m -= tt; if (n >= m - tt) { x = -k + (m - n); y = k; } else { x = k; y = k - (m - n - tt); } } } return [x * 1.4, y * 1.4, 0]; }, 900, true, 0x2ec4b6, 60);

    constellation('sacks', 'Sacks spiral', function (n) { var r = Math.sqrt(n) * 1.9, th = Math.sqrt(n) * PI2; return [Math.cos(th) * r, Math.sin(th) * r, 0]; }, 1200, true, 0x4d8bf0, 60);

    constellation('sunflower', 'Phyllotaxis sunflower', function (n) { var r = Math.sqrt(n) * 1.5, th = n * GA; return [Math.cos(th) * r, Math.sin(th) * r, 0]; }, 700, false, 0xffd23f, 60);

    constellation('fermat', 'Fermat spiral', function (n) { var t = n * 0.16, r = Math.sqrt(t) * 8, s = (n & 1) ? 1 : -1; return [Math.cos(t) * r * s, Math.sin(t) * r * s, 0]; }, 500, false, 0xff8f3f, 60);

    anchorsEdges('recaman', 'Recaman sequence', function (a, e, T, color) {
        var seen = {}, cur = 0, N = 70, xs = [cur], i; seen[0] = 1;
        for (i = 1; i <= N; i++) { var nx = cur - i; if (nx < 0 || seen[nx]) nx = cur + i; seen[nx] = 1; xs.push(nx); cur = nx; }
        var sc = 1.1;
        for (i = 1; i < xs.length; i++) { var x0 = xs[i - 1] * sc, x1 = xs[i] * sc, cx = (x0 + x1) / 2, rr = Math.abs(x1 - x0) / 2, up = (i & 1) ? 1 : -1, prev = null; for (var s = 0; s <= 24; s++) { var th = Math.PI * s / 24, p = new T.Vector3(cx - Math.cos(th) * rr * Math.sign(x1 - x0), up * Math.sin(th) * rr, 0); if (s % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } }
    }, 0xff5d8f, 54);

    anchorsEdges('timestable', 'Times-table cardioid', function (a, e, T, color) { var N = 200, mult = 2, R = 20, i; var pt = function (k) { var th = (k % N) / N * PI2 - Math.PI / 2; return new T.Vector3(Math.cos(th) * R, Math.sin(th) * R, 0); }; for (i = 0; i < N; i++) { var p = pt(i), q = pt(i * mult); a.push(p); e.push({ a: p, b: q, color: color }); } }, 0x9b5de5, 52);

    anchorsEdges('pascalmod', 'Pascal triangle mod 2', function (a, e, T, color) { var R = 34, row = [1], n, k, sc = 1.15; for (n = 0; n < R; n++) { for (k = 0; k <= n; k++) if (row[k] & 1) { var x = (k - n / 2) * sc, y = (R / 2 - n) * sc, h = sc / 2; var p = [[x - h, y - h], [x + h, y - h], [x + h, y + h], [x - h, y + h]]; a.push(new T.Vector3(x, y, 0)); for (var m = 0; m < 4; m++) e.push({ a: new T.Vector3(p[m][0], p[m][1], 0), b: new T.Vector3(p[(m + 1) % 4][0], p[(m + 1) % 4][1], 0), color: color }); } var nr = [1]; for (k = 1; k <= n; k++) nr[k] = ((row[k - 1] || 0) + (row[k] || 0)) & 1; nr[n + 1] = 1; row = nr; } }, 0x00d2a0, 58);

    anchorsEdges('sternbrocot', 'Stern-Brocot tree', function (a, e, T, color) { var D = 6, sp = 46; function rec(depth, x, w, py) { var y = 18 - depth * 6; var p = new T.Vector3(x, y, 0); a.push(p); if (py) e.push({ a: py, b: p, color: color }); if (depth < D) { rec(depth + 1, x - w / 2, w / 2, p); rec(depth + 1, x + w / 2, w / 2, p); } } rec(0, 0, sp, null); }, 0xffb454, 56);

    G.create({ id: 'fibsphere', name: 'Fibonacci sphere', rotateSpeed: 0.4, camZ: 56, layout: function (d, THREE) { var N = 360, pts = [], i; for (i = 0; i < N; i++) { var y = 1 - (i / (N - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * GA; pts.push(new THREE.Vector3(Math.cos(th) * r * 20, y * 20, Math.sin(th) * r * 20)); } return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 3, 0x4d8bf0)); } });

    G.create({ id: 'goldencone', name: 'Phyllotaxis cone', rotateSpeed: 0.4, camZ: 60, layout: function (d, THREE) { var N = 420, pts = [], i; for (i = 0; i < N; i++) { var f = i / N, r = Math.sqrt(i) * 1.5, th = i * GA; pts.push(new THREE.Vector3(Math.cos(th) * r, (f - 0.5) * 34, Math.sin(th) * r)); } return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 2, 0xffd23f)); } });
})();
