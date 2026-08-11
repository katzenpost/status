(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function graph(id, name, fn, color, camZ, N) { G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 54, layout: function (d, THREE) { var P = [], i, n = N || 600; for (i = 0; i <= n; i++) { var x = i / n; P.push(new THREE.Vector3((x - 0.5) * 42, (fn(x) - 0.5) * 34, 0)); } return G.curveLayout(d, THREE, P, color); } }); }
    function turtleCurve(id, name, bitsFn, ang, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 54, layout: function (d, THREE) { var bits = bitsFn(), x = 0, y = 0, dir = 0, pts = [[0, 0]], i; for (i = 0; i < bits.length; i++) { x += Math.cos(dir); y += Math.sin(dir); pts.push([x, y]); dir += (bits[i] ? 1 : -1) * ang; } var mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9; pts.forEach(function (p) { if (p[0] < mnx) mnx = p[0]; if (p[0] > mxx) mxx = p[0]; if (p[1] < mny) mny = p[1]; if (p[1] > mxy) mxy = p[1]; }); var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, sc = 40 / Math.max(1e-6, Math.max(mxx - mnx, mxy - mny)); return G.curveLayout(d, THREE, pts.map(function (p) { return new THREE.Vector3((p[0] - cx) * sc, (p[1] - cy) * sc, 0); }), color); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 54, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function isPrime(n) { if (n < 2) return false; for (var i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; }

    turtleCurve('thuemorse', 'Thue-Morse curve', function () { var b = [0], i; for (i = 0; i < 4000; i++) b.push(1 - b[i]); var out = []; for (i = 0; i < b.length; i++) { var n = i, p = 0; while (n) { p ^= (n & 1); n >>= 1; } out.push(p); } return out; }, Math.PI / 3, 0x2ec4b6, 54);
})();
