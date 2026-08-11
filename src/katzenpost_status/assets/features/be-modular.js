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

    turtleCurve('rudinshapiro', 'Rudin-Shapiro curve', function () { var out = [], i; for (i = 0; i < 4000; i++) { var n = i, c = 0, prev = 0; while (n) { if ((n & 3) === 3) c++; n >>= 1; } out.push(c & 1); } return out; }, Math.PI / 2, 0x4d8bf0, 54);

    graph('questionmark', 'Minkowski question-mark', function (x) { if (x <= 0) return 0; if (x >= 1) return 1; var cf = [], v = x, i; for (i = 0; i < 25 && v > 1e-9; i++) { var a = Math.floor(1 / v); cf.push(a); v = 1 / v - a; } var y = 0, sign = 1, exp = 0, k; for (k = 0; k < cf.length; k++) { exp += cf[k]; y += sign * 2 / Math.pow(2, exp); sign = -sign; } return y; }, 0x9b5de5, 54, 800);

    graph('blancmange', 'Blancmange function', function (x) { var y = 0, n; for (n = 0; n < 16; n++) { var v = x * (1 << n); y += Math.abs(v - Math.round(v)) / (1 << n); } return y * 0.75; }, 0xff8f3f, 54, 900);

    graph('weierstrass', 'Weierstrass function', function (x) { var y = 0, n; for (n = 0; n < 9; n++) y += Math.pow(0.5, n) * Math.cos(Math.pow(7, n) * Math.PI * x); return (y + 2) / 4; }, 0xff5d8f, 54, 1000);

    graph("devilsstaircase", "Devil's staircase", function (x) { var b = 0.5, y = 0, i; for (i = 0; i < 25; i++) { x *= 3; if (x >= 2) { x -= 2; y += b; } else if (x >= 1) { y += b; break; } b /= 2; } return y; }, 0x00d2a0, 54, 900);

    ae('gaussmap', 'Gauss map cobweb', function (a, e, T, color) { var N = 400, i, prev = null; for (i = 1; i <= N; i++) { var x = i / N, y = 1 / x - Math.floor(1 / x); var p = new T.Vector3((x - 0.5) * 40, (y - 0.5) * 40, 0); if (i % 3 === 0) a.push(p); if (prev && Math.abs(y - prev.__y) < 0.5) e.push({ a: prev, b: p, color: color }); p.__y = y; prev = p; } var cx = 0.4, cy = 0; for (i = 0; i < 40; i++) { var yy = 1 / cx - Math.floor(1 / cx); var p1 = new T.Vector3((cx - 0.5) * 40, (yy - 0.5) * 40, 0), p2 = new T.Vector3((yy - 0.5) * 40, (yy - 0.5) * 40, 0); a.push(p1); e.push({ a: p1, b: p2, color: 0xffd23f }); cx = yy; if (cx < 0.02) break; } }, 0x9b5de5, 54);

    G.create({ id: 'gaussianprimes', name: 'Gaussian primes', rotateSpeed: 0.28, camZ: 56, layout: function (d, THREE) { var pts = [], R = 18, a, b; function gprime(a, b) { var n = a * a + b * b; if (a === 0) return isPrime(Math.abs(b)) && (Math.abs(b) % 4 === 3); if (b === 0) return isPrime(Math.abs(a)) && (Math.abs(a) % 4 === 3); return isPrime(n); } for (a = -R; a <= R; a++) for (b = -R; b <= R; b++) if (gprime(a, b)) pts.push(new THREE.Vector3(a * 1.4, b * 1.4, 0)); return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 2, 0xffb454)); } });

    ae('divisorplot', 'Divisor plot', function (a, e, T, color) { var N = 46, n, dd; for (n = 2; n <= N; n++) { var col = [], prev = null; for (dd = 1; dd <= n; dd++) if (n % dd === 0) { var p = new T.Vector3((n - N / 2) * 1.5, (dd / n * 40) - 20, 0); a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); prev = p; } } }, 0x4d8bf0, 56);
})();
