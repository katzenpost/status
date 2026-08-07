(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2var = Math.PI * 2;

    // Parametric surface as a grid mesh; packets route the grid lines.
    function surf(id, name, pFn, ures, vres, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 60,
            layout: function (d, THREE) {
                var A = [], idx = {}, E = [], i, j;
                for (i = 0; i <= ures; i++) for (j = 0; j <= vres; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ures, j / vres, THREE)); }
                function add(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); }
                for (i = 0; i < ures; i++) for (j = 0; j < vres; j++) { add(i, j, i + 1, j); add(i, j, i, j + 1); }
                return G.anchorLayout(d, THREE, A, E);
            } });
    }
    function knn(pts, THREE, k, color) {
        var E = [], seen = {}, i, j, m;
        for (i = 0; i < pts.length; i++) {
            var ds = [];
            for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]);
            ds.sort(function (a, b) { return a[0] - b[0]; });
            for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } }
        }
        return E;
    }
    // Sample a triply-periodic implicit surface f=0 into a shell point cloud.
    function tpms(id, name, f, span, eps, sc, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58,
            layout: function (d, THREE) {
                var N = 30, pts = [], i, j, l;
                for (i = 0; i <= N && pts.length < 520; i++) for (j = 0; j <= N && pts.length < 520; j++) for (l = 0; l <= N && pts.length < 520; l++) {
                    var x = -span + 2 * span * i / N, y = -span + 2 * span * j / N, z = -span + 2 * span * l / N;
                    if (Math.abs(f(x, y, z)) < eps) pts.push(new THREE.Vector3(x * sc, y * sc, z * sc));
                }
                if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []);
                return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 3, color));
            } });
    }

    tpms('gyroid', 'Gyroid (TPMS)', function (x, y, z) { return Math.sin(x) * Math.cos(y) + Math.sin(y) * Math.cos(z) + Math.sin(z) * Math.cos(x); }, Math.PI * 1.5, 0.16, 4.0, 0x2ec4b6, 58);

    tpms('schwarzp', 'Schwarz P surface', function (x, y, z) { return Math.cos(x) + Math.cos(y) + Math.cos(z); }, Math.PI * 1.3, 0.2, 4.6, 0x4d8bf0, 58);

    tpms('schwarzd', 'Schwarz D surface', function (x, y, z) { return Math.sin(x) * Math.sin(y) * Math.sin(z) + Math.sin(x) * Math.cos(y) * Math.cos(z) + Math.cos(x) * Math.sin(y) * Math.cos(z) + Math.cos(x) * Math.cos(y) * Math.sin(z); }, Math.PI * 1.3, 0.2, 4.6, 0x9b5de5, 58);

    surf('catenoid', 'Catenoid', function (u, v, T) { var a = u * PI2var, b = (v - 0.5) * 2.4, c = 5; return new T.Vector3(c * Math.cosh(b) * Math.cos(a), c * Math.cosh(b) * Math.sin(a), c * b * 2); }, 40, 18, 0x00d2a0, 62);

    surf('helicoid', 'Helicoid', function (u, v, T) { var th = u * PI2var * 1.5, r = (v - 0.5) * 34; return new T.Vector3(r * Math.cos(th), r * Math.sin(th), th * 3); }, 60, 20, 0xffb454, 62);

    surf('enneper', 'Enneper surface', function (u, v, T) { var a = (u - 0.5) * 4, b = (v - 0.5) * 4, s = 2.2; return new T.Vector3((a - a * a * a / 3 + a * b * b) * s, (b - b * b * b / 3 + b * a * a) * s, (a * a - b * b) * s); }, 34, 34, 0xff5d8f, 60);

    surf('dini', 'Dini surface', function (u, v, T) { var a = u * PI2var * 2, b = 0.05 + v * 1.9, s = 5; return new T.Vector3(s * Math.cos(a) * Math.sin(b), s * Math.sin(a) * Math.sin(b), s * (Math.cos(b) + Math.log(Math.tan(b / 2))) + 2.4 * a); }, 60, 24, 0xffd23f, 54);
})();
