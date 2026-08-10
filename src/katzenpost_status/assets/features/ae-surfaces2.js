(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function finite(v) { return isFinite(v.x) && isFinite(v.y) && isFinite(v.z) && v.length() < 400; }
    function surf(id, name, pFn, ur, vr, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 58, layout: function (d, THREE) {
            var A = [], idx = {}, E = [], i, j;
            for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { var p = pFn(i / ur, j / vr, THREE); idx[i + '_' + j] = A.length; A.push(finite(p) ? p : new THREE.Vector3()); }
            function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); }
            for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); }
            return G.anchorLayout(d, THREE, A, E);
        } });
    }
    function knn(pts, THREE, k, color) { var E = [], seen = {}, i, j, m; for (i = 0; i < pts.length; i++) { var ds = []; for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]); ds.sort(function (a, b) { return a[0] - b[0]; }); for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], a = Math.min(i, jj), b = Math.max(i, jj), key = a + '_' + b; if (!seen[key]) { seen[key] = 1; E.push({ a: pts[i], b: pts[jj], color: color }); } } } return E; }
    function tpms(id, name, f, span, eps, sc, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, THREE) {
            var N = 44, pts = [], i, j, l;
            for (i = 0; i <= N && pts.length < 850; i++) for (j = 0; j <= N && pts.length < 850; j++) for (l = 0; l <= N && pts.length < 850; l++) { var x = -span + 2 * span * i / N, y = -span + 2 * span * j / N, z = -span + 2 * span * l / N; if (Math.abs(f(x, y, z)) < eps) pts.push(new THREE.Vector3(x * sc, y * sc, z * sc)); }
            if (pts.length < 4) return G.anchorLayout(d, THREE, pts, []);
            return G.anchorLayout(d, THREE, pts, knn(pts, THREE, 3, color));
        } });
    }
    function C(a) { return Math.cos(a); } function S(a) { return Math.sin(a); }

    surf('scherk', 'Scherk surface', function (u, v, T) { var x = (u - 0.5) * 2.7, y = (v - 0.5) * 2.7, z = Math.log(Math.abs(Math.cos(x)) + 1e-3) - Math.log(Math.abs(Math.cos(y)) + 1e-3); return new T.Vector3(x * 6, y * 6, z * 5); }, 46, 46, 0x2ec4b6, 58);

    surf('henneberg', 'Henneberg surface', function (u, v, T) { var a = (u - 0.5) * 1.4, b = v * Math.PI, s = 2.2; return new T.Vector3(s * (2 * Math.sinh(a) * Math.cos(b) - (2 / 3) * Math.sinh(3 * a) * Math.cos(3 * b)), s * (2 * Math.sinh(a) * Math.sin(b) + (2 / 3) * Math.sinh(3 * a) * Math.sin(3 * b)), s * 2 * Math.cosh(2 * a) * Math.cos(2 * b)); }, 44, 44, 0x4d8bf0, 56);

    surf('catalan', 'Catalan minimal surface', function (u, v, T) { var a = u * PI2 * 1.5, b = (v - 0.5) * 4, s = 2.6; return new T.Vector3(s * (a - Math.sin(a) * Math.cosh(b)), s * (1 - Math.cos(a) * Math.cosh(b)), s * 4 * Math.sin(a / 2) * Math.sinh(b / 2)); }, 60, 30, 0x9b5de5, 54);

    surf('bour', 'Bour surface', function (u, v, T) { var r = 0.15 + u * 1.9, a = v * PI2, s = 4.5; return new T.Vector3(s * (r * Math.cos(a) - r * r / 2 * Math.cos(2 * a)), s * (-r * Math.sin(a) - r * r / 2 * Math.sin(2 * a)), s * (4 / 3) * Math.pow(r, 1.5) * Math.cos(1.5 * a)); }, 44, 60, 0xff8f3f, 54);

    surf('monkeysaddle', 'Monkey saddle', function (u, v, T) { var x = (u - 0.5) * 4, y = (v - 0.5) * 4; return new T.Vector3(x * 6, y * 6, (x * x * x - 3 * x * y * y) * 1.2); }, 40, 40, 0xff5d8f, 60);

    surf('whitney', 'Whitney umbrella', function (u, v, T) { var a = (u - 0.5) * 3, b = (v - 0.5) * 3; return new T.Vector3(a * b * 4, a * 7, b * b * 4); }, 40, 40, 0x00d2a0, 58);

    tpms('neovius', 'Neovius surface (TPMS)', function (x, y, z) { return 3 * (Math.cos(x) + Math.cos(y) + Math.cos(z)) + 4 * Math.cos(x) * Math.cos(y) * Math.cos(z); }, Math.PI * 1.25, 0.5, 5.4, 0xffd23f, 58);

    tpms('iwp', 'I-WP surface (TPMS)', function (x, y, z) { return 2 * (Math.cos(x) * Math.cos(y) + Math.cos(y) * Math.cos(z) + Math.cos(z) * Math.cos(x)) - (Math.cos(2 * x) + Math.cos(2 * y) + Math.cos(2 * z)); }, Math.PI * 1.25, 0.35, 5.4, 0x4d8bf0, 58);

    tpms('splitp', 'Split-P surface (TPMS)', function (x, y, z) { return 1.1 * (Math.sin(2 * x) * Math.sin(z) * Math.cos(y) + Math.sin(2 * y) * Math.sin(x) * Math.cos(z) + Math.sin(2 * z) * Math.sin(y) * Math.cos(x)) - 0.2 * (Math.cos(2 * x) * Math.cos(2 * y) + Math.cos(2 * y) * Math.cos(2 * z) + Math.cos(2 * z) * Math.cos(2 * x)) - 0.4 * (Math.cos(2 * x) + Math.cos(2 * y) + Math.cos(2 * z)); }, Math.PI * 1.25, 0.28, 5.4, 0x9b5de5, 58);

    tpms('fischerkoch', 'Fischer-Koch S (TPMS)', function (x, y, z) { return Math.cos(2 * x) * Math.sin(y) * Math.cos(z) + Math.cos(2 * y) * Math.sin(z) * Math.cos(x) + Math.cos(2 * z) * Math.sin(x) * Math.cos(y); }, Math.PI * 1.25, 0.22, 5.4, 0xff8f3f, 58);
})();
