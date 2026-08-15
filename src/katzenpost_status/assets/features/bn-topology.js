(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, T) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, T)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, T, A, E); } }); }
    // Tube surface around a space curve (numerical frame).
    function tube(id, name, cFn, r, ur, vr, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.42, camZ: camZ || 58, layout: function (d, T) {
            var A = [], idx = {}, E = [], i, j, up = new T.Vector3(0, 1, 0);
            for (i = 0; i <= ur; i++) {
                var t = i / ur, c0 = cFn(t, T), c1 = cFn(t + 0.001, T);
                var tan = c1.clone().sub(c0).normalize(); if (tan.length() < 1e-6) tan.set(1, 0, 0);
                var n = new T.Vector3().crossVectors(tan, up); if (n.length() < 1e-4) n = new T.Vector3().crossVectors(tan, new T.Vector3(1, 0, 0)); n.normalize();
                var b = new T.Vector3().crossVectors(tan, n).normalize();
                for (j = 0; j <= vr; j++) { var ph = j / vr * PI2, p = c0.clone().add(n.clone().multiplyScalar(Math.cos(ph) * r)).add(b.clone().multiplyScalar(Math.sin(ph) * r)); idx[i + '_' + j] = A.length; A.push(p); }
            }
            function ad(a, b2, c, e) { var k1 = idx[a + '_' + b2], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); }
            for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); }
            return G.anchorLayout(d, T, A, E);
        } });
    }
    function sf(m, n1, n2, n3, a, ang) { var t1 = Math.pow(Math.abs(Math.cos(m * ang / 4) / a), n2), t2 = Math.pow(Math.abs(Math.sin(m * ang / 4) / a), n3); return Math.pow(t1 + t2, -1 / n1); }

    surf('horntorus', 'Horn torus', function (u, v, T) { var a = u * PI2, b = v * PI2, R = 10, r = 10; return new T.Vector3((R + r * Math.cos(b)) * Math.cos(a), r * Math.sin(b), (R + r * Math.cos(b)) * Math.sin(a)); }, 60, 40, 0x2ec4b6, 58);
})();
