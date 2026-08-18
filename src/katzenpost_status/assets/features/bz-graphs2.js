(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, D = 20;
    function circ(id, name, n, offs, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 56, layout: function (d, T) {
            var P = [], e = [], i, o; for (i = 0; i < n; i++) { var th = i / n * PI2 - Math.PI / 2; P.push(new T.Vector3(Math.cos(th) * D, Math.sin(th) * D, 0)); }
            var seen = {};
            for (i = 0; i < n; i++) offs.forEach(function (o) { var j = (i + o) % n, k = Math.min(i, j) + '_' + Math.max(i, j); if (!seen[k]) { seen[k] = 1; e.push({ a: P[i], b: P[j], color: color }); } });
            return G.anchorLayout(d, T, P, e);
        } });
    }
    function paley(id, name, q, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 56, layout: function (d, T) {
            var P = [], e = [], i, qr = {}; for (i = 1; i < q; i++) qr[(i * i) % q] = 1; var offs = Object.keys(qr).map(Number);
            for (i = 0; i < q; i++) { var th = i / q * PI2 - Math.PI / 2; P.push(new T.Vector3(Math.cos(th) * D, Math.sin(th) * D, 0)); }
            var seen = {};
            for (i = 0; i < q; i++) offs.forEach(function (o) { var j = (i + o) % q, k = Math.min(i, j) + '_' + Math.max(i, j); if (!seen[k]) { seen[k] = 1; e.push({ a: P[i], b: P[j], color: color }); } });
            return G.anchorLayout(d, T, P, e);
        } });
    }

    circ('circ-24-1-2', 'Circulant C24(1,2)', 24, [1, 2], 0x2ec4b6, 56);

    circ('circ-24-1-5', 'Circulant C24(1,5)', 24, [1, 5], 0x4d8bf0, 56);

    circ('circ-24-2-7', 'Circulant C24(2,7)', 24, [2, 7], 0x9b5de5, 56);

    circ('circ-24-1-2-3', 'Circulant C24(1,2,3)', 24, [1, 2, 3], 0xff8f3f, 56);

    circ('circ-24-1-4-9', 'Circulant C24(1,4,9)', 24, [1, 4, 9], 0xff5d8f, 56);

    circ('circ-24-3-8', 'Circulant C24(3,8)', 24, [3, 8], 0x00d2a0, 56);
})();
