(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 56, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function V(T, x, y, z) { return new T.Vector3(x, y, z || 0); }
    function seg(e, a, p, q, color) { e.push({ a: p, b: q, color: color }); a.push(p); }

    ae('miuraori', 'Miura-ori crease pattern', function (a, e, T, color) { var cols = 10, rows = 8, dx = 4, dy = 4.5, sh = 1.6, i, j; function P(i, j) { return V(T, (i - cols / 2) * dx, (j - rows / 2) * dy + (i % 2 ? sh : 0), 0); } for (i = 0; i <= cols; i++) for (j = 0; j <= rows; j++) { if (i < cols) seg(e, a, P(i, j), P(i + 1, j), color); if (j < rows) seg(e, a, P(i, j), P(i, j + 1), color); } }, 0x2ec4b6, 56);

    ae('waterbomb', 'Waterbomb tessellation', function (a, e, T, color) { var n = 7, s = 6, i, j; function P(x, y) { return V(T, (x - n / 2) * s, (y - n / 2) * s, 0); } for (i = 0; i < n; i++) for (j = 0; j < n; j++) { seg(e, a, P(i, j), P(i + 1, j), color); seg(e, a, P(i, j), P(i, j + 1), color); seg(e, a, P(i, j), P(i + 1, j + 1), color); seg(e, a, P(i + 1, j), P(i, j + 1), color); seg(e, a, P(i, j + 0.5), P(i + 1, j + 0.5), color); seg(e, a, P(i + 0.5, j), P(i + 0.5, j + 1), color); } }, 0x4d8bf0, 58);

    ae('yoshimura', 'Yoshimura diamond pattern', function (a, e, T, color) { var cols = 10, rows = 8, dx = 4, dy = 4, i, j; function P(i, j) { return V(T, (i - cols / 2) * dx + (j % 2 ? dx / 2 : 0), (j - rows / 2) * dy, 0); } for (i = 0; i <= cols; i++) for (j = 0; j <= rows; j++) { if (j < rows) { seg(e, a, P(i, j), P(i, j + 1), color); seg(e, a, P(i, j), P(i - (j % 2 ? 0 : 1), j + 1), color); seg(e, a, P(i, j), P(i + (j % 2 ? 1 : 0), j + 1), color); } } }, 0x9b5de5, 56);
})();
