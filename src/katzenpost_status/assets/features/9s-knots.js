(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;

    function curve(id, name, fn, color, camZ, N) {
        G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 60,
            layout: function (d, THREE) { var P = [], i, n = N || 340; for (i = 0; i <= n; i++) P.push(fn(i / n, THREE)); return G.curveLayout(d, THREE, P, color); } });
    }
    function tk(id, name, p, q, color) {
        curve(id, name, function (t, T) { var R = 15, r = 6, a = t * PI2; return new T.Vector3((R + r * Math.cos(q * a)) * Math.cos(p * a), (R + r * Math.cos(q * a)) * Math.sin(p * a), r * Math.sin(q * a)); }, color, 60, 480);
    }
    function ring(anchors, edges, THREE, ax, R, segs, color) {
        var prev = null, first = null;
        for (var s = 0; s <= segs; s++) {
            var a = s / segs * PI2, c = Math.cos(a) * R, si = Math.sin(a) * R, p;
            if (ax === 0) p = new THREE.Vector3(0, c, si); else if (ax === 1) p = new THREE.Vector3(c, 0, si); else p = new THREE.Vector3(c, si, 0);
            if (s % 4 === 0) anchors.push(p);
            if (prev) edges.push({ a: prev, b: p, color: color }); else first = p;
            prev = p;
        }
        if (first && prev) edges.push({ a: prev, b: first, color: color });
    }
    function linkView(id, name, fn, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 56,
            layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE); return G.anchorLayout(d, THREE, a, e); } });
    }

    curve('figure8', 'Figure-eight knot', function (t, T) { var u = t * PI2, s = 6; return new T.Vector3((2 + Math.cos(2 * u)) * Math.cos(3 * u) * s, (2 + Math.cos(2 * u)) * Math.sin(3 * u) * s, Math.sin(4 * u) * s); }, 0x2ec4b6, 58, 480);

    tk('cinquefoil', 'Cinquefoil knot', 2, 5, 0x4d8bf0);
})();
