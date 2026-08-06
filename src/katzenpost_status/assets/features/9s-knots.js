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

    tk('knot34', '(3,4) torus knot', 3, 4, 0x9b5de5);

    tk('knot35', '(3,5) torus knot', 3, 5, 0xff8f3f);

    tk('septafoil', 'Septafoil knot', 2, 7, 0xff5d8f);

    tk('knot45', '(4,5) torus knot', 4, 5, 0x00d2a0);

    linkView('borromean', 'Borromean rings', function (a, e, T) {
        var R = 12, b = 7;
        // three mutually interlocking ellipses in orthogonal planes
        for (var s = 0; s <= 60; s++) { var t = s / 60 * PI2; }
        function ell(ax) { var prev = null, first = null; for (var s = 0; s <= 64; s++) { var t = s / 64 * PI2, x = Math.cos(t) * R, y = Math.sin(t) * b, p; if (ax === 0) p = new T.Vector3(x, y, 0); else if (ax === 1) p = new T.Vector3(0, x, y); else p = new T.Vector3(y, 0, x); if (s % 4 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: 0xffd23f }); else first = p; prev = p; } e.push({ a: prev, b: first, color: 0xffd23f }); }
        ell(0); ell(1); ell(2);
    }, 54);

    linkView('hopflink', 'Hopf link', function (a, e, T) { ring(a, e, T, 2, 12, 64, 0x4d8bf0); var e2 = []; ring(a, e2, T, 1, 12, 64, 0xff8f3f); e2.forEach(function (x) { x.a.x += 12; x.b.x += 12; e.push(x); }); }, 52);

    linkView('chainmail', 'Chain-mail lattice', function (a, e, T) {
        for (var gx = -1; gx <= 1; gx++) for (var gy = -1; gy <= 1; gy++) {
            var ax = ((gx + gy) & 1) ? 1 : 2, e2 = []; ring(a, e2, T, ax, 6, 40, 0x2ec4b6);
            e2.forEach(function (x) { x.a.x += gx * 9; x.a.y += gy * 9; x.b.x += gx * 9; x.b.y += gy * 9; e.push(x); });
        }
    }, 58);

    tk('turkshead', "Turk's-head weave", 3, 7, 0xffb454);
})();
