(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    // Spherical-harmonic lobe surface: radius = |Y(theta,phi)|.
    function ylm(id, name, fn, color, camZ, sc) {
        G.create({ id: id, name: name, rotateSpeed: 0.42, camZ: camZ || 52, layout: function (d, THREE) {
            var ur = 40, vr = 60, A = [], idx = {}, E = [], i, j, S = sc || 22;
            for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { var th = i / ur * Math.PI, ph = j / vr * PI2, r = Math.abs(fn(th, ph)) * S; A.push(new THREE.Vector3(r * Math.sin(th) * Math.cos(ph), r * Math.cos(th), r * Math.sin(th) * Math.sin(ph))); idx[i + '_' + j] = A.length - 1; }
            function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); }
            for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); }
            return G.anchorLayout(d, THREE, A, E);
        } });
    }
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.35, camZ: camZ || 58, layout: function (d, THREE) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, THREE)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, THREE, A, E); } }); }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 54, layout: function (d, THREE) { var a = [], e = []; fn(a, e, THREE, color); return G.anchorLayout(d, THREE, a, e); } }); }
    function besselish(x) { return Math.cos(x - Math.PI / 4) / Math.sqrt(1 + x); }

    ylm('orbital_pz', 'Orbital 2p_z (Y10)', function (th, ph) { return Math.cos(th); }, 0x2ec4b6, 50);

    ylm('orbital_dz2', 'Orbital 3d_z2 (Y20)', function (th, ph) { return 3 * Math.cos(th) * Math.cos(th) - 1; }, 0x4d8bf0, 52);

    ylm('orbital_dxy', 'Orbital 3d_xy (Y22)', function (th, ph) { return Math.sin(th) * Math.sin(th) * Math.cos(2 * ph); }, 0x9b5de5, 50);

    ylm('orbital_fz3', 'Orbital 4f_z3 (Y30)', function (th, ph) { var c = Math.cos(th); return 5 * c * c * c - 3 * c; }, 0xff8f3f, 52);
})();
