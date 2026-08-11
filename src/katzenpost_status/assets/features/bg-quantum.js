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

    ylm('orbital_f33', 'Orbital 4f (Y33)', function (th, ph) { var s = Math.sin(th); return s * s * s * Math.cos(3 * ph); }, 0xff5d8f, 50);

    ylm('harmonic_y21', 'Harmonic Y21', function (th, ph) { return Math.sin(th) * Math.cos(th) * Math.cos(ph); }, 0x00d2a0, 50);

    ylm('harmonic_y43', 'Harmonic Y43', function (th, ph) { var s = Math.sin(th), c = Math.cos(th); return s * s * s * c * Math.cos(3 * ph); }, 0xffd23f, 50);

    surf('besseldrum', 'Bessel drum mode', function (u, v, T) { var r = u * 20, th = v * PI2, z = besselish(r * 0.8) * Math.cos(3 * th) * 30; return new T.Vector3(r * Math.cos(th), z, r * Math.sin(th)); }, 40, 60, 0x4d8bf0, 58);

    surf('wavepacket', 'Gaussian wave packet', function (u, v, T) { var x = (u - 0.5) * 40, y = (v - 0.5) * 40, r2 = (x * x + y * y) / 120, z = Math.exp(-r2) * Math.cos(Math.sqrt(x * x + y * y) * 0.8) * 14; return new T.Vector3(x, y, z); }, 46, 46, 0x9b5de5, 60);

    ae('blochsphere', 'Bloch sphere', function (a, e, T, color) { var R = 18, i, j, M = 12; function P(la, lo) { return new T.Vector3(R * Math.cos(la) * Math.cos(lo), R * Math.sin(la), R * Math.cos(la) * Math.sin(lo)); } for (i = 1; i < M; i++) { var la = -Math.PI / 2 + Math.PI * i / M, prev = null; for (j = 0; j <= M * 2; j++) { var p = P(la, j / (M * 2) * PI2); if (prev) e.push({ a: prev, b: p, color: color }); if (j % 3 === 0) a.push(p); prev = p; } } for (j = 0; j < M * 2; j++) { var lo = j / (M * 2) * PI2, prev2 = null; for (i = 0; i <= M; i++) { var p2 = P(-Math.PI / 2 + Math.PI * i / M, lo); if (prev2) e.push({ a: prev2, b: p2, color: color }); prev2 = p2; } } var st = P(0.9, 0.8); a.push(st); e.push({ a: new T.Vector3(0, 0, 0), b: st, color: 0xffd23f }); }, 0x2ec4b6, 54);
})();
