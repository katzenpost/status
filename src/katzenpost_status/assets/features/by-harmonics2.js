(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    function ylm(id, name, fn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.42, camZ: camZ || 50, layout: function (d, THREE) {
            var ur = 44, vr = 64, A = [], idx = {}, E = [], i, j, S = 20;
            for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { var th = i / ur * Math.PI, ph = j / vr * PI2, r = Math.abs(fn(th, ph)) * S; A.push(new THREE.Vector3(r * Math.sin(th) * Math.cos(ph), r * Math.cos(th), r * Math.sin(th) * Math.sin(ph))); idx[i + '_' + j] = A.length - 1; }
            function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); }
            for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); }
            return G.anchorLayout(d, THREE, A, E);
        } });
    }
    function C(a) { return Math.cos(a); } function S(a) { return Math.sin(a); }

    ylm('harm-y31', 'Harmonic Y(3,1)', function (t, p) { return S(t) * (5 * C(t) * C(t) - 1) * C(p); }, 0x2ec4b6, 50);

    ylm('harm-y32', 'Harmonic Y(3,2)', function (t, p) { return S(t) * S(t) * C(t) * C(2 * p); }, 0x4d8bf0, 50);

    ylm('harm-y40', 'Harmonic Y(4,0)', function (t, p) { var c = C(t); return 35 * Math.pow(c, 4) - 30 * c * c + 3; }, 0x9b5de5, 52);

    ylm('harm-y42', 'Harmonic Y(4,2)', function (t, p) { return S(t) * S(t) * (7 * C(t) * C(t) - 1) * C(2 * p); }, 0xff8f3f, 50);

    ylm('harm-y44', 'Harmonic Y(4,4)', function (t, p) { return Math.pow(S(t), 4) * C(4 * p); }, 0xff5d8f, 50);

    ylm('harm-y50', 'Harmonic Y(5,0)', function (t, p) { var c = C(t); return 63 * Math.pow(c, 5) - 70 * Math.pow(c, 3) + 15 * c; }, 0x00d2a0, 52);

    ylm('harm-y53', 'Harmonic Y(5,3)', function (t, p) { return Math.pow(S(t), 3) * (9 * C(t) * C(t) - 1) * C(3 * p); }, 0xffd23f, 50);

    ylm('harm-y55', 'Harmonic Y(5,5)', function (t, p) { return Math.pow(S(t), 5) * C(5 * p); }, 0x4d8bf0, 50);
})();
