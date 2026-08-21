(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function tt(id, name, n, k, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.22, camZ: camZ || 58, layout: function (d, T) { var pts = [], i, E = []; for (i = 0; i < n; i++) { var a = 2 * PI * i / n; pts.push(new T.Vector3(18 * Math.cos(a), 18 * Math.sin(a), 0)); } for (i = 0; i < n; i++) E.push({ a: pts[i], b: pts[(i + 1) % n], color: color }); for (i = 0; i < n; i++) { var j = (i * k) % n; if (j !== i) E.push({ a: pts[i], b: pts[j], color: color }); } return G.anchorLayout(d, T, pts, E); } }); }

    tt('tt-2', 'Times table x2 (mod 200)', 200, 2, 0x2ec4b6);

    tt('tt-3', 'Times table x3 (mod 200)', 200, 3, 0x4d8bf0);

    tt('tt-4', 'Times table x4 (mod 200)', 200, 4, 0x9b5de5);

    tt('tt-5', 'Times table x5 (mod 220)', 220, 5, 0xff5d8f);

    tt('tt-7', 'Times table x7 (mod 200)', 200, 7, 0xff8f3f);

    tt('tt-9', 'Times table x9 (mod 240)', 240, 9, 0x00d2a0);

    tt('tt-29', 'Times table x29 (mod 200)', 200, 29, 0xffd23f);

    tt('tt-33', 'Times table x33 (mod 200)', 200, 33, 0xff5d6c);
})();
