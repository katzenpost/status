(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI;
    function fit(A, R) { var i, n = A.length, cx = 0, cy = 0, cz = 0; for (i = 0; i < n; i++) { cx += A[i].x; cy += A[i].y; cz += A[i].z; } cx /= n; cy /= n; cz /= n; var mx = 1e-9; for (i = 0; i < n; i++) { A[i].x -= cx; A[i].y -= cy; A[i].z -= cz; mx = Math.max(mx, Math.abs(A[i].x), Math.abs(A[i].y), Math.abs(A[i].z)); } var s = R / mx; for (i = 0; i < n; i++) { A[i].x *= s; A[i].y *= s; A[i].z *= s; } return A; }
    function phy(id, name, n, c, lift, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 60, layout: function (d, T) { var pts = [], i, E = [], GA = PI * (3 - Math.sqrt(5)); for (i = 0; i < n; i++) { var r = c * Math.sqrt(i), a = i * GA; pts.push(new T.Vector3(r * Math.cos(a), r * Math.sin(a), lift(r))); } fit(pts, 18); for (i = 0; i < n - 1; i++) E.push({ a: pts[i], b: pts[i + 1], color: color }); for (i = 0; i + 8 < n; i++) E.push({ a: pts[i], b: pts[i + 8], color: color }); for (i = 0; i + 13 < n; i++) E.push({ a: pts[i], b: pts[i + 13], color: color }); return G.anchorLayout(d, T, pts, E); } }); }

    phy('phy-disc', 'Phyllotaxis disc', 700, 0.9, function (r) { return 0; }, 0x2ec4b6);

    phy('phy-daisy', 'Phyllotaxis daisy', 900, 0.8, function (r) { return 0; }, 0x4d8bf0);

    phy('phy-dome', 'Phyllotaxis dome', 700, 0.9, function (r) { return 8 - r * r * 0.02; }, 0x9b5de5);

    phy('phy-cone', 'Phyllotaxis cone', 700, 0.9, function (r) { return r * 0.6; }, 0xff5d8f);

    phy('phy-wave', 'Phyllotaxis wave', 700, 0.9, function (r) { return 4 * Math.sin(r * 0.5); }, 0xff8f3f);
})();
