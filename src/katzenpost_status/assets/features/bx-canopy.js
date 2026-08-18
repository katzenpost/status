(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    // Recursive fractal canopy in the plane (stellated into 3D by the factory).
    function canopy(id, name, angs, ratio, depth, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 58, layout: function (d, T) {
            var a = [], e = [];
            function grow(x, y, dir, len, dep) {
                var nx = x + Math.cos(dir) * len, ny = y + Math.sin(dir) * len;
                e.push({ a: new T.Vector3(x, y, 0), b: new T.Vector3(nx, ny, 0), color: color }); a.push(new T.Vector3(nx, ny, 0));
                if (dep <= 0) return;
                for (var i = 0; i < angs.length; i++) grow(nx, ny, dir + angs[i], len * ratio, dep - 1);
            }
            a.push(new T.Vector3(0, -20, 0));
            grow(0, -20, Math.PI / 2, 12, depth);
            return G.anchorLayout(d, T, a, e);
        } });
    }
    var D = Math.PI / 180;

    canopy('canopy-binary30', 'Binary canopy (30 deg)', [30 * D, -30 * D], 0.75, 9, 0x2ec4b6, 58);

    canopy('canopy-binary45', 'Binary canopy (45 deg)', [45 * D, -45 * D], 0.72, 9, 0x4d8bf0, 58);

    canopy('canopy-ternary', 'Ternary canopy', [40 * D, 0, -40 * D], 0.62, 7, 0x9b5de5, 58);

    canopy('canopy-asymmetric', 'Asymmetric canopy', [20 * D, -50 * D], 0.76, 9, 0xff8f3f, 58);

    canopy('canopy-pine', 'Pine canopy (narrow)', [15 * D, -15 * D], 0.8, 9, 0x00d2a0, 58);

    canopy('canopy-fan', 'Fan canopy (wide)', [65 * D, -65 * D], 0.68, 8, 0xff5d8f, 58);

    canopy('canopy-quaternary', 'Quaternary canopy', [50 * D, 18 * D, -18 * D, -50 * D], 0.56, 6, 0xffd23f, 58);

    canopy('canopy-sympodial', 'Sympodial canopy', [12 * D, -55 * D, 55 * D], 0.66, 7, 0x4d8bf0, 58);

    canopy('canopy-windswept', 'Windswept canopy', [55 * D, 10 * D], 0.74, 9, 0x9b5de5, 58);

    canopy('canopy-bushy', 'Bushy canopy', [35 * D, 12 * D, -12 * D, -35 * D], 0.6, 6, 0x2ec4b6, 58);
})();
