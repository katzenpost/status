(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    G.create({
        id: 'brownian-lattice', name: 'Brownian lattice walk', rotateSpeed: 0.3, camZ: 60,
        layout: function (d, THREE) {
            var seed = 1337, step = 1.1, N = 280, cap = 20;
            function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }
            var x = 0, y = 0, z = 0, pts = [new THREE.Vector3(0, 0, 0)], i, bias = 0.63;
            for (i = 0; i < N; i++) {
                var ax = (rnd() * 3) | 0, dir = (rnd() < bias) ? 1 : -1;
                var nx = x, ny = y, nz = z;
                if (ax === 0) nx = x + dir * step; else if (ax === 1) ny = y + dir * step; else nz = z + dir * step;
                if (nx > cap || nx < -cap) nx = x - dir * step;
                if (ny > cap || ny < -cap) ny = y - dir * step;
                if (nz > cap || nz < -cap) nz = z - dir * step;
                x = nx; y = ny; z = nz;
                pts.push(new THREE.Vector3(x, y, z));
            }
            return G.curveLayout(d, THREE, pts, 0x00d2a0);
        }
    });
})();
