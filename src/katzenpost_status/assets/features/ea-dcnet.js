(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];

    G.create({
        id: 'dcnet-ring', name: 'Dining cryptographers ring', rotateSpeed: 0.35, camZ: 58, stellate: false,
        layout: function (d, THREE) {
            var cols = G.columns(d), ns = [], ci, j;
            for (ci = 0; ci < cols.length; ci++) for (j = 0; j < cols[ci].length; j++) ns.push(cols[ci][j]);
            (d.nodes || []).forEach(function (n) { if (ns.indexOf(n) < 0) ns.push(n); });
            var n = ns.length, R = 16, nodes = [], pos = [], i;
            if (!n) return { nodes: [], edges: [] };
            for (i = 0; i < n; i++) {
                var a = PI2 * i / n, p = new THREE.Vector3(R * Math.cos(a), R * Math.sin(a), 0);
                nodes.push({ name: ns[i].name, type: ns[i].type, pos: p }); pos.push(p);
            }
            var edges = [];
            for (i = 0; i < n; i++) edges.push({ a: pos[i], b: pos[(i + 1) % n], color: PAL[i % PAL.length] });
            var chord = Math.max(1, Math.floor(n / 3)), half = Math.floor(n / 2);
            for (i = 0; i < chord; i++) {
                var s = (i * n / chord) | 0;
                edges.push({ a: pos[s], b: pos[(s + half) % n], color: 0x8a5bff });
            }
            function spawn() {
                if (n < 2) return null;
                var s = (Math.random() * n) | 0, hops = Math.min(n, 6 + ((Math.random() * n) | 0)), path = [], k;
                for (k = 0; k <= hops; k++) path.push(pos[(s + k) % n]);
                return path.length >= 2 ? path : null;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        }
    });
})();
