(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, ADV = 0xff5d6c;
    var TIER = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0x00d2a0, 0xffd23f, 0x33ccff];
    function hsh(s) { var h = 0, i; for (i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0x7fffffff; return h; }
    function isAdv(name) { return (hsh(name || '') % 100) < 30; }

    G.create({
        id: 'sybil-fraction', name: 'Sybil fraction', rotateSpeed: 0.3, camZ: 62,
        layout: function (d, THREE) {
            var cols = G.columns(d), pos = {}, nodes = [], nc = cols.length, ci;
            for (ci = 0; ci < nc; ci++) {
                var c = cols[ci], x = nc <= 1 ? 0 : -16 + 32 * ci / (nc - 1), m = c.length;
                c.forEach(function (nd, i) {
                    var a = PI2 * i / (m || 1), r = 9 + (i % 2) * 2;
                    var p = new THREE.Vector3(x, r * Math.sin(a), r * Math.cos(a));
                    pos[nd.name] = p; nodes.push({ name: nd.name, type: nd.type, pos: p });
                });
            }
            var edges = [];
            nodes.forEach(function (nd) {
                if (isAdv(nd.name)) {
                    var o = nd.pos.clone(); o.x += 1.2;
                    edges.push({ a: nd.pos, b: o, color: ADV });
                }
            });
            for (ci = 0; ci + 1 < nc; ci++) {
                cols[ci].forEach(function (a) {
                    cols[ci + 1].forEach(function (b) {
                        if (!pos[a.name] || !pos[b.name]) return;
                        var comp = isAdv(a.name) || isAdv(b.name);
                        edges.push({ a: pos[a.name], b: pos[b.name], color: comp ? ADV : TIER[ci % TIER.length] });
                    });
                });
            }
            function spawn() {
                if (nc < 2) return null;
                var path = [], k;
                for (k = 0; k < nc; k++) { var col = cols[k], nm = col[(Math.random() * col.length) | 0].name; if (pos[nm]) path.push(pos[nm]); }
                return path.length >= 2 ? path : null;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        }
    });
})();
