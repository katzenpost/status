(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function knn(pts, cols, k) {
        var edges = [], seen = {}, i, j, m;
        for (i = 0; i < pts.length; i++) {
            var ds = [];
            for (j = 0; j < pts.length; j++) if (j !== i) ds.push([pts[i].distanceToSquared(pts[j]), j]);
            ds.sort(function (a, b) { return a[0] - b[0]; });
            for (m = 0; m < k && m < ds.length; m++) { var jj = ds[m][1], key = Math.min(i, jj) + '_' + Math.max(i, jj); if (!seen[key]) { seen[key] = 1; edges.push({ a: pts[i], b: pts[jj], color: cols[i] }); } }
        }
        return edges;
    }
    // Sample the zero level set of a triply-periodic implicit F(x,y,z) over ~1.2
    // periods: a cell that straddles F=0 with a neighbour is a surface point.
    // Colour by octant so the interwoven networks separate.
    function tpms(id, name, F, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.24, camZ: camZ || 60, layout: function (d, THREE) {
            var n = 30, PER = Math.PI * 1.2, i, jx, jy, jz, val = new Float32Array(n * n * n);
            var ang = []; for (i = 0; i < n; i++) ang.push(-PER + 2 * PER * i / (n - 1));
            function id3(a, b, c) { return (a * n + b) * n + c; }
            for (jx = 0; jx < n; jx++) for (jy = 0; jy < n; jy++) for (jz = 0; jz < n; jz++) val[id3(jx, jy, jz)] = F(ang[jx], ang[jy], ang[jz]);
            var raw = [];
            for (jx = 0; jx < n - 1; jx++) for (jy = 0; jy < n - 1; jy++) for (jz = 0; jz < n - 1; jz++) {
                var v0 = val[id3(jx, jy, jz)];
                if (v0 * val[id3(jx + 1, jy, jz)] < 0 || v0 * val[id3(jx, jy + 1, jz)] < 0 || v0 * val[id3(jx, jy, jz + 1)] < 0) raw.push([jx, jy, jz]);
            }
            var stride = Math.max(1, Math.ceil(raw.length / 490)), pts = [], cols = [];
            for (i = 0; i < raw.length; i += stride) {
                var e = raw[i], x = ang[e[0]] / PER * 18, y = ang[e[1]] / PER * 18, z = ang[e[2]] / PER * 18;
                pts.push(new THREE.Vector3(x, y, z));
                cols.push(PAL[(((e[0] & 1) << 2) | ((e[1] & 1) << 1) | (e[2] & 1)) % PAL.length]);
            }
            if (pts.length < 8) { pts = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; cols = [PAL[0], PAL[0]]; }
            return G.anchorLayout(d, THREE, pts, knn(pts, cols, 3));
        } });
    }
    function GY(x, y, z) { return Math.cos(x) * Math.sin(y) + Math.cos(y) * Math.sin(z) + Math.cos(z) * Math.sin(x); }
    function PP(x, y, z) { return Math.cos(x) + Math.cos(y) + Math.cos(z); }
    function DD(x, y, z) { return Math.sin(x) * Math.sin(y) * Math.sin(z) + Math.sin(x) * Math.cos(y) * Math.cos(z) + Math.cos(x) * Math.sin(y) * Math.cos(z) + Math.cos(x) * Math.cos(y) * Math.sin(z); }
    function IWP(x, y, z) { return 2 * (Math.cos(x) * Math.cos(y) + Math.cos(y) * Math.cos(z) + Math.cos(z) * Math.cos(x)) - (Math.cos(2 * x) + Math.cos(2 * y) + Math.cos(2 * z)); }
    function NEO(x, y, z) { return 3 * (Math.cos(x) + Math.cos(y) + Math.cos(z)) + 4 * Math.cos(x) * Math.cos(y) * Math.cos(z); }

    tpms('tp-frd', 'Schoen F-RD surface', function (x, y, z) { return 4 * Math.cos(x) * Math.cos(y) * Math.cos(z) - (Math.cos(2 * x) * Math.cos(2 * y) + Math.cos(2 * y) * Math.cos(2 * z) + Math.cos(2 * z) * Math.cos(2 * x)); }, 60);

    tpms('tp-lidinoid', 'Lidinoid surface', function (x, y, z) { return 0.5 * (Math.sin(2 * x) * Math.cos(y) * Math.sin(z) + Math.sin(2 * y) * Math.cos(z) * Math.sin(x) + Math.sin(2 * z) * Math.cos(x) * Math.sin(y)) - 0.5 * (Math.cos(2 * x) * Math.cos(2 * y) + Math.cos(2 * y) * Math.cos(2 * z) + Math.cos(2 * z) * Math.cos(2 * x)) + 0.15; }, 60);

    tpms('tp-doublegyroid', 'Double gyroid', function (x, y, z) { var g = GY(x, y, z); return g * g - 0.4; }, 60);

    tpms('tp-doublediamond', 'Double diamond', function (x, y, z) { var s = DD(x, y, z); return s * s - 0.5; }, 60);

    tpms('tp-doubleprimitive', 'Double primitive', function (x, y, z) { var p = PP(x, y, z); return p * p - 1.0; }, 60);

    tpms('tp-doubleiwp', 'Double I-WP', function (x, y, z) { var w = IWP(x, y, z); return w * w - 2.0; }, 60);

    tpms('tp-doubleneovius', 'Double Neovius', function (x, y, z) { var v = NEO(x, y, z); return v * v - 3.0; }, 60);
})();
