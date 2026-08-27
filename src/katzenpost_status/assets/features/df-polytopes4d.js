(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function fit(v) {
        var i, mx = 1e-6, cx = 0, cy = 0, cz = 0;
        for (i = 0; i < v.length; i++) { cx += v[i].x; cy += v[i].y; cz += v[i].z; }
        cx /= v.length; cy /= v.length; cz /= v.length;
        for (i = 0; i < v.length; i++) { v[i].x -= cx; v[i].y -= cy; v[i].z -= cz; mx = Math.max(mx, Math.abs(v[i].x), Math.abs(v[i].y), Math.abs(v[i].z)); }
        var s = 18 / mx; for (i = 0; i < v.length; i++) { v[i].x *= s; v[i].y *= s; v[i].z *= s; }
    }
    // Stereographic-like projection of S^3 (from a point just outside) to R^3.
    function proj(q, THREE) { var w = 1.05 - q[3]; return new THREE.Vector3(q[0] / w, q[1] / w, q[2] / w); }
    // Hopf fibres: each base (eta,phi) lifts to a circle on S^3, projected to a
    // (possibly linked) circle in R^3. Bases coloured distinctly.
    function hopf(id, name, bases, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 60, layout: function (d, THREE) {
            var nt = 90, v = [], edges = [], bi, ti;
            for (bi = 0; bi < bases.length; bi++) {
                var eta = bases[bi][0], ph = bases[bi][1], ce = Math.cos(eta), se = Math.sin(eta), col = PAL[bi % PAL.length], base = v.length;
                for (ti = 0; ti < nt; ti++) { var t = 2 * Math.PI * ti / nt; v.push(proj([ce * Math.cos(t), ce * Math.sin(t), se * Math.cos(t + ph), se * Math.sin(t + ph)], THREE)); }
                for (ti = 0; ti < nt; ti++) edges.push({ a: v[base + ti], b: v[base + (ti + 1) % nt], color: col });
            }
            fit(v);
            return G.anchorLayout(d, THREE, v, edges);
        } });
    }
    // Nested Clifford tori on S^3 at several eta latitudes, projected to R^3.
    function cliffordNest(id, name, etas, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.28, camZ: camZ || 60, layout: function (d, THREE) {
            var nt = 40, ns = 24, v = [], edges = [], e, iu, iv;
            for (e = 0; e < etas.length; e++) {
                var eta = etas[e], ce = Math.cos(eta), se = Math.sin(eta), col = PAL[e % PAL.length], base = v.length;
                for (iu = 0; iu < nt; iu++) for (iv = 0; iv < ns; iv++) { var t = 2 * Math.PI * iu / nt, s = 2 * Math.PI * iv / ns; v.push(proj([ce * Math.cos(t), ce * Math.sin(t), se * Math.cos(s), se * Math.sin(s)], THREE)); }
                function gi(a, b) { return base + a * ns + b; }
                for (iu = 0; iu < nt; iu++) for (iv = 0; iv < ns; iv++) { edges.push({ a: v[gi(iu, iv)], b: v[gi((iu + 1) % nt, iv)], color: col }); edges.push({ a: v[gi(iu, iv)], b: v[gi(iu, (iv + 1) % ns)], color: col }); }
            }
            fit(v);
            return G.anchorLayout(d, THREE, v, edges);
        } });
    }
    // (m,n) duoprism: product of an m-gon and an n-gon in 4D, 4D-rotated then
    // perspective-projected to 3D. Ring edges coloured by which factor they close.
    function duoprism(id, name, m, n, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.34, camZ: camZ || 60, layout: function (d, THREE) {
            var v = [], edges = [], i, j, ax = 0.9, ay = 0.5, ca = Math.cos(ax), sa = Math.sin(ax), cb = Math.cos(ay), sb = Math.sin(ay);
            function P(i, j) {
                var x = Math.cos(2 * Math.PI * i / m), y = Math.sin(2 * Math.PI * i / m), z = Math.cos(2 * Math.PI * j / n), w = Math.sin(2 * Math.PI * j / n);
                var x2 = x * ca - w * sa, w2 = x * sa + w * ca, y2 = y * cb - z * sb, z2 = y * sb + z * cb;
                var dv = 2.6 - w2; return new THREE.Vector3(x2 / dv, y2 / dv, z2 / dv);
            }
            var grid = [];
            for (i = 0; i < m; i++) { grid[i] = []; for (j = 0; j < n; j++) { grid[i][j] = v.length; v.push(P(i, j)); } }
            for (i = 0; i < m; i++) for (j = 0; j < n; j++) {
                edges.push({ a: v[grid[i][j]], b: v[grid[(i + 1) % m][j]], color: PAL[j % PAL.length] });
                edges.push({ a: v[grid[i][j]], b: v[grid[i][(j + 1) % n]], color: PAL[i % PAL.length] });
            }
            fit(v);
            return G.anchorLayout(d, THREE, v, edges);
        } });
    }
    function ring(nEta, nPh) { var b = [], i, j; for (i = 0; i < nEta; i++) for (j = 0; j < nPh; j++) b.push([0.35 + (i + 1) / (nEta + 1) * 0.9, 2 * Math.PI * j / nPh]); return b; }

    hopf('p4-hopf-fibration', 'Hopf fibration (base grid)', ring(3, 8), 60);

    hopf('p4-hopf-torus', 'Hopf fibres over one latitude', (function () { var b = [], j; for (j = 0; j < 24; j++) b.push([0.9, 2 * Math.PI * j / 24]); return b; })(), 60);

    hopf('p4-hopf-linked', 'Hopf fibres (linking)', [[0.4, 0], [0.7, 1.4], [1.0, 2.8], [1.2, 4.2], [0.55, 5.4]], 60);

    hopf('p4-hopf-spiral', 'Hopf fibres over a spiral', (function () { var b = [], j; for (j = 0; j < 28; j++) b.push([0.25 + 1.1 * j / 28, 2 * Math.PI * j * 3 / 28]); return b; })(), 60);

    hopf('p4-hopf-hexbase', 'Hopf fibres (hex base)', (function () { var b = [[0.5, 0]], i; for (i = 0; i < 6; i++) b.push([1.0, 2 * Math.PI * i / 6]); for (i = 0; i < 6; i++) b.push([0.75, 2 * Math.PI * (i + 0.5) / 6]); return b; })(), 60);

    cliffordNest('p4-cliffordnest', 'Nested Clifford tori', [0.5, 0.785, 1.05], 60);
})();
