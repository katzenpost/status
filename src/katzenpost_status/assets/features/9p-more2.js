(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    // 64-tetrahedron grid (isotropic vector matrix): the FCC lattice, whose
    // nearest-neighbour bonds tile space with tetrahedra and octahedra.
    G.create({
        id: 'ivm64', name: '64-tetrahedron grid', rotateSpeed: 0.4, camZ: 62,
        layout: function (d, THREE) {
            var S = 6, pts = [], x, y, z, i, j;
            for (x = -2; x <= 2; x++) for (y = -2; y <= 2; y++) for (z = -2; z <= 2; z++) {
                if (((x + y + z) & 1) === 0 && x * x + y * y + z * z <= 6) pts.push(new THREE.Vector3(x * S, y * S, z * S));
            }
            var edges = [], nn = Math.SQRT2 * S;
            for (i = 0; i < pts.length; i++) for (j = i + 1; j < pts.length; j++) if (Math.abs(pts[i].distanceTo(pts[j]) - nn) < 0.4 * S) edges.push({ a: pts[i], b: pts[j], color: 0xffb454 });
            return G.anchorLayout(d, THREE, pts, edges);
        }
    });

    function uniqueVerts(geo, THREE) {
        var pos = geo.attributes.position, seen = {}, out = [], i;
        for (i = 0; i < pos.count; i++) {
            var v = new THREE.Vector3().fromBufferAttribute(pos, i), k = Math.round(v.x * 40) + ',' + Math.round(v.y * 40) + ',' + Math.round(v.z * 40);
            if (!seen[k]) { seen[k] = 1; out.push(v); }
        }
        return out;
    }
    function geoEdges(geo, THREE, color) {
        var eg = new THREE.EdgesGeometry(geo, 1), ep = eg.attributes.position, edges = [], i;
        for (i = 0; i < ep.count; i += 2) edges.push({ a: new THREE.Vector3().fromBufferAttribute(ep, i), b: new THREE.Vector3().fromBufferAttribute(ep, i + 1), color: color });
        eg.dispose();
        return edges;
    }

    // Stellated dodecahedron: a dodecahedron spiked along its dual directions.
    G.create({
        id: 'stellateddodec', name: 'Stellated dodecahedron', rotateSpeed: 0.42, camZ: 66,
        layout: function (d, THREE) {
            var dg = new THREE.DodecahedronGeometry(15), dv = uniqueVerts(dg, THREE), edges = geoEdges(dg, THREE, 0x9b5de5); dg.dispose();
            var ig = new THREE.IcosahedronGeometry(1), iv = uniqueVerts(ig, THREE); ig.dispose();
            var anchors = dv.slice();
            iv.forEach(function (dir) {
                var sp = dir.clone().normalize().multiplyScalar(26); anchors.push(sp);
                var d5 = dv.map(function (v, i) { return [v.distanceTo(sp), i]; }).sort(function (a, b) { return a[0] - b[0]; }).slice(0, 5);
                d5.forEach(function (pr) { edges.push({ a: sp, b: dv[pr[1]], color: 0xffd23f }); });
            });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });

    // Penrose tiling (P3): fat and thin rhombi from Robinson-triangle deflation.
    G.create({
        id: 'penrose', name: 'Penrose tiling', rotateSpeed: 0.25, camZ: 58,
        layout: function (d, THREE) {
            var phi = (1 + Math.sqrt(5)) / 2;
            function cx(a, b) { return { re: a.re + b.re, im: a.im + b.im }; }
            function sub(a, b) { return { re: a.re - b.re, im: a.im - b.im }; }
            function div(a, s) { return { re: a.re / s, im: a.im / s }; }
            function lerp(a, b) { return cx(a, div(sub(b, a), phi)); }   // a + (b-a)/phi
            var tris = [], i, S = 26;
            for (i = 0; i < 10; i++) {
                var b = { re: Math.cos((2 * i - 1) * Math.PI / 10) * S, im: Math.sin((2 * i - 1) * Math.PI / 10) * S };
                var c = { re: Math.cos((2 * i + 1) * Math.PI / 10) * S, im: Math.sin((2 * i + 1) * Math.PI / 10) * S };
                if (i % 2 === 0) { var t = b; b = c; c = t; }
                tris.push([0, { re: 0, im: 0 }, b, c]);
            }
            for (var g = 0; g < 5; g++) {
                var next = [];
                tris.forEach(function (tr) {
                    var col = tr[0], A = tr[1], B = tr[2], C = tr[3];
                    if (col === 0) { var P = lerp(A, B); next.push([0, C, P, B], [1, P, C, A]); }
                    else { var Q = lerp(B, A), R = lerp(B, C); next.push([1, R, C, A], [1, Q, R, B], [0, R, Q, A]); }
                });
                tris = next;
            }
            var seen = {}, edges = [], anchors = [], anchSeen = {};
            function push(p, q) {
                var k = Math.round(p.re * 8) + ',' + Math.round(p.im * 8) + '|' + Math.round(q.re * 8) + ',' + Math.round(q.im * 8);
                var k2 = Math.round(q.re * 8) + ',' + Math.round(q.im * 8) + '|' + Math.round(p.re * 8) + ',' + Math.round(p.im * 8);
                if (seen[k] || seen[k2]) return; seen[k] = 1;
                edges.push({ a: new THREE.Vector3(p.re, p.im, 0), b: new THREE.Vector3(q.re, q.im, 0), color: 0x4d8bf0 });
            }
            function anch(p) { var k = Math.round(p.re * 8) + ',' + Math.round(p.im * 8); if (anchSeen[k]) return; anchSeen[k] = 1; anchors.push(new THREE.Vector3(p.re, p.im, 0)); }
            tris.forEach(function (tr) { var A = tr[1], B = tr[2], C = tr[3]; push(A, B); push(A, C); push(B, C); anch(A); anch(B); anch(C); });
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });

    // Chladni figure (cymatics): the nodal lines of a vibrating square plate,
    // traced by marching squares. Packets ride the standing-wave nodes.
    G.create({
        id: 'chladni', name: 'Chladni figure', rotateSpeed: 0.2, camZ: 52,
        layout: function (d, THREE) {
            var n = 4, m = 3, N = 60, S = 44, edges = [], anchors = [], anchSeen = {};
            function f(u, v) { return Math.cos(n * Math.PI * u) * Math.cos(m * Math.PI * v) - Math.cos(m * Math.PI * u) * Math.cos(n * Math.PI * v); }
            function XY(u, v) { return new THREE.Vector3((u - 0.5) * S, (v - 0.5) * S, 0); }
            function anch(p) { var k = Math.round(p.x) + ',' + Math.round(p.y); if (anchSeen[k]) return; anchSeen[k] = 1; anchors.push(p); }
            var i, j;
            for (i = 0; i < N; i++) for (j = 0; j < N; j++) {
                var u0 = i / N, u1 = (i + 1) / N, v0 = j / N, v1 = (j + 1) / N;
                var f00 = f(u0, v0), f10 = f(u1, v0), f11 = f(u1, v1), f01 = f(u0, v1), cross = [];
                if ((f00 < 0) !== (f10 < 0)) cross.push(XY(u0 + (u1 - u0) * (f00 / (f00 - f10)), v0));
                if ((f10 < 0) !== (f11 < 0)) cross.push(XY(u1, v0 + (v1 - v0) * (f10 / (f10 - f11))));
                if ((f11 < 0) !== (f01 < 0)) cross.push(XY(u1 + (u0 - u1) * (f11 / (f11 - f01)), v1));
                if ((f01 < 0) !== (f00 < 0)) cross.push(XY(u0, v1 + (v0 - v1) * (f01 / (f01 - f00))));
                if (cross.length >= 2) { edges.push({ a: cross[0], b: cross[1], color: 0x2ec4b6 }); anch(cross[0]); anch(cross[1]); if (cross.length === 4) { edges.push({ a: cross[2], b: cross[3], color: 0x2ec4b6 }); anch(cross[2]); anch(cross[3]); } }
            }
            return G.anchorLayout(d, THREE, anchors, edges);
        }
    });
})();
