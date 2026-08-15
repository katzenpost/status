(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, THREE = K.THREE, PHI = (1 + Math.sqrt(5)) / 2;
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.32, camZ: camZ || 58, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function circle(a, e, T, cx, cy, cz, R, segs, color, axis) { var prev = null, first = null; for (var s = 0; s <= segs; s++) { var t = s / segs * PI2, c = Math.cos(t) * R, si = Math.sin(t) * R, p; if (axis === 1) p = new T.Vector3(cx, cy + c, cz + si); else p = new T.Vector3(cx + c, cy + si, cz); if (s % 3 === 0) a.push(p); if (prev) e.push({ a: prev, b: p, color: color }); else first = p; prev = p; } }
    function geoVE(g, a, e, color, scale) { var eg = new THREE.EdgesGeometry(g, 1), ep = eg.attributes.position, i; for (i = 0; i < ep.count; i += 2) { var p1 = new THREE.Vector3().fromBufferAttribute(ep, i).multiplyScalar(scale || 1), p2 = new THREE.Vector3().fromBufferAttribute(ep, i + 1).multiplyScalar(scale || 1); e.push({ a: p1, b: p2, color: color }); if (i % 6 === 0) a.push(p1); } eg.dispose(); }

    ae('eggoflife', 'Egg of Life', function (a, e, T, color) { var R = 6, i; circle(a, e, T, 0, 0, 0, R, 44, color); for (i = 0; i < 6; i++) { var an = i * Math.PI / 3; circle(a, e, T, Math.cos(an) * R, Math.sin(an) * R, 0, R, 44, color); } }, 0x2ec4b6, 54);

    ae('genesispattern', 'Genesis pattern', function (a, e, T, color) { var R = 7, i; circle(a, e, T, 0, 0, 0, R, 48, color); for (i = 0; i < 6; i++) { var an = i * Math.PI / 3; circle(a, e, T, Math.cos(an) * R, Math.sin(an) * R, 0, R, 48, [0x4d8bf0, 0x9b5de5, 0xff8f3f, 0xff5d8f, 0x00d2a0, 0xffd23f][i]); } }, 0x2ec4b6, 56);

    ae('floweroflife3d', 'Flower of Life (3D)', function (a, e, T, color) { var R = 5, S3 = Math.sqrt(3), zl = [-3, 0, 3], k; zl.forEach(function (z, zi) { var col = [0x4d8bf0, 0x2ec4b6, 0x9b5de5][zi]; circle(a, e, T, 0, 0, z, R, 36, col); for (k = 0; k < 6; k++) { var an = k * Math.PI / 3; circle(a, e, T, Math.cos(an) * R, Math.sin(an) * R, z, R, 36, col); } }); }, 0x2ec4b6, 58);

    ae('metatron3d', 'Metatron cube (3D)', function (a, e, T, color) { var base = [[1, 1, 0], [1, -1, 0], [-1, 1, 0], [-1, -1, 0], [1, 0, 1], [1, 0, -1], [-1, 0, 1], [-1, 0, -1], [0, 1, 1], [0, 1, -1], [0, -1, 1], [0, -1, -1], [0, 0, 0]]; var V = base.map(function (b) { return new T.Vector3(b[0] * 12, b[1] * 12, b[2] * 12); }); V.forEach(function (v) { a.push(v); }); for (var i = 0; i < V.length; i++) for (var j = i + 1; j < V.length; j++) e.push({ a: V[i], b: V[j], color: color }); }, 0x9b5de5, 56);

    ae('merkabanested', 'Merkaba (nested stars)', function (a, e, T, color) { [10, 16].forEach(function (S, si) { var col = si ? 0xffd23f : 0x4d8bf0; var tA = [[1, 1, 1], [1, -1, -1], [-1, 1, -1], [-1, -1, 1]], tB = [[-1, -1, -1], [-1, 1, 1], [1, -1, 1], [1, 1, -1]]; [tA, tB].forEach(function (t, ti) { var P = t.map(function (b) { return new T.Vector3(b[0] * S, b[1] * S, b[2] * S); }); for (var i = 0; i < 4; i++) for (var j = i + 1; j < 4; j++) e.push({ a: P[i], b: P[j], color: ti ? col : (si ? 0xff8f3f : 0x00d2a0) }); P.forEach(function (p) { a.push(p); }); }); }); }, 0x4d8bf0, 56);

    ae('sriyantra3d', 'Sri Yantra (3D)', function (a, e, T, color) { function tri(sc, up, z, col) { var P = [], i; for (i = 0; i < 3; i++) { var an = (up ? -Math.PI / 2 : Math.PI / 2) + i * PI2 / 3; P.push(new T.Vector3(Math.cos(an) * sc, Math.sin(an) * sc, z)); } for (i = 0; i < 3; i++) { e.push({ a: P[i], b: P[(i + 1) % 3], color: col }); a.push(P[i]); } } [20, 15, 10].forEach(function (s, i) { tri(s, true, i * 2.5, 0xffd23f); }); [22, 16, 11, 7].forEach(function (s, i) { tri(s, false, -i * 2.5, 0xff5d8f); }); }, 0xffd23f, 58);
})();
