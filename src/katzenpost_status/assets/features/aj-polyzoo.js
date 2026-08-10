(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, THREE = K.THREE, PI2 = Math.PI * 2;

    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.5, camZ: camZ || 54, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function ngon(z, r, n, rot) { var p = []; for (var i = 0; i < n; i++) { var t = rot + i / n * PI2; p.push(new THREE.Vector3(Math.cos(t) * r, z, Math.sin(t) * r)); } return p; }
    function ring(a, e, pts, color) { for (var i = 0; i < pts.length; i++) { a.push(pts[i]); e.push({ a: pts[i], b: pts[(i + 1) % pts.length], color: color }); } }
    function fromGeo(geo, color) { var eg = new THREE.EdgesGeometry(geo, 1), ep = eg.attributes.position, e = [], a = [], seen = {}, i; var pos = geo.attributes.position; for (i = 0; i < pos.count; i++) { var v = new THREE.Vector3().fromBufferAttribute(pos, i), k = Math.round(v.x * 40) + ',' + Math.round(v.y * 40) + ',' + Math.round(v.z * 40); if (!seen[k]) { seen[k] = 1; a.push(v); } } for (i = 0; i < ep.count; i += 2) e.push({ a: new THREE.Vector3().fromBufferAttribute(ep, i), b: new THREE.Vector3().fromBufferAttribute(ep, i + 1), color: color }); eg.dispose(); return { a: a, e: e }; }

    ae('pentantiprism', 'Pentagonal antiprism', function (a, e, T, color) { var n = 5, R = 14, h = 7, top = ngon(h, R, n, 0), bot = ngon(-h, R, n, Math.PI / n); ring(a, e, top, color); ring(a, e, bot, color); for (var i = 0; i < n; i++) { e.push({ a: top[i], b: bot[i], color: color }); e.push({ a: top[i], b: bot[(i + n - 1) % n], color: color }); } }, 0x2ec4b6, 52);

    ae('hexantiprism', 'Hexagonal antiprism', function (a, e, T, color) { var n = 6, R = 14, h = 7, top = ngon(h, R, n, 0), bot = ngon(-h, R, n, Math.PI / n); ring(a, e, top, color); ring(a, e, bot, color); for (var i = 0; i < n; i++) { e.push({ a: top[i], b: bot[i], color: color }); e.push({ a: top[i], b: bot[(i + n - 1) % n], color: color }); } }, 0x4d8bf0, 52);

    ae('gyrobipyramid', 'Gyroelongated bipyramid', function (a, e, T, color) { var n = 5, R = 13, h = 6, top = ngon(h, R, n, 0), bot = ngon(-h, R, n, Math.PI / n); ring(a, e, top, color); ring(a, e, bot, color); var apT = new T.Vector3(0, h + 12, 0), apB = new T.Vector3(0, -h - 12, 0); a.push(apT); a.push(apB); for (var i = 0; i < n; i++) { e.push({ a: top[i], b: bot[i], color: color }); e.push({ a: top[i], b: bot[(i + n - 1) % n], color: color }); e.push({ a: apT, b: top[i], color: color }); e.push({ a: apB, b: bot[i], color: color }); } }, 0x9b5de5, 54);

    ae('elongpyramid', 'Elongated square pyramid (J8)', function (a, e, T, color) { var R = 11, top = ngon(6, R, 4, Math.PI / 4), bot = ngon(-6, R, 4, Math.PI / 4); ring(a, e, top, color); ring(a, e, bot, color); var ap = new T.Vector3(0, 18, 0); a.push(ap); for (var i = 0; i < 4; i++) { e.push({ a: top[i], b: bot[i], color: color }); e.push({ a: ap, b: top[i], color: color }); } }, 0xff8f3f, 54);

    G.create({ id: 'geodesicdome3', name: 'Geodesic dome (freq 3)', rotateSpeed: 0.45, camZ: 54, layout: function (d, T) { var g = new THREE.IcosahedronGeometry(18, 3), pe = fromGeo(g, 0x00d2a0); g.dispose(); return G.anchorLayout(d, T, pe.a, pe.e); } });

    ae('schwarzlantern', 'Schwarz lantern', function (a, e, T, color) { var n = 12, rows = 8, R = 13, H = 30, i, r; var rings = []; for (r = 0; r <= rows; r++) { rings.push(ngon(-H / 2 + H * r / rows, R, n, (r & 1) ? Math.PI / n : 0)); } for (r = 0; r <= rows; r++) ring(a, e, rings[r], color); for (r = 0; r < rows; r++) for (i = 0; i < n; i++) { e.push({ a: rings[r][i], b: rings[r + 1][i], color: color }); e.push({ a: rings[r][i], b: rings[r + 1][(i + ((r & 1) ? 0 : n - 1)) % n], color: color }); } }, 0xff5d8f, 56);
})();
