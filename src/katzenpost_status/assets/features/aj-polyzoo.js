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
})();
