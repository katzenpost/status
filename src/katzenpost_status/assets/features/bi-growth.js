(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI2 = Math.PI * 2, THREE = K.THREE;

    function lsys(axiom, rules, iters) { var s = axiom, k, i, o; for (k = 0; k < iters; k++) { o = ''; for (i = 0; i < s.length; i++) o += (rules[s[i]] != null ? rules[s[i]] : s[i]); s = o; if (s.length > 60000) break; } return s; }
    // Bracketed 2D turtle L-system plant.
    function lplant(id, name, axiom, rules, iters, ang, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 56, layout: function (d, T) {
            var s = lsys(axiom, rules, iters), x = 0, y = 0, dir = Math.PI / 2, stack = [], edges = [], anchors = [], i, step = 1;
            for (i = 0; i < s.length; i++) { var c = s[i]; if (c === 'F' || c === 'G') { var nx = x + Math.cos(dir) * step, ny = y + Math.sin(dir) * step; edges.push({ a: new T.Vector3(x, y, 0), b: new T.Vector3(nx, ny, 0), color: color }); anchors.push(new T.Vector3(nx, ny, 0)); x = nx; y = ny; } else if (c === '+') dir += ang; else if (c === '-') dir -= ang; else if (c === '[') stack.push([x, y, dir]); else if (c === ']') { var st = stack.pop(); if (st) { x = st[0]; y = st[1]; dir = st[2]; } } }
            var mnx = 1e9, mny = 1e9, mxx = -1e9, mxy = -1e9; anchors.forEach(function (p) { if (p.x < mnx) mnx = p.x; if (p.x > mxx) mxx = p.x; if (p.y < mny) mny = p.y; if (p.y > mxy) mxy = p.y; }); var cx = (mnx + mxx) / 2, cy = (mny + mxy) / 2, sc = 40 / Math.max(1e-6, Math.max(mxx - mnx, mxy - mny)); var all = anchors.slice(); edges.forEach(function (e) { all.push(e.a); all.push(e.b); }); all.forEach(function (p) { if (p.__s) return; p.__s = 1; p.x = (p.x - cx) * sc; p.y = (p.y - cy) * sc; }); return G.anchorLayout(d, T, anchors, edges);
        } });
    }
    function ae(id, name, fn, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 58, layout: function (d, T) { var a = [], e = []; fn(a, e, T, color); return G.anchorLayout(d, T, a, e); } }); }
    function surf(id, name, pFn, ur, vr, color, camZ) { G.create({ id: id, name: name, rotateSpeed: 0.4, camZ: camZ || 58, layout: function (d, T) { var A = [], idx = {}, E = [], i, j; for (i = 0; i <= ur; i++) for (j = 0; j <= vr; j++) { idx[i + '_' + j] = A.length; A.push(pFn(i / ur, j / vr, T)); } function ad(a, b, c, e) { var k1 = idx[a + '_' + b], k2 = idx[c + '_' + e]; if (k1 != null && k2 != null) E.push({ a: A[k1], b: A[k2], color: color }); } for (i = 0; i < ur; i++) for (j = 0; j < vr; j++) { ad(i, j, i + 1, j); ad(i, j, i, j + 1); } return G.anchorLayout(d, T, A, E); } }); }
    function rand(n) { return (Math.random() * 2 - 1) * n; }

    lplant('lsystemplant', 'L-system plant', 'X', { X: 'F+[[X]-X]-F[-FX]+X', F: 'FF' }, 5, 25 * Math.PI / 180, 0x2ec4b6, 56);

    lplant('lsystembush', 'L-system bush', 'F', { F: 'FF+[+F-F-F]-[-F+F+F]' }, 4, 22.5 * Math.PI / 180, 0x00d2a0, 56);

    lplant('lsystemweed', 'L-system weed', 'F', { F: 'F[+F]F[-F]F' }, 5, 25.7 * Math.PI / 180, 0x6ce0b0, 56);

    lplant('lsystemseaweed', 'L-system seaweed', 'F', { F: 'FF-[-F+F+F]+[+F-F-F]' }, 4, 20 * Math.PI / 180, 0x4d8bf0, 56);

    ae('vasculature', 'Vascular branching', function (a, e, T, color) { function grow(x, y, dir, len, depth) { var nx = x + Math.cos(dir) * len, ny = y + Math.sin(dir) * len; e.push({ a: new T.Vector3(x, y, 0), b: new T.Vector3(nx, ny, 0), color: color }); a.push(new T.Vector3(nx, ny, 0)); if (depth <= 0) return; grow(nx, ny, dir + 0.35 + rand(0.1), len * 0.75, depth - 1); grow(nx, ny, dir - 0.35 + rand(0.1), len * 0.75, depth - 1); } grow(0, -22, Math.PI / 2, 10, 8); }, 0xff5d8f, 58);

    ae('radiolaria', 'Radiolaria shell', function (a, e, T, color) { var g = new THREE.IcosahedronGeometry(14, 2), eg = new THREE.EdgesGeometry(g, 1), ep = eg.attributes.position, pos = g.attributes.position, seen = {}, i; for (i = 0; i < ep.count; i += 2) e.push({ a: new T.Vector3().fromBufferAttribute(ep, i), b: new T.Vector3().fromBufferAttribute(ep, i + 1), color: color }); for (i = 0; i < pos.count; i++) { var v = new T.Vector3().fromBufferAttribute(pos, i), k = Math.round(v.x * 30) + ',' + Math.round(v.y * 30) + ',' + Math.round(v.z * 30); if (seen[k]) continue; seen[k] = 1; a.push(v); var sp = v.clone().multiplyScalar(1.5); e.push({ a: v, b: sp, color: 0xffd23f }); } eg.dispose(); g.dispose(); }, 0x9b5de5, 54);

    surf('raupshell', 'Raup shell model', function (u, v, T) { var wh = u * PI2 * 3.2, ap = v * PI2, W = 1.28, r0 = 1.0; var R = r0 * Math.pow(W, wh / PI2) * 3.5, tube = R * 0.42; var cx = Math.cos(wh) * R, cy = Math.sin(wh) * R, cz = wh * 1.2; return new T.Vector3(cx + Math.cos(ap) * tube * Math.cos(wh), cy + Math.cos(ap) * tube * Math.sin(wh), cz + Math.sin(ap) * tube); }, 120, 24, 0xff8f3f, 56);

    ae('voronoicells', 'Voronoi cells', function (a, e, T, color) { var sites = [], i; for (i = 0; i < 26; i++) { var an = Math.random() * PI2, r = Math.sqrt(Math.random()) * 20; sites.push({ x: Math.cos(an) * r, y: Math.sin(an) * r }); } function circum(A, B, C) { var ax = A.x, ay = A.y, bx = B.x, by = B.y, cx = C.x, cy = C.y; var dd = 2 * (ax * (by - cy) + bx * (cy - ay) + cx * (ay - by)); if (Math.abs(dd) < 1e-9) return null; var ux = ((ax * ax + ay * ay) * (by - cy) + (bx * bx + by * by) * (cy - ay) + (cx * cx + cy * cy) * (ay - by)) / dd, uy = ((ax * ax + ay * ay) * (cx - bx) + (bx * bx + by * by) * (ax - cx) + (cx * cx + cy * cy) * (bx - ax)) / dd; return { x: ux, y: uy, r2: (ax - ux) * (ax - ux) + (ay - uy) * (ay - uy) }; } var st = [{ x: -1e4, y: -1e4 }, { x: 1e4, y: -1e4 }, { x: 0, y: 1e4 }]; var tris = [{ p: [st[0], st[1], st[2]], c: circum(st[0], st[1], st[2]) }]; sites.forEach(function (p) { var bad = [], k; for (k = tris.length - 1; k >= 0; k--) { var cc = tris[k].c; if (cc && (p.x - cc.x) * (p.x - cc.x) + (p.y - cc.y) * (p.y - cc.y) <= cc.r2 * 1.0000001) bad.push(tris.splice(k, 1)[0]); } var poly = []; bad.forEach(function (t) { [[t.p[0], t.p[1]], [t.p[1], t.p[2]], [t.p[2], t.p[0]]].forEach(function (ed) { var sh = false; bad.forEach(function (t2) { if (t2 === t) return; [[t2.p[0], t2.p[1]], [t2.p[1], t2.p[2]], [t2.p[2], t2.p[0]]].forEach(function (e2) { if ((ed[0] === e2[0] && ed[1] === e2[1]) || (ed[0] === e2[1] && ed[1] === e2[0])) sh = true; }); }); if (!sh) poly.push(ed); }); }); poly.forEach(function (ed) { tris.push({ p: [ed[0], ed[1], p], c: circum(ed[0], ed[1], p) }); }); }); var real = tris.filter(function (t) { return st.indexOf(t.p[0]) < 0 && st.indexOf(t.p[1]) < 0 && st.indexOf(t.p[2]) < 0; }); var emap = {}; function ekey(A, B) { var ka = sites.indexOf(A), kb = sites.indexOf(B); return Math.min(ka, kb) + '_' + Math.max(ka, kb); } real.forEach(function (t) { if (!t.c) return; [[t.p[0], t.p[1]], [t.p[1], t.p[2]], [t.p[2], t.p[0]]].forEach(function (ed) { var kk = ekey(ed[0], ed[1]); if (emap[kk]) { var c2 = emap[kk]; e.push({ a: new T.Vector3(t.c.x, t.c.y, 0), b: new T.Vector3(c2.x, c2.y, 0), color: color }); } else emap[kk] = t.c; }); a.push(new T.Vector3(t.c.x, t.c.y, 0)); }); }, 0x4d8bf0, 56);

    ae('lsystemtree3d', 'L-system tree (3D)', function (a, e, T, color) { function grow(pos, dir, len, depth) { var end = pos.clone().add(dir.clone().multiplyScalar(len)); e.push({ a: pos, b: end, color: color }); a.push(end); if (depth <= 0) return; for (var b = 0; b < 3; b++) { var nd = dir.clone(); nd.x += rand(0.5); nd.z += rand(0.5); nd.y += 0.45; nd.normalize(); grow(end, nd, len * 0.72, depth - 1); } } a.push(new T.Vector3(0, -20, 0)); grow(new T.Vector3(0, -20, 0), new T.Vector3(0, 1, 0), 9, 6); }, 0x2ec4b6, 60);

    lplant('lsystemfern', 'L-system fern', 'X', { X: 'F-[[X]+X]+F[+FX]-X', F: 'FF' }, 5, 22 * Math.PI / 180, 0xffb454, 56);
})();
