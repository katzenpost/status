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
})();
