(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

    function lsys(axiom, rules, iters) { var s = axiom, k, i, o; for (k = 0; k < iters; k++) { o = ""; for (i = 0; i < s.length; i++) o += (rules[s[i]] != null ? rules[s[i]] : s[i]); s = o; } return s; }
    function turtle(str, angleDeg, draw, THREE) {
        var x = 0, y = 0, dir = 0, rad = angleDeg * Math.PI / 180, pts = [new THREE.Vector3(0, 0, 0)], i, c;
        for (i = 0; i < str.length; i++) { c = str[i]; if (draw.indexOf(c) >= 0) { x += Math.cos(dir); y += Math.sin(dir); pts.push(new THREE.Vector3(x, y, 0)); } else if (c === '+') dir += rad; else if (c === '-') dir -= rad; }
        var minx = Infinity, miny = Infinity, maxx = -Infinity, maxy = -Infinity;
        pts.forEach(function (p) { if (p.x < minx) minx = p.x; if (p.x > maxx) maxx = p.x; if (p.y < miny) miny = p.y; if (p.y > maxy) maxy = p.y; });
        var cx = (minx + maxx) / 2, cy = (miny + maxy) / 2, sc = 42 / Math.max(1e-6, Math.max(maxx - minx, maxy - miny));
        pts.forEach(function (p) { p.x = (p.x - cx) * sc; p.y = (p.y - cy) * sc; });
        return pts;
    }
    function lcurve(id, name, axiom, rules, iters, angle, draw, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.22, camZ: camZ || 54,
            layout: function (d, THREE) { return G.curveLayout(d, THREE, turtle(lsys(axiom, rules, iters), angle, draw, THREE), color); } });
    }
    function areaFractal(id, name, cellsFn, color, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.3, camZ: camZ || 56,
            layout: function (d, THREE) {
                var cells = cellsFn(), anchors = [], edges = [];
                cells.forEach(function (c) { var x = c[0], y = c[1], s = c[2], h = s / 2;
                    var p = [new THREE.Vector3(x - h, y - h, 0), new THREE.Vector3(x + h, y - h, 0), new THREE.Vector3(x + h, y + h, 0), new THREE.Vector3(x - h, y + h, 0)];
                    anchors.push(new THREE.Vector3(x, y, 0));
                    for (var i = 0; i < 4; i++) edges.push({ a: p[i], b: p[(i + 1) % 4], color: color });
                });
                return G.anchorLayout(d, THREE, anchors, edges);
            } });
    }

    lcurve('peano', 'Peano curve', 'F', { F: 'F-F+F+F+F-F-F-F+F' }, 3, 90, 'F', 0x2ec4b6, 52);

    lcurve('moore', 'Moore curve', 'LFL+F+LFL', { L: '-RF+LFL+FR-', R: '+LF-RFR-FL+' }, 4, 90, 'F', 0x4d8bf0, 52);

    lcurve('gosper', 'Gosper flowsnake', 'A', { A: 'A-B--B+A++AA+B-', B: '+A-BB--B-A++A+B' }, 3, 60, 'AB', 0x9b5de5, 54);

    lcurve('arrowhead', 'Sierpinski arrowhead', 'A', { A: 'B-A-B', B: 'A+B+A' }, 6, 60, 'AB', 0xff8f3f, 54);

    lcurve('levyc', 'Levy C curve', 'F', { F: '+F--F+' }, 12, 45, 'F', 0xff5d8f, 54);

    lcurve('terdragon', 'Terdragon curve', 'F', { F: 'F+F-F' }, 7, 120, 'F', 0x00d2a0, 54);

    lcurve('cesaro', 'Cesaro fractal', 'F', { F: 'F+F--F+F' }, 4, 85, 'F', 0xffd23f, 52);
})();
