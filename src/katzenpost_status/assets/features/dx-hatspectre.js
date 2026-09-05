(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D, PI = Math.PI, hr3 = 0.8660254037844386;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];

    function pt(x, y) { return { x: x, y: y }; }
    function hexPt(x, y) { return pt(x + 0.5 * y, hr3 * y); }
    function inv(T) { var d = T[0] * T[4] - T[1] * T[3]; return [T[4] / d, -T[1] / d, (T[1] * T[5] - T[2] * T[4]) / d, -T[3] / d, T[0] / d, (T[2] * T[3] - T[0] * T[5]) / d]; }
    function mul(A, B) { return [A[0] * B[0] + A[1] * B[3], A[0] * B[1] + A[1] * B[4], A[0] * B[2] + A[1] * B[5] + A[2], A[3] * B[0] + A[4] * B[3], A[3] * B[1] + A[4] * B[4], A[3] * B[2] + A[4] * B[5] + A[5]]; }
    function padd(p, q) { return { x: p.x + q.x, y: p.y + q.y }; }
    function psub(p, q) { return { x: p.x - q.x, y: p.y - q.y }; }
    function trot(a) { var c = Math.cos(a), s = Math.sin(a); return [c, -s, 0, s, c, 0]; }
    function ttrans(tx, ty) { return [1, 0, tx, 0, 1, ty]; }
    function transTo(p, q) { return ttrans(q.x - p.x, q.y - p.y); }
    function rotAbout(p, a) { return mul(ttrans(p.x, p.y), mul(trot(a), ttrans(-p.x, -p.y))); }
    function transPt(M, P) { return pt(M[0] * P.x + M[1] * P.y + M[2], M[3] * P.x + M[4] * P.y + M[5]); }
    function matchSeg(p, q) { return [q.x - p.x, p.y - q.y, p.x, q.y - p.y, q.x - p.x, p.y]; }
    function matchTwo(p1, q1, p2, q2) { return mul(matchSeg(p2, q2), inv(matchSeg(p1, q1))); }
    function intersect(p1, q1, p2, q2) { var d = (q2.y - p2.y) * (q1.x - p1.x) - (q2.x - p2.x) * (q1.y - p1.y); var uA = ((q2.x - p2.x) * (p1.y - p2.y) - (q2.y - p2.y) * (p1.x - p2.x)) / d; return pt(p1.x + uA * (q1.x - p1.x), p1.y + uA * (q1.y - p1.y)); }
    var ID = [1, 0, 0, 0, 1, 0];

    function colFor(label) { var h = 0, i; for (i = 0; i < label.length; i++) h = (h * 31 + label.charCodeAt(i)) & 0x7fffffff; return PAL[h % PAL.length]; }

    function Leaf(label) { this.label = label; this.leaf = true; }
    function Meta(shape, width) { this.shape = shape; this.width = width; this.children = []; this.geometries = []; }
    Meta.prototype.addChild = function (T, geom) { this.children.push({ T: T, geom: geom }); };
    Meta.prototype.evalChild = function (n, i) { return transPt(this.children[n].T, this.children[n].geom.shape[i]); };

    function flattenHat(geom, T, out) { if (geom.leaf) { out.push({ label: geom.label, T: T }); return; } for (var i = 0; i < geom.children.length; i++) flattenHat(geom.children[i].geom, mul(T, geom.children[i].T), out); }

    var hat_outline = [hexPt(0, 0), hexPt(-1, -1), hexPt(0, -2), hexPt(2, -2), hexPt(2, -1), hexPt(4, -2), hexPt(5, -1), hexPt(4, 0), hexPt(3, 0), hexPt(2, 2), hexPt(0, 3), hexPt(0, 2), hexPt(-1, 2)];

    function hatInits() {
        var H1 = new Leaf('H1'), Hh = new Leaf('H'), Th = new Leaf('T'), Ph = new Leaf('P'), Fh = new Leaf('F');
        var Ho = [pt(0, 0), pt(4, 0), pt(4.5, hr3), pt(2.5, 5 * hr3), pt(1.5, 5 * hr3), pt(-0.5, hr3)];
        var H = new Meta(Ho, 2);
        H.addChild(matchTwo(hat_outline[5], hat_outline[7], Ho[5], Ho[0]), Hh);
        H.addChild(matchTwo(hat_outline[9], hat_outline[11], Ho[1], Ho[2]), Hh);
        H.addChild(matchTwo(hat_outline[5], hat_outline[7], Ho[3], Ho[4]), Hh);
        H.addChild(mul(ttrans(2.5, hr3), mul([-0.5, -hr3, 0, hr3, -0.5, 0], [0.5, 0, 0, 0, -0.5, 0])), H1);
        var To = [pt(0, 0), pt(3, 0), pt(1.5, 3 * hr3)], T = new Meta(To, 2);
        T.addChild([0.5, 0, 0.5, 0, 0.5, hr3], Th);
        var Po = [pt(0, 0), pt(4, 0), pt(3, 2 * hr3), pt(-1, 2 * hr3)], P = new Meta(Po, 2);
        P.addChild([0.5, 0, 1.5, 0, 0.5, hr3], Ph);
        P.addChild(mul(ttrans(0, 2 * hr3), mul([0.5, hr3, 0, -hr3, 0.5, 0], [0.5, 0, 0, 0, 0.5, 0])), Ph);
        var Fo = [pt(0, 0), pt(3, 0), pt(3.5, hr3), pt(3, 2 * hr3), pt(-1, 2 * hr3)], F = new Meta(Fo, 2);
        F.addChild([0.5, 0, 1.5, 0, 0.5, hr3], Fh);
        F.addChild(mul(ttrans(0, 2 * hr3), mul([0.5, hr3, 0, -hr3, 0.5, 0], [0.5, 0, 0, 0, 0.5, 0])), Fh);
        return [H, T, P, F];
    }
    function hatPatch(H, T, P, F) {
        var rules = [['H'], [0, 0, 'P', 2], [1, 0, 'H', 2], [2, 0, 'P', 2], [3, 0, 'H', 2], [4, 4, 'P', 2], [0, 4, 'F', 3], [2, 4, 'F', 3], [4, 1, 3, 2, 'F', 0], [8, 3, 'H', 0], [9, 2, 'P', 0], [10, 2, 'H', 0], [11, 4, 'P', 2], [12, 0, 'H', 2], [13, 0, 'F', 3], [14, 2, 'F', 1], [15, 3, 'H', 4], [8, 2, 'F', 1], [17, 3, 'H', 0], [18, 2, 'P', 0], [19, 2, 'H', 2], [20, 4, 'F', 3], [20, 0, 'P', 2], [22, 0, 'H', 2], [23, 4, 'F', 3], [23, 0, 'F', 3], [16, 0, 'P', 2], [9, 4, 0, 2, 'T', 2], [4, 0, 'F', 3]];
        var ret = new Meta([], H.width), shapes = { H: H, T: T, P: P, F: F }, i;
        for (i = 0; i < rules.length; i++) {
            var r = rules[i];
            if (r.length === 1) { ret.addChild(ID, shapes[r[0]]); }
            else if (r.length === 4) {
                var poly = ret.children[r[0]].geom.shape, Tt = ret.children[r[0]].T;
                var Pp = transPt(Tt, poly[(r[1] + 1) % poly.length]), Qq = transPt(Tt, poly[r[1]]);
                var ns = shapes[r[2]], np = ns.shape;
                ret.addChild(matchTwo(np[r[3]], np[(r[3] + 1) % np.length], Pp, Qq), ns);
            } else {
                var chP = ret.children[r[0]], chQ = ret.children[r[2]];
                var Pp2 = transPt(chQ.T, chQ.geom.shape[r[3]]), Qq2 = transPt(chP.T, chP.geom.shape[r[1]]);
                var ns2 = shapes[r[4]], np2 = ns2.shape;
                ret.addChild(matchTwo(np2[r[5]], np2[(r[5] + 1) % np2.length], Pp2, Qq2), ns2);
            }
        }
        return ret;
    }
    function hatMetatiles(patch) {
        var bps1 = patch.evalChild(8, 2), bps2 = patch.evalChild(21, 2);
        var rbps = transPt(rotAbout(bps1, -2 * PI / 3), bps2);
        var p72 = patch.evalChild(7, 2), p252 = patch.evalChild(25, 2);
        var llc = intersect(bps1, rbps, patch.evalChild(6, 2), p72), w = psub(patch.evalChild(6, 2), llc);
        var nHo = [llc, bps1], ch, arr;
        w = transPt(trot(-PI / 3), w); nHo.push(padd(nHo[1], w));
        nHo.push(patch.evalChild(14, 2));
        w = transPt(trot(-PI / 3), w); nHo.push(psub(nHo[3], w));
        nHo.push(patch.evalChild(6, 2));
        var nH = new Meta(nHo, patch.width * 2);
        arr = [0, 9, 16, 27, 26, 6, 1, 8, 10, 15]; for (ch = 0; ch < arr.length; ch++) nH.addChild(patch.children[arr[ch]].T, patch.children[arr[ch]].geom);
        var nPo = [p72, padd(p72, psub(bps1, llc)), bps1, llc], nP = new Meta(nPo, patch.width * 2);
        arr = [7, 2, 3, 4, 28]; for (ch = 0; ch < arr.length; ch++) nP.addChild(patch.children[arr[ch]].T, patch.children[arr[ch]].geom);
        var nFo = [bps2, patch.evalChild(24, 2), patch.evalChild(25, 0), p252, padd(p252, psub(llc, bps1))], nF = new Meta(nFo, patch.width * 2);
        arr = [21, 20, 22, 23, 24, 25]; for (ch = 0; ch < arr.length; ch++) nF.addChild(patch.children[arr[ch]].T, patch.children[arr[ch]].geom);
        var AAA = nHo[2], BBB = padd(nHo[1], psub(nHo[4], nHo[5])), CCC = transPt(rotAbout(BBB, -PI / 3), AAA);
        var nT = new Meta([BBB, CCC, AAA], patch.width * 2);
        nT.addChild(patch.children[11].T, patch.children[11].geom);
        return [nH, nT, nP, nF];
    }

    var S3 = Math.sqrt(3);
    var SP = [pt(0, 0), pt(1, 0), pt(1.5, -S3 / 2), pt(1.5 + S3 / 2, 0.5 - S3 / 2), pt(1.5 + S3 / 2, 1.5 - S3 / 2), pt(2.5 + S3 / 2, 1.5 - S3 / 2), pt(3 + S3 / 2, 1.5), pt(3, 2), pt(3 - S3 / 2, 1.5), pt(2.5 - S3 / 2, 1.5 + S3 / 2), pt(1.5 - S3 / 2, 1.5 + S3 / 2), pt(0.5 - S3 / 2, 1.5 + S3 / 2), pt(-S3 / 2, 1.5), pt(0, 1)];
    var SNAMES = ["Gamma", "Delta", "Theta", "Lambda", "Xi", "Pi", "Sigma", "Phi", "Psi"];
    function SLeaf(label) { this.label = label; this.leaf = true; this.quad = [SP[3], SP[5], SP[7], SP[11]]; }
    function SMeta(geoms, quad) { this.geometries = geoms; this.quad = quad; }
    function specBase() {
        var c = {}, i;
        for (i = 0; i < SNAMES.length; i++) if (SNAMES[i] !== 'Gamma') c[SNAMES[i]] = new SLeaf(SNAMES[i]);
        var mystic = new SMeta([[new SLeaf('Gamma1'), ID], [new SLeaf('Gamma2'), mul(ttrans(SP[8].x, SP[8].y), trot(PI / 6))]], [SP[3], SP[5], SP[7], SP[11]]);
        c['Gamma'] = mystic; return c;
    }
    function specSupertiles(sys) {
        var quad = sys['Delta'].quad, R = [-1, 0, 0, 0, 1, 0];
        var rules = [[60, 3, 1], [0, 2, 0], [60, 3, 1], [60, 3, 1], [0, 2, 0], [60, 3, 1], [-120, 3, 3]];
        var tf = [ID], total = 0, rot = ID, tq = quad.slice(), i, j;
        for (i = 0; i < rules.length; i++) {
            var ang = rules[i][0], frm = rules[i][1], to = rules[i][2];
            if (ang !== 0) { total += ang; rot = trot(total * PI / 180); tq = []; for (j = 0; j < quad.length; j++) tq.push(transPt(rot, quad[j])); }
            var ttt = transTo(tq[to], transPt(tf[tf.length - 1], quad[frm]));
            tf.push(mul(ttt, rot));
        }
        for (i = 0; i < tf.length; i++) tf[i] = mul(R, tf[i]);
        var sr = {
            "Gamma": ["Pi", "Delta", null, "Theta", "Sigma", "Xi", "Phi", "Gamma"],
            "Delta": ["Xi", "Delta", "Xi", "Phi", "Sigma", "Pi", "Phi", "Gamma"],
            "Theta": ["Psi", "Delta", "Pi", "Phi", "Sigma", "Pi", "Phi", "Gamma"],
            "Lambda": ["Psi", "Delta", "Xi", "Phi", "Sigma", "Pi", "Phi", "Gamma"],
            "Xi": ["Psi", "Delta", "Pi", "Phi", "Sigma", "Psi", "Phi", "Gamma"],
            "Pi": ["Psi", "Delta", "Xi", "Phi", "Sigma", "Psi", "Phi", "Gamma"],
            "Sigma": ["Xi", "Delta", "Xi", "Phi", "Sigma", "Pi", "Lambda", "Gamma"],
            "Phi": ["Psi", "Delta", "Psi", "Phi", "Sigma", "Pi", "Phi", "Gamma"],
            "Psi": ["Psi", "Delta", "Psi", "Phi", "Sigma", "Psi", "Phi", "Gamma"]
        };
        var sq = [transPt(tf[6], quad[2]), transPt(tf[5], quad[1]), transPt(tf[3], quad[2]), transPt(tf[0], quad[1])], out = {};
        for (var lab in sr) { var subs = sr[lab], geoms = []; for (i = 0; i < subs.length; i++) if (subs[i]) geoms.push([sys[subs[i]], tf[i]]); out[lab] = new SMeta(geoms, sq); }
        return out;
    }
    function flattenSpec(shape, T, out) { if (shape.leaf) { out.push({ label: shape.label, T: T }); return; } for (var i = 0; i < shape.geometries.length; i++) flattenSpec(shape.geometries[i][0], mul(T, shape.geometries[i][1]), out); }

    function build(d, THREE, tiles, outline) {
        var minx = 1e9, maxx = -1e9, miny = 1e9, maxy = -1e9, i, j, k;
        var segs = [], seen = {};
        function key(a, b) { return Math.round(a.x * 100) + ',' + Math.round(a.y * 100) + '|' + Math.round(b.x * 100) + ',' + Math.round(b.y * 100); }
        for (i = 0; i < tiles.length; i++) {
            var T = tiles[i].T, col = colFor(tiles[i].label), n = outline.length;
            for (j = 0; j < n; j++) {
                var a = transPt(T, outline[j]), b = transPt(T, outline[(j + 1) % n]);
                var k1 = key(a, b), k2 = key(b, a);
                if (seen[k1] || seen[k2]) continue; seen[k1] = 1;
                segs.push({ a: a, b: b, color: col });
                if (a.x < minx) minx = a.x; if (a.x > maxx) maxx = a.x; if (a.y < miny) miny = a.y; if (a.y > maxy) maxy = a.y;
                if (b.x < minx) minx = b.x; if (b.x > maxx) maxx = b.x; if (b.y < miny) miny = b.y; if (b.y > maxy) maxy = b.y;
            }
        }
        var cx = (minx + maxx) / 2, cy = (miny + maxy) / 2, half = Math.max(maxx - minx, maxy - miny) / 2;
        var s = half > 1e-6 ? 20 / half : 1;
        function V(p) { return new THREE.Vector3((p.x - cx) * s, (p.y - cy) * s, 0); }
        var edges = [], anchors = [], anchSeen = {};
        function anch(p) { var kk = Math.round(p.x * 4) + ',' + Math.round(p.y * 4); if (anchSeen[kk]) return; anchSeen[kk] = 1; anchors.push(new THREE.Vector3((p.x - cx) * s, (p.y - cy) * s, 0)); }
        for (k = 0; k < segs.length; k++) { edges.push({ a: V(segs[k].a), b: V(segs[k].b), color: segs[k].color }); anch(segs[k].a); anch(segs[k].b); }
        return G.anchorLayout(d, THREE, anchors, edges);
    }

    G.create({
        id: 'hat-monotile', name: 'Hat monotile tiling', rotateSpeed: 0.22, camZ: 58,
        layout: function (d, THREE) {
            var tiles = hatInits(), g;
            for (g = 0; g < 2; g++) tiles = hatMetatiles(hatPatch(tiles[0], tiles[1], tiles[2], tiles[3]));
            var out = []; flattenHat(tiles[0], ID, out);
            return build(d, THREE, out, hat_outline);
        }
    });

    G.create({
        id: 'spectre-monotile', name: 'Spectre monotile tiling', rotateSpeed: 0.22, camZ: 58,
        layout: function (d, THREE) {
            var shapes = specBase(), it;
            for (it = 0; it < 2; it++) shapes = specSupertiles(shapes);
            var out = []; flattenSpec(shapes['Delta'], ID, out);
            return build(d, THREE, out, SP);
        }
    });
})();
