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
    // Two-species reaction-diffusion on a toroidal grid: integrate explicitly for
    // `steps`, then lift the chosen field into a coloured relief point cloud.
    // react(u,v) -> [du,dv] reaction terms (diffusion added separately).
    function rd2(p) {
        G.create({ id: p.id, name: p.name, rotateSpeed: 0.2, camZ: p.camZ || 60, layout: function (d, THREE) {
            var W = p.W, N = W * W, u = new Float32Array(N), v = new Float32Array(N), nu = new Float32Array(N), nv = new Float32Array(N), i, s;
            p.init(u, v, W);
            for (s = 0; s < p.steps; s++) {
                for (i = 0; i < N; i++) {
                    var x = i % W, y = (i / W) | 0;
                    var l = ((x - 1 + W) % W) + y * W, r = ((x + 1) % W) + y * W, up = x + ((y - 1 + W) % W) * W, dn = x + ((y + 1) % W) * W;
                    var lu = u[l] + u[r] + u[up] + u[dn] - 4 * u[i], lv = v[l] + v[r] + v[up] + v[dn] - 4 * v[i];
                    var rr = p.react(u[i], v[i]);
                    var a = u[i] + (p.Du * lu + rr[0]) * p.dt, b = v[i] + (p.Dv * lv + rr[1]) * p.dt;
                    if (!isFinite(a)) a = 0; if (!isFinite(b)) b = 0;
                    nu[i] = a < -60 ? -60 : (a > 60 ? 60 : a); nv[i] = b < -60 ? -60 : (b > 60 ? 60 : b);
                }
                var t = u; u = nu; nu = t; t = v; v = nv; nv = t;
            }
            var fld = p.field === 'v' ? v : u, mn = 1e9, mx = -1e9;
            for (i = 0; i < N; i++) { if (fld[i] < mn) mn = fld[i]; if (fld[i] > mx) mx = fld[i]; }
            var rng = (mx - mn) || 1, thr = mn + (p.frac || 0.5) * rng, raw = [];
            for (i = 0; i < N; i++) if (fld[i] > thr) raw.push(i);
            var stride = Math.max(1, Math.ceil(raw.length / 480)), pts = [], cols = [], cx = (W - 1) / 2, sc = 34 / W;
            for (i = 0; i < raw.length; i += stride) {
                var idx = raw[i], gx = idx % W, gy = (idx / W) | 0, hval = (fld[idx] - mn) / rng;
                pts.push(new THREE.Vector3((gx - cx) * sc, (gy - cx) * sc, hval * 8 - 4));
                cols.push(PAL[Math.min(PAL.length - 1, (hval * PAL.length) | 0)]);
            }
            if (pts.length < 8) { pts = [new THREE.Vector3(-6, 0, 0), new THREE.Vector3(6, 0, 0)]; cols = [PAL[0], PAL[0]]; }
            return G.anchorLayout(d, THREE, pts, knn(pts, cols, 3));
        } });
    }
    function seedGS(u, v, W) { var i, N = W * W; for (i = 0; i < N; i++) { u[i] = 1; v[i] = 0; } var c = (W >> 1), a, b; for (a = -6; a <= 6; a++) for (b = -6; b <= 6; b++) { var idx = (c + a) + (c + b) * W; u[idx] = 0.5 + (Math.random() - 0.5) * 0.02; v[idx] = 0.25 + (Math.random() - 0.5) * 0.02; } }
    function gs(id, name, F, k) { return { id: id, name: name, W: 50, steps: 2200, dt: 1.0, Du: 0.16, Dv: 0.08, field: 'v', frac: 0.28, init: seedGS, react: function (u, v) { var uvv = u * v * v; return [-uvv + F * (1 - u), uvv - (F + k) * v]; } }; }
    function noiseInit(u, v, W, u0, v0) { var i, N = W * W; for (i = 0; i < N; i++) { u[i] = u0 + (Math.random() - 0.5) * 0.1; v[i] = v0 + (Math.random() - 0.5) * 0.1; } }

    rd2(gs('rd-grayscott-coral', 'Gray-Scott (coral)', 0.0545, 0.062));

    rd2(gs('rd-grayscott-mitosis', 'Gray-Scott (mitosis)', 0.0367, 0.0649));
})();
