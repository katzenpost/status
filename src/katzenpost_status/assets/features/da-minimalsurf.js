(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;
    var PAL = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff5d8f, 0xff8f3f, 0x00d2a0, 0xffd23f, 0xff5d6c, 0x33ccff, 0x8a5bff];
    function cmul(a, b) { return [a[0] * b[0] - a[1] * b[1], a[0] * b[1] + a[1] * b[0]]; }
    // Centre a point set on its centroid and rescale so it fits radius ~18.
    function fit(v, THREE) {
        var cx = 0, cy = 0, cz = 0, i, mx = 1e-6;
        for (i = 0; i < v.length; i++) { cx += v[i].x; cy += v[i].y; cz += v[i].z; }
        cx /= v.length; cy /= v.length; cz /= v.length;
        for (i = 0; i < v.length; i++) { v[i].x -= cx; v[i].y -= cy; v[i].z -= cz; mx = Math.max(mx, Math.abs(v[i].x), Math.abs(v[i].y), Math.abs(v[i].z)); }
        var s = 18 / mx; for (i = 0; i < v.length; i++) { v[i].x *= s; v[i].y *= s; v[i].z *= s; }
    }
    // Structured quad-grid edges over a (nu x nv) surface (angular index wraps
    // when wrap=1). Radial/u lines coloured by v-band, v-lines by u-band.
    function gridEdges(v, nu, nv, wrap) {
        var edges = [], iu, iv;
        function gi(a, b) { return b * nu + a; }
        for (iu = 0; iu < nu; iu++) for (iv = 0; iv < nv; iv++) {
            if (iv + 1 < nv) edges.push({ a: v[gi(iu, iv)], b: v[gi(iu, iv + 1)], color: PAL[iu % PAL.length] });
            var iu2 = iu + 1; if (iu2 >= nu) { if (!wrap) continue; iu2 = 0; }
            edges.push({ a: v[gi(iu, iv)], b: v[gi(iu2, iv)], color: PAL[iv % PAL.length] });
        }
        return edges;
    }
    // Numeric Weierstrass-Enneper: minimal surface from holomorphic f(z),g(z) by
    // integrating (f(1-g^2)/2, i f(1+g^2)/2, f g) radially outward on the disk.
    function weSurf(id, name, fFn, gFn, r0, r1, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.2, camZ: camZ || 58, layout: function (d, THREE) {
            var nth = 54, nr = 26, v = [], iu, ir, dr = (r1 - r0) / (nr - 1);
            for (iu = 0; iu < nth; iu++) {
                var th = 2 * Math.PI * iu / nth, c = Math.cos(th), s = Math.sin(th), X = 0, Y = 0, Z = 0, dz = [c * dr, s * dr];
                for (ir = 0; ir < nr; ir++) {
                    var r = r0 + dr * ir, z = [r * c, r * s], f = fFn(z), g = gFn(z), g2 = cmul(g, g);
                    var p1 = cmul(f, [(1 - g2[0]) / 2, -g2[1] / 2]);
                    var p2 = cmul(f, cmul([0, 1], [(1 + g2[0]) / 2, g2[1] / 2]));
                    var p3 = cmul(f, g);
                    if (ir > 0) { X += p1[0] * dz[0] - p1[1] * dz[1]; Y += p2[0] * dz[0] - p2[1] * dz[1]; Z += p3[0] * dz[0] - p3[1] * dz[1]; }
                    v.push(new THREE.Vector3(X, Y, Z));
                }
            }
            // reindex to [iu*nr+ir]; gridEdges wants nu=nr fastest? build directly:
            var edges = [], a, b;
            function gi(iu, ir) { return iu * nr + ir; }
            for (iu = 0; iu < nth; iu++) for (ir = 0; ir < nr; ir++) {
                if (ir + 1 < nr) edges.push({ a: v[gi(iu, ir)], b: v[gi(iu, ir + 1)], color: PAL[iu % PAL.length] });
                var iu2 = (iu + 1) % nth; edges.push({ a: v[gi(iu, ir)], b: v[gi(iu2, ir)], color: PAL[ir % PAL.length] });
            }
            fit(v, THREE);
            return G.anchorLayout(d, THREE, v, edges);
        } });
    }
    // Associate (Bonnet) family blending helicoid (t=0) and catenoid (t=pi/2).
    function assoc(id, name, t, camZ) {
        G.create({ id: id, name: name, rotateSpeed: 0.24, camZ: camZ || 58, layout: function (d, THREE) {
            var nu = 60, nv = 24, v = [], iu, iv, ct = Math.cos(t), st = Math.sin(t);
            for (iu = 0; iu < nu; iu++) for (iv = 0; iv < nv; iv++) {
                var u = 2 * Math.PI * iu / (nu - 1), vv = -1.7 + 3.4 * iv / (nv - 1), ch = Math.cosh(vv), sh = Math.sinh(vv);
                v.push(new THREE.Vector3(ct * sh * Math.sin(u) + st * ch * Math.cos(u), -ct * sh * Math.cos(u) + st * ch * Math.sin(u), u * ct + vv * st));
            }
            var edges = gridEdges(v, nu, nv, 0);
            fit(v, THREE);
            return G.anchorLayout(d, THREE, v, edges);
        } });
    }
    function zpow(z, n) { var r = [1, 0], k; for (k = 0; k < n; k++) r = cmul(r, z); return r; }

    weSurf('ms-enneper2', 'Enneper surface (order 2)', function (z) { return [1, 0]; }, function (z) { return zpow(z, 2); }, 0.0, 1.15, 56);

    weSurf('ms-enneper3', 'Enneper surface (order 3)', function (z) { return [1, 0]; }, function (z) { return zpow(z, 3); }, 0.0, 1.12, 56);

    weSurf('ms-enneper4', 'Enneper surface (order 4)', function (z) { return [1, 0]; }, function (z) { return zpow(z, 4); }, 0.0, 1.1, 56);

    weSurf('ms-enneper5', 'Enneper surface (order 5)', function (z) { return [1, 0]; }, function (z) { return zpow(z, 5); }, 0.0, 1.08, 56);

    weSurf('ms-richmond', 'Richmond surface', function (z) { var d = z[0] * z[0] + z[1] * z[1] || 1e-9; var i = cmul([1, 0], [z[0] / d, -z[1] / d]); return cmul(i, i); }, function (z) { return z; }, 0.4, 1.5, 56);

    weSurf('ms-richmond3', 'Richmond surface (g=z^3)', function (z) { var d = z[0] * z[0] + z[1] * z[1] || 1e-9; var i = [z[0] / d, -z[1] / d]; return cmul(i, i); }, function (z) { return zpow(z, 3); }, 0.45, 1.45, 56);

    weSurf('ms-twisted', 'Twisted Enneper (g=i z^2)', function (z) { return [1, 0]; }, function (z) { return cmul([0, 1], zpow(z, 2)); }, 0.0, 1.15, 56);

    assoc('ms-associate-25', 'Associate family (25 deg)', 25 * Math.PI / 180, 56);

    assoc('ms-associate-50', 'Associate family (50 deg)', 50 * Math.PI / 180, 56);
})();
