(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback
    var THREE = K.THREE;

    var R = 48;              // globe radius (larger => geography spreads out more)
    var SURF = R + 1.5;      // node radius (just above the surface)
    var _vh = location.hash + location.search;
    var mode = /view=flat/.test(_vh) ? 'flat' : /view=rings/.test(_vh) ? 'rings'
        : /view=cascade/.test(_vh) ? 'cascade' : /view=radial/.test(_vh) ? 'radial' : /view=depend/.test(_vh) ? 'depend' : /view=jenga/.test(_vh) ? 'jenga' : /view=spire/.test(_vh) ? 'spire' : /view=shells/.test(_vh) ? 'shells' : /view=arch/.test(_vh) ? 'arch' : /view=tree/.test(_vh) ? 'tree' : /view=suspend/.test(_vh) ? 'suspend'
            : /view=spiral/.test(_vh) ? 'spiral' : /view=fibsphere/.test(_vh) ? 'fibsphere' : /view=flower/.test(_vh) ? 'flower'
                : /view=hypercube/.test(_vh) ? 'hypercube' : /view=torus/.test(_vh) ? 'torus'
                    : /view=helix/.test(_vh) ? 'helix' : /view=mobius/.test(_vh) ? 'mobius' : /view=tspiral/.test(_vh) ? 'tspiral'
                        : /view=force/.test(_vh) ? 'force' : 'earth';
    var globe = null;
    var flatMap = null;      // 2D map backdrop (land + cables), Earth-flat mode
    var K_FLAT = 0.7;        // degrees -> world units for the flat projection
    var extras = [];         // arcs + vantage marker, added in Earth mode
    var spinEnabled = true;   // 3D views slowly auto-rotate unless Rotate is off
    var SPIN3D = {
        earth: 1, rings: 1, spiral: 1, radial: 1, depend: 1, jenga: 1, spire: 1, shells: 1, arch: 1, tree: 1, suspend: 1, fibsphere: 1,
        hypercube: 1, torus: 1, helix: 1, mobius: 1, force: 1
    };
    var landRings = null;    // [[ [lon,lat], ... ], ...] once loaded
    var firstBuild = true;   // frame the globe once, on the first data build
    var showFiber = true;    // default: real submarine cables instead of arcs
    var cableLines = null;   // submarine cable polylines once loaded
    var cablePolysVec = null;// same, as Vector3 near the surface (for routing)
    var cableMesh = null;    // merged cable line-segments, child of the globe
    var routeIndex = {};     // "keyA>keyB" -> routed polyline, so packets follow it
    var cascadeHeaders = [];   // [{x,y,title,subtitle}] column/band headers (cascade)
    var cascadeClients = [];   // [{pos,gw}] synthetic clients feeding gateways
    var radialHeaders = [];    // ring labels (radial view)
    var radialClients = [];    // synthetic clients on the radial clients ring
    var cascadeExtras = [];    // live header sprites + client dots + links, for teardown
    var cascadeFlow = [];      // animated flow dots travelling the pipeline
    var geoClients = [];       // scattered clients around gateways (earth/flat views)
    var cascadeTopY = 0;       // top of the dir-auth band, for framing

    var wrap = document.createElement('div');
    wrap.style.margin = '0 0 12px';
    var btn = document.createElement('button');
    btn.style.width = '100%';
    var MODE_ORDER = ['earth', 'flat', 'rings', 'cascade', 'radial', 'depend', 'jenga', 'spire', 'shells', 'arch', 'tree', 'suspend', 'spiral', 'fibsphere',
        'flower', 'hypercube', 'torus', 'helix', 'mobius', 'tspiral', 'force'];
    var MODE_NAME = {
        earth: 'Earth', flat: 'Flat map', rings: 'Rings', cascade: 'Cascade', radial: 'Radial',
        depend: 'Dependency', jenga: 'Quorum stack', spire: 'Threshold spire', shells: 'Nested shells', arch: 'Keystone arch', tree: 'Root tree', suspend: 'Suspension', spiral: 'Spiral', fibsphere: 'Fib sphere', hypercube: 'Hypercube',
        flower: 'Flower of Life', torus: 'Trefoil', helix: 'Helix', mobius: 'Mobius strip', tspiral: 'Time spiral', force: 'Force graph'
    };
    function nextMode(m) { return MODE_ORDER[(MODE_ORDER.indexOf(m) + 1) % MODE_ORDER.length]; }
    var curOverlay = null;
    function overlayList() { return window.KATZEN_OVERLAYS || (window.KATZEN_OVERLAYS = []); }
    function findOverlay(id) {
        var l = overlayList();
        for (var i = 0; i < l.length; i++) if (l[i].id === id) return l[i];
        return null;
    }
    function viewIds() { return MODE_ORDER.concat(overlayList().map(function (o) { return 'overlay:' + o.id; })); }
    function curViewId() { return curOverlay ? ('overlay:' + curOverlay) : mode; }
    function viewName(vid) {
        if (vid.indexOf('overlay:') === 0) { var o = findOverlay(vid.slice(8)); return o ? o.name : vid; }
        return MODE_NAME[vid];
    }
    function nextViewId() {
        var ids = viewIds(), i = ids.indexOf(curViewId());
        return ids[(i + 1) % ids.length];
    }
    function showOverlay(id) {
        overlayList().forEach(function (o) { if (o.el) o.el.style.display = (o.id === id) ? 'block' : 'none'; });
        curOverlay = id;
        var ov = findOverlay(id); if (ov && ov.onShow) ov.onShow();
        updateBtn();
    }
    function hideOverlays() {
        if (curOverlay) { var ov = findOverlay(curOverlay); if (ov && ov.onHide) ov.onHide(); }
        overlayList().forEach(function (o) { if (o.el) o.el.style.display = 'none'; });
        curOverlay = null;
    }
    function gotoNextView() { gotoView(nextViewId()); }
    function gotoView(vid) {
        if (vid.indexOf('overlay:') === 0) { showOverlay(vid.slice(8)); }
        else { hideOverlays(); setMode(vid); updateBtn(); }
        try { if (window.localStorage) localStorage.setItem('katzen.view', vid); } catch (e) { }
        setViewParam(vid);
    }
    // Reflect the current view in the URL hash (preserving node/group params) so
    // the address bar is shareable and reload restores it.
    function setViewParam(vid) {
        try {
            var p = {};
            (location.hash || '').replace(/^#/, '').split('&').forEach(function (kv) {
                if (!kv) return; var q = kv.split('='); p[q[0]] = q.slice(1).join('=');
            });
            delete p.view; delete p.overlay;
            if (vid.indexOf('overlay:') === 0) p.overlay = vid.slice(8);
            else if (vid !== 'earth') p.view = vid;
            var parts = Object.keys(p).filter(function (k) { return p[k] != null; })
                .map(function (k) { return k + '=' + p[k]; });
            var h = parts.length ? '#' + parts.join('&') : '';
            if (h !== location.hash) history.replaceState(null, '', h || (location.pathname + location.search));
        } catch (e) { }
    }
    function rebuildViewSelect() {
        if (!viewSelect) return;
        var here = curViewId();
        if (viewSelect.options.length !== viewIds().length) {
            viewSelect.innerHTML = '';
            viewIds().forEach(function (vid) {
                var op = document.createElement('option');
                op.value = vid; op.textContent = viewName(vid);
                viewSelect.appendChild(op);
            });
        }
        viewSelect.value = here;
    }
    function updateBtn() {
        var here = curViewId(), nx = nextViewId();
        btn.textContent = 'View: ' + viewName(here) + ' (next: ' + viewName(nx) + ')';
        rebuildViewSelect();
    }
    // No dedicated overlay-close button: an overlay is just another view, so
    // switching views (via the chooser) replaces it. Selecting a spatial view
    // hides any overlay in gotoView/hideOverlays.
    var viewSelect = document.createElement('select');
    viewSelect.id = 'view-select';
    viewSelect.setAttribute('aria-label', 'Choose view');
    viewSelect.setAttribute('autocomplete', 'off');   // we restore the view ourselves
    viewSelect.style.cssText = 'position:fixed;z-index:30;top:calc(max(12px, env(safe-area-inset-top)) + 52px);' +
        'left:max(12px, env(safe-area-inset-left));max-width:160px;height:34px;' +
        'background:rgba(8,12,20,0.9);border:1px solid rgba(255,180,84,0.4);color:#ffb454;' +
        'border-radius:8px;font:12px/1 monospace;cursor:pointer;padding:0 8px;' +
        'box-shadow:0 4px 16px rgba(0,0,0,0.6)';
    viewSelect.addEventListener('change', function () { gotoView(viewSelect.value); });
    document.body.appendChild(viewSelect);
    updateBtn();
    wrap.appendChild(btn);
    function checkboxLabel(html, onchange) {
        var l = document.createElement('label');
        l.style.cssText = 'display:flex;align-items:center;gap:6px;margin-top:6px;font-size:11px;color:#9fb3c2';
        l.innerHTML = html;
        l.querySelector('input').addEventListener('change', onchange);
        return l;
    }
    var rotLabel = checkboxLabel('<input type="checkbox" checked aria-label="Rotate"> Rotate',
        function (e) { spinEnabled = e.target.checked; });
    var crtLabel = checkboxLabel('<input type="checkbox" aria-label="CRT effect"> CRT effect',
        function (e) { K.setCRT(e.target.checked); });
    var fiberLabel = checkboxLabel('<input type="checkbox" checked aria-label="Fiber cables"> Fiber cables',
        function (e) { showFiber = e.target.checked; applyLinks(); });
    var linksLabel = checkboxLabel('<input type="checkbox" checked aria-label="All links"> All links',
        function (e) { K.setAllLinks(e.target.checked); });
    var linksInput = linksLabel.querySelector('input');
    function setAllLinksUI(on) { if (linksInput) linksInput.checked = on; K.setAllLinks(on); }
    function nonDirauthLink(a, b) { return a.data.type !== 'dirauth' && b.data.type !== 'dirauth'; }
    function structLinksOn() { K.setLinkFilter(nonDirauthLink); if (linksInput) linksInput.checked = true; K.setAllLinks(true); }
    function fullLinksOn() { K.setLinkFilter(null); if (linksInput) linksInput.checked = true; K.setAllLinks(true); }
    function ownLinksOnly() { K.setLinkFilter(null); if (linksInput) linksInput.checked = false; K.setAllLinks(false); }
    var checks = [rotLabel, crtLabel, fiberLabel, linksLabel];
    var labelsToggle = document.getElementById('labels-toggle');
    if (labelsToggle) {
        labelsToggle.style.cssText = 'display:flex;align-items:center;gap:6px;margin-top:6px;font-size:11px;color:#9fb3c2';
        checks.push(labelsToggle);
    }
    checks.sort(function (a, b) {
        return a.textContent.trim().toLowerCase() < b.textContent.trim().toLowerCase() ? -1 : 1;
    });
    checks.forEach(function (l) { wrap.appendChild(l); });
    var regionRow = document.createElement('div');
    regionRow.style.cssText = 'display:flex;gap:6px;margin-top:6px';
    var euBtn = document.createElement('button');
    euBtn.style.flex = '1'; euBtn.textContent = 'Europe';
    var naBtn = document.createElement('button');
    naBtn.style.flex = '1'; naBtn.textContent = 'N. America';
    regionRow.appendChild(euBtn); regionRow.appendChild(naBtn);
    wrap.appendChild(regionRow);
    var shareBtn = document.createElement('button');
    shareBtn.textContent = 'Copy link to this view';
    shareBtn.style.cssText = 'width:100%;margin-top:6px';
    shareBtn.addEventListener('click', function () {
        setViewParam(curViewId());
        var url = location.href, orig = shareBtn.textContent;
        function done() { shareBtn.textContent = 'Link copied'; setTimeout(function () { shareBtn.textContent = orig; }, 1500); }
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, done);
        else {
            try {
                var ta = document.createElement('textarea'); ta.value = url;
                document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
            } catch (e) { }
            done();
        }
    });
    wrap.appendChild(shareBtn);
    euBtn.addEventListener('click', function () { if (mode === 'earth') frameSubset(function (ll) { return ll[1] > -15 && ll[1] < 45; }); });
    naBtn.addEventListener('click', function () { if (mode === 'earth') frameSubset(function (ll) { return ll[1] <= -15; }); });
    var hud = K.hudPanel();
    if (hud) hud.insertBefore(wrap, hud.firstChild);

    function hashU32(s) {
        var h = 2166136261 >>> 0;
        for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
        return h >>> 0;
    }
    function geoToVec(lat, lon, radius) {
        var la = lat * Math.PI / 180, lo = lon * Math.PI / 180;
        return new THREE.Vector3(
            radius * Math.cos(la) * Math.cos(lo),
            radius * Math.sin(la),
            -radius * Math.cos(la) * Math.sin(lo));
    }
    function baseLatLon(o) {
        var d = o.data;
        if (d.geo) return [d.geo.lat, d.geo.lon];
        var h = hashU32(d.name + '|' + d.type);
        return [(h % 18000) / 100 - 90, (Math.floor(h / 18000) % 36000) / 100 - 180];
    }
    function vantageEarthPos() {
        var v = (K.data() || {}).vantage;
        if (v && typeof v.lat === 'number') return geoToVec(v.lat, v.lon, SURF + 0.5);
        return geoToVec(25, 0, SURF + 0.5);
    }

    function arcPoints(a, b, segs) {
        var ra = a.length(), rb = b.length();
        var ua = a.clone().normalize(), ub = b.clone().normalize();
        var dot = THREE.MathUtils.clamp(ua.dot(ub), -1, 1), omega = Math.acos(dot);
        var out = [];
        for (var i = 0; i <= segs; i++) {
            var t = i / segs, p;
            if (omega < 1e-4) { p = ua.clone(); }
            else {
                var s1 = Math.sin((1 - t) * omega) / Math.sin(omega);
                var s2 = Math.sin(t * omega) / Math.sin(omega);
                p = ua.clone().multiplyScalar(s1).add(ub.clone().multiplyScalar(s2)).normalize();
            }
            p.multiplyScalar(ra + (rb - ra) * t + 2 * Math.sin(Math.PI * t));
            out.push(p);
        }
        return out;
    }

    function addLand(group) {
        if (!landRings) return;
        var mat = new THREE.LineBasicMaterial({ color: 0xffb454, transparent: true, opacity: 0.6 });
        landRings.forEach(function (ring) {
            var pts = ring.map(function (c) { return geoToVec(c[1], c[0], R - 0.25); });
            group.add(new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(pts), mat));
        });
    }
    function addGraticule(group) {
        var mat = new THREE.LineBasicMaterial({ color: 0xc8791f, transparent: true, opacity: 0.28 });
        var lat, lon, pts, i;
        for (lat = -60; lat <= 60; lat += 30) {
            pts = [];
            for (i = 0; i <= 72; i++) pts.push(geoToVec(lat, i * 5 - 180, R - 0.28));
            group.add(new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(pts), mat));
        }
        for (lon = 0; lon < 180; lon += 30) {
            pts = [];
            for (i = 0; i <= 72; i++) pts.push(geoToVec(i * 5 - 180, lon, R - 0.28));
            group.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), mat));
        }
    }

    function addGlobe() {
        globe = new THREE.Group();
        globe.add(new THREE.Mesh(
            new THREE.SphereGeometry(R - 0.4, 48, 32),
            new THREE.MeshStandardMaterial({
                color: 0x0d0803, emissive: 0x140a02, emissiveIntensity: 0.3,
                roughness: 0.95, metalness: 0.0
            })));
        globe.add(new THREE.Mesh(
            new THREE.SphereGeometry(R * 1.06, 48, 32),
            new THREE.MeshBasicMaterial({
                color: 0x7a4a12, transparent: true, opacity: 0.16,
                side: THREE.BackSide, blending: THREE.AdditiveBlending, depthWrite: false
            })));
        addGraticule(globe);
        addLand(globe);
        K.worldRoot().add(globe);
    }

    // Break a cable polyline at the antimeridian (|dlon|>180) and densify long
    // spans so the segments hug the globe surface instead of chording through
    // it (which is what made the trans-Pacific cables near Hawaii look wrong).
    function densifyCable(line, stepDeg) {
        stepDeg = stepDeg || 2;
        var subs = [], cur = [];
        for (var i = 0; i < line.length; i++) {
            var p = line[i];
            if (cur.length) {
                var q = cur[cur.length - 1], dlon = p[0] - q[0];
                if (Math.abs(dlon) > 180) { subs.push(cur); cur = []; }
                else {
                    var dist = Math.max(Math.abs(dlon), Math.abs(p[1] - q[1]));
                    var k = Math.ceil(dist / stepDeg);
                    for (var s = 1; s < k; s++) {
                        var t = s / k;
                        cur.push([q[0] + dlon * t, q[1] + (p[1] - q[1]) * t]);
                    }
                }
            }
            cur.push(p);
        }
        if (cur.length) subs.push(cur);
        return subs;
    }
    function ensureCables() {
        if (cableMesh || !cableLines || !globe) return;
        var pts = [];
        cableLines.forEach(function (line) {
            densifyCable(line).forEach(function (sub) {
                for (var i = 0; i < sub.length - 1; i++) {
                    pts.push(geoToVec(sub[i][1], sub[i][0], R - 0.1));
                    pts.push(geoToVec(sub[i + 1][1], sub[i + 1][0], R - 0.1));
                }
            });
        });
        cableMesh = new THREE.LineSegments(
            new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({
                color: 0x45b8e0, transparent: true, opacity: 0.32, depthWrite: false
            }));
        cableMesh.renderOrder = -2;
        globe.add(cableMesh);
    }
    function applyLinks() {
        ensureCables();
        if (cableMesh) cableMesh.visible = showFiber;
        if (mode === 'earth') { computeRoutes(); K.rebuildLinks(); }
        else if (mode === 'flat') { clearFlatMap(); buildFlatMap(); }   // cables on/off
    }

    function drawVantageMarker() {
        var va = vantageEarthPos();
        var vm = new THREE.Mesh(
            new THREE.OctahedronGeometry(1.2),
            new THREE.MeshStandardMaterial({ color: 0xdfe8f0, emissive: 0x8899aa, emissiveIntensity: 0.6 }));
        vm.position.copy(va);
        vm.userData = { katzenSelect: function () { K.showVantage(); } };
        K.worldRoot().add(vm); extras.push(vm); K.addPickable(vm);
    }

    function earthPathBuilder(node) {
        if (!node.earthPos) return null;
        var va = vantageEarthPos();
        return K.makeTube(arcPoints(va, node.earthPos, Math.max(24, (node.data.hop_count || 1) * 2)),
            0.45, K.groupColor(node), 0.8);
    }
    function clearExtras() {
        extras.forEach(function (o) {
            K.worldRoot().remove(o);
            K.removePickable(o);
            if (o.geometry) o.geometry.dispose();
            if (o.material) o.material.dispose();
        });
        extras = [];
    }

    function setSceneryVisible(v) {
        var keep = {};
        K.nodes().forEach(function (o) { keep[o.mesh.id] = true; });
        K.clients().forEach(function (c) { keep[c.mesh.id] = true; });
        K.packets().forEach(function (p) { if (p.mesh) keep[p.mesh.id] = true; });   // don't hide in-flight packets
        K.worldRoot().children.forEach(function (ch) {
            if (globe && ch === globe) return;
            if (ch.type === 'Group') return;   // globe and the selection path
            if (extras.indexOf(ch) >= 0) return;
            if (ch.userData && (ch.userData.isLink || ch.userData.isClusterMarker)) return;   // core-managed
            if (!keep[ch.id]) ch.visible = v;
        });
    }

    function cableRoute(a, b) {
        if (!cablePolysVec || !cablePolysVec.length) return null;
        if (a.angleTo(b) < 0.18) return null;          // only very local hops skip fiber
        var gc = a.distanceTo(b), best = null;
        for (var p = 0; p < cablePolysVec.length; p++) {
            var poly = cablePolysVec[p], da = Infinity, ia = 0, db = Infinity, ib = 0;
            for (var i = 0; i < poly.length; i++) {
                var d1 = poly[i].distanceToSquared(a); if (d1 < da) { da = d1; ia = i; }
                var d2 = poly[i].distanceToSquared(b); if (d2 < db) { db = d2; ib = i; }
            }
            if (!best || da + db < best.s) best = { s: da + db, poly: poly, ia: ia, ib: ib };
        }
        if (!best) return null;
        var thr = (0.6 * gc) * (0.6 * gc);             // snap to fiber even when a bit farther
        if (best.poly[best.ia].distanceToSquared(a) > thr) return null;
        if (best.poly[best.ib].distanceToSquared(b) > thr) return null;
        var lo = Math.min(best.ia, best.ib), hi = Math.max(best.ia, best.ib);
        var slice = best.poly.slice(lo, hi + 1);
        if (best.ia > best.ib) slice.reverse();
        var slen = 0;
        for (var s = 0; s < slice.length - 1; s++) slen += slice[s].distanceTo(slice[s + 1]);
        if (slen > 4.0 * gc) return null;              // ...and not a wildly indirect detour
        var pts = [a.clone()];
        for (var j = 0; j < slice.length; j += 3) pts.push(slice[j].clone().setLength(SURF * 1.01));
        pts.push(b.clone());
        return pts;
    }

    function keyOf(v) {
        return Math.round(v.x * 10) + ',' + Math.round(v.y * 10) + ',' + Math.round(v.z * 10);
    }

    var routeMemo = {};   // cache cableRoute per pair within a build (it scans ~1900 cables)
    function routePoints(aObj, bObj) {
        var a = aObj.earthPos, b = bObj.earthPos;
        var isDA = aObj.data.type === 'dirauth' && bObj.data.type === 'dirauth';
        if (!(showFiber && !isDA)) return arcPoints(a, b, 20);
        var key = aObj.data.name + '|' + aObj.data.type + '>' + bObj.data.name + '|' + bObj.data.type;
        var routed = (key in routeMemo) ? routeMemo[key] : (routeMemo[key] = cableRoute(a, b));
        return routed || arcPoints(a, b, 20);
    }

    function computeRoutes() {
        routeIndex = {};
        (K.topoPairs() || []).forEach(function (pr) {
            if (!pr[0] || !pr[1] || !pr[0].earthPos || !pr[1].earthPos) return;
            var pts = routePoints(pr[0], pr[1]);
            var cum = [0];
            for (var j = 1; j < pts.length; j++) cum.push(cum[j - 1] + pts[j].distanceTo(pts[j - 1]));
            var rp = { pts: pts, cum: cum, total: cum[cum.length - 1] || 1 };
            routeIndex[keyOf(pr[0].earthPos) + '>' + keyOf(pr[1].earthPos)] = { rp: rp, fwd: true };
            routeIndex[keyOf(pr[1].earthPos) + '>' + keyOf(pr[0].earthPos)] = { rp: rp, fwd: false };
        });
    }

    function earthLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        if (!aObj.earthPos || !bObj.earthPos) return null;
        var isDA = aObj.data.type === 'dirauth' && bObj.data.type === 'dirauth';
        var pts = routePoints(aObj, bObj);
        var ang = aObj.earthPos.angleTo(bObj.earthPos);
        var op = (opacity == null ? 0.9 : opacity) * (ang > 1.2 ? 0.45 : 1);   // fade long links
        return K.makeTube(pts, (isDA ? 0.14 : 0.22) * (rscale || 1), hex, op);
    }

    function sampleRoute(entry, t) {
        var rp = entry.rp, cum = rp.cum, tt = entry.fwd ? t : 1 - t;
        var target = tt * rp.total, i = 1;
        while (i < cum.length && cum[i] < target) i++;
        var i0 = i - 1, seg = cum[i] - cum[i0] || 1;
        return rp.pts[i0].clone().lerp(rp.pts[i], (target - cum[i0]) / seg);
    }
    function earthSegInterp(a, b, t) {
        var entry = routeIndex[keyOf(a) + '>' + keyOf(b)];
        return entry ? sampleRoute(entry, t) : arcInterp(a, b, t);
    }

    function disposeObj(o) {
        o.traverse(function (c) {
            if (c.geometry) c.geometry.dispose();
            if (c.material) {
                var ms = Array.isArray(c.material) ? c.material : [c.material];
                ms.forEach(function (m) { if (m.map) m.map.dispose(); m.dispose(); });
            }
        });
    }
    function nearSide(o) {
        var wp = o.mesh.getWorldPosition(new THREE.Vector3()), cam = K.camera().position;
        if (wp.lengthSq() < 1 || cam.lengthSq() < 1) return true;
        return wp.normalize().dot(cam.clone().normalize()) > R / cam.length();
    }
    function enterEarth() {
        if (!globe) addGlobe();
        drawVantageMarker();
        K.setLinkBuilder(earthLinkBuilder);
        fullLinksOn();    // route links over the globe
        K.setSegmentInterpolator(earthSegInterp);   // packets follow the routed links
        K.setPathBuilder(earthPathBuilder);    // selected node's path arcs
        K.setOrbitOrigin(true);                // orbit about the globe centre
        K.setPlanar(false);
        K.setClusterFilter(nearSide);
        applyLinks();                          // cable map + routes + redraw shown links
        setSceneryVisible(false);
        buildGeoClients(false);                 // scattered clients around gateways
        K.drawSelectionPath();                 // redraw current selection as an arc
        var c = K.controls();                  // do not let the camera go inside the globe
        if (c) { c.minDistance = R + 6; c.maxDistance = R * 4.2; }
    }
    function leaveEarth() {
        if (globe) { K.worldRoot().remove(globe); disposeObj(globe); globe = null; cableMesh = null; }
        clearExtras();
        clearGeoClients();
        K.setClusterFilter(null);
    }

    function geoToFlat(lat, lon) { return new THREE.Vector3(lon * K_FLAT, lat * K_FLAT, 0); }

    function buildFlatMap() {
        if (flatMap) return;
        flatMap = new THREE.Group();
        var grat = new THREE.LineBasicMaterial({ color: 0xc8791f, transparent: true, opacity: 0.14 });
        for (var la = -60; la <= 60; la += 30)
            flatMap.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([geoToFlat(la, -180), geoToFlat(la, 180)]), grat));
        for (var lo = -180; lo <= 180; lo += 30)
            flatMap.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([geoToFlat(-84, lo), geoToFlat(84, lo)]), grat));
        if (landRings) {
            var lm = new THREE.LineBasicMaterial({ color: 0xffb454, transparent: true, opacity: 0.5 });
            landRings.forEach(function (ring) {
                flatMap.add(new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(
                    ring.map(function (c) { return geoToFlat(c[1], c[0]); })), lm));
            });
        }
        if (showFiber && cableLines) {
            var pts = [];
            cableLines.forEach(function (line) {
                densifyCable(line).forEach(function (sub) {
                    for (var i = 0; i < sub.length - 1; i++) {
                        pts.push(geoToFlat(sub[i][1], sub[i][0]));
                        pts.push(geoToFlat(sub[i + 1][1], sub[i + 1][0]));
                    }
                });
            });
            flatMap.add(new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(pts),
                new THREE.LineBasicMaterial({ color: 0x45b8e0, transparent: true, opacity: 0.3 })));
        }
        flatMap.position.z = -0.5;             // sit just behind the nodes
        K.worldRoot().add(flatMap);
    }
    function clearFlatMap() {
        if (!flatMap) return;
        flatMap.traverse(function (o) { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); });
        K.worldRoot().remove(flatMap); flatMap = null;
    }
    function flatLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        if (!aObj.flatPos || !bObj.flatPos) return null;
        return K.makeTube([aObj.flatPos.clone(), bObj.flatPos.clone()], 0.16 * (rscale || 1), hex,
            opacity == null ? 0.85 : opacity);
    }
    function vantageFlatPos() {
        var v = (K.data() || {}).vantage;
        return (v && typeof v.lat === 'number') ? geoToFlat(v.lat, v.lon) : geoToFlat(25, 0);
    }
    function drawFlatVantage() {
        var vm = new THREE.Mesh(new THREE.OctahedronGeometry(0.9),
            new THREE.MeshStandardMaterial({ color: 0xdfe8f0, emissive: 0x8899aa, emissiveIntensity: 0.6 }));
        vm.position.copy(vantageFlatPos());
        vm.userData = { katzenSelect: function () { K.showVantage(); } };
        K.worldRoot().add(vm); extras.push(vm); K.addPickable(vm);
    }
    function flatPathBuilder(node) {
        if (!node.flatPos) return null;
        return K.makeTube([vantageFlatPos(), node.flatPos.clone()], 0.3, K.groupColor(node), 0.8);
    }
    function ringLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        var a = aObj.ringPos || aObj.mesh.position, b = bObj.ringPos || bObj.mesh.position;
        return K.makeTube([a.clone(), b.clone()], 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function enterFlat() {
        buildFlatMap();
        drawFlatVantage();
        K.setLinkBuilder(flatLinkBuilder);
        fullLinksOn();
        K.setSegmentInterpolator(null);        // straight packet motion on the plane
        K.setPathBuilder(flatPathBuilder);
        K.setOrbitOrigin(false);
        K.setPlanar(true);                     // camera looks at the plane face-on
        K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        buildGeoClients(true);                 // scattered clients around gateways
        K.rebuildLinks();
        K.drawSelectionPath();
        var c = K.controls();
        if (c) { c.minDistance = 5; c.maxDistance = 500; }
    }
    function leaveFlat() { clearFlatMap(); clearExtras(); clearGeoClients(); }

    function clearGeoClients() {
        geoClients.forEach(function (g) {
            [g.marker, g.link, g.flow].forEach(function (m) {
                if (!m) return; K.worldRoot().remove(m);
                if (m.geometry) m.geometry.dispose(); if (m.material) m.material.dispose();
            });
        });
        geoClients = [];
        K.clients().forEach(function (c) { if (c.mesh) c.mesh.visible = true; });
    }
    function buildGeoClients(isFlat) {
        clearGeoClients();
        K.clients().forEach(function (c) { if (c.mesh) c.mesh.visible = false; });
        var perGw = Math.max(1, ((K.data() || {}).clients_per_gateway) || 3);
        K.nodes().filter(function (o) { return o.data.type === 'gateway'; }).forEach(function (gw, gi) {
            if (!gw._bll) return;
            var lat0 = gw._bll[0], lon0 = gw._bll[1];
            var gpos = isFlat ? geoToFlat(lat0, lon0) : geoToVec(lat0, lon0, SURF);
            for (var i = 0; i < perGw; i++) {
                var ang = (i / perGw) * Math.PI * 2 + gi;
                var dr = 4 + (i % 2) * 2.5;
                var lat = lat0 + Math.sin(ang) * dr;
                var lon = lon0 + Math.cos(ang) * dr / Math.max(0.3, Math.cos(lat0 * Math.PI / 180));
                var cpos = isFlat ? geoToFlat(lat, lon) : geoToVec(lat, lon, SURF);
                var marker = new THREE.Mesh(new THREE.SphereGeometry(isFlat ? 0.5 : 0.7, 10, 10),
                    new THREE.MeshBasicMaterial({ color: 0x88bbff }));
                marker.position.copy(cpos); marker.renderOrder = 3; K.worldRoot().add(marker);
                var link = K.makeTube([cpos.clone(), gpos.clone()], isFlat ? 0.06 : 0.1, 0x88bbff, 0.4);
                if (link) { link.renderOrder = -1; K.worldRoot().add(link); }
                var flow = new THREE.Mesh(new THREE.SphereGeometry(isFlat ? 0.3 : 0.42, 8, 8),
                    new THREE.MeshBasicMaterial({ color: 0x00f3ff }));
                flow.renderOrder = 4; K.worldRoot().add(flow);
                geoClients.push({ marker: marker, link: link, flow: flow, a: cpos.clone(), b: gpos.clone(), t: Math.random(), speed: 0.4 + Math.random() * 0.3 });
            }
        });
    }
    function animateGeoClients(dt) {
        for (var i = 0; i < geoClients.length; i++) {
            var g = geoClients[i]; g.t += dt * g.speed; if (g.t >= 1) g.t -= 1;
            g.flow.position.copy(g.a).lerp(g.b, g.t);
        }
    }
    function enterRings() {
        K.setLinkBuilder(ringLinkBuilder);
        fullLinksOn();
        K.setSegmentInterpolator(null);
        K.setPathBuilder(null);
        K.setOrbitOrigin(false);
        K.setPlanar(false);
        K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(true);
        K.rebuildLinks();
        K.drawSelectionPath();
        var c = K.controls();
        if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function frameFlat() {
        var xs = [], ys = [];
        K.nodes().forEach(function (o) { if (o.flatPos) { xs.push(o.flatPos.x); ys.push(o.flatPos.y); } });
        if (!xs.length) return;
        var minx = Math.min.apply(null, xs), maxx = Math.max.apply(null, xs);
        var miny = Math.min.apply(null, ys), maxy = Math.max.apply(null, ys);
        var cx = (minx + maxx) / 2, cy = (miny + maxy) / 2;
        var w = Math.max(6, maxx - minx), h = Math.max(6, maxy - miny);
        var fov = K.camera().fov, asp = K.camera().aspect || 1.5;
        var tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = Math.max(h / (2 * tan), w / (2 * tan * asp)) * 1.35 + 8;
        K.snapTo(cx, cy, dist, cx, cy, 0);
    }

    function cascadeLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        var a = aObj.cascadePos || aObj.mesh.position, b = bObj.cascadePos || bObj.mesh.position;
        return K.makeTube([a.clone(), b.clone()], 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function computeCascade(ns) {
        var maxLayer = 0;
        ns.forEach(function (o) {
            if (o.data.type === 'mix' && typeof o.data.layer === 'number') maxLayer = Math.max(maxLayer, o.data.layer);
        });
        var layerCount = maxLayer + 1;
        function colOf(o) {
            var t = o.data.type;
            if (t === 'gateway') return 0;
            if (t === 'mix') return 1 + (o.data.layer || 0);
            if (t === 'service') return 1 + layerCount;
            if (t === 'storage') return 2 + layerCount;
            return 3 + layerCount;   // out / anything else
        }
        function colDesc(c) {
            if (c === 0) return ['Gateways', 'client entry'];
            if (c >= 1 && c < 1 + layerCount) return ['Mix L' + c, 'unlink + delay'];
            if (c === 1 + layerCount) return ['Services', 'echo / courier / keys'];
            if (c === 2 + layerCount) return ['Storage', 'pigeonhole replicas'];
            return ['Other', 'not in consensus'];
        }
        var dirauths = ns.filter(function (o) { return o.data.type === 'dirauth'; });
        var pipeline = ns.filter(function (o) { return o.data.type !== 'dirauth'; });
        var cols = {};
        pipeline.forEach(function (o) { var c = colOf(o); (cols[c] || (cols[c] = [])).push(o); });
        var keys = Object.keys(cols).map(Number).sort(function (a, b) { return a - b; });
        var COLW = 11, ROWH = 4.4;
        var nCols = keys.length, total = nCols + 1, center = (total - 1) / 2;
        function xAt(pos) { return (pos - center) * COLW; }
        cascadeHeaders = [];
        var maxTopY = ROWH;
        keys.forEach(function (c, ci) {
            var g = cols[c], k = g.length;
            g.sort(function (a, b) { return (a.data.name || '').localeCompare(b.data.name || ''); });
            var x = xAt(ci + 1);
            g.forEach(function (o, i) { o.cascadePos = new THREE.Vector3(x, ((k - 1) / 2 - i) * ROWH, 0); });
            var topY = ((k - 1) / 2) * ROWH; if (topY > maxTopY) maxTopY = topY;
            var d = colDesc(c), hH = topY + 2.4;
            cascadeHeaders.push({ x: x, cy: 0, halfW: COLW * 0.42, halfH: hH, y: hH + 2.2, title: d[0], subtitle: d[1] });
        });
        var gateways = pipeline.filter(function (o) { return o.data.type === 'gateway'; });
        var nClients = Math.min(6, Math.max(3, gateways.length));
        var clientX = xAt(0);
        cascadeClients = [];
        for (var i = 0; i < nClients; i++) {
            var gw = gateways.length ? gateways[i % gateways.length] : null;
            cascadeClients.push({ pos: new THREE.Vector3(clientX, ((nClients - 1) / 2 - i) * ROWH, 0), gw: gw, gwPos: gw ? gw.cascadePos : null });
        }
        var chH = ((nClients - 1) / 2) * ROWH + 2.4;
        cascadeHeaders.push({ x: clientX, cy: 0, halfW: COLW * 0.42, halfH: chH, y: chH + 2.2, title: 'Clients', subtitle: 'send + receive' });
        var bandY = maxTopY + 11, xL = xAt(0), xR = xAt(total - 1);
        dirauths.sort(function (a, b) { return (a.data.name || '').localeCompare(b.data.name || ''); });
        var dn = dirauths.length;
        dirauths.forEach(function (o, i) {
            var x = dn <= 1 ? (xL + xR) / 2 : xL + (xR - xL) * (i / (dn - 1));
            o.cascadePos = new THREE.Vector3(x, bandY, 0);
        });
        if (dn) {
            var dHW = (xR - xL) / 2 + COLW * 0.42, dHH = 2.6;
            cascadeHeaders.push({ x: (xL + xR) / 2, cy: bandY, halfW: dHW, halfH: dHH, y: bandY + dHH + 2.2, title: 'Directory Authorities', subtitle: 'sign the consensus for every node' });
        }
        cascadeTopY = bandY + 8;
    }
    function makeTextSprite(title, subtitle) {
        var W = 320, H = 96, cv = document.createElement('canvas');
        cv.width = W; cv.height = H;
        var g = cv.getContext('2d');
        g.textAlign = 'center'; g.textBaseline = 'middle';
        g.font = 'bold 26px monospace'; g.fillStyle = '#ffb454';
        g.fillText(title, W / 2, 28);
        g.font = '15px monospace'; g.fillStyle = '#9fb3c2';
        g.fillText(subtitle, W / 2, 62);
        var tex = new THREE.CanvasTexture(cv); tex.minFilter = THREE.LinearFilter;
        var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
        sp.scale.set(18, 5.4, 1);
        return sp;
    }
    function clearCascadeExtras() {
        cascadeExtras.forEach(function (s) {
            K.worldRoot().remove(s);
            if (s.geometry) s.geometry.dispose();
            if (s.material) { if (s.material.map) s.material.map.dispose(); s.material.dispose(); }
        });
        cascadeExtras = [];
        cascadeFlow = [];
    }
    function buildCascadeFlow(clients) {
        var ns = K.nodes();
        var gws = ns.filter(function (o) { return o.data.type === 'gateway'; });
        var svcs = ns.filter(function (o) { return o.data.type === 'service'; });
        if (!gws.length) return;
        var mixByLayer = {}, maxL = 0;
        ns.forEach(function (o) { if (o.data.type === 'mix') { var L = o.data.layer || 0; (mixByLayer[L] || (mixByLayer[L] = [])).push(o); if (L > maxL) maxL = L; } });
        function pick(a) { return a && a.length ? a[Math.floor(Math.random() * a.length)] : null; }
        var nFlow = Math.min(7, Math.max(4, (clients && clients.length) || 4));
        for (var i = 0; i < nFlow; i++) {
            // Start at THIS client's own gateway so the dot follows the drawn
            // client->gateway line instead of flying off to a random gateway.
            var client = (clients && clients.length) ? clients[i % clients.length] : null;
            var gw = (client && client.gw) ? client.gw : pick(gws);
            if (!gw) continue;
            var stops = [gw];
            for (var L = 0; L <= maxL; L++) { var m = pick(mixByLayer[L]); if (m) stops.push(m); }
            if (svcs.length) stops.push(pick(svcs));
            stops = stops.filter(Boolean);
            var cpos = client ? client.pos.clone() : (gw.cascadePos || gw.mesh.position).clone();
            var dot = new THREE.Mesh(new THREE.SphereGeometry(0.42, 10, 10),
                new THREE.MeshBasicMaterial({ color: 0x00f3ff }));
            dot.renderOrder = 4; K.worldRoot().add(dot); cascadeExtras.push(dot);
            cascadeFlow.push({ clientPos: cpos, stops: stops, seg: 0, t: Math.random(), speed: 0.5 + Math.random() * 0.4, mesh: dot });
        }
    }
    function animateCascadeFlow(dt) {
        for (var i = 0; i < cascadeFlow.length; i++) {
            var f = cascadeFlow[i];
            var pts = [f.clientPos];
            for (var k = 0; k < f.stops.length; k++) pts.push(f.stops[k].mesh.position);
            var nseg = pts.length - 1;
            f.t += dt * f.speed;
            while (f.t >= 1) { f.t -= 1; f.seg = (f.seg + 1) % nseg; }
            f.mesh.position.copy(pts[f.seg]).lerp(pts[f.seg + 1], f.t);
        }
    }
    function roundedRectLoop(hw, hh, rad, colorHex) {
        var r = Math.min(rad, hw, hh), pts = [], seg = 5, i, a, cx, cy;
        var corners = [[hw - r, hh - r, 0], [-(hw - r), hh - r, Math.PI / 2],
        [-(hw - r), -(hh - r), Math.PI], [hw - r, -(hh - r), 3 * Math.PI / 2]];
        corners.forEach(function (c) {
            cx = c[0]; cy = c[1];
            for (i = 0; i <= seg; i++) { a = c[2] + (i / seg) * (Math.PI / 2); pts.push(new THREE.Vector3(cx + Math.cos(a) * r, cy + Math.sin(a) * r, 0)); }
        });
        return new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({ color: colorHex, transparent: true, opacity: 0.5 }));
    }
    function addCascadeExtras(headers, clients) {
        clearCascadeExtras();
        (headers || []).forEach(function (h) {
            if (h.halfW && h.halfH) {
                var box = roundedRectLoop(h.halfW, h.halfH, 1.4, 0xffb454);
                box.position.set(h.x, h.cy, 0); box.renderOrder = 4;
                K.worldRoot().add(box); cascadeExtras.push(box);
            }
            var sp = makeTextSprite(h.title, h.subtitle);
            sp.position.set(h.x, h.y, h.z || 0); sp.renderOrder = 5;
            K.worldRoot().add(sp); cascadeExtras.push(sp);
        });
        (clients || []).forEach(function (c) {
            var m = new THREE.Mesh(new THREE.SphereGeometry(0.7, 12, 12),
                new THREE.MeshBasicMaterial({ color: 0x88bbff }));
            m.position.copy(c.pos); m.renderOrder = 3;
            K.worldRoot().add(m); cascadeExtras.push(m);
            var gp = c.gwPos || (c.gw && (c.gw.cascadePos || c.gw.mesh.position));
            if (gp) {
                var tube = K.makeTube([c.pos.clone(), gp.clone()], 0.08, 0x88bbff, 0.4);
                if (tube) { tube.renderOrder = 1; K.worldRoot().add(tube); cascadeExtras.push(tube); }
            }
        });
    }
    function enterCascade() {
        K.setLinkBuilder(cascadeLinkBuilder);
        fullLinksOn();
        K.setSegmentInterpolator(null);
        K.setPathBuilder(null);
        K.setOrbitOrigin(false);
        K.setPlanar(true);                     // look at the layered plane face-on
        K.setClusterFilter(noCluster);         // show every node; the layer box groups them
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);              // no rings/globe behind the columns
        addCascadeExtras(cascadeHeaders, cascadeClients);   // headers, client dots, links
        buildCascadeFlow(cascadeClients);
        K.rebuildLinks();
        K.drawSelectionPath();
        var c = K.controls();
        if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function leaveCascade() { clearCascadeExtras(); }
    function frameCascade() {
        var xs = [], ys = [];
        K.nodes().forEach(function (o) { if (o.cascadePos) { xs.push(o.cascadePos.x); ys.push(o.cascadePos.y); } });
        cascadeClients.forEach(function (c) { xs.push(c.pos.x); ys.push(c.pos.y); });
        if (!xs.length) return;
        var minx = Math.min.apply(null, xs), maxx = Math.max.apply(null, xs);
        var miny = Math.min.apply(null, ys), maxy = Math.max.apply(null, ys);
        maxy = Math.max(maxy + 4, cascadeTopY);   // include the dir-auth band + headers
        var cx = (minx + maxx) / 2, cy = (miny + maxy) / 2;
        var w = Math.max(6, maxx - minx), h = Math.max(6, maxy - miny);
        var fov = K.camera().fov, asp = K.camera().aspect || 1.5;
        var tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var panel = document.getElementById('hud-panel');
        var vw = window.innerWidth || 1;
        var pw = (panel && !panel.classList.contains('hidden')) ? panel.getBoundingClientRect().width : 0;
        if (pw > vw * 0.6) pw = 0;
        var visFrac = (vw - pw) / vw, effAsp = asp * visFrac;
        var dist = Math.max(h / (2 * tan), w / (2 * tan * effAsp)) * 1.3 + 8;
        var shift = (pw / vw) * (2 * dist * tan * asp) * 0.5;
        K.snapTo(cx - shift, cy, dist, cx - shift, cy, 0);
    }

    var GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
    function noCluster() { return false; }   // exclude every node from LOD clustering
    function tierRank(o) {
        var t = o.data.type;
        return t === 'dirauth' ? 0 : t === 'gateway' ? 1 : t === 'mix' ? 2 : t === 'service' ? 3 : t === 'storage' ? 4 : 5;
    }
    function tierSort(a, b) {
        var d = tierRank(a) - tierRank(b); if (d) return d;
        var la = a.data.layer == null ? 0 : a.data.layer, lb = b.data.layer == null ? 0 : b.data.layer;
        return (la - lb) || (a.data.name || '').localeCompare(b.data.name || '');
    }
    function straightLinkBuilder(field) {
        return function (aObj, bObj, hex, opacity, rscale) {
            var a = aObj[field] || aObj.mesh.position, b = bObj[field] || bObj.mesh.position;
            return K.makeTube([a.clone(), b.clone()], 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
        };
    }
    function computeSpiral(ns) {
        var order = ns.slice().sort(function (a, b) {
            var d = tierRank(a) - tierRank(b); if (d) return d;
            var la = a.data.layer == null ? 0 : a.data.layer, lb = b.data.layer == null ? 0 : b.data.layer;
            return (la - lb) || (a.data.name || '').localeCompare(b.data.name || '');
        });
        var n = order.length, turns = 3, H = 34;
        order.forEach(function (o, i) {
            var frac = n <= 1 ? 0 : i / (n - 1);
            var th = frac * turns * Math.PI * 2, r = 3 + (1 - frac) * 22, y = (frac - 0.5) * H;
            o.spiralPos = new THREE.Vector3(Math.cos(th) * r, y, Math.sin(th) * r);
        });
    }
    var spiralLinkBuilder = straightLinkBuilder('spiralPos');
    function enterSpiral() {
        K.setLinkBuilder(spiralLinkBuilder);
        structLinksOn();
        K.setSegmentInterpolator(null);
        K.setPathBuilder(null);
        K.setOrbitOrigin(true);
        K.setPlanar(false);
        K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        K.rebuildLinks();
        K.drawSelectionPath();
        var c = K.controls();
        if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function frameSpiral() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (26 / tan) * 1.25 + 12;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.55, dist * 0.28, dist * 0.75, 0, 0, 0);
    }

    // Flower of Life: nodes on concentric hex rings by tier (gateways central,
    // mix layers outward, services on the rim); the overlapping circles are
    // drawn as scenery. Logical placement, face-on.
    var flowerExtras = [], maxFlowerRing = 0, FLOWER_S = 6;
    function computeFlower(ns) {
        var order = ns.slice().sort(tierSort);
        maxFlowerRing = 0;
        order.forEach(function (o, idx) {
            var r = 0, base = 0;
            while (base + (r === 0 ? 1 : 6 * r) <= idx) { base += (r === 0 ? 1 : 6 * r); r++; }
            var cap = r === 0 ? 1 : 6 * r, rad = r * FLOWER_S;
            var ang = cap > 0 ? (idx - base) / cap * Math.PI * 2 : 0;
            if (r > maxFlowerRing) maxFlowerRing = r;
            o.flowerPos = new THREE.Vector3(Math.cos(ang) * rad, Math.sin(ang) * rad, (r % 2 ? 1 : -1) * 1.6);
        });
    }
    function clearFlowerExtras() {
        flowerExtras.forEach(function (s) { K.worldRoot().remove(s); if (s.geometry) s.geometry.dispose(); if (s.material) s.material.dispose(); });
        flowerExtras = [];
    }
    function drawFlowerCircles() {
        var seg = 40;
        for (var r = 0; r <= maxFlowerRing; r++) {
            var cnt = r === 0 ? 1 : 6 * r;
            for (var k = 0; k < cnt; k++) {
                var a = (k / cnt) * Math.PI * 2, cx = Math.cos(a) * r * FLOWER_S, cy = Math.sin(a) * r * FLOWER_S, pts = [];
                for (var i = 0; i <= seg; i++) { var t = (i / seg) * Math.PI * 2; pts.push(new THREE.Vector3(cx + Math.cos(t) * FLOWER_S, cy + Math.sin(t) * FLOWER_S, 0)); }
                var cir = new THREE.LineLoop(new THREE.BufferGeometry().setFromPoints(pts),
                    new THREE.LineBasicMaterial({ color: 0x2ec4b6, transparent: true, opacity: 0.13 }));
                cir.renderOrder = -1; K.worldRoot().add(cir); flowerExtras.push(cir);
            }
        }
    }
    function enterFlower() {
        clearFlowerExtras();
        K.setLinkBuilder(straightLinkBuilder('flowerPos'));
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(false); K.setPlanar(true); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        drawFlowerCircles();
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 260; }
    }
    function leaveFlower() { clearFlowerExtras(); }
    function frameFlower() {
        var span = (maxFlowerRing + 1) * FLOWER_S;
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (span / tan) * 1.15 + 10;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(0, 0, dist, 0, 0, 0);
    }

    var FIB_R = 26;
    function computeFib(ns) {
        var order = ns.slice().sort(function (a, b) {
            var d = tierRank(a) - tierRank(b); if (d) return d;
            var la = a.data.layer == null ? 0 : a.data.layer, lb = b.data.layer == null ? 0 : b.data.layer;
            return (la - lb) || (a.data.name || '').localeCompare(b.data.name || '');
        });
        var n = order.length;
        order.forEach(function (o, i) {
            var y = n === 1 ? 0 : 1 - (i / (n - 1)) * 2;   // 1 .. -1
            var rad = Math.sqrt(Math.max(0, 1 - y * y)), th = i * GOLDEN_ANGLE;
            o.fibPos = new THREE.Vector3(Math.cos(th) * rad * FIB_R, y * FIB_R, Math.sin(th) * rad * FIB_R);
        });
    }
    function fibLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        var a = aObj.fibPos || aObj.mesh.position, b = bObj.fibPos || bObj.mesh.position;
        return K.makeTube([a.clone(), b.clone()], 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function enterFib() {
        K.setLinkBuilder(fibLinkBuilder);
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function frameFib() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (FIB_R / tan) * 1.5 + 10;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.4, dist * 0.25, dist, 0, 0, 0);
    }

    var HC_SIZE = 15, hcWire = null, hcVerts4 = null, hcEdges = null, hcAngle = 0;
    function hcInit() {
        hcVerts4 = [];
        for (var v = 0; v < 16; v++) {
            hcVerts4.push([(v & 1) ? 1 : -1, (v & 2) ? 1 : -1, (v & 4) ? 1 : -1, (v & 8) ? 1 : -1]);
        }
        hcEdges = [];
        for (var a = 0; a < 16; a++) for (var b = a + 1; b < 16; b++) {
            var diff = a ^ b;
            if (diff && (diff & (diff - 1)) === 0) hcEdges.push([a, b]);   // differ in one bit
        }
    }
    function hcProject(v4) {   // rotate in the XW and ZW planes, then perspective-project 4D->3D
        var c1 = Math.cos(hcAngle), s1 = Math.sin(hcAngle);
        var c2 = Math.cos(hcAngle * 0.6), s2 = Math.sin(hcAngle * 0.6);
        var x = v4[0], y = v4[1], z = v4[2], w = v4[3];
        var x2 = x * c1 - w * s1, w2 = x * s1 + w * c1;         // XW rotation
        var z2 = z * c2 - w2 * s2, w3 = z * s2 + w2 * c2;       // ZW rotation
        var k = 2.2 / (2.2 - w3);                               // 4D perspective
        return new THREE.Vector3(x2 * k * HC_SIZE, y * k * HC_SIZE, z2 * k * HC_SIZE);
    }
    function computeHyper(ns) {
        if (!hcVerts4) hcInit();
        var order = ns.slice().sort(function (a, b) {
            var d = tierRank(a) - tierRank(b); return d || (a.data.name || '').localeCompare(b.data.name || '');
        });
        var perV = {};
        order.forEach(function (o, i) {
            var v = i % 16; o._hcV = v;
            var seen = (perV[v] = (perV[v] || 0)); perV[v]++;
            o._hcJit = new THREE.Vector3((seen % 2 ? 1 : -1) * seen * 0.8, seen * 0.8, 0);
        });
    }
    function hyperLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        var a = aObj.mesh.position, b = bObj.mesh.position;
        return K.makeTube([a.clone(), b.clone()], 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function updateHyper() {   // per-frame: project vertices, move nodes, redraw the wireframe
        var proj = hcVerts4.map(hcProject);
        K.nodes().forEach(function (o) {
            if (o._hcV == null) return;
            o.mesh.position.copy(proj[o._hcV]).add(o._hcJit || ZERO3);
        });
        var pts = [];
        hcEdges.forEach(function (e) { pts.push(proj[e[0]], proj[e[1]]); });
        if (!hcWire) {
            hcWire = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(pts),
                new THREE.LineBasicMaterial({ color: 0x8f7bff, transparent: true, opacity: 0.35, depthWrite: false }));
            hcWire.renderOrder = -1;
            K.worldRoot().add(hcWire);
        } else {
            hcWire.geometry.setFromPoints(pts);
            hcWire.geometry.attributes.position.needsUpdate = true;
        }
    }
    var ZERO3 = new THREE.Vector3();
    function enterHyper() {
        K.setLinkBuilder(hyperLinkBuilder);
        ownLinksOnly();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        computeHyper(K.nodes()); updateHyper();
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function leaveHyper() {
        if (hcWire) { K.worldRoot().remove(hcWire); hcWire.geometry.dispose(); hcWire.material.dispose(); hcWire = null; }
    }
    function frameHyper() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (HC_SIZE * 2.4 / tan) * 1.2 + 10;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.3, dist * 0.2, dist, 0, 0, 0);
    }

    function computeTorus(ns) {
        var order = ns.slice().sort(tierSort), n = order.length, S = 7.5;
        order.forEach(function (o, i) {
            var t = (i / n) * Math.PI * 2;
            o.torusPos = new THREE.Vector3(
                (Math.sin(t) + 2 * Math.sin(2 * t)) * S,
                (Math.cos(t) - 2 * Math.cos(2 * t)) * S,
                -Math.sin(3 * t) * S);
        });
    }
    function enterTorus() {
        K.setLinkBuilder(straightLinkBuilder('torusPos'));
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function frameTorus() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (22 / tan) * 1.3 + 10;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.25, dist * 0.2, dist, 0, 0, 0);
    }

    function computeHelix(ns) {
        var order = ns.slice().sort(tierSort), n = order.length;
        var R = 9, rise = 2.4, turn = 0.62, levels = Math.ceil(n / 2);
        order.forEach(function (o, i) {
            var level = Math.floor(i / 2), strand = i % 2;
            var ang = level * turn + strand * Math.PI;
            o.helixPos = new THREE.Vector3(
                Math.cos(ang) * R, (level - (levels - 1) / 2) * rise, Math.sin(ang) * R);
        });
    }
    function enterHelix() {
        K.setLinkBuilder(straightLinkBuilder('helixPos'));
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 260; }
    }
    function frameHelix() {
        var n = K.nodes().length, h = Math.max(20, Math.ceil(n / 2) * 2.4);
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (h / 2 / tan) * 1.2 + 14;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.7, 0, dist * 0.7, 0, 0, 0);
    }

    // Mobius strip as one continuous edge curve: nodes sit in order along the
    // single boundary line (which loops twice through the half-twist), and both
    // the links and the packets flow along that line.
    var MOB_R = 20, MOB_W = 6, mobiusExtras = [], mobiusRoute = {};
    function mobiusEdge(u) {
        var half = u / 2, rad = MOB_R + MOB_W * Math.cos(half);
        return new THREE.Vector3(Math.cos(u) * rad, MOB_W * Math.sin(half), Math.sin(u) * rad);
    }
    function computeMobius(ns) {
        var order = ns.slice().sort(tierSort), n = order.length;
        order.forEach(function (o, i) {
            o.mobiusU = (i / n) * Math.PI * 4;   // spread along the full single edge
            o.mobiusPos = mobiusEdge(o.mobiusU);
        });
    }
    function mobiusArc(ua, ub, segs) {
        var pts = []; for (var i = 0; i <= segs; i++) pts.push(mobiusEdge(ua + (ub - ua) * (i / segs))); return pts;
    }
    function mobiusLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        if (aObj.mobiusU == null || bObj.mobiusU == null) return null;
        return K.makeTube(mobiusArc(aObj.mobiusU, bObj.mobiusU, 22), 0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function computeMobiusRoutes() {
        mobiusRoute = {};
        (K.topoPairs() || []).forEach(function (pr) {
            if (!pr[0] || !pr[1] || pr[0].mobiusU == null || pr[1].mobiusU == null) return;
            var arc = mobiusArc(pr[0].mobiusU, pr[1].mobiusU, 22), cum = [0];
            for (var j = 1; j < arc.length; j++) cum.push(cum[j - 1] + arc[j].distanceTo(arc[j - 1]));
            var rp = { pts: arc, cum: cum, total: cum[cum.length - 1] || 1 };
            mobiusRoute[keyOf(pr[0].mobiusPos) + '>' + keyOf(pr[1].mobiusPos)] = { rp: rp, fwd: true };
            mobiusRoute[keyOf(pr[1].mobiusPos) + '>' + keyOf(pr[0].mobiusPos)] = { rp: rp, fwd: false };
        });
    }
    function mobiusSegInterp(a, b, t) {
        var e = mobiusRoute[keyOf(a) + '>' + keyOf(b)];
        if (!e) return a.clone().lerp(b, t);
        return sampleRoute(e, t);
    }
    function clearMobiusExtras() {
        mobiusExtras.forEach(function (s) { K.worldRoot().remove(s); if (s.geometry) s.geometry.dispose(); if (s.material) s.material.dispose(); });
        mobiusExtras = [];
    }
    function drawMobiusEdge() {
        var pts = [], S = 260;
        for (var i = 0; i <= S; i++) pts.push(mobiusEdge(i / S * Math.PI * 4));
        var line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({ color: 0x9b5de5, transparent: true, opacity: 0.5 }));
        line.renderOrder = -1; K.worldRoot().add(line); mobiusExtras.push(line);
    }
    function enterMobius() {
        clearMobiusExtras();
        K.setLinkBuilder(mobiusLinkBuilder);
        structLinksOn();
        K.setSegmentInterpolator(mobiusSegInterp); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        drawMobiusEdge();
        computeMobiusRoutes();
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 240; }
    }
    function leaveMobius() { clearMobiusExtras(); }
    function frameMobius() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (30 / tan) * 1.25 + 12;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.25, dist * 0.45, dist, 0, 0, 0);
    }

    function computeTimeSpiral(ns) {
        var order = ns.slice().sort(tierSort), n = order.length, turns = 3;
        order.forEach(function (o, i) {
            var frac = n <= 1 ? 0 : i / (n - 1), th = frac * turns * Math.PI * 2, r = 3 + frac * 26;
            o.tspiralPos = new THREE.Vector3(Math.cos(th) * r, Math.sin(th) * r, 0);
        });
    }
    function enterTimeSpiral() {
        K.setLinkBuilder(straightLinkBuilder('tspiralPos'));
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(false); K.setPlanar(true); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 220; }
    }
    function frameTimeSpiral() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (30 / tan) * 1.3 + 8;
        K.snapTo(0, 0, dist, 0, 0, 0);
    }

    var forceEdges = null, forceWire = null;
    function forceEdgeList(ns) {
        var edges = [], mixByLayer = {}, gws = [], svcs = [], stor = [], dirs = [], maxL = 0, i, j;
        ns.forEach(function (o, k) {
            var t = o.data.type;
            if (t === 'mix') { var L = o.data.layer || 0; (mixByLayer[L] || (mixByLayer[L] = [])).push(k); if (L > maxL) maxL = L; }
            else if (t === 'gateway') gws.push(k);
            else if (t === 'service') svcs.push(k);
            else if (t === 'storage') stor.push(k);
            else if (t === 'dirauth') dirs.push(k);
        });
        dirs.forEach(function (d) { ns.forEach(function (o, k) { if (k !== d) edges.push([d, k]); }); });
        (mixByLayer[0] || []).forEach(function (m) { gws.forEach(function (g) { edges.push([g, m]); }); });
        for (var L = 0; L < maxL; L++) {
            (mixByLayer[L] || []).forEach(function (a) { (mixByLayer[L + 1] || []).forEach(function (b) { edges.push([a, b]); }); });
        }
        (mixByLayer[maxL] || []).forEach(function (a) { svcs.forEach(function (s) { edges.push([a, s]); }); });
        svcs.forEach(function (s) {
            var caps = (ns[s].data.details || {}).capabilities || [];
            if (caps.indexOf('courier') >= 0) stor.forEach(function (st) { edges.push([s, st]); });
        });
        for (i = 0; i < stor.length; i++) for (j = i + 1; j < stor.length; j++) edges.push([stor[i], stor[j]]);
        return edges;
    }
    function computeForce(ns) {
        forceEdges = forceEdgeList(ns);
        ns.forEach(function (o, i) {
            var a = i * GOLDEN_ANGLE, r = 8 + (i % 5) * 2;
            o.forcePos = new THREE.Vector3(Math.cos(a) * r, Math.sin(a) * r, ((i % 7) - 3) * 3);
            o.forceVel = new THREE.Vector3();
        });
    }
    function updateForce(dt) {
        var ns = K.nodes(), n = ns.length, i, j;
        if (!n || !forceEdges) return;
        dt = Math.min(dt, 0.05);
        var KREP = 260, KSPRING = 0.9, REST = 11, KC = 0.06, DAMP = 0.85, VMAX = 40;
        var fx = [], fy = [], fz = [], d = new THREE.Vector3();
        for (i = 0; i < n; i++) { fx[i] = 0; fy[i] = 0; fz[i] = 0; }
        for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) {
            d.copy(ns[i].forcePos).sub(ns[j].forcePos);
            var dist = d.length() + 0.05, f = Math.min(KREP / (dist * dist), 60) / dist;
            fx[i] += d.x * f; fy[i] += d.y * f; fz[i] += d.z * f;
            fx[j] -= d.x * f; fy[j] -= d.y * f; fz[j] -= d.z * f;
        }
        forceEdges.forEach(function (e) {
            var a = e[0], b = e[1];
            d.copy(ns[b].forcePos).sub(ns[a].forcePos);
            var dist = d.length() + 0.05, s = KSPRING * (dist - REST) / dist;
            fx[a] += d.x * s; fy[a] += d.y * s; fz[a] += d.z * s;
            fx[b] -= d.x * s; fy[b] -= d.y * s; fz[b] -= d.z * s;
        });
        for (i = 0; i < n; i++) {
            var o = ns[i], p = o.forcePos, v = o.forceVel;
            v.x = (v.x + (fx[i] - p.x * KC) * dt) * DAMP;
            v.y = (v.y + (fy[i] - p.y * KC) * dt) * DAMP;
            v.z = (v.z + (fz[i] - p.z * KC) * dt) * DAMP;
            var sp = v.length(); if (sp > VMAX) v.multiplyScalar(VMAX / sp);
            p.addScaledVector(v, dt);
            o.mesh.position.copy(p);
        }
        var pts = [];
        forceEdges.forEach(function (e) { pts.push(ns[e[0]].forcePos, ns[e[1]].forcePos); });
        if (!forceWire) {
            forceWire = new THREE.LineSegments(new THREE.BufferGeometry().setFromPoints(pts),
                new THREE.LineBasicMaterial({ color: 0x4d8bf0, transparent: true, opacity: 0.22, depthWrite: false }));
            forceWire.renderOrder = -1; K.worldRoot().add(forceWire);
        } else {
            forceWire.geometry.setFromPoints(pts);
            forceWire.geometry.attributes.position.needsUpdate = true;
        }
    }
    function enterForce() {
        K.setLinkBuilder(straightLinkBuilder('forcePos'));
        ownLinksOnly();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(null);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        computeForce(K.nodes());
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 260; }
    }
    function leaveForce() {
        if (forceWire) { K.worldRoot().remove(forceWire); forceWire.geometry.dispose(); forceWire.material.dispose(); forceWire = null; }
    }
    function frameForce() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (30 / tan) * 1.2 + 12;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.4, dist * 0.2, dist, 0, 0, 0);
    }

    var DEP_LEVEL = 9, DEP_GROUND = -9;
    var dependGroups = [], dependExtras = [];
    function thresholdFor(key, x) {
        if (key === 'dirauth') return Math.min(x, Math.floor(x / 2) + 1);
        if (key === 'storage') return Math.min(x, 2);
        return Math.min(x, 1);   // a mix layer, gateway or service needs at least one
    }
    function depGroups(ns) {
        var byType = { dirauth: [], gateway: [], service: [], storage: [], out: [] }, mixByLayer = {};
        ns.forEach(function (o) {
            var t = o.data.type;
            if (t === 'mix') { var L = o.data.layer || 0; (mixByLayer[L] || (mixByLayer[L] = [])).push(o); }
            else if (byType[t]) byType[t].push(o);
        });
        var order = [];
        function add(key, label, arr) {
            if (!arr || !arr.length) return;
            var a = arr.slice().sort(function (x, y) { return (x.data.name || '').localeCompare(y.data.name || ''); });
            order.push({ key: key, label: label, nodes: a, count: a.length, thresh: thresholdFor(key, a.length) });
        }
        add('dirauth', 'Dir auth', byType.dirauth);
        add('storage', 'Storage', byType.storage);
        Object.keys(mixByLayer).map(Number).sort(function (a, b) { return a - b; })
            .forEach(function (L) { add('mix' + L, 'Mix L' + (L + 1), mixByLayer[L]); });
        add('gateway', 'Gateways', byType.gateway);
        add('service', 'Services', byType.service);
        add('out', 'Not in consensus', byType.out);
        return order;
    }
    function computeDepend(ns) {
        dependGroups = depGroups(ns);
        dependGroups.forEach(function (g, gi) {
            var baseY = gi * DEP_LEVEL, baseAng = gi * 1.25;
            g.baseY = baseY;
            g.nodes.forEach(function (o, j) {
                var ang = baseAng + j * 0.7, r = 5 + j * 1.35, y = baseY + j * 1.0;
                o.dependPos = new THREE.Vector3(Math.cos(ang) * r, y, Math.sin(ang) * r);
            });
        });
    }
    var dependLinkBuilder = straightLinkBuilder('dependPos');
    function clearDependExtras() {
        dependExtras.forEach(function (m) {
            K.worldRoot().remove(m);
            if (m.geometry) m.geometry.dispose();
            if (m.material) { if (m.material.map) m.material.map.dispose(); m.material.dispose(); }
        });
        dependExtras = [];
    }
    function buildDependExtras() {
        clearDependExtras();
        function push(m) { if (m) { K.worldRoot().add(m); dependExtras.push(m); } }
        dependGroups.forEach(function (g) {
            var pts = g.nodes.map(function (o) { return o.dependPos; });
            if (g.thresh >= 2) {
                push(K.makeTube(pts.slice(0, g.thresh).map(function (p) { return p.clone(); }), 0.24, 0x00e0a0, 0.8));
            }
            if (g.count > g.thresh) {
                push(K.makeTube(pts.slice(g.thresh - 1).map(function (p) { return p.clone(); }), 0.1, 0x66788a, 0.5));
            }
            var tp = pts[Math.min(g.thresh, g.count) - 1];
            var ring = new THREE.Mesh(new THREE.TorusGeometry(1.5, 0.14, 8, 22),
                new THREE.MeshBasicMaterial({ color: 0xffb454, transparent: true, opacity: 0.85 }));
            ring.position.copy(tp); ring.lookAt(tp.x * 2, tp.y, tp.z * 2); push(ring);
            if (g.key === 'dirauth') {
                g.nodes.forEach(function (o) {
                    var p = o.dependPos, h = p.y - DEP_GROUND;
                    var pil = new THREE.Mesh(new THREE.CylinderGeometry(0.28, 0.5, h, 8),
                        new THREE.MeshStandardMaterial({ color: 0x1a1f2a, emissive: 0xffd23f, emissiveIntensity: 0.25, roughness: 0.6 }));
                    pil.position.set(p.x, (p.y + DEP_GROUND) / 2, p.z); push(pil);
                });
            }
            var spare = g.count - g.thresh;
            var sub = g.thresh + ' of ' + g.count + ' required' + (spare > 0 ? ' (' + spare + ' spare)' : ' (no spare)');
            var lab = makeTextSprite(g.label, sub);
            lab.position.set(pts[0].x * 1.15, g.baseY + 3, pts[0].z * 1.15); lab.renderOrder = 5; push(lab);
        });
        var disk = new THREE.Mesh(new THREE.CircleGeometry(10, 40),
            new THREE.MeshBasicMaterial({ color: 0xffd23f, transparent: true, opacity: 0.06, side: THREE.DoubleSide }));
        disk.rotation.x = Math.PI / 2; disk.position.y = DEP_GROUND; push(disk);
    }
    function enterDepend() {
        K.setLinkBuilder(dependLinkBuilder);
        structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        buildDependExtras();
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function leaveDepend() { clearDependExtras(); }
    function frameDepend() {
        var top = DEP_LEVEL * Math.max(1, dependGroups.length);
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (top / 2 / tan) * 1.25 + 16;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.75, top * 0.35, dist * 0.75, 0, top * 0.35, 0);
    }

    var structExtras = [], structGroups = [];
    function clearStructExtras() {
        structExtras.forEach(function (m) {
            K.worldRoot().remove(m);
            if (m.geometry) m.geometry.dispose();
            if (m.material) { if (m.material.map) m.material.map.dispose(); m.material.dispose(); }
        });
        structExtras = [];
    }
    function pushStruct(m) { if (m) { K.worldRoot().add(m); structExtras.push(m); } }
    function threshLabel(g) {
        var spare = g.count - g.thresh;
        return g.thresh + ' of ' + g.count + ' required' + (spare > 0 ? ' (' + spare + ' spare)' : ' (no spare)');
    }
    function frame3q(ext, cy) {   // a 3/4 elevated framing for a structure of vertical extent `ext`
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (ext / 2 / tan) * 1.3 + 14;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.7, cy + ext * 0.25, dist * 0.7, 0, cy, 0);
    }
    var AMBER = 0xffb454, REQ = 0x00e0a0, DIM = 0x66788a;

    var JEN_LH = 4.2, JEN_BW = 2.8;
    function computeJenga(ns) {
        structGroups = depGroups(ns);
        structGroups.forEach(function (g, gi) {
            var horiz = (gi % 2 === 0);
            g.nodes.forEach(function (o, j) {
                var off = (j - (g.count - 1) / 2) * JEN_BW;
                o.jengaPos = horiz ? new THREE.Vector3(off, gi * JEN_LH, 0) : new THREE.Vector3(0, gi * JEN_LH, off);
            });
        });
    }
    function buildJengaExtras() {
        clearStructExtras();
        structGroups.forEach(function (g, gi) {
            var horiz = (gi % 2 === 0);
            g.nodes.forEach(function (o, j) {
                var req = j < g.thresh;
                var geo = horiz ? new THREE.BoxGeometry(JEN_BW * 0.9, JEN_LH * 0.7, JEN_BW * 2.2)
                    : new THREE.BoxGeometry(JEN_BW * 2.2, JEN_LH * 0.7, JEN_BW * 0.9);
                var m = new THREE.Mesh(geo, new THREE.MeshStandardMaterial({
                    color: 0x0c1119, emissive: req ? AMBER : DIM, emissiveIntensity: req ? 0.5 : 0.12,
                    transparent: true, opacity: req ? 0.55 : 0.32, roughness: 0.7
                }));
                m.position.copy(o.jengaPos); pushStruct(m);
            });
            var lab = makeTextSprite(g.label, threshLabel(g));
            var side = (g.count / 2) * JEN_BW + 5;
            lab.position.set((gi % 2 === 0) ? side : 0, gi * JEN_LH, (gi % 2 === 0) ? 0 : side);
            lab.renderOrder = 5; pushStruct(lab);
        });
    }
    function enterJenga() {
        K.setLinkBuilder(straightLinkBuilder('jengaPos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildJengaExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function frameJenga() { var top = JEN_LH * Math.max(1, structGroups.length); frame3q(top, top * 0.4); }

    var SPIRE_LH = 5, SPIRE_R = 8;
    function computeSpire(ns) {
        structGroups = depGroups(ns);
        structGroups.forEach(function (g, gi) {
            g.nodes.forEach(function (o, j) {
                var ang = (j / g.count) * Math.PI * 2;
                o.spirePos = new THREE.Vector3(Math.cos(ang) * SPIRE_R, gi * SPIRE_LH, Math.sin(ang) * SPIRE_R);
            });
        });
    }
    function buildSpireExtras() {
        clearStructExtras();
        var top = SPIRE_LH * Math.max(1, structGroups.length);
        var spire = new THREE.Mesh(new THREE.CylinderGeometry(0.5, 0.7, top + 2, 12),
            new THREE.MeshStandardMaterial({ color: 0x11161f, emissive: AMBER, emissiveIntensity: 0.15, roughness: 0.6 }));
        spire.position.y = top / 2 - SPIRE_LH / 2; pushStruct(spire);
        structGroups.forEach(function (g, gi) {
            var reqArc = new THREE.Mesh(new THREE.TorusGeometry(SPIRE_R, 0.2, 8, 40, Math.PI * 2 * g.thresh / g.count),
                new THREE.MeshBasicMaterial({ color: REQ, transparent: true, opacity: 0.85 }));
            reqArc.position.y = gi * SPIRE_LH; reqArc.rotation.x = Math.PI / 2; pushStruct(reqArc);
            if (g.count > g.thresh) {
                var spArc = new THREE.Mesh(new THREE.TorusGeometry(SPIRE_R, 0.09, 8, 40, Math.PI * 2 * (g.count - g.thresh) / g.count),
                    new THREE.MeshBasicMaterial({ color: DIM, transparent: true, opacity: 0.6 }));
                spArc.position.y = gi * SPIRE_LH; spArc.rotation.x = Math.PI / 2;
                spArc.rotation.z = -Math.PI * 2 * g.thresh / g.count; pushStruct(spArc);
            }
            var lab = makeTextSprite(g.label, threshLabel(g));
            lab.position.set(SPIRE_R + 6, gi * SPIRE_LH, 0); lab.renderOrder = 5; pushStruct(lab);
        });
    }
    function enterSpire() {
        K.setLinkBuilder(straightLinkBuilder('spirePos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildSpireExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function frameSpire() { var top = SPIRE_LH * Math.max(1, structGroups.length); frame3q(top, top * 0.4); }

    var SHELL_IN = 8, SHELL_GAP = 5;
    function computeShells(ns) {
        structGroups = depGroups(ns);
        structGroups.forEach(function (g, gi) {
            var r = SHELL_IN + gi * SHELL_GAP; g.shellR = r;
            g.nodes.forEach(function (o, j) {
                var y = g.count <= 1 ? 0 : 1 - (j / (g.count - 1)) * 2;
                var rad = Math.sqrt(Math.max(0, 1 - y * y)), th = j * GOLDEN_ANGLE;
                o.shellsPos = new THREE.Vector3(Math.cos(th) * rad * r, y * r, Math.sin(th) * rad * r);
            });
        });
    }
    var SHELL_HUE = [0xffd23f, 0x00d2a0, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0x2ec4b6, 0xff2d6b];
    function buildShellExtras() {
        clearStructExtras();
        structGroups.forEach(function (g, gi) {
            var col = SHELL_HUE[gi % SHELL_HUE.length];
            var sph = new THREE.Mesh(new THREE.SphereGeometry(g.shellR, 20, 14),
                new THREE.MeshBasicMaterial({ color: col, wireframe: true, transparent: true, opacity: 0.16 }));
            pushStruct(sph);
            var lab = makeTextSprite(g.label, threshLabel(g));
            lab.position.set(0, g.shellR + 1.5, 0); lab.renderOrder = 5; pushStruct(lab);
        });
    }
    function enterShells() {
        K.setLinkBuilder(straightLinkBuilder('shellsPos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildShellExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 320; }
    }
    function frameShells() {
        var r = SHELL_IN + SHELL_GAP * Math.max(1, structGroups.length);
        frame3q(r * 2, 0);
    }
    function threshRing(pos, r) {
        var ring = new THREE.Mesh(new THREE.TorusGeometry(r || 1.5, 0.14, 8, 22),
            new THREE.MeshBasicMaterial({ color: AMBER, transparent: true, opacity: 0.85 }));
        ring.position.copy(pos); pushStruct(ring); return ring;
    }
    function tierLabel(g, pos) {
        var lab = makeTextSprite(g.label, threshLabel(g)); lab.position.copy(pos); lab.renderOrder = 5; pushStruct(lab);
    }

    var ARCH_R = 27, ARCH_H = 22;
    function computeArch(ns) {
        structGroups = depGroups(ns);
        var seq = []; structGroups.forEach(function (g) { g.nodes.forEach(function (o) { seq.push(o); }); });
        var N = seq.length;
        seq.forEach(function (o, i) {
            var t = N <= 1 ? 0.5 : i / (N - 1), ang = t * Math.PI;
            o.archPos = new THREE.Vector3(-Math.cos(ang) * ARCH_R, Math.sin(ang) * ARCH_H, 0);
        });
    }
    function buildArchExtras() {
        clearStructExtras();
        var pts = [];
        for (var i = 0; i <= 60; i++) { var a = (i / 60) * Math.PI; pts.push(new THREE.Vector3(-Math.cos(a) * ARCH_R, Math.sin(a) * ARCH_H, 0)); }
        pushStruct(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({ color: AMBER, transparent: true, opacity: 0.3 })));
        var key = new THREE.Mesh(new THREE.BoxGeometry(3, 2.2, 2),
            new THREE.MeshStandardMaterial({ color: 0x1a1200, emissive: AMBER, emissiveIntensity: 0.6, roughness: 0.5 }));
        key.position.set(0, ARCH_H, 0); pushStruct(key);
        structGroups.forEach(function (g) {
            threshRing(g.nodes[Math.min(g.thresh, g.count) - 1].archPos, 1.5);
            var mid = g.nodes[Math.floor((g.count - 1) / 2)].archPos;
            tierLabel(g, new THREE.Vector3(mid.x * 1.12, mid.y + 2.2, 0));
        });
    }
    function enterArch() {
        K.setLinkBuilder(straightLinkBuilder('archPos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildArchExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function frameArch() { frame3q(ARCH_H * 2 + 8, ARCH_H * 0.4); }

    function computeTree(ns) {
        structGroups = depGroups(ns);
        var G = structGroups.length;
        structGroups.forEach(function (g, gi) {
            var frac = G <= 1 ? 0 : gi / (G - 1);
            var y = -8 + frac * 42, rad = 3 + Math.abs(frac - 0.32) * 20;
            g.treeY = y;
            g.nodes.forEach(function (o, j) {
                var ang = (j / Math.max(1, g.count)) * Math.PI * 2 + gi * 1.1;
                o.treePos = new THREE.Vector3(Math.cos(ang) * rad, y, Math.sin(ang) * rad);
            });
        });
    }
    function buildTreeExtras() {
        clearStructExtras();
        var trunk = new THREE.Mesh(new THREE.CylinderGeometry(1.6, 2.6, 50, 10),
            new THREE.MeshStandardMaterial({ color: 0x3a2a18, emissive: 0x1a1206, emissiveIntensity: 0.4, roughness: 0.9 }));
        trunk.position.y = -8 + 21; pushStruct(trunk);
        structGroups.forEach(function (g) {
            threshRing(g.nodes[Math.min(g.thresh, g.count) - 1].treePos, 1.5);
            tierLabel(g, new THREE.Vector3(0, g.treeY, 0));
        });
    }
    function enterTree() {
        K.setLinkBuilder(straightLinkBuilder('treePos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildTreeExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function frameTree() { frame3q(52, 12); }

    var SUS_LH = 8, SUS_BW = 3.4;
    function computeSuspend(ns) {
        structGroups = depGroups(ns);
        structGroups.forEach(function (g, gi) {
            g.susY = gi * SUS_LH;
            g.nodes.forEach(function (o, j) {
                o.suspendPos = new THREE.Vector3((j - (g.count - 1) / 2) * SUS_BW, gi * SUS_LH, 0);
            });
        });
    }
    function buildSuspendExtras() {
        clearStructExtras();
        if (structGroups.length) {
            structGroups[0].nodes.forEach(function (o) {
                var p = o.suspendPos;
                var an = new THREE.Mesh(new THREE.BoxGeometry(2.2, 1.6, 2.2),
                    new THREE.MeshStandardMaterial({ color: 0x1a1f2a, emissive: 0xffd23f, emissiveIntensity: 0.3, roughness: 0.7 }));
                an.position.set(p.x, p.y - 1.2, p.z); pushStruct(an);
            });
        }
        for (var gi = 1; gi < structGroups.length; gi++) {
            var g = structGroups[gi], below = structGroups[gi - 1];
            var bc = new THREE.Vector3(0, below.susY, 0);
            g.nodes.forEach(function (o) {
                var a = o.suspendPos, mid = a.clone().add(bc).multiplyScalar(0.5); mid.y -= 2.2;
                pushStruct(K.makeTube([a.clone(), mid, bc.clone()], 0.07, 0x9fb3c2, 0.4));
            });
        }
        structGroups.forEach(function (g) {
            threshRing(g.nodes[Math.min(g.thresh, g.count) - 1].suspendPos, 1.4);
            tierLabel(g, new THREE.Vector3((g.count / 2) * SUS_BW + 5, g.susY, 0));
        });
    }
    function enterSuspend() {
        K.setLinkBuilder(straightLinkBuilder('suspendPos')); structLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0); setSceneryVisible(false);
        buildSuspendExtras(); K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 300; }
    }
    function frameSuspend() { var top = SUS_LH * Math.max(1, structGroups.length); frame3q(top, top * 0.4); }

    var radialMaxR = 30;
    function computeRadial(ns) {
        var maxLayer = 0;
        ns.forEach(function (o) { if (o.data.type === 'mix' && typeof o.data.layer === 'number') maxLayer = Math.max(maxLayer, o.data.layer); });
        var layerCount = maxLayer + 1;
        function stageOf(o) {
            var t = o.data.type;
            if (t === 'dirauth') return 0;
            if (t === 'gateway') return 2;
            if (t === 'mix') return 3 + (o.data.layer || 0);
            if (t === 'service') return 3 + layerCount;
            if (t === 'storage') return 4 + layerCount;
            return 5 + layerCount;  // out
        }
        function stageName(s) {
            if (s === 0) return 'Dir auth';
            if (s === 1) return 'Clients';
            if (s === 2) return 'Gateways';
            if (s >= 3 && s < 3 + layerCount) return 'Mix L' + (s - 2);
            if (s === 3 + layerCount) return 'Services';
            if (s === 4 + layerCount) return 'Storage';
            return 'Other';
        }
        var byStage = {};
        ns.forEach(function (o) { var s = stageOf(o); (byStage[s] || (byStage[s] = [])).push(o); });
        byStage[1] = byStage[1] || [];   // ensure a clients ring exists
        var stages = Object.keys(byStage).map(Number);
        stages.push(1);
        stages = stages.filter(function (v, i, a) { return a.indexOf(v) === i; }).sort(function (a, b) { return a - b; });
        var count = stages.length, RIN = 7, GAPR = Math.max(4.5, (radialMaxR - RIN) / Math.max(1, count - 1));
        var H_RAD = 30;
        function ringR(stage) { return RIN + (count - 1 - stages.indexOf(stage)) * GAPR; }
        function ringY(stage) { return (stages.indexOf(stage) / Math.max(1, count - 1)) * H_RAD - H_RAD / 2; }
        radialHeaders = []; radialClients = [];
        var gateways = (byStage[2] || []).slice();
        stages.forEach(function (s) {
            var r = ringR(s), y = ringY(s);
            if (s === 1) {
                var nC = Math.min(6, Math.max(3, gateways.length));
                for (var i = 0; i < nC; i++) {
                    var a = (i / nC) * Math.PI * 2 + 0.3;
                    radialClients.push({ pos: new THREE.Vector3(Math.cos(a) * r, y, Math.sin(a) * r), gw: gateways.length ? gateways[i % gateways.length] : null, gwPos: null });
                }
            } else {
                var g = byStage[s] || [], k = g.length;
                g.sort(function (a, b) { return (a.data.name || '').localeCompare(b.data.name || ''); });
                g.forEach(function (o, i) {
                    var a = (k <= 1 ? 0.25 : (i / k) * Math.PI * 2) + s * 0.4;
                    o.radialPos = new THREE.Vector3(Math.cos(a) * r, y, Math.sin(a) * r);
                });
            }
            radialHeaders.push({ x: 0, y: y + 1.2, z: r + 1.5, title: stageName(s), subtitle: '' });
        });
        radialClients.forEach(function (c) { if (c.gw) c.gwPos = c.gw.radialPos; });
    }
    function frameRings() {
        var xs = [], ys = [], zs = [];
        K.nodes().forEach(function (o) { var p = o.ringPos; if (p) { xs.push(p.x); ys.push(p.y); zs.push(p.z); } });
        if (!xs.length) { K.frameNodes(); return; }
        var ext = Math.max(
            Math.max.apply(null, xs) - Math.min.apply(null, xs),
            Math.max.apply(null, ys) - Math.min.apply(null, ys),
            Math.max.apply(null, zs) - Math.min.apply(null, zs), 10);
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (ext / 2 / tan) * 1.5 + 10;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.5, dist * 0.5, dist * 0.7, 0, 0, 0);
    }
    var radialLinkBuilder = straightLinkBuilder('radialPos');
    function enterRadial() {
        K.setLinkBuilder(radialLinkBuilder);
        fullLinksOn();
        K.setSegmentInterpolator(null); K.setPathBuilder(null);
        K.setOrbitOrigin(true); K.setPlanar(false); K.setClusterFilter(noCluster);
        K.worldRoot().rotation.set(0, 0, 0);
        setSceneryVisible(false);
        addCascadeExtras(radialHeaders, radialClients);   // ring labels + client dots
        buildCascadeFlow(radialClients);
        K.rebuildLinks(); K.drawSelectionPath();
        var c = K.controls(); if (c) { c.minDistance = 8; c.maxDistance = 260; }
    }
    function frameRadial() {
        var fov = K.camera().fov, tan = Math.tan(THREE.MathUtils.degToRad(fov * 0.5));
        var dist = (radialMaxR / tan) * 1.5 + 12;
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(dist * 0.6, dist * 0.3, dist * 0.7, 0, 0, 0);
    }

    function setMode(m) {
        if (m === mode) return;
        if (mode === 'earth') leaveEarth();
        else if (mode === 'flat') leaveFlat();
        else if (mode === 'cascade' || mode === 'radial') leaveCascade();
        else if (mode === 'hypercube') leaveHyper();
        else if (mode === 'force') leaveForce();
        else if (mode === 'depend') leaveDepend();
        else if (mode === 'jenga' || mode === 'spire' || mode === 'shells' || mode === 'arch' || mode === 'tree' || mode === 'suspend') clearStructExtras();
        else if (mode === 'flower') leaveFlower();
        else if (mode === 'mobius') leaveMobius();
        mode = m;
        updateBtn();
        if (mode === 'earth') { enterEarth(); frameCluster(); }
        else if (mode === 'flat') { enterFlat(); frameFlat(); }
        else if (mode === 'cascade') { enterCascade(); frameCascade(); }
        else if (mode === 'radial') { enterRadial(); frameRadial(); }
        else if (mode === 'depend') { enterDepend(); frameDepend(); }
        else if (mode === 'jenga') { enterJenga(); frameJenga(); }
        else if (mode === 'spire') { enterSpire(); frameSpire(); }
        else if (mode === 'shells') { enterShells(); frameShells(); }
        else if (mode === 'arch') { enterArch(); frameArch(); }
        else if (mode === 'tree') { enterTree(); frameTree(); }
        else if (mode === 'suspend') { enterSuspend(); frameSuspend(); }
        else if (mode === 'spiral') { enterSpiral(); frameSpiral(); }
        else if (mode === 'fibsphere') { enterFib(); frameFib(); }
        else if (mode === 'flower') { enterFlower(); frameFlower(); }
        else if (mode === 'hypercube') { enterHyper(); frameHyper(); }
        else if (mode === 'torus') { enterTorus(); frameTorus(); }
        else if (mode === 'helix') { enterHelix(); frameHelix(); }
        else if (mode === 'mobius') { enterMobius(); frameMobius(); }
        else if (mode === 'tspiral') { enterTimeSpiral(); frameTimeSpiral(); }
        else if (mode === 'force') { enterForce(); frameForce(); }
        else { enterRings(); frameRings(); }
    }

    function meanLatLon(pred) {
        var sla = 0, slo = 0, n = 0;
        K.nodes().forEach(function (o) {
            if (!o._bll || (pred && !pred(o._bll))) return;
            sla += o._bll[0]; slo += o._bll[1]; n++;
        });
        return n ? [sla / n, slo / n] : null;
    }

    function frame(pred, dist, lonClamp) {
        var ll = meanLatLon(pred);
        if (!ll) { K.goTo(0, 14, R * 2.4, 0, 0, 0); return; }
        var clat = ll[0], clon = ll[1];
        var camLon = THREE.MathUtils.clamp(clon, lonClamp[0], lonClamp[1]);
        var camLat = THREE.MathUtils.clamp(clat - 28, -10, 40);
        var cam = geoToVec(camLat, camLon, R * dist);
        var look = geoToVec(clat, clon, SURF * 0.85);
        K.worldRoot().rotation.set(0, 0, 0);   // north up
        K.goTo(cam.x, cam.y, cam.z, look.x, look.y, look.z);
    }

    function frameCluster() {
        var ll = meanLatLon(null) || [45, -20];
        var camLat = THREE.MathUtils.clamp(ll[0] - 5, -20, 55);
        var narrow = window.matchMedia && window.matchMedia('(max-width: 600px)').matches;
        var cam = geoToVec(camLat, ll[1], R * (narrow ? 2.6 : 1.62));
        K.worldRoot().rotation.set(0, 0, 0);
        K.snapTo(cam.x, cam.y, cam.z, 0, 0, 0);
    }
    function frameSubset(pred) { frame(pred, 1.45, [-140, 30]); }

    function arcInterp(a, b, t) {
        var ra = a.length(), rb = b.length();
        var ua = a.clone().normalize(), ub = b.clone().normalize();
        var dot = THREE.MathUtils.clamp(ua.dot(ub), -1, 1), om = Math.acos(dot), p;
        if (om < 1e-4) { p = ua.clone(); }
        else {
            var s1 = Math.sin((1 - t) * om) / Math.sin(om), s2 = Math.sin(t * om) / Math.sin(om);
            p = ua.multiplyScalar(s1).add(ub.multiplyScalar(s2)).normalize();
        }
        return p.multiplyScalar(ra + (rb - ra) * t + 4 * Math.sin(Math.PI * t) * (om / Math.PI));
    }

    function surfaceLine(points, color) {
        var pts = [];
        for (var i = 0; i < points.length - 1; i++) {
            var a = points[i].clone().normalize(), b = points[i + 1].clone().normalize();
            var dot = THREE.MathUtils.clamp(a.dot(b), -1, 1), om = Math.acos(dot);
            var segs = Math.max(2, Math.round(om / (Math.PI / 36)));
            for (var k = (i > 0 ? 1 : 0); k <= segs; k++) {
                var t = k / segs, p;
                if (om < 1e-4) { p = a.clone(); }
                else {
                    var s1 = Math.sin((1 - t) * om) / Math.sin(om), s2 = Math.sin(t * om) / Math.sin(om);
                    p = a.clone().multiplyScalar(s1).add(b.clone().multiplyScalar(s2)).normalize();
                }
                pts.push(p.multiplyScalar(SURF * 1.01));
            }
        }
        return new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0.55 }));
    }

    function applyMode() {
        globe = null; extras = []; cableMesh = null; flatMap = null; routeIndex = {}; routeMemo = {};
        var ns = K.nodes();
        var groups = {};
        ns.forEach(function (o) {
            o.ringPos = o.mesh.position.clone();
            o._bll = baseLatLon(o);
            var key = o._bll[0].toFixed(2) + ',' + o._bll[1].toFixed(2);
            (groups[key] || (groups[key] = [])).push(o);
        });
        Object.keys(groups).forEach(function (key) {
            var g = groups[key], k = g.length;
            g.forEach(function (o, i) {
                var lat = o._bll[0], lon = o._bll[1];
                if (k > 1) {
                    var ang = (i / k) * Math.PI * 2, rDeg = 0.32;
                    lat += rDeg * Math.sin(ang);
                    lon += rDeg * Math.cos(ang) / Math.max(0.3, Math.cos(lat * Math.PI / 180));
                }
                o.earthPos = geoToVec(lat, lon, SURF);
                o.flatPos = geoToFlat(lat, lon);
            });
        });
        computeCascade(ns);
        computeRadial(ns);
        computeDepend(ns);
        if (mode === 'jenga') computeJenga(ns);
        else if (mode === 'spire') computeSpire(ns);
        else if (mode === 'shells') computeShells(ns);
        else if (mode === 'arch') computeArch(ns);
        else if (mode === 'tree') computeTree(ns);
        else if (mode === 'suspend') computeSuspend(ns);
        computeSpiral(ns);
        computeFib(ns);
        computeFlower(ns);
        computeHyper(ns);
        computeTorus(ns);
        computeHelix(ns);
        computeMobius(ns);
        computeTimeSpiral(ns);
        if (mode === 'force') computeForce(ns);
        ns.forEach(function (o) {
            var tgt = modeTarget(o);
            if (tgt) o.mesh.position.copy(tgt);
        });
        if (mode === 'earth') enterEarth();
        else if (mode === 'flat') enterFlat();
        else if (mode === 'cascade') enterCascade();
        else if (mode === 'radial') enterRadial();
        else if (mode === 'depend') enterDepend();
        else if (mode === 'jenga') enterJenga();
        else if (mode === 'spire') enterSpire();
        else if (mode === 'shells') enterShells();
        else if (mode === 'arch') enterArch();
        else if (mode === 'tree') enterTree();
        else if (mode === 'suspend') enterSuspend();
        else if (mode === 'spiral') enterSpiral();
        else if (mode === 'fibsphere') enterFib();
        else if (mode === 'flower') enterFlower();
        else if (mode === 'hypercube') enterHyper();
        else if (mode === 'torus') enterTorus();
        else if (mode === 'helix') enterHelix();
        else if (mode === 'mobius') enterMobius();
        else if (mode === 'tspiral') enterTimeSpiral();
        else if (mode === 'force') enterForce();
        else enterRings();
        if (firstBuild) {
            if (mode === 'earth') frameCluster();
            else if (mode === 'flat') frameFlat();
            else if (mode === 'cascade') frameCascade();
            else if (mode === 'radial') frameRadial();
            else if (mode === 'depend') frameDepend();
            else if (mode === 'jenga') frameJenga();
            else if (mode === 'spire') frameSpire();
            else if (mode === 'shells') frameShells();
            else if (mode === 'arch') frameArch();
            else if (mode === 'tree') frameTree();
            else if (mode === 'suspend') frameSuspend();
            else if (mode === 'spiral') frameSpiral();
            else if (mode === 'fibsphere') frameFib();
            else if (mode === 'flower') frameFlower();
            else if (mode === 'hypercube') frameHyper();
            else if (mode === 'torus') frameTorus();
            else if (mode === 'helix') frameHelix();
            else if (mode === 'mobius') frameMobius();
            else if (mode === 'tspiral') frameTimeSpiral();
            else if (mode === 'force') frameForce();
            else frameRings();
        }
        firstBuild = false;
    }
    function modeTarget(o) {
        if (mode === 'hypercube' || mode === 'force') return null;   // positions set per frame
        return mode === 'earth' ? o.earthPos : mode === 'flat' ? o.flatPos
            : mode === 'cascade' ? o.cascadePos : mode === 'radial' ? o.radialPos
                : mode === 'spiral' ? o.spiralPos : mode === 'fibsphere' ? o.fibPos : mode === 'flower' ? o.flowerPos
                    : mode === 'torus' ? o.torusPos : mode === 'helix' ? o.helixPos
                        : mode === 'mobius' ? o.mobiusPos : mode === 'tspiral' ? o.tspiralPos : mode === 'depend' ? o.dependPos : mode === 'jenga' ? o.jengaPos : mode === 'spire' ? o.spirePos : mode === 'shells' ? o.shellsPos : mode === 'arch' ? o.archPos : mode === 'tree' ? o.treePos : mode === 'suspend' ? o.suspendPos : o.ringPos;
    }
    K.on('build', applyMode);

    K.on('frame', function (dt) {
        var a = Math.min(1, dt * 2.5), ns = K.nodes();
        for (var i = 0; i < ns.length; i++) {
            var o = ns[i];
            if (!o.ringPos || !o.earthPos) continue;
            var target = modeTarget(o);
            if (target) o.mesh.position.lerp(target, a);
        }
        if (mode === 'hypercube') { hcAngle += dt * 0.35; updateHyper(); }        // 4D rotation
        else if (mode === 'force') updateForce(dt);                              // physics step
        if (mode === 'cascade' || mode === 'radial') animateCascadeFlow(dt);      // pipeline traffic
        if (mode === 'earth' || mode === 'flat') animateGeoClients(dt);           // client->gateway traffic
        if (spinEnabled && SPIN3D[mode]) K.worldRoot().rotation.y += dt * 0.07;
    });

    btn.addEventListener('click', function () { gotoNextView(); });

    K.on('boot', function () {
        rebuildViewSelect();
        var qs = location.hash + location.search;
        var om = /[?#&]overlay=([a-z0-9-]+)/i.exec(qs);
        if (om && findOverlay(om[1])) { showOverlay(om[1]); return; }
        if (/[?#&]view=/i.test(qs)) return;   // explicit spatial view in the URL: keep it
        // No deep link: start on a random visualization.
        var ids = viewIds(), pick = ids[(Math.random() * ids.length) | 0];
        if (pick && pick !== curViewId()) gotoView(pick);
    });
    K.on('boot', function () {
        fetch('katzenpost-viz/earth/land-110m.geo.json', { cache: 'force-cache' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d || !d.rings) return;
                landRings = d.rings;
                if (globe) addLand(globe);
                if (mode === 'flat') { clearFlatMap(); buildFlatMap(); }
            })
            .catch(function () { /* graticule-only globe is fine */ });
        fetch('katzenpost-viz/earth/cables.geo.json', { cache: 'force-cache' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d || !d.lines) return;
                cableLines = d.lines;
                cablePolysVec = cableLines.map(function (line) {
                    return line.map(function (c) { return geoToVec(c[1], c[0], SURF); });
                });
                applyLinks();   // add the cables + reroute links if we are in Earth mode
            })
            .catch(function () { /* arcs still work without the cable map */ });
    });
})();
