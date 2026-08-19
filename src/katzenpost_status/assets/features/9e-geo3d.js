(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;

    // Shared factory for 3D "sacred geometry / fractal" overlays. A geometry
    // supplies a layout(data) -> { nodes:[{name,type,pos}], edges:[{a,b,color}],
    // spawn():[Vec3...] } and this builds the three.js scene: role-coloured node
    // spheres (clickable -> the real node), the geometry edges, and packets that
    // flow along the returned paths (the structure). Rotatable via OrbitControls.
    window.KATZEN_GEO3D = {
        // The mixnet pipeline as ordered columns of node-data: gateways -> mix
        // layers -> services. Geometries use this to place nodes logically and
        // to route packets along the structure.
        columns: function (d) {
            var nodes = (d && d.nodes) || [], byName = {};
            nodes.forEach(function (n) { byName[n.name] = n; });
            var cols = [], gws = nodes.filter(function (n) { return n.type === 'gateway'; });
            var svcs = nodes.filter(function (n) { return n.type === 'service'; });
            if (gws.length) cols.push(gws);
            ((d && d.layers) || []).forEach(function (names) {
                var a = names.map(function (nm) { return byName[nm]; }).filter(Boolean);
                if (a.length) cols.push(a);
            });
            if (svcs.length) cols.push(svcs);
            return cols;
        },
        // Place nodes in pipeline order along a curve (array of Vector3) and
        // flow packets along the curve between the first and last column.
        curveLayout: function (d, THREE, pts, color, edgeStep) {
            var self = this, edges = [], i, st = edgeStep || 1;
            for (i = 0; i + st < pts.length; i += st) edges.push({ a: pts[i], b: pts[i + st], color: color });
            var cols = self.columns(d), ordered = [];
            cols.forEach(function (c) { c.forEach(function (n) { ordered.push(n); }); });
            (d.nodes || []).forEach(function (n) { if (ordered.indexOf(n) < 0) ordered.push(n); });
            var nodes = [], nodePos = {}, idxOf = {}, n = ordered.length;
            ordered.forEach(function (nd, k) { var ci = n <= 1 ? 0 : Math.round(k / (n - 1) * (pts.length - 1)); var p = pts[ci].clone(); nodes.push({ name: nd.name, type: nd.type, pos: p }); nodePos[nd.name] = p; idxOf[nd.name] = ci; });
            function spawn() {
                if (cols.length < 2) return null;
                var s = cols[0], e = cols[cols.length - 1];
                var a = idxOf[s[(Math.random() * s.length) | 0].name], b = idxOf[e[(Math.random() * e.length) | 0].name];
                if (a == null || b == null) return null;
                var lo = Math.min(a, b), hi = Math.max(a, b), path = [];
                for (var i = lo; i <= hi; i++) path.push(pts[i]);
                return path.length >= 2 ? path : null;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        },
        // Stellate a planar layout into a 3D crown so no shape stays flat:
        // deterministically displace z as a function of (x,y) - a central apex
        // plus K-fold star points at the rim - applied to node AND edge points
        // alike so the routed lines follow the new relief. Already-3D layouts
        // (metatron, polyhedra, attractors, ...) are detected and left alone.
        stellate: function (lay, THREE) {
            if (!lay || !lay.nodes) return lay;
            var all = [], i;
            lay.nodes.forEach(function (n) { if (n.pos) all.push(n.pos); });
            (lay.edges || []).forEach(function (e) { if (e.a) all.push(e.a); if (e.b) all.push(e.b); });
            if (all.length < 3) return lay;
            var cx = 0, cy = 0, minz = Infinity, maxz = -Infinity;
            all.forEach(function (p) { cx += p.x; cy += p.y; if (p.z < minz) minz = p.z; if (p.z > maxz) maxz = p.z; });
            cx /= all.length; cy /= all.length;
            var maxr = 0;
            all.forEach(function (p) { var dx = p.x - cx, dy = p.y - cy, r = Math.sqrt(dx * dx + dy * dy); if (r > maxr) maxr = r; });
            if (maxr < 1e-3) return lay;
            if ((maxz - minz) > 0.18 * maxr) return lay;   // already a 3D shape
            var A = 0.55 * maxr, K = 6;
            all.forEach(function (p) {
                if (p.__stel) return; p.__stel = 1;
                var dx = p.x - cx, dy = p.y - cy, r = Math.sqrt(dx * dx + dy * dy), u = Math.min(1, r / maxr), th = Math.atan2(dy, dx);
                p.z += A * (Math.pow(1 - u, 0.5) + 0.62 * u * Math.cos(K * th));
            });
            return lay;
        },
        // Place nodes on a set of anchor points (cycling), with given edges, and
        // flow packets along the gateway->mix->service pipeline.
        anchorLayout: function (d, THREE, anchors, edges) {
            var self = this, order = (d.nodes || []).slice().sort(function (a, b) { return (a.type + a.name).localeCompare(b.type + b.name); });
            var nodes = [], nodePos = {}, cnt = order.length, used = {};
            order.forEach(function (n, i) {
                var ai = anchors.length ? Math.floor(i * anchors.length / cnt) % anchors.length : 0;
                var p = anchors.length ? anchors[ai].clone() : new THREE.Vector3();
                if (used[ai]) p.multiplyScalar(0.82);   // nudge duplicates onto an inner shell
                used[ai] = true;
                nodes.push({ name: n.name, type: n.type, pos: p }); nodePos[n.name] = p;
            });
            var cols = self.columns(d);
            function spawn() {
                if (cols.length < 2) return null;
                var path = [];
                for (var ci = 0; ci < cols.length; ci++) { var c = cols[ci], nm = c[(Math.random() * c.length) | 0].name; if (nodePos[nm]) path.push(nodePos[nm]); }
                return path;
            }
            return { nodes: nodes, edges: edges, spawn: spawn };
        },
        create: function (opts) {
            var el = document.createElement('div');
            el.id = opts.id + '-overlay';
            el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#04060c;overflow:hidden';
            document.body.appendChild(el);

            var mob = window.matchMedia('(max-width: 600px)').matches;
            var PACK_MAX = mob ? 120 : 320;
            var renderer = null, scene = null, camera = null, controls = null, world = null;
            var nodeGroup = null, edgeLines = null, nodePos = {}, spawnFn = null;
            var gVerts = [], gAdj = [], nodeVert = {}, pipeCols = [];   // edge graph for routing
            var packets = [], packPts = null, packPos = null, packCol = null, spawnAcc = 0, lastT = 0;
            var running = false, raf = 0;
            var shellPool = [], heartAcc = 0, ORIGIN = new THREE.Vector3(0, 0, 0);   // onion-peel shells + epoch heartbeat

            // Colour nodes across the whole scheme: healthy nodes take their
            // ROLE colour (gateway/mix-layer/service/storage/dirauth), so the
            // balls span the palette instead of all reading status-cyan; nodes
            // with a problem keep their status colour (amber/red) so faults still
            // stand out. Both palettes are themeable (see K.groupColor/statusColor
            // and window.KATZEN_THEME).
            function roleColor(n) {
                try { var st = n && n.status; if (st && st !== 'ok' && K.statusColor) return new THREE.Color(K.statusColor(st)); } catch (e) { }
                try { return new THREE.Color(K.groupColor({ data: n })); } catch (e2) { return new THREE.Color(0x8aa0b4); }
            }
            function onResize() {
                if (!renderer) return;
                var w = el.clientWidth || window.innerWidth, h = el.clientHeight || window.innerHeight;
                renderer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix();
            }
            function disposeGroup(g) { g.traverse(function (o) { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); }); }

            function initGL() {
                try { renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' }); }
                catch (e) { return false; }
                renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
                el.appendChild(renderer.domElement);
                renderer.domElement.style.cssText = 'display:block;width:100%;height:100%';
        if (window.KATZEN_CRT) window.KATZEN_CRT(el);
                scene = new THREE.Scene();
                camera = new THREE.PerspectiveCamera(52, 1, 0.1, 4000);
                // elevated 3/4 view by default so stellated relief reads as 3D
                camera.position.set(0, (opts.camY != null ? opts.camY : (opts.camZ || 60) * 0.42), opts.camZ || 60);
                world = new THREE.Group(); scene.add(world);
                if (THREE.OrbitControls) {
                    controls = new THREE.OrbitControls(camera, renderer.domElement);
                    controls.enableDamping = true; controls.dampingFactor = 0.08;
                    controls.autoRotate = opts.autoRotate !== false; controls.autoRotateSpeed = opts.rotateSpeed || 0.5;
                    controls.minDistance = 8; controls.maxDistance = 400; controls.target.set(0, 0, 0);
                }
                packPos = new Float32Array(PACK_MAX * 3); packCol = new Float32Array(PACK_MAX * 3);
                var pg = new THREE.BufferGeometry();
                var ppa = new THREE.BufferAttribute(packPos, 3); ppa.setUsage(THREE.DynamicDrawUsage);
                var pca = new THREE.BufferAttribute(packCol, 3); pca.setUsage(THREE.DynamicDrawUsage);
                pg.setAttribute('position', ppa); pg.setAttribute('color', pca); pg.setDrawRange(0, 0);
                packPts = new THREE.Points(pg, new THREE.PointsMaterial({
                    size: mob ? 1.0 : 0.8, vertexColors: true, transparent: true, opacity: 1,
                    blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true
                }));
                world.add(packPts);

                // Onion-peel / heartbeat ring pool: thin annuli we scale + fade.
                var cgeo = new THREE.RingGeometry(0.82, 1.0, 44), ci;
                for (ci = 0; ci < 30; ci++) {
                    var lm = new THREE.MeshBasicMaterial({ color: 0xffd23f, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false, side: THREE.DoubleSide });
                    var ring = new THREE.Mesh(cgeo, lm); ring.visible = false; ring.scale.set(0.01, 0.01, 0.01);
                    world.add(ring); shellPool.push({ mesh: ring, active: false, age: 0, max: 1, grow: 6 });
                }

                var ray = new THREE.Raycaster(), ptr = new THREE.Vector2(), dx = 0, dy = 0;
                renderer.domElement.addEventListener('pointerdown', function (ev) { dx = ev.clientX; dy = ev.clientY; });
                renderer.domElement.addEventListener('pointerup', function (ev) {
                    if (!nodeGroup || Math.abs(ev.clientX - dx) + Math.abs(ev.clientY - dy) > 6) return;
                    var rect = renderer.domElement.getBoundingClientRect();
                    ptr.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
                    ptr.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
                    ray.setFromCamera(ptr, camera);
                    var hit = ray.intersectObjects(nodeGroup.children, false)[0];
                    if (hit && hit.object.userData.node && K.reselect) { var n = hit.object.userData.node; K.reselect(n.name, n.type); }
                });
                onResize();
                return true;
            }

            function rebuild() {
                if (nodeGroup) { world.remove(nodeGroup); disposeGroup(nodeGroup); nodeGroup = null; }
                if (edgeLines) { world.remove(edgeLines); disposeGroup(edgeLines); edgeLines = null; }
                nodePos = {}; spawnFn = null;
                var lay = opts.layout(K.data() || {}, THREE, K) || {};
                if (opts.stellate !== false) window.KATZEN_GEO3D.stellate(lay, THREE);   // no shape stays flat
                var nodes = lay.nodes || [], edges = lay.edges || [];
                nodeGroup = new THREE.Group();
                var sph = new THREE.SphereGeometry(mob ? 0.9 : 0.7, 12, 12);
                var metaByName = {};   // layouts drop status/layer; look them up for colour
                ((K.data() || {}).nodes || []).forEach(function (x) { metaByName[x.name] = x; });
                nodes.forEach(function (nd) {
                    nodePos[nd.name] = nd.pos;
                    var meta = metaByName[nd.name] || {};
                    var col = roleColor({ status: nd.status || meta.status, type: nd.type, name: nd.name, layer: meta.layer });
                    var m = new THREE.Mesh(sph, new THREE.MeshBasicMaterial({ color: col }));
                    m.position.copy(nd.pos); m.userData = { node: nd }; nodeGroup.add(m);
                });
                world.add(nodeGroup);
                if (edges.length) {
                    var pa = new Float32Array(edges.length * 6), ca = new Float32Array(edges.length * 6);
                    edges.forEach(function (e, i) {
                        var raw = e.color == null ? 0x2ec4b6 : e.color;
                        var c = new THREE.Color(K.themeColor ? K.themeColor(raw) : raw), o = i * 6;
                        pa[o] = e.a.x; pa[o + 1] = e.a.y; pa[o + 2] = e.a.z;
                        pa[o + 3] = e.b.x; pa[o + 4] = e.b.y; pa[o + 5] = e.b.z;
                        ca[o] = c.r; ca[o + 1] = c.g; ca[o + 2] = c.b; ca[o + 3] = c.r; ca[o + 4] = c.g; ca[o + 5] = c.b;
                    });
                    var eg = new THREE.BufferGeometry();
                    eg.setAttribute('position', new THREE.BufferAttribute(pa, 3));
                    eg.setAttribute('color', new THREE.BufferAttribute(ca, 3));
                    edgeLines = new THREE.LineSegments(eg, new THREE.LineBasicMaterial({
                        vertexColors: true, transparent: true, opacity: opts.edgeOpacity || 0.28, depthWrite: false
                    }));
                    world.add(edgeLines);
                }
                spawnFn = lay.spawn || null;
                buildGraph(edges, nodes);
                if (controls && lay.target) { controls.target.copy(lay.target); controls.update(); }
            }

            // Build a routing graph from the edges (merging near-coincident
            // endpoints) so packets can follow the geometry's lines, and snap
            // each node to its nearest graph vertex.
            function buildGraph(edges, nodes) {
                gVerts = []; gAdj = []; nodeVert = {};
                var vmap = {}, Q = opts.snap || 0.35;
                function vidx(v) {
                    var k = Math.round(v.x / Q) + '_' + Math.round(v.y / Q) + '_' + Math.round(v.z / Q);
                    if (vmap[k] == null) { vmap[k] = gVerts.length; gVerts.push(v.clone()); gAdj.push([]); }
                    return vmap[k];
                }
                edges.forEach(function (e) {
                    var ia = vidx(e.a), ib = vidx(e.b);
                    if (ia !== ib) { if (gAdj[ia].indexOf(ib) < 0) gAdj[ia].push(ib); if (gAdj[ib].indexOf(ia) < 0) gAdj[ib].push(ia); }
                });
                // Connect disconnected components (e.g. the separate circles of a
                // Seed of Life) with a short bridge to the nearest other vertex,
                // so packets can still route along the lines across the pattern.
                var comp = new Array(gVerts.length), nc = 0, s;
                for (s = 0; s < gVerts.length; s++) comp[s] = -1;
                for (s = 0; s < gVerts.length; s++) {
                    if (comp[s] >= 0) continue;
                    var stack = [s]; comp[s] = nc;
                    while (stack.length) { var u = stack.pop(); for (var t = 0; t < gAdj[u].length; t++) { var w2 = gAdj[u][t]; if (comp[w2] < 0) { comp[w2] = nc; stack.push(w2); } } }
                    nc++;
                }
                if (nc > 1 && gVerts.length < 1500) {
                    for (var cc = 1; cc < nc; cc++) {
                        var bi = -1, bj = -1, bd = Infinity;
                        for (var i = 0; i < gVerts.length; i++) {
                            if (comp[i] !== cc) continue;
                            for (var j = 0; j < gVerts.length; j++) { if (comp[j] >= cc) continue; var dd = gVerts[i].distanceToSquared(gVerts[j]); if (dd < bd) { bd = dd; bi = i; bj = j; } }
                        }
                        if (bi >= 0) { gAdj[bi].push(bj); gAdj[bj].push(bi); }
                    }
                }
                nodes.forEach(function (nd) {
                    var best = -1, bd = Infinity;
                    for (var i = 0; i < gVerts.length; i++) { var dd = gVerts[i].distanceToSquared(nd.pos); if (dd < bd) { bd = dd; best = i; } }
                    nodeVert[nd.name] = best;
                });
                pipeCols = window.KATZEN_GEO3D.columns(K.data() || {});
            }
            function bfs(src, dst) {
                if (src < 0 || dst < 0) return null;
                if (src === dst) return [src];
                var prev = {}, q = [src], seen = {}, head = 0; seen[src] = 1;
                while (head < q.length) {
                    var u = q[head++], nb = gAdj[u];
                    for (var i = 0; i < nb.length; i++) {
                        var w = nb[i];
                        if (!seen[w]) {
                            seen[w] = 1; prev[w] = u;
                            if (w === dst) { var path = [dst], c = dst; while (c !== src) { c = prev[c]; path.push(c); } path.reverse(); return path; }
                            q.push(w);
                        }
                    }
                }
                return null;
            }
            function routeAlongEdges() {
                if (!pipeCols || pipeCols.length < 2 || !gVerts.length) return null;
                var chosen = [], ci;
                for (ci = 0; ci < pipeCols.length; ci++) { var c = pipeCols[ci]; chosen.push(c[(Math.random() * c.length) | 0]); }
                var pts = [];
                for (var i = 0; i < chosen.length - 1; i++) {
                    var vp = bfs(nodeVert[chosen[i].name], nodeVert[chosen[i + 1].name]);
                    if (!vp) return null;   // disconnected: caller falls back
                    for (var k = 0; k < vp.length; k++) { if (i > 0 && k === 0) continue; pts.push(gVerts[vp[k]]); }
                }
                return pts.length >= 2 ? pts : null;
            }

            function meanDwell() {
                var d = K.data() || {}, mu = (d.parameters && d.parameters.Mu) || 0;
                return mu > 0 ? Math.max(0.25, Math.min(1.4, (1 / mu) / 200)) : 0.6;
            }
            function spawnPacket() {
                if (packets.length >= PACK_MAX) return;
                var p = routeAlongEdges();   // packets follow the geometry's lines
                if (!p && spawnFn) p = spawnFn();   // fall back only if the graph is disconnected
                if (!p || p.length < 2) return;
                if (Math.random() < 0.5) p = p.slice().reverse();   // flows in both directions
                packets.push({ path: p, seg: 0, t: 0, dwell: 0, speed: 10 + Math.random() * 8 });
            }
            var _zAxis = new THREE.Vector3(0, 0, 1), _q = new THREE.Quaternion();
            function triggerShell(pos, color, max, grow, normal) {
                if (window.KATZEN_FX_SHELLS === false) return;   // menu toggle
                for (var i = 0; i < shellPool.length; i++) {
                    var s = shellPool[i];
                    if (s.active) continue;
                    s.active = true; s.age = 0; s.max = max; s.grow = grow;
                    s.mesh.visible = true; s.mesh.position.copy(pos); s.mesh.material.color.setHex(color);
                    s.mesh.scale.set(0.01, 0.01, 0.01); s.mesh.material.opacity = 0.9;
                    // Orient the ring in 3D: its plane faces the packet's travel
                    // direction (a ripple it passes through), plus a little jitter
                    // so no two are coplanar. Heartbeat rings (no normal) tumble.
                    var n;
                    if (normal && normal.lengthSq() > 1e-6) n = normal.clone().normalize();
                    else n = new THREE.Vector3(Math.random() * 2 - 1, Math.random() * 2 - 1, Math.random() * 2 - 1).normalize();
                    n.x += (Math.random() - 0.5) * 0.5; n.y += (Math.random() - 0.5) * 0.5; n.normalize();
                    _q.setFromUnitVectors(_zAxis, n); s.mesh.quaternion.copy(_q);
                    return;
                }
            }
            function updateShells(dt) {
                for (var i = 0; i < shellPool.length; i++) {
                    var s = shellPool[i]; if (!s.active) continue;
                    s.age += dt; var f = s.age / s.max;
                    if (f >= 1) { s.active = false; s.mesh.visible = false; continue; }
                    var r = 0.01 + s.age * s.grow; s.mesh.scale.set(r, r, r); s.mesh.material.opacity = 0.9 * (1 - f);
                }
            }
            function updatePackets(dt) {
                var w = packPos, c = packCol, k = 0, md = meanDwell();
                // Packet colours come from the live theme palette so they match
                // the rest of the scene: payload cyan while moving, loop amber
                // while queued/dwelling (both re-themed via K.themeColor).
                var moveHex = K.themeColor ? K.themeColor(0x00f3ff) : 0x00f3ff;
                var dwellHex = K.themeColor ? K.themeColor(0xffaa00) : 0xffaa00;
                var mr = ((moveHex >> 16) & 255) / 255, mg = ((moveHex >> 8) & 255) / 255, mb = (moveHex & 255) / 255;
                var dr = ((dwellHex >> 16) & 255) / 255, dg = ((dwellHex >> 8) & 255) / 255, db = (dwellHex & 255) / 255;
                for (var i = packets.length - 1; i >= 0; i--) {
                    var pk = packets[i], a = pk.path[pk.seg], b = pk.path[pk.seg + 1];
                    if (pk.dwell > 0) {
                        // queued at the mix: dwell an exponential (Loopix) delay,
                        // so packets leave in a shuffled order.
                        pk.dwell -= dt;
                        if (k < PACK_MAX) { var o0 = k * 3; w[o0] = b.x; w[o0 + 1] = b.y; w[o0 + 2] = b.z; c[o0] = dr; c[o0 + 1] = dg; c[o0 + 2] = db; k++; }
                        if (pk.dwell <= 0) { pk.seg++; pk.t = 0; if (pk.seg >= pk.path.length - 1) packets.splice(i, 1); }
                        continue;
                    }
                    var segLen = a.distanceTo(b) || 1;
                    pk.t += dt * pk.speed / segLen;
                    if (pk.t >= 1) { pk.t = 1; pk.dwell = -Math.log(Math.max(1e-6, Math.random())) * md; triggerShell(b, K.themeColor ? K.themeColor(0xffc24d) : 0xffc24d, 1.0, 9, b.clone().sub(a)); }   // arrive -> shed a ripple facing travel dir
                    if (k < PACK_MAX) {
                        var t = pk.t, o = k * 3;
                        w[o] = a.x + (b.x - a.x) * t; w[o + 1] = a.y + (b.y - a.y) * t; w[o + 2] = a.z + (b.z - a.z) * t;
                        c[o] = mr; c[o + 1] = mg; c[o + 2] = mb; k++;
                    }
                }
                packPts.geometry.setDrawRange(0, k);
                packPts.geometry.attributes.position.needsUpdate = true;
                packPts.geometry.attributes.color.needsUpdate = true;
            }

            function loop() {
                if (!running) return;
                var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
                var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016; lastT = now;
                var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
                spawnAcc += dt * (6 + Math.min(40, rate * 0.6));
                while (spawnAcc >= 1) { spawnPacket(); spawnAcc -= 1; }
                heartAcc += dt;
                if (heartAcc >= 12) { heartAcc = 0; triggerShell(ORIGIN, K.themeColor ? K.themeColor(0x00f3ff) : 0x00f3ff, 2.6, 22); }   // epoch heartbeat
                updatePackets(dt);
                updateShells(dt);
                if (controls) controls.update();
                renderer.render(scene, camera);
                raf = requestAnimationFrame(loop);
            }

            K.on('data', function () { if (world && running) rebuild(); });
            K.on('theme', function () { if (world && running) rebuild(); });   // recolour balls on theme switch
            window.addEventListener('resize', function () { if (running) onResize(); });

            window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
            window.KATZEN_OVERLAYS.push({
                id: opts.id, name: opts.name, el: el,
                onShow: function () {
                    if (!renderer && !initGL()) return;
                    rebuild(); packets = []; spawnAcc = 0; lastT = 0; onResize();
                    if (!running) { running = true; raf = requestAnimationFrame(loop); }
                },
                onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; }
            });
        }
    };
})();
