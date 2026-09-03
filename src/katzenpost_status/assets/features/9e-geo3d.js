(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var THREE = K.THREE;
    if (!THREE) return;
    var SHARED_R = null;
    function snd(t) { if (K.playSound) K.playSound(t); }
    function shapeGeom(THREE, r) {
        switch (window.KATZEN_SHAPE) {
            case 'cubes': return new THREE.BoxGeometry(r * 1.6, r * 1.6, r * 1.6);
            case 'octahedra': return new THREE.OctahedronGeometry(r * 1.15);
            case 'tetrahedra': return new THREE.TetrahedronGeometry(r * 1.3);
            case 'dodecahedra': return new THREE.DodecahedronGeometry(r * 1.05);
            case 'icosahedra': return new THREE.IcosahedronGeometry(r * 1.1);
            case 'cones': return new THREE.ConeGeometry(r * 1.1, r * 2.2, 14);
            case 'cylinders': return new THREE.CylinderGeometry(r * 0.9, r * 0.9, r * 1.8, 14);
            case 'rings': return new THREE.TorusGeometry(r * 0.95, r * 0.4, 10, 20);
            case 'crystals': return new THREE.OctahedronGeometry(r * 1.5, 0);
            default: return new THREE.SphereGeometry(r, 12, 12);
        }
    }
    var _spriteCache = {};
    function packetSprite(THREE) {
        var kind = { cubes: 'sq', octahedra: 'di', crystals: 'st', tetrahedra: 'tri', cones: 'tri', rings: 'ring', cylinders: 'sq' }[window.KATZEN_SHAPE] || 'dot';
        if (_spriteCache[kind]) return _spriteCache[kind];
        var s = 32, cv = document.createElement('canvas'); cv.width = cv.height = s;
        var c = cv.getContext('2d'); c.fillStyle = '#fff'; c.strokeStyle = '#fff'; c.lineWidth = 4; var h = s / 2;
        c.beginPath();
        if (kind === 'sq') { c.rect(6, 6, 20, 20); c.fill(); }
        else if (kind === 'di') { c.moveTo(h, 3); c.lineTo(29, h); c.lineTo(h, 29); c.lineTo(3, h); c.closePath(); c.fill(); }
        else if (kind === 'tri') { c.moveTo(h, 4); c.lineTo(28, 28); c.lineTo(4, 28); c.closePath(); c.fill(); }
        else if (kind === 'ring') { c.arc(h, h, 11, 0, 6.2832); c.stroke(); }
        else if (kind === 'st') { var i, a; for (i = 0; i < 10; i++) { a = -Math.PI / 2 + i * Math.PI / 5; var rr = (i % 2) ? 5 : 13; var x = h + rr * Math.cos(a), y = h + rr * Math.sin(a); if (i) c.lineTo(x, y); else c.moveTo(x, y); } c.closePath(); c.fill(); }
        else { c.arc(h, h, 13, 0, 6.2832); c.fill(); }
        var tex = new THREE.CanvasTexture(cv);
        _spriteCache[kind] = tex; return tex;
    }

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
            var gVerts = [], gAdj = [], nodeVert = {}, pipeCols = [], _distCache = {};   // edge graph for routing
            var packets = [], packPts = null, packPos = null, packCol = null, spawnAcc = 0, coverAcc = 0, lastT = 0;
            var fpsEma = 60, slowMode = false;
            var running = false, raf = 0;
            var shellPool = [], heartAcc = 0, ORIGIN = new THREE.Vector3(0, 0, 0);   // onion-peel shells + epoch heartbeat
            var pdHandler = null, puHandler = null, lastSig = null;

            function onResize() {
                if (!renderer) return;
                var w = el.clientWidth || window.innerWidth, h = el.clientHeight || window.innerHeight;
                renderer.setSize(w, h); camera.aspect = w / h; camera.updateProjectionMatrix();
            }
            function disposeGroup(g) { g.traverse(function (o) { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); }); }

            function initGL() {
                if (!SHARED_R) {
                    try { SHARED_R = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'low-power' }); }
                    catch (e) { SHARED_R = null; return false; }
                    SHARED_R.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
                    SHARED_R.domElement.style.cssText = 'display:block;width:100%;height:100%';
                }
                renderer = SHARED_R;
                if (renderer.domElement.parentNode !== el) el.appendChild(renderer.domElement);
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
                pdHandler = function (ev) { dx = ev.clientX; dy = ev.clientY; };
                puHandler = function (ev) {
                    if (!nodeGroup || Math.abs(ev.clientX - dx) + Math.abs(ev.clientY - dy) > 6) return;
                    var rect = renderer.domElement.getBoundingClientRect();
                    ptr.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
                    ptr.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
                    ray.setFromCamera(ptr, camera);
                    var hit = ray.intersectObjects(nodeGroup.children, false)[0];
                    if (hit && hit.object.userData.node) { var n = hit.object.userData.node; if (K.reselect) K.reselect(n.name, n.type); spawnFromNode(n.name); }
                };
                renderer.domElement.addEventListener('pointerdown', pdHandler);
                renderer.domElement.addEventListener('pointerup', puHandler);
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
                var sph = shapeGeom(THREE, mob ? 0.9 : 0.7);
                if (packPts) { packPts.material.map = packetSprite(THREE); packPts.material.needsUpdate = true; }
                var metaByName = {};   // layouts drop status/layer; look them up for colour
                ((K.data() || {}).nodes || []).forEach(function (x) { metaByName[x.name] = x; });
                var baseHex = (opts.color != null ? opts.color : 0x2ec4b6);
                function geomHex(pos) {
                    if (!edges.length) return baseHex;
                    var best = baseHex, bd = Infinity, i, e, d;
                    for (i = 0; i < edges.length; i++) {
                        e = edges[i]; if (!e.a || !e.b) continue;
                        d = pos.distanceToSquared(e.a); if (d < bd) { bd = d; best = e.color == null ? baseHex : e.color; }
                        d = pos.distanceToSquared(e.b); if (d < bd) { bd = d; best = e.color == null ? baseHex : e.color; }
                    }
                    return best;
                }
                function hashName(s) { var h = 0, i; for (i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) & 0x7fffffff; return h; }
                nodes.forEach(function (nd) {
                    nodePos[nd.name] = nd.pos;
                    var raw = geomHex(nd.pos), themed = K.themeColor ? K.themeColor(raw) : raw;
                    var base = new THREE.Color(themed);
                    base.multiplyScalar(0.74 + 0.42 * ((hashName(nd.name || '') % 100) / 100));
                    var meta = metaByName[nd.name] || {}, st = nd.status || meta.status;
                    var col = (st && st !== 'ok' && K.statusColor) ? new THREE.Color(K.statusColor(st)) : base;
                    var m = new THREE.Mesh(sph, new THREE.MeshBasicMaterial({ color: col }));
                    m.position.copy(nd.pos); m.userData = { node: nd, base: base }; nodeGroup.add(m);
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
                lastSig = nodeSig();
            }

            function nodeSig() {
                var d = K.data() || {}, ns = d.nodes || [], i, out = '';
                for (i = 0; i < ns.length; i++) out += ns[i].name + ':' + ns[i].type + ':' + ns[i].layer + '|';
                return out + '#' + JSON.stringify(d.layers || []);
            }
            function recolorNodes() {
                if (!nodeGroup) return;
                var meta = {}; ((K.data() || {}).nodes || []).forEach(function (x) { meta[x.name] = x; });
                nodeGroup.children.forEach(function (m) {
                    var nd = m.userData.node, st = (meta[nd.name] || {}).status;
                    var c = (st && st !== 'ok' && K.statusColor) ? new THREE.Color(K.statusColor(st)) : m.userData.base;
                    if (c) m.material.color.copy(c);
                });
            }

            // Build a routing graph from the edges (merging near-coincident
            // endpoints) so packets can follow the geometry's lines, and snap
            // each node to its nearest graph vertex.
            function buildGraph(edges, nodes) {
                gVerts = []; gAdj = []; nodeVert = {}; _distCache = {};
                var vmap = {}, keyOf = [], Q = opts.snap || 0.35, s, i, t;
                function vidx(v) {
                    var rx = Math.round(v.x / Q), ry = Math.round(v.y / Q), rz = Math.round(v.z / Q);
                    var k = rx + '_' + ry + '_' + rz;
                    if (vmap[k] == null) { vmap[k] = gVerts.length; gVerts.push(v.clone()); gAdj.push([]); keyOf.push([rx, ry, rz]); }
                    return vmap[k];
                }
                edges.forEach(function (e) {
                    var ia = vidx(e.a), ib = vidx(e.b);
                    if (ia !== ib) { if (gAdj[ia].indexOf(ib) < 0) gAdj[ia].push(ib); if (gAdj[ib].indexOf(ia) < 0) gAdj[ib].push(ia); }
                });
                // Stitch the geometry into ONE traversable graph so packets always
                // follow the drawn lines (even huge grids like Langton's ant that
                // used to be too big to bridge). Union-find the components, then
                // bridge each island outward through the quantized grid (the vmap
                // keys ARE a grid at resolution Q) to the nearest other component.
                var parent = new Array(gVerts.length);
                for (s = 0; s < gVerts.length; s++) parent[s] = s;
                function find(x) { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
                function union(a, b) { var ra = find(a), rb = find(b); if (ra !== rb) { parent[ra] = rb; return true; } return false; }
                for (s = 0; s < gVerts.length; s++) { var a0 = gAdj[s]; for (t = 0; t < a0.length; t++) union(s, a0[t]); }
                var CAP = 30;
                function ringBridge(vi) {
                    var kk = keyOf[vi], bx = kk[0], by = kk[1], bz = kk[2], r, dx, dy, dz;
                    for (r = 1; r <= CAP; r++) {
                        for (dx = -r; dx <= r; dx++) for (dy = -r; dy <= r; dy++) for (dz = -r; dz <= r; dz++) {
                            if (Math.max(Math.abs(dx), Math.abs(dy), Math.abs(dz)) !== r) continue;   // shell only
                            var vj = vmap[(bx + dx) + '_' + (by + dy) + '_' + (bz + dz)];
                            if (vj == null || find(vj) === find(vi)) continue;
                            gAdj[vi].push(vj); gAdj[vj].push(vi); union(vi, vj); return true;
                        }
                    }
                    return false;
                }
                if (gVerts.length > 1) {
                    var guard = 0, merged = true;
                    while (merged && guard++ < 24) {
                        merged = false;
                        var cnt = {}, main = -1, bn = -1, r2;
                        for (i = 0; i < gVerts.length; i++) { r2 = find(i); cnt[r2] = (cnt[r2] || 0) + 1; if (cnt[r2] > bn) { bn = cnt[r2]; main = r2; } }
                        for (s = 0; s < gVerts.length; s++) { if (find(s) === main) continue; if (ringBridge(s)) merged = true; }
                    }
                }
                nodes.forEach(function (nd) {
                    var best = -1, bd = Infinity;
                    for (var j = 0; j < gVerts.length; j++) { var dd = gVerts[j].distanceToSquared(nd.pos); if (dd < bd) { bd = dd; best = j; } }
                    nodeVert[nd.name] = best;
                });
                pipeCols = window.KATZEN_GEO3D.columns(K.data() || {});
            }
            // BFS distance field from a destination vertex over the routing
            // graph (cached per dst; cleared when the graph rebuilds).
            function distField(dst) {
                if (_distCache[dst]) return _distCache[dst];
                var dist = new Array(gVerts.length), q = [dst], head = 0, i;
                for (i = 0; i < dist.length; i++) dist[i] = -1;
                dist[dst] = 0;
                while (head < q.length) {
                    var u = q[head++], nb = gAdj[u];
                    for (i = 0; i < nb.length; i++) { var w = nb[i]; if (dist[w] < 0) { dist[w] = dist[u] + 1; q.push(w); } }
                }
                _distCache[dst] = dist; return dist;
            }
            // Route one leg src->dst as a BIASED RANDOM WALK: at each vertex pick
            // among its links (roughly 1/n), so consecutive packets take DIFFERENT
            // routes and every edge gets used over time (not always the shortest
            // path). A fraction of steps drift toward dst; after an explore budget
            // we descend the distance field so the leg always ARRIVES (no partial
            // legs -> no discontinuous jumps). Immediate backtrack is avoided
            // except at dead-ends (so L-system trees can escape leaves).
            function walkLeg(src, dst) {
                if (src == null || dst == null || src < 0 || dst < 0) return null;
                if (src === dst) return [src];
                var dist = distField(dst);
                if (dist[src] < 0) return null;   // disconnected: caller falls back
                var path = [src], cur = src, prev = -1, i, budget = Math.min(dist[src] * 2, 120), steps = 0;
                while (cur !== dst && steps < budget) {
                    var nb = gAdj[cur]; if (!nb.length) break;
                    var cand = []; for (i = 0; i < nb.length; i++) if (nb[i] !== prev) cand.push(nb[i]);
                    if (!cand.length) cand = nb;   // dead-end: allow backtrack
                    var pick;
                    if (Math.random() < 0.45) {   // drift toward dst
                        var bd = Infinity, best = [];
                        for (i = 0; i < cand.length; i++) { var dd = dist[cand[i]]; if (dd < 0) continue; if (dd < bd) { bd = dd; best = [cand[i]]; } else if (dd === bd) best.push(cand[i]); }
                        pick = best.length ? best[(Math.random() * best.length) | 0] : cand[(Math.random() * cand.length) | 0];
                    } else {
                        pick = cand[(Math.random() * cand.length) | 0];   // ~1/n exploration
                    }
                    prev = cur; cur = pick; path.push(cur); steps++;
                }
                var guard = 0;   // guaranteed descent to dst on the distance field
                while (cur !== dst && guard++ < gVerts.length + 5) {
                    var nb2 = gAdj[cur], nxt = -1, cd = dist[cur];
                    for (i = 0; i < nb2.length; i++) if (dist[nb2[i]] === cd - 1) { nxt = nb2[i]; break; }
                    if (nxt < 0) break;
                    cur = nxt; path.push(cur);
                }
                return path.length >= 2 ? path : null;
            }
            function routeAlongEdges() {
                if (!pipeCols || pipeCols.length < 2 || !gVerts.length) return null;
                var chosen = [], ci;
                for (ci = 0; ci < pipeCols.length; ci++) { var c = pipeCols[ci]; chosen.push(c[(Math.random() * c.length) | 0]); }
                var pts = [], stops = [];
                for (var i = 0; i < chosen.length - 1; i++) {
                    var vp = walkLeg(nodeVert[chosen[i].name], nodeVert[chosen[i + 1].name]);
                    if (!vp) return null;   // disconnected: caller falls back
                    for (var k = 0; k < vp.length; k++) { if (i > 0 && k === 0) continue; pts.push(gVerts[vp[k]]); }
                    stops.push(pts.length - 1);   // end of this hop = a real pipeline node (dwell + ripple here)
                }
                // The intermediate BFS vertices are geometry lines the packet just
                // traverses; only the hop endpoints (mixes) dwell/shed a ripple.
                return pts.length >= 2 ? { pts: pts, stops: stops } : null;
            }

            function meanDwell() {
                var d = K.data() || {}, mu = (d.parameters && d.parameters.Mu) || 0;
                var base = mu > 0 ? Math.max(0.25, Math.min(1.4, (1 / mu) / 200)) : 0.6;
                return base * (window.KATZEN_DELAY || 1);
            }
            function spawnPacket(cover) {
                if (packets.length >= (slowMode ? (PACK_MAX * 0.4) | 0 : PACK_MAX)) return;
                var r = routeAlongEdges(), path = null, stops = null;   // packets follow the geometry's lines
                if (r) { path = r.pts; stops = r.stops; }
                else if (spawnFn) { path = spawnFn(); }   // fall back only if the graph is disconnected
                if (!path || path.length < 2) return;
                if (Math.random() < 0.5) {   // flows in both directions
                    path = path.slice().reverse();
                    if (stops) stops = stops.map(function (si) { return path.length - 1 - si; });
                }
                // Which path indices are "hops" (dwell + shed a ripple): the real
                // pipeline nodes for routed paths, or every vertex for the short
                // fallback paths. The final vertex is always a hop (arrival).
                var stopSet = {};
                if (stops) { stops.forEach(function (si) { if (si >= 1) stopSet[si] = 1; }); }
                else { for (var j = 1; j < path.length; j++) stopSet[j] = 1; }
                stopSet[path.length - 1] = 1;
                // Scale speed by total path length so long geometry routes (hundreds
                // of graph verts) transit in bounded time instead of crawling.
                var total = 0, m; for (m = 0; m < path.length - 1; m++) total += path[m].distanceTo(path[m + 1]);
                var speed = (10 + Math.random() * 8) * Math.max(1, total / 26);
                packets.push({ path: path, seg: 0, t: 0, dwell: 0, speed: speed, stops: stopSet, cover: cover ? 1 : 0 });
            }
            function spawnFromNode(name) {
                if (packets.length >= PACK_MAX || nodeVert[name] == null || !pipeCols || pipeCols.length < 2) return;
                var last = pipeCols[pipeCols.length - 1], dst = last[(Math.random() * last.length) | 0];
                if (!dst || nodeVert[dst.name] == null) return;
                var vp = walkLeg(nodeVert[name], nodeVert[dst.name]);
                if (!vp || vp.length < 2) return;
                var path = [], i; for (i = 0; i < vp.length; i++) path.push(gVerts[vp[i]]);
                var stopSet = {}; stopSet[path.length - 1] = 1;
                var total = 0; for (i = 0; i < path.length - 1; i++) total += path[i].distanceTo(path[i + 1]);
                packets.push({ path: path, seg: 0, t: 0, dwell: 0, speed: (14 + Math.random() * 6) * Math.max(1, total / 26), stops: stopSet, user: 1 });
                triggerShell(path[0], K.themeColor ? K.themeColor(0x00f3ff) : 0x00f3ff, 1.6, 14);
                snd('send');
            }
            var _zAxis = new THREE.Vector3(0, 0, 1), _q = new THREE.Quaternion();
            function triggerShell(pos, color, max, grow, normal) {
                if (window.KATZEN_FX_SHELLS === false) return;   // menu toggle
                snd('ring');
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
                    pk.t += dt * pk.speed * (window.KATZEN_SPEED || 1) / segLen;
                    while (pk.t >= 1) {
                        if (pk.stops[pk.seg + 1]) {   // arrive at a real hop: dwell + shed a ripple facing travel dir
                            pk.t = 1;
                            pk.dwell = -Math.log(Math.max(1e-6, Math.random())) * md;
                            triggerShell(b, K.themeColor ? K.themeColor(0xffc24d) : 0xffc24d, 1.0, 9, b.clone().sub(a));
                            snd('arrive');
                            break;
                        }
                        // pass straight through an intermediate geometry vertex
                        pk.seg++;
                        if (pk.seg >= pk.path.length - 1) { pk.seg = pk.path.length - 1; pk.t = 1; break; }
                        pk.t -= 1;
                        a = pk.path[pk.seg]; b = pk.path[pk.seg + 1];
                    }
                    if (k < PACK_MAX) {
                        var t = pk.t, o = k * 3;
                        w[o] = a.x + (b.x - a.x) * t; w[o + 1] = a.y + (b.y - a.y) * t; w[o + 2] = a.z + (b.z - a.z) * t;
                        if (pk.cover) { c[o] = dr; c[o + 1] = dg; c[o + 2] = db; } else { c[o] = mr; c[o + 1] = mg; c[o + 2] = mb; } k++;
                    }
                }
                packPts.geometry.setDrawRange(0, k);
                packPts.geometry.attributes.position.needsUpdate = true;
                packPts.geometry.attributes.color.needsUpdate = true;
            }

            function loop() {
                if (!running) return;
                raf = requestAnimationFrame(loop);
                if (typeof document !== 'undefined' && document.hidden) { lastT = 0; return; }
                var now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : 0;
                var dt = lastT ? Math.min(0.05, (now - lastT) / 1000) : 0.016; lastT = now;
                fpsEma = fpsEma * 0.92 + (1 / Math.max(dt, 1e-3)) * 0.08;
                slowMode = fpsEma < 34;
                var rate = (typeof K.trafficRate === 'function' ? K.trafficRate() : 0) || 0;
                spawnAcc += dt * (slowMode ? 3 : (6 + Math.min(40, rate * 0.6)));
                while (spawnAcc >= 1) { spawnPacket(); spawnAcc -= 1; }
                var cover = window.KATZEN_COVER || 0;
                if (cover > 0 && !slowMode) { coverAcc += dt * cover * 42; while (coverAcc >= 1) { spawnPacket(true); coverAcc -= 1; } }
                heartAcc += dt;
                if (heartAcc >= 12) { heartAcc = 0; triggerShell(ORIGIN, K.themeColor ? K.themeColor(0x00f3ff) : 0x00f3ff, 2.6, 22); snd('heartbeat'); }
                updatePackets(dt);
                updateShells(dt);
                if (controls) controls.update();
                renderer.render(scene, camera);
            }

            K.on('data', function () { if (!world || !running) return; if (nodeSig() === lastSig) recolorNodes(); else rebuild(); });
            K.on('theme', function () { if (world && running) rebuild(); });
            K.on('shape', function () { if (world && running) rebuild(); });
            window.addEventListener('resize', function () { if (running) onResize(); });

            function teardownGL() {
                if (!renderer) return;
                try {
                    if (nodeGroup) { world.remove(nodeGroup); disposeGroup(nodeGroup); }
                    if (edgeLines) { world.remove(edgeLines); disposeGroup(edgeLines); }
                    if (packPts) { if (packPts.geometry) packPts.geometry.dispose(); if (packPts.material) packPts.material.dispose(); }
                    for (var i = 0; i < shellPool.length; i++) { var m = shellPool[i].mesh; if (m) { if (m.geometry) m.geometry.dispose(); if (m.material) m.material.dispose(); } }
                    if (controls && controls.dispose) controls.dispose();
                    if (pdHandler) renderer.domElement.removeEventListener('pointerdown', pdHandler);
                    if (puHandler) renderer.domElement.removeEventListener('pointerup', puHandler);
                    if (renderer.domElement.parentNode === el) el.removeChild(renderer.domElement);
                } catch (e) { }
                renderer = null; scene = null; camera = null; controls = null; world = null;
                nodeGroup = null; edgeLines = null; packPts = null; shellPool = []; packets = [];
                gVerts = []; gAdj = []; nodeVert = {}; _distCache = {};
                pdHandler = null; puHandler = null;
            }

            window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
            for (var _di = 0; _di < window.KATZEN_OVERLAYS.length; _di++) {
                if (window.KATZEN_OVERLAYS[_di].id === opts.id) { if (window.console) console.warn('KATZEN: duplicate overlay id ' + opts.id); break; }
            }
            window.KATZEN_OVERLAYS.push({
                id: opts.id, name: opts.name, el: el,
                onShow: function () {
                    if (!renderer && !initGL()) return;
                    rebuild(); packets = []; spawnAcc = 0; lastT = 0; onResize();
                    if (!running) { running = true; raf = requestAnimationFrame(loop); }
                },
                onHide: function () { running = false; if (raf) cancelAnimationFrame(raf); raf = 0; teardownGL(); }
            });
        }
    };
})();
