(function () {
    "use strict";

    (function () {
        var ok = false;
        try {
            var c = document.createElement('canvas');
            var gl = window.WebGLRenderingContext &&
                (c.getContext('webgl') || c.getContext('experimental-webgl'));
            ok = !!gl;
            if (gl) {   // release the probe context so we do not hold a GPU slot
                var lose = gl.getExtension && gl.getExtension('WEBGL_lose_context');
                if (lose) lose.loseContext();
            }
        } catch (e) { ok = false; }
        window.KATZEN_NO_WEBGL = !ok;
    })();

    var STATUS_HEX = { ok: 0x00f3ff, out: 0xffaa00, down: 0xff2d6b, unknown: 0x556677 };
    var STATUS_LABEL = {
        ok: "In consensus - reachable", out: "Reachable - not in consensus",
        down: "Down & out", unknown: "Address unknown"
    };
    function statusColor(s) { return STATUS_HEX[s] !== undefined ? STATUS_HEX[s] : 0x556677; }
    var LAT_STOPS = [[0x2c, 0xe0, 0xc0], [0x8f, 0xe0, 0x4a], [0xff, 0xb4, 0x54], [0xff, 0x5d, 0x8f]];
    function latencyColor(ms) {
        if (ms == null) return 0x556677;
        var t = Math.max(0, Math.min(1, (ms - 20) / 180));
        var x = t * (LAT_STOPS.length - 1), i = Math.min(LAT_STOPS.length - 2, Math.floor(x)), f = x - i;
        var a = LAT_STOPS[i], b = LAT_STOPS[i + 1];
        return (Math.round(a[0] + (b[0] - a[0]) * f) << 16)
            | (Math.round(a[1] + (b[1] - a[1]) * f) << 8)
            | Math.round(a[2] + (b[2] - a[2]) * f);
    }
    function isMobile() { return window.matchMedia('(max-width: 600px)').matches; }
    function hex6(n) { return '#' + (n >>> 0).toString(16).padStart(6, '0'); }
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    var scene, camera, renderer, controls, composer, worldRoot, dirauthRing = null;
    var crtPass = null;         // CRT post-processing (curvature, scanlines, phosphor)

    var CRT_SHADER = {
        uniforms: {
            tDiffuse: { value: null },
            uRes: { value: null },
            uCurve: { value: 0.10 },
            uScan: { value: 0.18 },
            uMask: { value: 0.12 },
            uVig: { value: 0.22 }
        },
        vertexShader:
            'varying vec2 vUv; void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.0); }',
        fragmentShader: [
            'uniform sampler2D tDiffuse; uniform vec2 uRes;',
            'uniform float uCurve, uScan, uMask, uVig; varying vec2 vUv;',
            'void main(){',
            '  vec2 uv = vUv * 2.0 - 1.0;',
            '  vec2 off = uv.yx * uv.yx * uCurve;',
            '  uv += uv * off;',                       // barrel curvature
            '  uv = uv * 0.5 + 0.5;',
            '  if (uv.x < 0.0 || uv.x > 1.0 || uv.y < 0.0 || uv.y > 1.0) {',
            '    gl_FragColor = vec4(0.0, 0.0, 0.0, 1.0); return; }',
            '  vec3 col = texture2D(tDiffuse, uv).rgb;',
            '  float sy = sin(gl_FragCoord.y * 3.14159265);',   // scanlines
            '  col *= 1.0 - uScan * sy * sy;',
            '  float m = mod(gl_FragCoord.x, 3.0);',            // RGB phosphor stripes
            '  vec3 mask = vec3(1.0 - uMask);',
            '  if (m < 1.0) mask.r = 1.0; else if (m < 2.0) mask.g = 1.0; else mask.b = 1.0;',
            '  col *= mask;',
            '  vec2 vd = vUv - 0.5; col *= clamp(1.0 - uVig * dot(vd, vd) * 3.0, 0.0, 1.0);',  // vignette
            '  gl_FragColor = vec4(col, 1.0);',
            '}'
        ].join('\n')
    };
    var nodeObjs = [], packets = [], layerCylinders = [], packetTimer = null;
    var clients = [];  // simulated Loopix clients orbiting their gateway
    var packetSpawn = null;     // frame-driven spawner set by setupTraffic
    var targetPacketRate = 0;   // derived packets/sec from the consensus rates
    var vantageObj = null;      // monitor vantage marker
    var vantagePos = null;      // THREE.Vector3 of the vantage, for the Earth view
    var pickExtras = [];        // non-node meshes that are clickable (e.g. vantage)
    var segInterp = null;       // optional path-segment interpolator (Earth arcs)
    var hoverObj = null, selectedObj = null, labelsAll = true;
    var selGroup = null;        // holds the selected node's traceroute path
    var pathBuilder = null;     // optional mode-specific path builder (Earth)
    var topoPairs = [];         // adjacent-tier node-object pairs (link topology)
    var allLinks = [];          // optional full topology mesh (context; off by default)
    var selLinkMeshes = [];     // links drawn for the current selection
    var selNodes = [];          // currently highlighted node objects
    var selColor = null;        // group highlight colour (null => by-tier / status)
    var linkBuilder = null;     // view-specific link mesh builder (Earth routes)
    var showAllLinks = true;    // "All links" context toggle (persists across builds)
    var linkFilter = null;      // optional (a,b)->bool: false => skip that topology link
    var linkPickables = [];     // clickable link meshes (only the shown full mesh)
    var clusterMarkers = [];    // aggregate "N nodes here" sprites (pickable)
    var clusterPool = [];       // reusable cluster-marker records
    var orbitOrigin = false;    // Earth mode: orbit about the globe centre
    var planarView = false;     // Flat map: camera looks at the z=0 plane face-on
    var clusterFilter = null;   // optional (node)->bool: false => never cluster/show
    var targetCamPos, targetLookAt, cameraInitialized = false;
    var gotoActive = false;     // true only while easing to a preset/focus
    var currentGeneratedAt = null;
    var netEpoch = null;        // current consensus epoch (for mix-key expiry)
    var historyMode = false;    // replaying an old snapshot: ignore live polls
    var clock;
    var coneGeo, UP_Y;
    var lastData = null;
    var contextLost = false;   // true while the WebGL context is gone (see initThree)
    var styleAttemptPending = false;   // a 3D-style build is unconfirmed until a frame renders

    var NODE_STYLES = ['flat', 'extruded', 'pieces', 'machine'];
    var HEAVY_STYLES = { machine: true };
    function constrainedGPU() {
        try {
            return window.matchMedia('(max-width: 600px)').matches ||
                window.matchMedia('(pointer: coarse)').matches;
        } catch (e) { return false; }
    }
    function styleAllowed(style) { return !(HEAVY_STYLES[style] && constrainedGPU()); }
    function nearestAllowedStyle(style) {
        if (styleAllowed(style)) return style;
        for (var j = NODE_STYLES.indexOf(style); j >= 0; j--) {
            if (styleAllowed(NODE_STYLES[j])) return NODE_STYLES[j];
        }
        return 'flat';
    }
    var _cands = NODE_STYLES.filter(styleAllowed).filter(function (s) { return s !== 'flat'; });
    var nodeStyle = _cands.length ? _cands[Math.floor(Math.random() * _cands.length)] : 'flat';
    try {
        if (window.localStorage && localStorage.getItem('katzen.styleAttempt')) {
            localStorage.removeItem('katzen.styleAttempt');
            localStorage.removeItem('katzen.nodeStyle');
            nodeStyle = 'flat';
        }
    } catch (e) { }

    var _sm = /[?#&]style=(flat|extruded|pieces|machine)/.exec(location.hash + location.search);
    if (_sm) {
        nodeStyle = _sm[1];
        try { if (window.localStorage) localStorage.setItem('katzen.nodeStyle', nodeStyle); } catch (e) { }
    }
    nodeStyle = nearestAllowedStyle(nodeStyle);
    function markStyleAttempt() {
        styleAttemptPending = (nodeStyle !== 'flat');
        try {
            if (!window.localStorage) return;
            if (nodeStyle === 'flat') localStorage.removeItem('katzen.styleAttempt');
            else localStorage.setItem('katzen.styleAttempt', nodeStyle);
        } catch (e) { }
    }
    function clearStyleAttempt() {
        try { if (window.localStorage) localStorage.removeItem('katzen.styleAttempt'); } catch (e) { }
    }

    var HOOKS = { boot: [], build: [], data: [], node: [], frame: [] };
    function runHooks(list, a, b) {
        for (var i = 0; i < list.length; i++) {
            try { list[i](a, b); } catch (e) { /* a feature must not break the app */ }
        }
    }

    function initThree() {
        var container = document.getElementById('canvas-container');
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x030508);
        scene.fog = new THREE.FogExp2(0x030508, 0.0035);
        worldRoot = new THREE.Group();
        scene.add(worldRoot);

        camera = new THREE.PerspectiveCamera(50, window.innerWidth / window.innerHeight, 0.1, 400);
        camera.position.set(38, 26, 60);
        targetCamPos = camera.position.clone();
        targetLookAt = new THREE.Vector3(0, 0, 0);

        var rendererOpts = [
            { antialias: true, powerPreference: "high-performance" },
            { antialias: true },
            { antialias: false },
            { antialias: false, failIfMajorPerformanceCaveat: false },
        ];
        var rendererErr = null;
        for (var ri = 0; ri < rendererOpts.length; ri++) {
            try { renderer = new THREE.WebGLRenderer(rendererOpts[ri]); break; }
            catch (e) { rendererErr = e; renderer = null; }
        }
        if (!renderer) {
            throw new Error('WebGL is unavailable in this browser: ' +
                (rendererErr && rendererErr.message ? rendererErr.message : rendererErr));
        }
        renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        renderer.setSize(window.innerWidth, window.innerHeight);

        renderer.domElement.addEventListener('webglcontextlost', function (ev) {
            ev.preventDefault();
            contextLost = true;
            downgradeToFlat('the GPU dropped the WebGL context');
        }, false);
        renderer.domElement.addEventListener('webglcontextrestored', function () {
            contextLost = false;
            try { if (lastData) buildSceneSafe(lastData); } catch (e) { }
        }, false);
        renderer.toneMapping = THREE.ReinhardToneMapping;
        renderer.toneMappingExposure = 2.2;
        container.appendChild(renderer.domElement);

        controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.08;
        controls.minDistance = 8;
        controls.maxDistance = 220;
        controls.touches = { ONE: THREE.TOUCH.ROTATE, TWO: THREE.TOUCH.DOLLY_PAN };
        controls.addEventListener('start', function () { gotoActive = false; });

        try {
            var renderScene = new THREE.RenderPass(scene, camera);
            var bloomPass = new THREE.UnrealBloomPass(
                new THREE.Vector2(window.innerWidth, window.innerHeight), 0.42, 0.3, 0.5);
            composer = new THREE.EffectComposer(renderer);
            composer.addPass(renderScene);
            composer.addPass(bloomPass);
            crtPass = new THREE.ShaderPass(CRT_SHADER);
            crtPass.uniforms.uRes.value = new THREE.Vector2(window.innerWidth, window.innerHeight);
            crtPass.enabled = false;   // off by default: it darkens the scene and costs CPU
            composer.addPass(crtPass);
        } catch (e) {
            composer = null;
            crtPass = null;
        }

        scene.add(new THREE.AmbientLight(0x334455, 1.2));
        var centerLight = new THREE.PointLight(0x00f3ff, 2.6, 220);
        scene.add(centerLight);
        var fillLight = new THREE.DirectionalLight(0x6688aa, 0.5);
        fillLight.position.set(30, 40, 20);
        scene.add(fillLight);

        coneGeo = new THREE.ConeGeometry(0.3, 1.2, 6);
        UP_Y = new THREE.Vector3(0, 1, 0);
        clock = new THREE.Clock();

        setupPointer();
        window.addEventListener('resize', onResize);
        if (window.visualViewport) window.visualViewport.addEventListener('resize', onResize);
        var labelsAllInput = document.getElementById('labels-all');
        if (labelsAllInput) labelsAllInput.addEventListener('change', function (e) {
            labelsAll = e.target.checked;
            nodeObjs.forEach(function (o) {
                if (o.label) o.label.visible = labelsAll || o === selectedObj || o === hoverObj;
            });
        });
        var consBtn = document.getElementById('consensus-btn');
        if (consBtn) consBtn.addEventListener('click', function () {
            selectedObj = null; clearSelPath(); showVantage();
        });
        var linkBtn = document.getElementById('link-btn');
        if (linkBtn) linkBtn.addEventListener('click', function () {
            selectedObj = null; clearSelPath(); showLink();
        });
        animate();
    }

    function setupChrome() {
        var toggle = document.getElementById('menu-toggle');
        if (toggle) toggle.addEventListener('click', function (e) {
            e.stopPropagation(); setMenuVisible(!menuVisible);
        });
        var infoClose = document.getElementById('info-close');
        if (infoClose) infoClose.addEventListener('click', function () {
            if (!window.KATZEN_NO_WEBGL) { selectedObj = null; clearSelPath(); }
            var i = document.getElementById('node-info'); if (i) i.style.display = 'none';
        });
        if (isMobile()) setMenuVisible(false);
    }

    function onResize() {
        var w = window.innerWidth, h = window.innerHeight;
        camera.aspect = w / h; camera.updateProjectionMatrix();
        renderer.setSize(w, h); if (composer) composer.setSize(w, h);
        if (crtPass) crtPass.uniforms.uRes.value.set(w, h);
    }

    var menuVisible = !isMobile();
    function setMenuVisible(v) {
        menuVisible = v;
        var panel = document.getElementById('hud-panel');
        var toggle = document.getElementById('menu-toggle');
        panel.classList.toggle('hidden', !v);
        toggle.setAttribute('aria-expanded', v ? 'true' : 'false');
        toggle.textContent = v ? '✕' : '☰';
        toggle.setAttribute('aria-label', v ? 'Hide menu' : 'Show menu');
    }

    function clearWorld() {
        if (packetTimer) { clearInterval(packetTimer); packetTimer = null; }
        packets.forEach(function (p) { worldRoot.remove(p.mesh); });
        packets = [];
        worldRoot.traverse(function (obj) {
            if (obj.geometry) obj.geometry.dispose();
            if (obj.material) {
                var mats = Array.isArray(obj.material) ? obj.material : [obj.material];
                mats.forEach(function (m) { if (m.map) m.map.dispose(); m.dispose(); });
            }
        });
        while (worldRoot.children.length) worldRoot.remove(worldRoot.children[0]);
        nodeObjs = [];
        clients = [];
        packetSpawn = null;
        targetPacketRate = 0;
        vantageObj = null;
        vantagePos = null;
        pickExtras = [];
        selGroup = null;
        clusterMarkers = [];
        clusterPool = [];
        topoPairs = [];
        allLinks = [];
        selLinkMeshes = [];
        selNodes = [];
        selColor = null;
        linkPickables = [];
        selectedObj = null;
        hoverObj = null;
        dirauthRing = null;
        layerCylinders = [];
        var info = document.getElementById('node-info');
        if (info) info.style.display = 'none';
    }

    function makeNodeIcon(type, colorHex, filled, expiring) {
        var s = 96, cv = document.createElement('canvas'); cv.width = cv.height = s;
        var g = cv.getContext('2d'), cx = s / 2, cy = s / 2, r = 30;
        g.lineJoin = 'round';
        g.beginPath();
        switch (type) {
            case 'gateway':                       // square
                g.rect(cx - r, cy - r, 2 * r, 2 * r); break;
            case 'dirauth':                       // diamond
                g.moveTo(cx, cy - r); g.lineTo(cx + r, cy); g.lineTo(cx, cy + r); g.lineTo(cx - r, cy); g.closePath(); break;
            case 'service':                       // triangle (up)
                g.moveTo(cx, cy - r); g.lineTo(cx + r, cy + r * 0.8); g.lineTo(cx - r, cy + r * 0.8); g.closePath(); break;
            case 'out':                           // triangle (down)
                g.moveTo(cx, cy + r); g.lineTo(cx + r, cy - r * 0.8); g.lineTo(cx - r, cy - r * 0.8); g.closePath(); break;
            case 'storage':                       // hexagon
                for (var i = 0; i < 6; i++) {
                    var a = Math.PI / 6 + i * Math.PI / 3, px = cx + r * Math.cos(a), py = cy + r * Math.sin(a);
                    if (i === 0) g.moveTo(px, py); else g.lineTo(px, py);
                }
                g.closePath(); break;
            default:                              // mix + fallback: circle
                g.arc(cx, cy, r, 0, Math.PI * 2);
        }
        if (filled) {
            g.fillStyle = 'rgba(8, 12, 20, 0.95)'; g.fill();
            g.fillStyle = hex6(colorHex); g.globalAlpha = 0.32; g.fill(); g.globalAlpha = 1;
            g.lineWidth = 12; g.strokeStyle = hex6(colorHex); g.stroke();
            g.beginPath(); g.arc(cx, cy, 8, 0, Math.PI * 2); g.fillStyle = hex6(colorHex); g.fill();
        } else {
            g.fillStyle = 'rgba(8, 12, 20, 0.95)'; g.fill();
            g.lineWidth = 7; g.strokeStyle = hex6(colorHex); g.stroke();
            g.beginPath(); g.arc(cx, cy, 4.5, 0, Math.PI * 2); g.fillStyle = hex6(colorHex); g.fill();
        }
        if (expiring) {
            g.beginPath(); g.arc(s - 20, 20, 11, 0, Math.PI * 2);
            g.fillStyle = '#ffaa00'; g.fill();
            g.lineWidth = 3; g.strokeStyle = 'rgba(8,12,20,0.95)'; g.stroke();
            g.fillStyle = 'rgba(8,12,20,0.95)'; g.font = 'bold 15px "Courier New", monospace';
            g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText('!', s - 20, 21);
        }
        var tex = new THREE.CanvasTexture(cv); tex.minFilter = THREE.LinearFilter; return tex;
    }

    function shapeMaterial(colorHex, dim) {
        return new THREE.MeshStandardMaterial({
            color: 0x0a0f18, emissive: colorHex, emissiveIntensity: dim ? 0.4 : 1.0,
            roughness: 0.35, metalness: 0.45
        });
    }

    function roleExtrudeShape(type) {
        var s = new THREE.Shape(), r = 1, i, a, px, py;
        switch (type) {
            case 'gateway':
                s.moveTo(-r, -r); s.lineTo(r, -r); s.lineTo(r, r); s.lineTo(-r, r); s.closePath(); break;
            case 'dirauth':
                s.moveTo(0, r); s.lineTo(r, 0); s.lineTo(0, -r); s.lineTo(-r, 0); s.closePath(); break;
            case 'service':
                s.moveTo(0, r); s.lineTo(r, -r * 0.8); s.lineTo(-r, -r * 0.8); s.closePath(); break;
            case 'out':
                s.moveTo(0, -r); s.lineTo(r, r * 0.8); s.lineTo(-r, r * 0.8); s.closePath(); break;
            case 'storage':
                for (i = 0; i < 6; i++) {
                    a = Math.PI / 6 + i * Math.PI / 3; px = r * Math.cos(a); py = r * Math.sin(a);
                    if (i === 0) s.moveTo(px, py); else s.lineTo(px, py);
                }
                s.closePath(); break;
            default:            // mix + fallback: circle
                s.absarc(0, 0, r, 0, Math.PI * 2, false);
        }
        return s;
    }

    function buildExtruded(type, colorHex, dim) {
        var geo = new THREE.ExtrudeGeometry(roleExtrudeShape(type), {
            depth: 0.5, bevelEnabled: true, bevelThickness: 0.12,
            bevelSize: 0.12, bevelSegments: 2, steps: 1
        });
        geo.center();
        var m = new THREE.Mesh(geo, shapeMaterial(colorHex, dim));
        var g = new THREE.Group(); g.add(m);
        g.userData.katzenMats = [m.material];
        g.userData.katzenAnim = function (dt) { g.rotation.y += dt * 0.6; };
        return g;
    }

    function latheProfile(type) {
        var P = function (x, y) { return new THREE.Vector2(x, y); };
        switch (type) {
            case 'dirauth':   // tall spire / obelisk (authority beacon)
                return [P(0, -1), P(0.45, -1), P(0.38, -0.6), P(0.22, 0), P(0.1, 0.7), P(0.03, 1.25), P(0, 1.35)];
            case 'gateway':   // ringed spool / gate
                return [P(0, -0.85), P(0.7, -0.85), P(0.7, -0.55), P(0.32, -0.4), P(0.32, 0.4), P(0.7, 0.55), P(0.7, 0.85), P(0, 0.85)];
            case 'service':   // chalice / cup
                return [P(0, -1), P(0.32, -1), P(0.34, -0.55), P(0.12, -0.3), P(0.12, 0.1), P(0.5, 0.7), P(0.56, 0.95), P(0, 0.95)];
            case 'storage':   // drum (disk platters)
                return [P(0, -0.8), P(0.72, -0.8), P(0.72, -0.3), P(0.62, -0.3), P(0.62, 0.3), P(0.72, 0.3), P(0.72, 0.8), P(0, 0.8)];
            case 'out':       // funnel / inverted cone (exit)
                return [P(0, -1), P(0.14, -1), P(0.14, 0.1), P(0.8, 0.9), P(0.8, 1.0), P(0, 1.0)];
            default:          // mix: bicone (a 3D diamond)
                return [P(0, -1), P(0.75, 0), P(0, 1)];
        }
    }

    function buildPieces(type, colorHex, dim) {
        var geo = new THREE.LatheGeometry(latheProfile(type), 28);
        var m = new THREE.Mesh(geo, shapeMaterial(colorHex, dim));
        var g = new THREE.Group(); g.add(m);
        g.userData.katzenMats = [m.material];
        g.userData.katzenAnim = function (dt) { g.rotation.y += dt * 0.5; };
        return g;
    }

    function buildMachine(type, colorHex, dim) {
        var g = new THREE.Group(), mats = [], orbiters = [];
        function mkMat() { var m = shapeMaterial(colorHex, dim); mats.push(m); return m; }
        function add(geo, mat, x, y, z) {
            var me = new THREE.Mesh(geo, mat); me.position.set(x || 0, y || 0, z || 0); g.add(me); return me;
        }
        var ring, cone, base, sat, i, k;
        switch (type) {
            case 'gateway':   // torus portal the packets pass through
                add(new THREE.TorusGeometry(0.8, 0.16, 12, 28), mkMat()).rotation.x = Math.PI / 2;
                break;
            case 'service':   // cube with orbiting satellites
                add(new THREE.BoxGeometry(0.8, 0.8, 0.8), mkMat());
                for (i = 0; i < 3; i++) {
                    sat = add(new THREE.SphereGeometry(0.14, 8, 8), mkMat());
                    orbiters.push({ mesh: sat, r: 0.95, a: i * 2.1, sp: 1.4, tilt: i });
                }
                break;
            case 'storage':   // stack of platters
                for (k = -1; k <= 1; k++) add(new THREE.CylinderGeometry(0.7, 0.7, 0.22, 20), mkMat(), 0, k * 0.32, 0);
                break;
            case 'dirauth':   // pillar + slow orbiting ring
                add(new THREE.CylinderGeometry(0.22, 0.28, 1.5, 12), mkMat());
                ring = add(new THREE.TorusGeometry(0.62, 0.06, 8, 24), mkMat());
                ring.rotation.x = Math.PI / 2.4; orbiters.push({ ring: ring });
                break;
            case 'out':       // cone (pointing down) + base ring
                cone = add(new THREE.ConeGeometry(0.55, 1.1, 16), mkMat(), 0, 0.1, 0); cone.rotation.x = Math.PI;
                base = add(new THREE.TorusGeometry(0.5, 0.08, 8, 20), mkMat(), 0, -0.5, 0); base.rotation.x = Math.PI / 2;
                break;
            case 'mix':       // icosahedron core inside a wire cage
                add(new THREE.IcosahedronGeometry(0.55, 0), mkMat());
                var cage = shapeMaterial(colorHex, dim); cage.wireframe = true; mats.push(cage);
                add(new THREE.IcosahedronGeometry(0.92, 0), cage);
                break;
            default:          // client / fallback: tetrahedron
                add(new THREE.TetrahedronGeometry(0.6), mkMat());
        }
        g.userData.katzenMats = mats;
        g.userData.katzenAnim = function (dt) {
            g.rotation.y += dt * 0.4;
            for (var j = 0; j < orbiters.length; j++) {
                var o = orbiters[j];
                if (o.mesh) {
                    o.a += dt * o.sp;
                    o.mesh.position.set(Math.cos(o.a) * o.r, Math.sin(o.a + o.tilt) * 0.3, Math.sin(o.a) * o.r);
                } else if (o.ring) { o.ring.rotation.z += dt * 0.8; }
            }
        };
        return g;
    }

    function buildNodeShape(type, colorHex, style, dim) {
        if (style === 'extruded') return buildExtruded(type, colorHex, dim);
        if (style === 'pieces') return buildPieces(type, colorHex, dim);
        if (style === 'machine') return buildMachine(type, colorHex, dim);
        return null;
    }

    function highlightGroup(objs) {
        (objs || []).forEach(function (o) { if (o) o.groupTimer = 2.6; });
    }

    function makeTube(points, radius, color, opacity) {
        var pts = points.filter(function (p) { return p; });
        if (pts.length < 2) return null;
        var geo = new THREE.TubeGeometry(new THREE.CatmullRomCurve3(pts),
            Math.max(8, pts.length * 2), radius, 5, false);
        return new THREE.Mesh(geo, new THREE.MeshBasicMaterial(
            { color: color, transparent: opacity < 1, opacity: opacity }));
    }

    function glassMaterial(colorHex, opacity) {
        return new THREE.MeshStandardMaterial({
            color: colorHex, transparent: true, opacity: opacity, side: THREE.DoubleSide,
            roughness: 0.15, metalness: 0.1, depthWrite: false,
            emissive: colorHex, emissiveIntensity: 0.03
        });
    }

    function createLabel(text, colorHex) {
        var pad = 10, font = 36;
        var fam = 'bold ' + font + 'px "Courier New", monospace';
        var measure = document.createElement('canvas').getContext('2d');
        measure.font = fam;
        var w = Math.ceil(measure.measureText(text).width) + pad * 2;
        var h = font + pad * 2;
        var canvas = document.createElement('canvas');
        canvas.width = w; canvas.height = h;
        var ctx = canvas.getContext('2d');
        ctx.font = fam;
        ctx.textBaseline = 'middle';
        ctx.fillStyle = 'rgba(4, 8, 14, 0.78)';
        var r = 8;
        ctx.beginPath();
        ctx.moveTo(r, 0); ctx.arcTo(w, 0, w, h, r); ctx.arcTo(w, h, 0, h, r);
        ctx.arcTo(0, h, 0, 0, r); ctx.arcTo(0, 0, w, 0, r); ctx.closePath(); ctx.fill();
        ctx.shadowColor = hex6(colorHex);
        ctx.shadowBlur = 10;
        ctx.fillStyle = '#ffffff';
        ctx.fillText(text, pad, h / 2 + 2);
        ctx.shadowBlur = 0;
        ctx.fillStyle = hex6(colorHex);
        ctx.globalAlpha = 0.55;
        ctx.fillText(text, pad, h / 2 + 2);
        ctx.globalAlpha = 1;
        var tex = new THREE.CanvasTexture(canvas);
        tex.minFilter = THREE.LinearFilter;
        var sprite = new THREE.Sprite(new THREE.SpriteMaterial(
            { map: tex, transparent: true, depthWrite: false, depthTest: true }));
        sprite.scale.set(w * 0.013, h * 0.013, 1);
        return sprite;
    }

    var ICON = 2.4;   // node icon size in world units (billboarded, so on-screen)

    function createNode(x, y, z, data, tierRadius, isDirauth) {
        var colorHex = statusColor(data.status);
        var dim = (data.status === 'unknown');
        var isDown = (data.status === 'down');
        var mke = (data.details && data.details.mixkey_epochs) || [];
        var expiring = (netEpoch != null && mke.length > 0 && Math.max.apply(null, mke) <= netEpoch);
        var flat = (nodeStyle === 'flat');
        var mesh, shape = null;
        if (flat) {
            var mat = new THREE.MeshBasicMaterial({
                map: makeNodeIcon(data.type, colorHex, false, expiring), transparent: true, opacity: dim ? 0.7 : 1,
                alphaTest: 0.35, depthTest: true, depthWrite: true
            });
            mesh = new THREE.Mesh(new THREE.PlaneGeometry(ICON, ICON), mat);
        } else {
            mesh = new THREE.Mesh(new THREE.SphereGeometry(ICON * 0.7, 8, 6),
                new THREE.MeshBasicMaterial({ visible: false }));
            shape = buildNodeShape(data.type, colorHex, nodeStyle, dim);
            if (shape) mesh.add(shape);
            if (expiring) {   // amber "expiring soon" badge (the glyph draws its own)
                var badge = new THREE.Mesh(new THREE.SphereGeometry(0.22, 10, 10),
                    new THREE.MeshStandardMaterial({ color: 0x1a1200, emissive: 0xffaa00, emissiveIntensity: 1.5 }));
                badge.position.set(0.9, 0.9, 0); mesh.add(badge);
            }
        }
        mesh.position.set(x, y, z);
        mesh.renderOrder = 2;   // draw nodes over the links
        worldRoot.add(mesh);

        var label = createLabel(data.name, colorHex);
        label.position.set(0, ICON * 0.85, 0);
        mesh.add(label);

        var q = new THREE.Quaternion();
        var obj = {
            mesh: mesh, shape: shape, flat: flat, data: data, isDown: isDown,
            pulseTimer: 0, groupTimer: 0, statusHex: colorHex, expiring: expiring,
            billboard: function () {
                if (!this.flat) return;
                q.copy(worldRoot.quaternion).invert().multiply(camera.quaternion);
                this.mesh.quaternion.copy(q);
            },
            setScale: function (s) {
                if (this.flat) this.mesh.scale.set(s, s, 1); else this.mesh.scale.set(s, s, s);
            },
            _setIcon: function (hex, filled) {
                if (this.flat) {
                    var old = this.mesh.material.map;
                    this.mesh.material.map = makeNodeIcon(this.data.type, hex, filled, this.expiring);
                    this.mesh.material.needsUpdate = true;
                    if (old) old.dispose();
                } else if (this.shape && this.shape.userData.katzenMats) {
                    this.shape.userData.katzenMats.forEach(function (m) {
                        m.emissive.setHex(hex);
                        m.emissiveIntensity = filled ? 1.7 : (dim ? 0.4 : 1.0);
                    });
                }
            },
            setIconColor: function (hex) {
                if (this.data.status === 'down') return;
                this._setIcon(hex, true);
            },
            resetIcon: function () { this._setIcon(this.statusHex, false); },
            flash: function () { this.setScale(1.5); this.pulseTimer = 1.0; },
            update: function (dt, t) {
                this.billboard();
                if (this.shape && this.shape.userData.katzenAnim) this.shape.userData.katzenAnim(dt, t);
                if (this.groupTimer > 0) {          // a selected group pulses together
                    this.groupTimer -= dt;
                    var gp = 0.5 + 0.5 * Math.sin(t * 8.0);
                    this.setScale(1.0 + 0.55 * gp);
                    if (this.groupTimer <= 0) this.setScale(1);
                    return;
                }
                if (this.pulseTimer > 0) {
                    this.pulseTimer -= dt * 4.0;
                    var ps = this.pulseTimer <= 0 ? 1 : (1.0 + 0.5 * this.pulseTimer);
                    this.setScale(ps);
                    if (this.pulseTimer <= 0) this.pulseTimer = 0;
                    return;
                }
                if (isDown) {                        // down nodes pulse so they stand out
                    var s = 0.5 + 0.5 * Math.sin(t * 5.0);
                    this.setScale(1.0 + 0.22 * s);
                }
            }
        };
        mesh.userData = obj;
        obj.label = label;
        label.userData = obj;        // clicking a name label selects its node
        label.visible = labelsAll;   // declutter: labels show on hover/selection
        nodeObjs.push(obj);
        data._obj = obj;
        return obj;
    }

    function drawVantage() {
        vantagePos = new THREE.Vector3(0, 30, 0);
        vantageObj = new THREE.Mesh(
            new THREE.OctahedronGeometry(1.1),
            new THREE.MeshStandardMaterial({
                color: 0xdfe8f0, emissive: 0x8899aa, emissiveIntensity: 0.6,
                roughness: 0.3, metalness: 0.6
            }));
        vantageObj.position.copy(vantagePos);
        vantageObj.userData = { katzenSelect: showVantage };
        worldRoot.add(vantageObj);
        pickExtras.push(vantageObj);
        var lab = createLabel('monitor', 0xdfe8f0);
        lab.position.set(0, 2.0, 0);
        vantageObj.add(lab);
    }

    function ensureSelGroup() {
        if (!selGroup) { selGroup = new THREE.Group(); worldRoot.add(selGroup); }
    }
    function clearSelPath() {
        if (!selGroup) return;
        while (selGroup.children.length) {
            var c = selGroup.children[0];
            selGroup.remove(c);
            if (c.geometry) c.geometry.dispose();
            if (c.material) c.material.dispose();
        }
    }
    function drawSelectionPath(node) {
        ensureSelGroup();
        clearSelPath();
        if (!node || !(node.data.hop_count || 0)) return;
        var line = pathBuilder
            ? pathBuilder(node)
            : makeTube([vantagePos.clone(), node.mesh.position.clone()], 0.45, latencyColor(node.data.latency_ms), 0.8);
        if (line) selGroup.add(line);
    }

    function vantageLink(a, b, hops, latency, curvePoints) {
        var col = latencyColor(latency);
        var seg = Math.min(hops, 30);
        var pts = [];
        var at = curvePoints
            ? function (t) { return sampleCurve(curvePoints, t); }
            : function (t) { return a.clone().lerp(b, t); };
        for (var i = 0; i < seg; i++) {
            pts.push(at(i / seg));
            pts.push(at((i + 0.6) / seg));
        }
        return new THREE.LineSegments(
            new THREE.BufferGeometry().setFromPoints(pts),
            new THREE.LineBasicMaterial({ color: col, transparent: true, opacity: 0.5 }));
    }

    function sampleCurve(pts, t) {
        var n = pts.length - 1, f = t * n, i = Math.floor(f), r = f - i;
        if (i >= n) return pts[n].clone();
        return pts[i].clone().lerp(pts[i + 1], r);
    }

    function downgradeToFlat(reason) {
        if (nodeStyle === 'flat') return false;
        nodeStyle = 'flat';
        styleAttemptPending = false;
        try {
            if (window.localStorage) {
                localStorage.removeItem('katzen.nodeStyle');
                localStorage.removeItem('katzen.styleAttempt');
            }
        } catch (e) { }
        setStatusLine('3D node shapes were too heavy for this device (' +
            (reason || 'render error') + '); switched to flat glyphs.');
        return true;
    }

    function buildSceneSafe(DATA) {
        markStyleAttempt();   // sentinel set now, cleared after the first frame
        try {
            buildScene(DATA);
        } catch (e) {
            if (downgradeToFlat(e && e.message ? e.message : 'error')) buildScene(DATA);
            else throw e;
        }
    }

    function buildScene(DATA) {
        lastData = DATA;
        netEpoch = (typeof DATA.epoch === 'number') ? DATA.epoch : null;
        clearWorld();

        var nodesByType = {};
        DATA.nodes.forEach(function (n) { (nodesByType[n.type] || (nodesByType[n.type] = [])).push(n); });
        var get = function (t) { return nodesByType[t] || []; };

        var tiers = [];
        if (get('gateway').length) tiers.push({ id: 'gateway', label: 'Gateways', nodes: get('gateway'), radius: 22 });
        (DATA.layers || []).forEach(function (layerNames, i) {
            tiers.push({ id: 'mix' + i, label: 'Mix Layer ' + (i + 1),
                         nodes: get('mix').filter(function (n) { return n.layer === i; }), radius: 15 });
        });
        if (get('service').length) tiers.push({ id: 'service', label: 'Service Nodes', nodes: get('service'), radius: 12 });
        if (get('storage').length) tiers.push({ id: 'storage', label: 'Storage Replicas', nodes: get('storage'), radius: 10 });
        if (get('out').length) tiers.push({ id: 'out', label: 'Reachable - Not in Consensus', nodes: get('out'), radius: 24 });

        var ySpan = 60, yStart = -ySpan / 2;
        var yStep = tiers.length > 1 ? ySpan / (tiers.length - 1) : 0;
        tiers.forEach(function (t, i) { t.y = yStart + i * yStep; });

        tiers.forEach(function (tier) {
            var cyl = new THREE.Mesh(
                new THREE.CylinderGeometry(tier.radius, tier.radius, 4.5, 32, 1, false),
                glassMaterial(0x2a3b52, 0.08));
            cyl.position.y = tier.y; worldRoot.add(cyl); layerCylinders.push(cyl);
            var ring = new THREE.Mesh(
                new THREE.RingGeometry(tier.radius - 0.25, tier.radius + 0.25, 64),
                new THREE.MeshBasicMaterial({ color: 0x3a86ff, side: THREE.DoubleSide, transparent: true, opacity: 0.28 }));
            ring.rotation.x = Math.PI / 2; ring.position.y = tier.y; worldRoot.add(ring);
            var n = tier.nodes.length;
            tier.nodes.forEach(function (nd, i) {
                var angle = n === 1 ? 0 : (i / n) * Math.PI * 2;
                var x = Math.cos(angle) * (n === 1 ? 0 : tier.radius);
                var z = Math.sin(angle) * (n === 1 ? 0 : tier.radius);
                createNode(x, tier.y, z, nd, tier.radius, false);
            });
        });

        var dirauths = get('dirauth');
        var maxR = tiers.reduce(function (m, t) { return Math.max(m, t.radius); }, 10);
        var dirauthRadius = maxR + 10;
        if (dirauths.length) {
            dirauthRing = new THREE.Mesh(
                new THREE.RingGeometry(dirauthRadius - 0.18, dirauthRadius + 0.18, 96),
                new THREE.MeshBasicMaterial({ color: 0xffaa00, side: THREE.DoubleSide, transparent: true, opacity: 0.35 }));
            dirauthRing.rotation.x = Math.PI / 2; worldRoot.add(dirauthRing);
            dirauths.forEach(function (nd, i) {
                var a = (i / dirauths.length) * Math.PI * 2;
                createNode(Math.cos(a) * dirauthRadius, 0, Math.sin(a) * dirauthRadius, nd, dirauthRadius, true);
            });
        }

        var dirauthObjs = nodeObjs.filter(function (o) { return o.data.type === 'dirauth'; });
        if (dirauthObjs.length) {
            var pkiMat = new THREE.LineBasicMaterial({ color: 0xffaa00, transparent: true, opacity: 0.06 });
            nodeObjs.filter(function (o) { return o.data.type !== 'dirauth' && o.data.in_consensus; }).forEach(function (o) {
                var nearest = dirauthObjs[0], min = Infinity;
                dirauthObjs.forEach(function (d) {
                    var dist = o.mesh.position.distanceTo(d.mesh.position);
                    if (dist < min) { min = dist; nearest = d; }
                });
                worldRoot.add(new THREE.Line(
                    new THREE.BufferGeometry().setFromPoints([o.mesh.position.clone(), nearest.mesh.position.clone()]),
                    pkiMat));
            });
        }

        drawVantage();
        buildTopology(tiers);
        setupTraffic(DATA, tiers);
        buildPresets(tiers, dirauths.length ? dirauthRadius : 0);
        updateHud(DATA);

        if (!cameraInitialized) {
            targetCamPos.set(38, 26, 60); targetLookAt.set(0, 0, 0);
            gotoActive = true;
            cameraInitialized = true;
        }
        runHooks(HOOKS.build, DATA);
    }

    function setupTraffic(DATA, tiers) {
        var pick = function (a) { return a[Math.floor(Math.random() * a.length)]; };
        var reachOf = function (objs) { var r = objs.filter(function (o) { return o.data.reachable; }); return r.length ? r : objs; };
        var objsOf = function (tier) { return tier ? reachOf(tier.nodes.map(function (n) { return n._obj; })) : []; };

        var gwPool = objsOf(tiers.find(function (t) { return t.id === 'gateway'; }));
        var mixPools = tiers.filter(function (t) { return /^mix\d+$/.test(t.id); }).map(objsOf).filter(function (p) { return p.length; });
        var exitPool = [];
        var svc = tiers.find(function (t) { return t.id === 'service'; });
        var sto = tiers.find(function (t) { return t.id === 'storage'; });
        if (svc) exitPool = exitPool.concat(svc.nodes.map(function (n) { return n._obj; }));
        if (sto) exitPool = exitPool.concat(sto.nodes.map(function (n) { return n._obj; }));
        exitPool = reachOf(exitPool);

        var perGw = (DATA.clients_per_gateway != null) ? DATA.clients_per_gateway : 3;
        var gwTier = tiers.find(function (t) { return t.id === 'gateway'; });
        var gwNodes = gwTier ? gwTier.nodes.map(function (n) { return n._obj; }) : [];
        var clientObjs = [];
        gwNodes.forEach(function (gw) {
            for (var ci = 0; ci < perGw; ci++) {
                var m = new THREE.Mesh(
                    new THREE.SphereGeometry(0.33, 10, 10),
                    new THREE.MeshBasicMaterial({ color: 0x88bbff, transparent: true, opacity: 0.75 }));
                m.position.copy(gw.mesh.position);
                worldRoot.add(m);
                var c = {
                    mesh: m, gw: gw, angle: (ci / Math.max(1, perGw)) * Math.PI * 2,
                    speed: 0.3 + 0.12 * ci, orbit: 3.2,
                    flash: function () { this.mesh.material.opacity = 1.0; }
                };
                clients.push(c);
                clientObjs.push(c);
            }
        });
        function clientOrigin() { return clientObjs.length ? clientObjs[Math.floor(Math.random() * clientObjs.length)] : null; }

        var P = DATA.parameters || {};
        var pos = function (v) { return (typeof v === 'number' && isFinite(v) && v > 0) ? v : 0; };
        var muMean = pos(P.Mu) ? 1 / P.Mu : 0;
        function expRand(mean) { return -Math.log(1 - Math.random()) * mean; }
        function hopDwell() {
            var mean = muMean > 0 ? Math.min(0.7, Math.max(0.08, muMean * 0.02)) : 0.18;
            return expRand(mean);
        }

        var weights = { real: pos(P.LambdaP), cloop: pos(P.LambdaL), drop: pos(P.LambdaD), mloop: pos(P.LambdaM), gloop: pos(P.LambdaG) };
        if (Object.keys(weights).reduce(function (a, k) { return a + weights[k]; }, 0) <= 0)
            weights = { real: 0.5, cloop: 0.25, drop: 0.15, mloop: 0.07, gloop: 0.03 };
        var TYPE_COLOR = { real: 0x00f3ff, cloop: 0xffaa00, drop: 0xff00aa, mloop: 0x8338ec, gloop: 0x00ff88 };

        function buildPath(type) {
            var L = mixPools;
            if (type === 'real') {
                var c = clientOrigin();
                if (!c || !L.length || !exitPool.length) return null;
                return [c, c.gw].concat(L.map(pick), [pick(exitPool)]);
            }
            if (type === 'cloop') {
                var c2 = clientOrigin();
                if (!c2 || !L.length) return null;
                return [c2, c2.gw].concat(L.map(pick), [c2.gw, c2]);
            }
            if (type === 'drop') {
                var c3 = clientOrigin();
                if (!c3 || !L.length) return null;
                var cut = 1 + Math.floor(Math.random() * L.length);
                return [c3, c3.gw].concat(L.slice(0, cut).map(pick));
            }
            if (type === 'mloop') { if (!L.length) return null; var li = Math.floor(Math.random() * L.length); var m = pick(L[li]); return [m].concat(L.slice(li + 1).map(pick), [m]); }
            if (type === 'gloop') { if (!gwPool.length || !L.length) return null; var g = pick(gwPool); return [g, pick(L[0]), g]; }
            return null;
        }

        var activeWeights = {};
        Object.keys(weights).forEach(function (k) { if (buildPath(k)) activeWeights[k] = weights[k]; });
        var wsum = Object.keys(activeWeights).reduce(function (a, k) { return a + activeWeights[k]; }, 0);
        function pickType() { var x = Math.random() * wsum, acc = 0; for (var k in activeWeights) { acc += activeWeights[k]; if (x <= acc) return k; } return Object.keys(activeWeights)[0]; }

        function Packet(type, path) {
            this.type = type; this.path = path;
            var color = TYPE_COLOR[type] || 0x00f3ff; this.color = color;
            this.mesh = new THREE.Mesh(coneGeo, new THREE.MeshStandardMaterial({ color: color, emissive: color, emissiveIntensity: 2.0, roughness: 0.2 }));
            this.seg = 0; this.progress = 0; this.speed = 0.7 + Math.random() * 0.6; this.dwell = 0;
            this.prev = path[0].mesh.position.clone();
            this.mesh.position.copy(this.prev);
            worldRoot.add(this.mesh);
        }
        Packet.prototype.update = function (dt) {
            if (this.dwell > 0) { this.dwell -= dt; return true; }
            if (this.seg >= this.path.length - 1) { worldRoot.remove(this.mesh); return false; }
            this.progress += dt * this.speed;
            if (this.progress >= 1.0) {
                var node = this.path[this.seg + 1]; node.flash(this.color);
                this.seg++; this.progress = 0; this.mesh.position.copy(node.mesh.position);
                if (this.seg >= this.path.length - 1) { worldRoot.remove(this.mesh); return false; }
                this.dwell = hopDwell(); return true;
            }
            var A = this.path[this.seg].mesh.position, B = this.path[this.seg + 1].mesh.position;
            if (segInterp) this.mesh.position.copy(segInterp(A, B, this.progress));
            else this.mesh.position.lerpVectors(A, B, this.progress);
            var dir = this.mesh.position.clone().sub(this.prev);
            if (dir.lengthSq() > 1e-8) this.mesh.quaternion.setFromUnitVectors(UP_Y, dir.normalize());
            this.prev.copy(this.mesh.position);
            return true;
        };

        var maxInFlight = isMobile() ? 60 : 170;
        var VIZ_SCALE = 1.0;
        var perSec = function (v) { return pos(v) * 1000; };
        var numMix = mixPools.reduce(function (a, p) { return a + p.length; }, 0);
        var rate = clients.length * (perSec(P.LambdaP) + perSec(P.LambdaL) + perSec(P.LambdaD))
            + numMix * perSec(P.LambdaM)
            + gwPool.length * perSec(P.LambdaG);
        if (rate <= 0) rate = 8;   // fallback so something animates
        targetPacketRate = rate;

        var acc = 0;
        packetSpawn = function (dt) {
            if (wsum <= 0) return;
            acc += rate * VIZ_SCALE * dt;
            var guard = 0;
            while (acc >= 1 && packets.length < maxInFlight && guard < 40) {
                acc -= 1; guard++;
                var type = pickType(), path = buildPath(type);
                if (path && path.length >= 2) packets.push(new Packet(type, path));
            }
            if (acc > 5) acc = 5;   // do not accumulate a backlog while hidden
        };
    }

    function frameNodes(objs) {
        var ps = [];
        (objs || []).forEach(function (o) {
            if (!o || !o.mesh) return;
            ps.push((planarView && o.flatPos) ? o.flatPos.clone() : o.mesh.getWorldPosition(new THREE.Vector3()));
        });
        if (!ps.length) return;
        var c = new THREE.Vector3();
        ps.forEach(function (p) { c.add(p); });
        c.multiplyScalar(1 / ps.length);
        var rad = 6;
        ps.forEach(function (p) { rad = Math.max(rad, p.distanceTo(c)); });
        var dist = rad / Math.tan(THREE.MathUtils.degToRad(camera.fov * 0.5)) * 1.5 + 8;
        var dir = c.clone();
        if (dir.lengthSq() < 1) dir.set(0.5, 0.5, 0.9);   // symmetric ring -> pick an angle
        dir.normalize();
        if (planarView) {
            targetLookAt.set(c.x, c.y, 0);
            targetCamPos.set(c.x, c.y, dist);
            controls.target.copy(targetLookAt);
        } else if (orbitOrigin) {
            targetLookAt.set(0, 0, 0);
            targetCamPos.copy(dir.multiplyScalar(Math.max(controls ? controls.minDistance + 4 : 40, c.length() + dist)));
        } else {
            targetLookAt.copy(c);
            targetCamPos.copy(c).add(dir.multiplyScalar(dist));
        }
        gotoActive = true;
    }

    var PRESET_COLORS = [null, 0xff8f3f, 0x9b5de5, 0xff5d8f, 0xffd23f, 0x00e0a0, 0x4d8bf0, 0xffa3d5];

    function buildPresets(tiers, hasDirauths) {
        var presets = [{ label: 'Full Network View', get: function () { return nodeObjs; } }];
        tiers.forEach(function (t) {
            presets.push({ label: t.label, get: function () { return t.nodes.map(function (n) { return n._obj; }); } });
        });
        if (hasDirauths) presets.push({
            label: 'Directory Authorities',
            get: function () { return nodeObjs.filter(function (o) { return o.data.type === 'dirauth'; }); }
        });
        var box = document.getElementById('view-buttons');
        box.innerHTML = '';
        presets.forEach(function (p, idx) {
            var btn = document.createElement('button');
            btn.textContent = p.label;
            if (idx === 0) btn.classList.add('active');
            btn.addEventListener('click', function () {
                var all = document.querySelectorAll('#view-buttons button');
                for (var i = 0; i < all.length; i++) all[i].classList.remove('active');
                btn.classList.add('active');
                var objs = p.get();
                if (idx === 0) clearSelection();          // "all" resets, keeps status colours
                else highlightSelection(objs, PRESET_COLORS[idx % PRESET_COLORS.length] || 0x2ec4b6);
                frameNodes(objs);
                if (isMobile()) setMenuVisible(false);
            });
            box.appendChild(btn);
        });
    }
    function selectGroupByLabel(name) {
        var btns = document.querySelectorAll('#view-buttons button');
        for (var i = 0; i < btns.length; i++) {
            if (btns[i].textContent.toLowerCase().indexOf(String(name).toLowerCase()) >= 0) { btns[i].click(); return true; }
        }
        return false;
    }

    function updateHud(DATA) {
        var c = DATA.counts || {}, by = c.by_status || {};
        document.getElementById('hud-title').innerText = (DATA.network_name || 'Katzenpost') + ' Mixnet';
        var bits = [];
        if (DATA.epoch_time_str) bits.push('Epoch: ' + esc(DATA.epoch_time_str) + ' UTC'
            + (DATA.epoch != null ? ' #' + esc(DATA.epoch) : ''));
        bits.push((c.total || DATA.nodes.length) + ' nodes - ' + (c.layers || 0) + ' mix layers');
        bits.push('ok ' + (by.ok || 0) + ' - out ' + (by.out || 0) + ' - down ' + (by.down || 0) + ' - unknown ' + (by.unknown || 0));
        var P = DATA.parameters || {};
        var pf = function (v) { return (typeof v === 'number' && isFinite(v)) ? v : '-'; };
        var lam = [];
        [['λP', P.LambdaP], ['λL', P.LambdaL], ['λD', P.LambdaD], ['λM', P.LambdaM], ['λG', P.LambdaG], ['λR', P.LambdaR]]
            .forEach(function (kv) { if (kv[1] != null) lam.push(kv[0] + ' ' + pf(kv[1])); });
        if (lam.length) bits.push('Traffic: ' + lam.join(' - '));
        if (P.Mu != null || P.SendRatePerMinute != null)
            bits.push('Mu ' + pf(P.Mu) + (P.SendRatePerMinute != null ? ' - SendRate ' + pf(P.SendRatePerMinute) + '/min' : ''));
        var cs = DATA.consensus || {};
        if (cs.version) bits.push('PKI version: ' + esc(cs.version));
        if (cs.pki_signature_scheme) bits.push('Consensus signed with: ' + esc(cs.pki_signature_scheme));
        if (cs.wire) bits.push('Wire link: ' + esc(cs.wire) + (cs.link_kem ? ' / ' + esc(cs.link_kem) : ''));
        if (DATA.generated_at) bits.push('Updated: ' + esc(DATA.generated_at) + ' UTC');
        document.getElementById('hud-meta').innerHTML = bits.join('<br>');
        document.title = (DATA.network_name || 'Katzenpost') + ' Mixnet - Live Consensus Visualization';
    }

    function setupPointer() {
        var raycaster = new THREE.Raycaster(), pointer = new THREE.Vector2();
        function setPointer(clientX, clientY) {
            var nx = (clientX / window.innerWidth) * 2 - 1;
            var ny = -(clientY / window.innerHeight) * 2 + 1;
            if (crtPass && crtPass.enabled) {
                var c = crtPass.uniforms.uCurve.value;
                nx += nx * (ny * ny * c);
                ny += ny * (nx * nx * c);
            }
            pointer.x = nx; pointer.y = ny;
        }
        var linkTip = document.createElement('div');
        linkTip.style.cssText = 'position:fixed;z-index:45;pointer-events:none;display:none;' +
            'background:rgba(8,12,20,0.94);border:1px solid rgba(255,180,84,0.4);color:#dfe8f0;' +
            'font:11px "Courier New",monospace;padding:4px 8px;border-radius:5px;max-width:260px';
        document.body.appendChild(linkTip);
        renderer.domElement.addEventListener('pointermove', function (e) {
            setPointer(e.clientX, e.clientY);
            raycaster.setFromCamera(pointer, camera);
            var vis = nodeObjs.map(function (n) { return n.mesh; }).filter(function (m) { return m.visible; });
            var hits = raycaster.intersectObjects(vis);
            var obj = hits.length ? hits[0].object.userData : null;
            if (!obj) {
                var links = allLinks.concat(selLinkMeshes).filter(function (m) { return m && m.visible; });
                var lh = raycaster.intersectObjects(links);
                var info = lh.length ? lh[0].object.userData.info : null;
                if (info) {
                    linkTip.innerHTML = esc(info.a) + ' &harr; ' + esc(info.b) + '<br><span style="color:#7b8e9d">'
                        + esc(info.kind) + ' &middot; PQ Noise</span>';
                    linkTip.style.left = (e.clientX + 12) + 'px';
                    linkTip.style.top = (e.clientY + 12) + 'px';
                    linkTip.style.display = 'block';
                } else { linkTip.style.display = 'none'; }
            } else { linkTip.style.display = 'none'; }
            if (obj === hoverObj) return;
            if (hoverObj && hoverObj.label && !labelsAll && hoverObj !== selectedObj) hoverObj.label.visible = false;
            hoverObj = (obj && obj.mesh) ? obj : null;
            if (hoverObj && hoverObj.label) hoverObj.label.visible = true;
            renderer.domElement.style.cursor = hoverObj ? 'pointer' : '';
        });
        renderer.domElement.addEventListener('pointerdown', function (e) { renderer.domElement._ps = { x: e.clientX, y: e.clientY }; });
        renderer.domElement.addEventListener('pointerup', function (e) {
            if (e.pointerType === 'mouse' && e.button !== 0) return;
            if (e.target.closest('#hud-panel') || e.target.closest('#menu-toggle') || e.target.closest('#node-info')) return;
            var s = renderer.domElement._ps;
            if (s) { var dx = e.clientX - s.x, dy = e.clientY - s.y; if (dx * dx + dy * dy > 100) return; }
            setPointer(e.clientX, e.clientY);
            raycaster.setFromCamera(pointer, camera);
            var nodePick = [];
            nodeObjs.forEach(function (n) {
                if (n.mesh.visible) nodePick.push(n.mesh);
                if (n.label && n.label.visible) nodePick.push(n.label);   // clicking a label picks its node
            });
            var nodeHits = raycaster.intersectObjects(nodePick);
            if (nodeHits.length) { focusNode(nodeHits[0].object.userData); return; }
            var extras = pickExtras.concat(linkPickables).concat(clusterMarkers).filter(function (m) { return m && m.visible; });
            var exHits = raycaster.intersectObjects(extras);
            if (exHits.length) {
                var ud = exHits[0].object.userData;
                if (ud && ud.katzenSelect) ud.katzenSelect();
                else if (ud && ud.mesh) focusNode(ud);
            } else {
                deselect();
            }
        });
    }

    function row(label, value) { return '<p><span style="color:#7b8e9d">' + esc(label) + ':</span> ' + value + '</p>'; }

    function deselect() {
        if (selectedObj && !labelsAll && selectedObj.label && selectedObj !== hoverObj) {
            selectedObj.label.visible = false;
        }
        selectedObj = null;
        clearSelection();
        clearSelPath();
        showVantage();   // fall back to the consensus summary, not an empty box
        runHooks(HOOKS.node, null);   // let features (deeplink) drop their tracked selection
    }

    function showNode(obj) {
        if (selectedObj && selectedObj !== obj && !labelsAll && selectedObj.label && selectedObj !== hoverObj) {
            selectedObj.label.visible = false;
        }
        selectedObj = obj;
        if (obj.label) obj.label.visible = true;
        var d = obj.data, det = d.details || {};
        var box = document.getElementById('node-info');
        box.style.display = 'block';
        box.style.borderColor = hex6(statusColor(d.status));
        document.getElementById('info-title').innerText = d.name;
        var html = '<p style="margin:0 0 6px"><a href="#" class="copy-link" data-name="' + esc(d.name)
            + '" style="color:#00e0a0;font-size:10.5px;text-decoration:none">&#128279; copy link to this node</a></p>';
        var role = (d.type === 'out' ? (d.role || 'node') : d.type) + (d.layer != null ? ' (layer ' + (d.layer + 1) + ')' : '');
        html += row('Role', esc(role));
        html += row('Status', esc(STATUS_LABEL[d.status] || d.status));
        if (det.capabilities && det.capabilities.length) {
            var chips = det.capabilities.map(function (cap) {
                return '<span class="cap-chip" data-cap="' + esc(cap) + '" title="Highlight nodes with this capability" '
                    + 'style="cursor:pointer;display:inline-block;background:rgba(0,255,136,0.12);'
                    + 'border:1px solid rgba(0,255,136,0.4);color:#8effc0;border-radius:8px;padding:1px 7px;'
                    + 'margin:0 4px 3px 0;font-size:10px">' + esc(cap) + '</span>';
            }).join('');
            html += '<p><span style="color:#7b8e9d">Services:</span> ' + chips + '</p>';
        }
        html += row('Reachable', d.reachable ? 'yes' : 'no');
        if (d.latency_ms != null) html += row('Latency', esc(d.latency_ms) + ' ms');
        html += row('Traceroute hops', esc(d.hop_count || 0) + (d.reachable ? '' : ' (no path)'));
        if (det.addresses && det.addresses.length) html += row('Addresses', det.addresses.map(esc).join('<br>'));
        if (det.version) html += row('Version', esc(det.version));
        if (det.auth_type) html += row('Auth', esc(det.auth_type));
        if (det.load_weight != null) html += row('Load weight', esc(det.load_weight));
        if (det.replica_id != null) html += row('Replica ID', esc(det.replica_id));
        if (det.mixkey_epochs && det.mixkey_epochs.length) html += row('Mix-key epochs', esc(det.mixkey_epochs.join(', ')));
        if (det.envelope_key_epochs && det.envelope_key_epochs.length) html += row('Envelope-key epochs', esc(det.envelope_key_epochs.join(', ')));
        if (det.identity_fingerprint) html += row('Identity key', '<span style="font-family:monospace">' + esc(det.identity_fingerprint.slice(0, 16)) + '...</span>');
        if (det.link_fingerprint) html += row('Link key', '<span style="font-family:monospace">' + esc(det.link_fingerprint.slice(0, 16)) + '...</span>');
        var hops = d.hops || [];
        if (hops.length) {
            var lines = hops.map(function (h) {
                var loc = (h.geo && h.geo.label) ? h.geo.label : (h.ip || '*');
                return esc(h.hop + '. ' + loc + (h.asn ? ' ' + h.asn : ''));
            });
            var shown = lines.slice(0, 14).join('<br>') + (lines.length > 14 ? '<br>...' : '');
            html += row('Path (' + hops.length + ' hops)', '<span style="font-size:10px">' + shown + '</span>');
        }
        document.getElementById('info-body').innerHTML = html;
        runHooks(HOOKS.node, obj);
    }

    function showVantage() {
        var d = lastData || {}, box = document.getElementById('node-info');
        box.style.display = 'block';
        box.style.borderColor = hex6(0xdfe8f0);
        document.getElementById('info-title').innerText = 'Consensus summary';
        var c = d.counts || {}, by = c.by_status || {}, cs = d.consensus || {}, P = d.parameters || {};
        var html = '';
        if (d.vantage) html += row('Location', esc(d.vantage.label || (d.vantage.lat + ', ' + d.vantage.lon)));
        html += row('Role', 'monitor host / traceroute vantage');
        if (d.network_name) html += row('Network', esc(d.network_name));
        if (d.epoch_time_str) html += row('Epoch', esc(d.epoch_time_str) + ' UTC' + (d.epoch != null ? ' #' + esc(d.epoch) : ''));
        if (d.generated_at) html += row('Updated', esc(d.generated_at) + ' UTC');
        html += row('Nodes', (c.total || (d.nodes || []).length) + ' - ok ' + (by.ok || 0) +
            ', out ' + (by.out || 0) + ', down ' + (by.down || 0) + ', unknown ' + (by.unknown || 0));
        html += row('Traffic target', Math.round(targetPacketRate) + ' packets/s');
        var lam = [];
        [['λP', P.LambdaP], ['λL', P.LambdaL], ['λM', P.LambdaM], ['λG', P.LambdaG], ['λR', P.LambdaR]]
            .forEach(function (kv) { if (kv[1] != null) lam.push(kv[0] + ' ' + kv[1]); });
        if (P.Mu != null) html += row('Mu', esc(P.Mu));
        if (lam.length) html += row('Rates', esc(lam.join('  ')));
        if (cs.version) html += row('PKI version', esc(cs.version));
        if (cs.pki_signature_scheme)
            html += row('Consensus signature', esc(cs.pki_signature_scheme));
        if (cs.wire) html += row('Wire link', esc(cs.wire));
        if (cs.link_kem) html += row('Link KEM', esc(cs.link_kem));
        document.getElementById('info-body').innerHTML = html;
    }

    function showLink() {
        var cs = (lastData || {}).consensus || {}, box = document.getElementById('node-info');
        box.style.display = 'block';
        box.style.borderColor = hex6(0x8338ec);
        document.getElementById('info-title').innerText = 'Link protocol';
        var html = row('Type', 'node-to-node wire link');
        html += row('Protocol', esc(cs.wire || 'PQ Noise'));
        if (cs.link_kem) html += row('Link KEM', esc(cs.link_kem));
        if (cs.pki_signature_scheme) html += row('PKI signatures', esc(cs.pki_signature_scheme));
        html += '<p style="font-size:10px;color:#7b8e9d">Post-quantum Noise handshake; ' +
            'the same wire protocol secures every link between nodes.</p>';
        document.getElementById('info-body').innerHTML = html;
    }

    var TIER_LINK_COLORS = [0x2ec4b6, 0x4d8bf0, 0x9b5de5, 0xff8f3f, 0xff5d8f];
    var DIRAUTH_LINK_COLOR = 0xffd23f;   // PKI: dirauth <-> everything
    var REPLICA_LINK_COLOR = 0x00d2a0;   // storage replica <-> replica
    var COURIER_LINK_COLOR = 0xc06cff;   // courier service <-> replica
    function isPkiLink(a, b) { return a.data.type === 'dirauth' || b.data.type === 'dirauth'; }
    function linkColor(a, b) {
        if (!a || !b) return 0x4a7a9a;
        var ta = a.data.type, tb = b.data.type;
        if (ta === 'dirauth' || tb === 'dirauth') return DIRAUTH_LINK_COLOR;
        if (ta === 'storage' && tb === 'storage') return REPLICA_LINK_COLOR;
        if ((ta === 'service' && tb === 'storage') || (ta === 'storage' && tb === 'service')) return COURIER_LINK_COLOR;
        var t1 = (typeof a._tier === 'number') ? a._tier : 0;
        var t2 = (typeof b._tier === 'number') ? b._tier : 0;
        return TIER_LINK_COLORS[Math.min(t1, t2)] || 0x4a7a9a;
    }
    function hasCap(o, cap) {
        var c = (o.data.details && o.data.details.capabilities) || [];
        return c.indexOf(cap) >= 0;
    }
    function linkKind(a, b) {
        var ta = a.data.type, tb = b.data.type;
        if (ta === 'dirauth' || tb === 'dirauth') return 'PKI: consensus + descriptors';
        if (ta === 'storage' && tb === 'storage') return 'replica replication';
        if ((ta === 'service' && tb === 'storage') || (ta === 'storage' && tb === 'service')) return 'courier to replica';
        return 'Sphinx data path';
    }
    function linkInfo(a, b) { return { a: a.data.name, b: b.data.name, kind: linkKind(a, b) }; }

    function buildTopology(tiers) {
        topoPairs = [];
        var gw = tiers.filter(function (t) { return t.id === 'gateway'; });
        var mix = tiers.filter(function (t) { return /^mix\d+$/.test(t.id); });
        var order = gw.concat(mix);
        var services = [];
        tiers.forEach(function (t) { if (t.id === 'service') services = services.concat(t.nodes); });
        order.forEach(function (t, k) { t.nodes.forEach(function (a) { if (a._obj) a._obj._tier = k; }); });
        services.forEach(function (a) { if (a._obj) a._obj._tier = order.length; });
        for (var i = 0; i < order.length - 1; i++) {
            order[i].nodes.forEach(function (a) {
                order[i + 1].nodes.forEach(function (b) { topoPairs.push([a._obj, b._obj]); });
            });
        }
        var lastMix = order[order.length - 1];
        if (lastMix) lastMix.nodes.forEach(function (a) {
            services.forEach(function (b) { topoPairs.push([a._obj, b._obj]); });
        });
        var da = nodeObjs.filter(function (o) { return o.data.type === 'dirauth'; });
        var reps = nodeObjs.filter(function (o) { return o.data.type === 'storage'; });
        nodeObjs.forEach(function (n) {
            if (n.data.type === 'dirauth') return;
            da.forEach(function (d) { topoPairs.push([d, n]); });
        });
        for (var i = 0; i < da.length; i++) {
            for (var j = i + 1; j < da.length; j++) topoPairs.push([da[i], da[j]]);
        }
        for (var i = 0; i < reps.length; i++) {
            for (var j = i + 1; j < reps.length; j++) topoPairs.push([reps[i], reps[j]]);
        }
        nodeObjs.filter(function (o) { return o.data.type === 'service' && hasCap(o, 'courier'); })
            .forEach(function (c) { reps.forEach(function (r) { topoPairs.push([c, r]); }); });
        rebuildLinks();   // nothing by default: links appear on selection
    }

    function defaultLinkBuilder(aObj, bObj, hex, opacity, rscale) {
        return makeTube([aObj.mesh.position.clone(), bObj.mesh.position.clone()],
            0.16 * (rscale || 1), hex, opacity == null ? 0.85 : opacity);
    }
    function buildLink(aObj, bObj, hex, opacity, rscale) {
        return (linkBuilder || defaultLinkBuilder)(aObj, bObj, hex, opacity, rscale);
    }
    function clearMeshes(arr) {
        arr.forEach(function (m) {
            worldRoot.remove(m);
            if (m.geometry) m.geometry.dispose();
            if (m.material) m.material.dispose();
        });
        arr.length = 0;
    }
    function drawAllLinks() {
        clearMeshes(allLinks);
        if (showAllLinks) {
            topoPairs.forEach(function (pr) {
                if (!pr[0] || !pr[1]) return;
                if (linkFilter && !linkFilter(pr[0], pr[1])) return;
                var pki = isPkiLink(pr[0], pr[1]);
                var m = buildLink(pr[0], pr[1], linkColor(pr[0], pr[1]), pki ? 0.12 : 0.3, pki ? 0.45 : 0.7);
                if (!m) return;
                m.userData = { katzenSelect: showLink, isLink: true, info: linkInfo(pr[0], pr[1]) };
                worldRoot.add(m); allLinks.push(m);
            });
        }
        linkPickables = allLinks;
    }
    function drawSelectionLinks() {
        clearMeshes(selLinkMeshes);
        if (!selNodes.length) return;
        selNodes.forEach(function (o) { o._sel = true; });
        var pairs = topoPairs.filter(function (pr) {
            return pr[0] && pr[1] && (pr[0]._sel || pr[1]._sel);
        });
        var n = pairs.length;
        var op = n > 30 ? 0.28 : n > 12 ? 0.4 : 0.8;
        var rs = n > 30 ? 0.45 : n > 12 ? 0.6 : 1;
        pairs.forEach(function (pr) {
            var hex = (selColor != null) ? selColor : linkColor(pr[0], pr[1]);
            var m = buildLink(pr[0], pr[1], hex, op, rs);
            if (!m) return;
            m.userData = { isLink: true, info: linkInfo(pr[0], pr[1]) };
            m.renderOrder = 1;
            worldRoot.add(m); selLinkMeshes.push(m);
        });
        selNodes.forEach(function (o) { o._sel = false; });
    }
    function rebuildLinks() { drawAllLinks(); drawSelectionLinks(); }

    function clearSelection() {
        clearMeshes(selLinkMeshes);
        selNodes.forEach(function (o) { o.resetIcon(); o.groupTimer = 0; o.setScale(1); });
        selNodes = []; selColor = null;
    }
    function highlightSelection(nodes, hex) {
        clearSelection();
        nodes = (nodes || []).filter(Boolean);
        if (!nodes.length) return;
        selNodes = nodes; selColor = (hex == null ? null : hex);
        nodes.forEach(function (o) { if (hex != null) o.setIconColor(hex); o.groupTimer = 2.6; });
        drawSelectionLinks();
    }
    function setAllLinks(on) { showAllLinks = !!on; drawAllLinks(); }
    function setLinkFilter(fn) { linkFilter = fn || null; }

    function focusNode(obj) {
        if (!obj) return;
        obj.flash(0xffffff);
        var wp = obj.mesh.getWorldPosition(new THREE.Vector3());
        var dir = wp.clone();
        if (dir.lengthSq() < 1e-6) dir.set(0, 0, 1);
        dir.normalize();
        if (planarView) {
            var fp = obj.flatPos || wp;
            targetLookAt.set(fp.x, fp.y, 0);
            targetCamPos.set(fp.x, fp.y, 22);
            controls.target.copy(targetLookAt);
        } else if (orbitOrigin) {
            targetLookAt.set(0, 0, 0);
            targetCamPos.copy(dir.multiplyScalar(Math.max((controls ? controls.minDistance : 54) + 4, wp.length() + 22)));
        } else {
            targetLookAt.copy(wp);
            targetCamPos.copy(wp).add(dir.multiplyScalar(18)).add(new THREE.Vector3(0, 6, 0));
        }
        gotoActive = true;
        showNode(obj);
        highlightSelection([obj], null);   // draw this node's links, coloured by tier
        drawSelectionPath(obj);
    }

    var _lw = new THREE.Vector3();
    function clusterTexture(n) {
        var s = 96, cv = document.createElement('canvas'); cv.width = cv.height = s;
        var g = cv.getContext('2d');
        g.beginPath(); g.arc(48, 48, 34, 0, Math.PI * 2);
        g.fillStyle = 'rgba(8, 12, 20, 0.92)'; g.fill();
        g.lineWidth = 6; g.strokeStyle = '#00f3ff'; g.stroke();
        g.fillStyle = '#dff3ff'; g.font = 'bold 42px "Courier New", monospace';
        g.textAlign = 'center'; g.textBaseline = 'middle';
        g.fillText(String(n), 48, 50);
        var t = new THREE.CanvasTexture(cv); t.minFilter = THREE.LinearFilter; return t;
    }
    function makeClusterMarker() {
        var rec = { members: [], count: -1 };
        rec.sprite = new THREE.Sprite(new THREE.SpriteMaterial({ transparent: true, depthTest: true, depthWrite: false }));
        rec.sprite.scale.set(3.4, 3.4, 1);
        rec.sprite.renderOrder = 3;
        rec.sprite.userData = { isClusterMarker: true, katzenSelect: function () { frameNodes(rec.members); } };
        worldRoot.add(rec.sprite);
        clusterMarkers.push(rec.sprite);
        clusterPool.push(rec);
        return rec;
    }
    function setClusterCount(rec, n) {
        if (rec.count === n) return;
        rec.count = n;
        var old = rec.sprite.material.map;
        rec.sprite.material.map = clusterTexture(n);
        rec.sprite.material.needsUpdate = true;
        if (old) old.dispose();
    }
    function screenXY(o, W, H) {
        var p = o.mesh.getWorldPosition(_lw).clone().project(camera);
        if (p.z > 1) return null;                 // behind the camera
        return { x: (p.x * 0.5 + 0.5) * W, y: (-p.y * 0.5 + 0.5) * H };
    }
    var FORM_PX = 28, BREAK_PX = 42;
    function updateClusters() {
        var W = renderer.domElement.clientWidth, H = renderer.domElement.clientHeight;
        var filtering = false;
        for (var f = 0; f < nodeObjs.length; f++) if (nodeObjs[f].filtered) { filtering = true; break; }
        if (filtering) {
            nodeObjs.forEach(function (o) { o.mesh.visible = !o.filtered; if (o.label && o.filtered) o.label.visible = false; });
            for (var m = 0; m < clusterPool.length; m++) clusterPool[m].sprite.visible = false;
            return;
        }
        var items = [];
        nodeObjs.forEach(function (o, idx) {
            o._idx = idx; o._sp = screenXY(o, W, H); o._done = false; o._ncid = null;
            o._excl = !o._sp || selNodes.indexOf(o) >= 0 || (clusterFilter && !clusterFilter(o));
            if (!o._excl) items.push(o);
        });
        var used = 0;
        for (var i = 0; i < items.length; i++) {
            var a = items[i]; if (a._done) continue;
            var grp = [a]; a._done = true;
            for (var j = 0; j < items.length; j++) {
                var b = items[j]; if (b._done) continue;
                var together = (a._pcid != null && a._pcid === b._pcid);
                var thr = together ? BREAK_PX : FORM_PX;
                var dx = a._sp.x - b._sp.x, dy = a._sp.y - b._sp.y;
                if (dx * dx + dy * dy < thr * thr) { grp.push(b); b._done = true; }
            }
            if (grp.length >= 2) {
                var cid = grp.reduce(function (m, o) { return Math.min(m, o._idx); }, Infinity);
                var c = new THREE.Vector3();
                grp.forEach(function (o) { o.mesh.visible = false; if (o.label) o.label.visible = false; o._ncid = cid; c.add(o.mesh.getWorldPosition(new THREE.Vector3())); });
                c.multiplyScalar(1 / grp.length); worldRoot.worldToLocal(c);
                var rec = clusterPool[used++] || makeClusterMarker();
                rec.sprite.position.copy(c); rec.sprite.visible = true;
                rec.members = grp; setClusterCount(rec, grp.length);
            } else {
                a.mesh.visible = true;
            }
        }
        nodeObjs.forEach(function (o) {
            if (o._excl) { o.mesh.visible = true; o._ncid = null; }
            o._pcid = o._ncid;                     // remember this pass for the next
        });
        for (var k = used; k < clusterPool.length; k++) clusterPool[k].sprite.visible = false;
    }

    function declutterLabels() {
        if (!labelsAll) return;
        var W = renderer.domElement.clientWidth, H = renderer.domElement.clientHeight;
        var list = nodeObjs.filter(function (o) { return o.label && o.mesh.visible; });
        nodeObjs.forEach(function (o) { if (o.label && !o.mesh.visible) o.label.visible = false; });
        list.forEach(function (o) { o._camd = o.mesh.getWorldPosition(_lw).distanceTo(camera.position); });
        list.sort(function (a, b) {
            var pa = (a === selectedObj ? 2 : a === hoverObj ? 1 : 0), pb = (b === selectedObj ? 2 : b === hoverObj ? 1 : 0);
            return pa !== pb ? pb - pa : a._camd - b._camd;
        });
        var kept = [];
        list.forEach(function (o) {
            var p = o.mesh.getWorldPosition(_lw).clone().project(camera);
            var forced = (o === selectedObj || o === hoverObj);
            if (p.z > 1) { o.label.visible = false; return; }   // behind the camera
            var sx = (p.x * 0.5 + 0.5) * W, sy = (-p.y * 0.5 + 0.5) * H;
            var rad = (o.data.name.length * 3.2 + 10) * (60 / Math.max(20, o._camd));
            var hide = false;
            if (!forced) {
                for (var i = 0; i < kept.length; i++) {
                    var dx = sx - kept[i].x, dy = sy - kept[i].y, rr = rad + kept[i].r;
                    if (dx * dx + dy * dy < rr * rr) { hide = true; break; }
                }
            }
            o.label.visible = !hide;
            if (!hide) kept.push({ x: sx, y: sy, r: rad });
        });
    }

    var declutterTimer = 0;
    function animate() {
        requestAnimationFrame(animate);
        if (document.hidden) return;   // pause the loop on a hidden tab (battery)
        if (contextLost) return;       // GPU dropped the context; wait for restore
        var dt = Math.min(clock.getDelta(), 0.1), t = clock.getElapsedTime();
        declutterTimer -= dt;
        if (declutterTimer <= 0) { declutterTimer = 0.25; updateClusters(); declutterLabels(); }
        layerCylinders.forEach(function (cyl, idx) { cyl.rotation.y += dt * (idx % 2 === 0 ? 0.05 : -0.05); });
        if (dirauthRing) dirauthRing.material.opacity = 0.3 + 0.22 * (0.5 + 0.5 * Math.sin(t * Math.PI / 10));
        nodeObjs.forEach(function (n) { n.update(dt, t); });
        clients.forEach(function (c) {
            c.angle += dt * c.speed;
            var g = c.gw.mesh.position;
            c.mesh.position.set(g.x + Math.cos(c.angle) * c.orbit, g.y + 1.2, g.z + Math.sin(c.angle) * c.orbit);
            if (c.mesh.material.opacity > 0.75) c.mesh.material.opacity += (0.75 - c.mesh.material.opacity) * 0.1;
        });
        if (packetSpawn) packetSpawn(dt);
        for (var i = packets.length - 1; i >= 0; i--) { if (!packets[i].update(dt)) packets.splice(i, 1); }
        runHooks(HOOKS.frame, dt, t);
        if (gotoActive) {
            camera.position.lerp(targetCamPos, 0.08);
            controls.target.lerp(targetLookAt, 0.08);
            if (camera.position.distanceTo(targetCamPos) < 0.5) gotoActive = false;
        }
        controls.update();
        if (composer) composer.render(); else renderer.render(scene, camera);
        if (styleAttemptPending) { styleAttemptPending = false; clearStyleAttempt(); }
    }

    function setStatusLine(msg) { var el = document.getElementById('load-status'); if (el) el.textContent = msg || ''; }

    function applyData(DATA) {
        if (!DATA) return;
        if (historyMode) return;   // scrubbing an old epoch: ignore live poll data
        if (DATA.generated_at && currentGeneratedAt && DATA.generated_at <= currentGeneratedAt) return;
        try {
            buildSceneSafe(DATA);   // sets lastData up front (K.data() during build hooks)
            currentGeneratedAt = DATA.generated_at || currentGeneratedAt;
            setStatusLine('');
            runHooks(HOOKS.data, DATA);
            showVantage();
        } catch (e) { setStatusLine('Error rendering data: ' + (e && e.message ? e.message : e)); }
    }

    function replay(DATA) {
        if (!DATA) return;
        historyMode = true;
        try { buildSceneSafe(DATA); runHooks(HOOKS.data, DATA); showVantage(); }
        catch (e) { setStatusLine('Error replaying snapshot: ' + (e && e.message ? e.message : e)); }
    }
    function goLive() {
        historyMode = false;
        currentGeneratedAt = null;   // force the next poll to apply
        fetchData();
    }

    function fetchData() {
        var url = window.KATZEN_DATA_URL;
        if (!url) { setStatusLine('No data URL configured.'); return; }
        fetch(url + (url.indexOf('?') >= 0 ? '&' : '?') + 'ts=' + Date.now(), { cache: 'no-store' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
            .then(applyData)
            .catch(function (e) {
                if (!currentGeneratedAt) {
                    setStatusLine('Could not load ' + url + ' (' + (e && e.message ? e.message : e) +
                        '). Serve this page over http (e.g. python3 -m http.server).');
                }
            });
    }

    function scheduleRefresh() {
        var secs = window.KATZEN_POLL_SECONDS || 60;
        if (secs > 0) setInterval(fetchData, secs * 1000);
    }

    window.KATZEN = {
        THREE: THREE,
        on: function (evt, fn) { if (HOOKS[evt] && typeof fn === 'function') HOOKS[evt].push(fn); },
        focusNode: focusNode,
        nodes: function () { return nodeObjs; },
        clients: function () { return clients; },
        data: function () { return lastData; },
        dataUrl: function () { return window.KATZEN_DATA_URL || ''; },
        replay: function (d) { replay(d); },
        goLive: function () { goLive(); },
        isHistory: function () { return historyMode; },
        packets: function () { return packets; },
        trafficRate: function () { return targetPacketRate; },
        vantagePos: function () { return vantagePos; },
        vantageLink: function (a, b, hops, latency, curvePoints) { return vantageLink(a, b, hops, latency, curvePoints); },
        latencyColor: latencyColor,
        showVantage: showVantage,
        showLink: showLink,
        topoPairs: function () { return topoPairs; },
        makeTube: function (points, radius, color, opacity) { return makeTube(points, radius, color, opacity); },
        addPickable: function (mesh) { if (mesh) pickExtras.push(mesh); },
        removePickable: function (mesh) { var i = pickExtras.indexOf(mesh); if (i >= 0) pickExtras.splice(i, 1); },
        goTo: function (px, py, pz, lx, ly, lz) {
            targetCamPos.set(px, py, pz);
            targetLookAt.set(lx || 0, ly || 0, lz || 0);
            gotoActive = true;
        },
        snapTo: function (px, py, pz, lx, ly, lz) {
            camera.position.set(px, py, pz); targetCamPos.copy(camera.position);
            controls.target.set(lx || 0, ly || 0, lz || 0); targetLookAt.copy(controls.target);
            gotoActive = false; controls.update();
        },
        frameNodes: function (objs) { frameNodes(objs || nodeObjs); },
        setSegmentInterpolator: function (fn) { segInterp = fn || null; },
        setPathBuilder: function (fn) { pathBuilder = fn || null; },
        drawSelectionPath: function () { drawSelectionPath(selectedObj); },
        worldRoot: function () { return worldRoot; },
        scene: function () { return scene; },
        camera: function () { return camera; },
        controls: function () { return controls; },
        setCRT: function (on) { if (crtPass) crtPass.enabled = (on !== false); },
        setOrbitOrigin: function (b) { orbitOrigin = !!b; },
        setPlanar: function (b) { planarView = !!b; },
        isPlanar: function () { return planarView; },
        setClusterFilter: function (fn) { clusterFilter = fn || null; },
        setLinkBuilder: function (fn) { linkBuilder = fn || null; },
        rebuildLinks: function () { rebuildLinks(); },
        setAllLinks: function (on) { setAllLinks(on); },
        setLinkFilter: function (fn) { setLinkFilter(fn); },
        nodeStyle: function () { return nodeStyle; },
        nodeStyles: function () { return NODE_STYLES.filter(styleAllowed); },
        setNodeStyle: function (style) {
            if (NODE_STYLES.indexOf(style) < 0 || !styleAllowed(style) || style === nodeStyle || !lastData) return;
            nodeStyle = style;
            try { if (window.localStorage) localStorage.setItem('katzen.nodeStyle', style); } catch (e) { }
            var sel = selectedObj ? { name: selectedObj.data.name, type: selectedObj.data.type } : null;
            buildSceneSafe(lastData);        // fires HOOKS.build; downgrades on error
            runHooks(HOOKS.data, lastData);
            showVantage();
            if (sel) this.reselect(sel.name, sel.type);
        },
        highlightSelection: function (nodes, hex) { highlightSelection(nodes, hex); },
        selection: function () { return selNodes; },
        reselect: function (name, type) {
            var o = null;   // prefer an exact name+type match (dual-role machines)
            for (var i = 0; i < nodeObjs.length; i++) {
                var n = nodeObjs[i];
                if (n.data.name !== name) continue;
                if (!o) o = n;
                if (type == null || n.data.type === type) { o = n; break; }
            }
            if (!o) return false;
            showNode(o);
            highlightSelection([o], null);
            o.groupTimer = 0; o.setScale(1);   // no attention pulse on auto-refresh
            drawSelectionPath(o);
            return true;
        },
        selectGroup: function (name) { return selectGroupByLabel(name); },
        linkColor: function (a, b) { return linkColor(a, b); },
        highlight: function (objs) { highlightGroup(objs); },
        hudPanel: function () { return document.getElementById('hud-panel'); },
        setStatus: setStatusLine,
        statusColor: statusColor,
        esc: esc,
        hex6: hex6
    };

    function setupPanelActions() {
        var body = document.getElementById('info-body');
        if (!body) return;
        body.addEventListener('click', function (e) {
            var chip = e.target.closest && e.target.closest('.cap-chip');
            if (chip) {
                var cap = chip.getAttribute('data-cap');
                var hit = nodeObjs.filter(function (o) {
                    return ((o.data.details && o.data.details.capabilities) || []).indexOf(cap) >= 0;
                });
                if (hit.length) { highlightSelection(hit, 0x00e0a0); frameNodes(hit); }
                return;
            }
            var cl = e.target.closest && e.target.closest('.copy-link');
            if (cl) {
                e.preventDefault();
                var url = location.origin + location.pathname + location.search + '#node=' + encodeURIComponent(cl.getAttribute('data-name'));
                if (navigator.clipboard) navigator.clipboard.writeText(url);
                var t = cl.textContent; cl.textContent = 'copied!';
                setTimeout(function () { cl.textContent = t; }, 1500);
            }
        });
    }

    function boot() {
        window.addEventListener('error', function (ev) {
            if (currentGeneratedAt) return;   // already rendered once; ignore later noise
            setStatusLine('Error: ' + ((ev && ev.message) || 'script error'));
        });
        var have3d = true;
        try {
            initThree();
        } catch (e) {
            have3d = false;
            setStatusLine('3D view unavailable (' + (e && e.message ? e.message : e) +
                '). Showing the 2D map.');
        }
        window.KATZEN_NO_WEBGL = !have3d;
        setupChrome();
        setupPanelActions();
        runHooks(HOOKS.boot);
        if (have3d) {
            setStatusLine('Loading...');
            fetchData();
            scheduleRefresh();
        }
    }
    if (document.readyState === 'complete') boot();
    else window.addEventListener('load', boot);
})();
