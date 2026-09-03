(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback
    var THREE = K.THREE;

    var DUR = [5, 7, 5];                       // seconds per phase
    var COL = [0x00d2ff, 0xffb454, 0x00ff88];  // submit / vote / fetch

    var active = false, group = null, meshGroup = null, parts = [], clock = 0, spawnAcc = 0;
    var meshTimer = 0, lastMeshPos = null;     // throttle + movement-gate mesh rebuilds

    var wrap = document.createElement('div');
    wrap.style.margin = '0 0 12px';
    var btn = document.createElement('button');
    btn.style.width = '100%';
    btn.textContent = 'Dirauth protocol: off';
    wrap.appendChild(btn);
    var hud = K.hudPanel();
    if (hud) hud.insertBefore(wrap, hud.firstChild);

    function dirauths() { return K.nodes().filter(function (o) { return o.data.type === 'dirauth'; }); }
    function others() { return K.nodes().filter(function (o) { return o.data.type !== 'dirauth' && o.data.in_consensus; }); }
    function rand(a) { return a[Math.floor(Math.random() * a.length)]; }

    function arc(a, b, t) {
        var p = a.clone().lerp(b, t);
        var out;
        if (K.isPlanar && K.isPlanar()) {
            out = new THREE.Vector3(0, 0, 1);   // flat map: lift off the plane
        } else {
            out = p.clone();
            if (out.lengthSq() > 1e-6) out.normalize(); else out.set(0, 1, 0);
        }
        return p.add(out.multiplyScalar(0.14 * a.distanceTo(b) * Math.sin(Math.PI * t)));
    }

    function ensureGroups() {
        if (!group) { group = new THREE.Group(); K.worldRoot().add(group); }
        if (!meshGroup) { meshGroup = new THREE.Group(); K.worldRoot().add(meshGroup); }
    }
    function disposeChildren(g) {
        if (!g) return;
        g.traverse(function (o) { if (o.geometry) o.geometry.dispose(); if (o.material) o.material.dispose(); });
        while (g.children.length) g.remove(g.children[0]);
    }
    function clearParts() { disposeChildren(group); parts = []; }

    function drawMesh() {
        ensureGroups();
        disposeChildren(meshGroup);
        var da = dirauths();
        for (var i = 0; i < da.length; i++) {
            for (var j = i + 1; j < da.length; j++) {
                var pts = [];
                for (var k = 0; k <= 18; k++) pts.push(arc(da[i].mesh.position, da[j].mesh.position, k / 18));
                var tube = K.makeTube(pts, 0.12, 0xffb454, 0.28);
                if (tube) meshGroup.add(tube);
            }
        }
        lastMeshPos = da.length ? da[0].mesh.position.clone() : null;
    }

    function addParticle(from, to, color) {
        ensureGroups();
        var m = new THREE.Mesh(new THREE.SphereGeometry(0.5, 10, 10),
            new THREE.MeshBasicMaterial({ color: color, transparent: true, opacity: 0.85 }));
        group.add(m);
        parts.push({ m: m, a: from.mesh.position.clone(), b: to.mesh.position.clone(), t: 0, sp: 0.55 + Math.random() * 0.4 });
        if (to.flash) to.flash(color);
    }

    function spawn(phase) {
        var da = dirauths(); if (!da.length) return;
        if (phase === 0) { var os = others(); if (os.length) addParticle(rand(os), rand(da), COL[0]); }
        else if (phase === 1) {
            if (da.length < 2) return;
            var a = rand(da), b = rand(da); if (a === b) return;
            addParticle(a, b, COL[1]);
        } else { var o2 = others(); if (o2.length) addParticle(rand(da), rand(o2), COL[2]); }
    }

    function setActive(on) {
        active = on;
        btn.textContent = 'Dirauth protocol: ' + (on ? 'on' : 'off');
        btn.classList.toggle('active', on);
        if (on) { clock = 0; meshTimer = 0; ensureGroups(); drawMesh(); }
        else {
            if (meshGroup) { K.worldRoot().remove(meshGroup); disposeChildren(meshGroup); meshGroup = null; }
            if (group) { K.worldRoot().remove(group); clearParts(); group = null; }
        }
    }
    btn.addEventListener('click', function () { setActive(!active); });

    K.on('build', function () {
        group = null; meshGroup = null; parts = []; lastMeshPos = null;
        if (active) setTimeout(function () { if (active) drawMesh(); }, 0);
    });

    K.on('frame', function (dt) {
        if (!active) return;
        meshTimer -= dt;
        if (meshTimer <= 0) {
            meshTimer = 0.4;
            var da0 = dirauths();
            if (da0.length && (!lastMeshPos || da0[0].mesh.position.distanceTo(lastMeshPos) > 0.5)) drawMesh();
        }
        var total = DUR[0] + DUR[1] + DUR[2];
        clock = (clock + dt) % total;
        var phase = clock < DUR[0] ? 0 : clock < DUR[0] + DUR[1] ? 1 : 2;
        spawnAcc += dt;
        if (spawnAcc > 0.2) { spawnAcc = 0; spawn(phase); }
        for (var i = parts.length - 1; i >= 0; i--) {
            var p = parts[i];
            p.t += dt * p.sp;
            if (p.t >= 1) {
                group.remove(p.m); p.m.geometry.dispose(); p.m.material.dispose();
                parts.splice(i, 1);
                continue;
            }
            p.m.position.copy(arc(p.a, p.b, p.t));
        }
    });

    K.on('boot', function () {
        if (!/nodirauth/.test(location.hash + location.search)) setActive(true);
    });
})();
