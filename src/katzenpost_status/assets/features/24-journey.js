(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;
    var THREE = K.THREE;

    var marker = null, path = [], seg = 0, segT = 0, pauseT = 0, active = false;
    var HL = 0x9b5de5;

    var btn = document.createElement('button');
    btn.id = 'journey-btn';
    btn.textContent = 'Trace a message';
    btn.style.cssText = 'width:100%;margin-bottom:8px';
    var hud = K.hudPanel();
    var statsBtn = document.getElementById('stats-btn');
    if (statsBtn && statsBtn.parentNode) statsBtn.parentNode.insertBefore(btn, statsBtn);
    else if (hud) hud.appendChild(btn);

    var cap = document.createElement('div');
    cap.id = 'journey-cap';
    cap.style.cssText = 'position:fixed;left:50%;bottom:56px;transform:translateX(-50%);z-index:41;' +
        'display:none;max-width:calc(100vw - 24px);text-align:center;background:rgba(8,12,20,0.92);' +
        'border:1px solid rgba(155,93,229,0.6);color:#d9c7ff;font:12px/1.4 monospace;' +
        'padding:8px 30px 8px 14px;border-radius:8px';
    var capText = document.createElement('span');
    var capX = document.createElement('button');
    capX.textContent = 'x'; capX.setAttribute('aria-label', 'Stop trace');
    capX.style.cssText = 'position:absolute;top:4px;right:6px;background:none;border:none;' +
        'color:#d9c7ff;cursor:pointer;font:12px monospace;padding:2px 4px';
    capX.addEventListener('click', function () { stop(false); });
    cap.appendChild(capText); cap.appendChild(capX);
    document.body.appendChild(cap);

    function pick(arr) { return arr.length ? arr[Math.floor(Math.random() * arr.length)] : null; }
    function ofType(t) { return K.nodes().filter(function (o) { return o.data.type === t; }); }
    function buildPath() {
        var p = [], data = K.data() || {};
        var g = pick(ofType('gateway')); if (g) p.push(g);
        var layers = (data.layers || []).length ||
            (function () { var m = 0; ofType('mix').forEach(function (o) { if (typeof o.data.layer === 'number') m = Math.max(m, o.data.layer + 1); }); return m; })();
        for (var i = 0; i < layers; i++) {
            var ln = ofType('mix').filter(function (o) { return o.data.layer === i; });
            var m = pick(ln); if (m) p.push(m);
        }
        var svc = pick(ofType('service')) || pick(ofType('out')); if (svc) p.push(svc);
        return p;
    }

    function ensureMarker() {
        if (marker) return;
        marker = new THREE.Mesh(new THREE.SphereGeometry(0.9, 16, 16),
            new THREE.MeshBasicMaterial({ color: HL }));
        marker.renderOrder = 6;
        K.worldRoot().add(marker);
    }
    function removeMarker() {
        if (!marker) return;
        K.worldRoot().remove(marker);
        marker.geometry.dispose(); marker.material.dispose(); marker = null;
    }
    function roleName(o) { return o.data.type === 'out' ? (o.data.role || 'node') : o.data.type; }

    function start() {
        path = buildPath();
        if (path.length < 2) { setCap('Not enough nodes to trace a path right now.'); return; }
        ensureMarker();
        seg = 0; segT = 0; pauseT = 0.4; active = true;
        marker.position.copy(path[0].mesh.position);
        K.highlightSelection([path[0]], HL);
        setCap('Message journey (illustrative) - hop 1/' + path.length + ': ' +
            (path[0].data.name || '') + ' [' + roleName(path[0]) + ']  enters the mixnet');
    }
    function setCap(t) { capText.textContent = t; cap.style.display = 'block'; }
    function stop(final) {
        active = false;
        if (final) {
            setCap('Delivered. This was one sampled path - real message paths are unlinkable by design.');
            setTimeout(function () { cap.style.display = 'none'; removeMarker(); }, 4500);
        } else { cap.style.display = 'none'; removeMarker(); }
    }

    btn.addEventListener('click', function () { if (active) stop(false); start(); });
    if (/[?#&]trace=1/.test(location.hash + location.search)) {
        K.on('build', function () { setTimeout(function () { if (!active) start(); }, 1200); });
    }

    K.on('frame', function (dt) {
        if (!active || !marker || path.length < 2) return;
        if (pauseT > 0) { pauseT -= dt; return; }   // dwell at each node (the "mixing")
        var a = path[seg].mesh.position, b = path[seg + 1].mesh.position;
        segT += dt / 1.1;                             // ~1.1s per hop
        if (segT >= 1) {
            segT = 0; seg++;
            marker.position.copy(path[seg].mesh.position);
            K.highlightSelection([path[seg]], HL);
            var isLast = (seg >= path.length - 1);
            pauseT = 0.5;
            setCap('Message journey (illustrative) - hop ' + (seg + 1) + '/' + path.length + ': ' +
                (path[seg].data.name || '') + ' [' + roleName(path[seg]) + ']' +
                (isLast ? '  delivers the message' : '  unlinks + delays'));
            if (isLast) stop(true);
            return;
        }
        marker.position.copy(a).lerp(b, segT);
    });
})();
