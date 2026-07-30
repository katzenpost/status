(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var applying = false;
    var wanted = null;
    var wantedType = null;   // remembered role, so a refresh reselects the right one
    var firstBuild = true;

    function hashParams() {
        var out = {};
        (location.hash || '').replace(/^#/, '').split('&').forEach(function (kv) {
            if (!kv) return; var p = kv.split('='); out[p[0]] = p.slice(1).join('=');
        });
        return out;
    }
    function parseHash() { var v = hashParams().node; return v ? decodeURIComponent(v) : null; }
    function parseGroup() { var v = hashParams().group; return v ? decodeURIComponent(v) : null; }
    function setNodeParam(name) {
        var p = hashParams();
        if (name) p.node = encodeURIComponent(name); else delete p.node;
        var parts = Object.keys(p).filter(function (k) { return p[k] != null; })
            .map(function (k) { return k + '=' + p[k]; });
        var h = parts.length ? '#' + parts.join('&') : '';
        if (h !== location.hash) history.replaceState(null, '', h || (location.pathname + location.search));
    }

    function focusWanted() {
        if (!wanted) return;
        var hit = K.nodes().filter(function (o) { return o.data.name === wanted; })[0];
        if (hit) { applying = true; K.focusNode(hit); applying = false; }
    }

    wanted = parseHash();
    K.on('build', function () {
        setTimeout(function () {
            if (firstBuild) {
                firstBuild = false;
                var g = parseGroup();
                if (g && K.selectGroup) K.selectGroup(g);
                focusWanted();
            } else if (wanted && K.reselect) {
                applying = true; K.reselect(wanted, wantedType); applying = false;
            }
        }, 0);
    });
    K.on('node', function (obj) {
        if (applying) return;
        if (!obj) { wanted = null; wantedType = null; setNodeParam(null); return; }   // deselected
        wanted = obj.data.name; wantedType = obj.data.type;
        setNodeParam(obj.data.name);
    });
    window.addEventListener('hashchange', function () {
        wanted = parseHash();
        setTimeout(focusWanted, 0);
    });
    var closeBtn = document.getElementById('info-close');
    if (closeBtn) closeBtn.addEventListener('click', function () { wanted = null; setNodeParam(null); });
})();
