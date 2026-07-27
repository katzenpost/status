(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;   // 3D view only
    if (!K.setNodeStyle) return;          // older app without the shape toggle

    var LABELS = {
        flat: 'Flat glyphs', extruded: 'Extruded badges',
        pieces: 'Game pieces', machine: 'Machines'
    };
    var IDS = (K.nodeStyles ? K.nodeStyles() : ['flat', 'extruded', 'pieces', 'machine']);
    var STYLES = IDS.map(function (id) { return [id, LABELS[id] || id]; });
    if (STYLES.length < 2) return;   // nothing to toggle between

    var btn = document.createElement('button');
    btn.id = 'nodestyle-btn';
    btn.style.cssText = 'width:100%;margin-bottom:8px';
    var view = document.getElementById('view-buttons');
    var hud = K.hudPanel();
    if (view && view.parentNode) view.parentNode.insertBefore(btn, view.nextSibling);
    else if (hud) hud.insertBefore(btn, hud.firstChild);

    function nameFor(id) {
        for (var i = 0; i < STYLES.length; i++) if (STYLES[i][0] === id) return STYLES[i][1];
        return 'Flat glyphs';
    }
    function relabel() {
        var cur = K.nodeStyle ? K.nodeStyle() : 'flat';
        btn.textContent = 'Node shape: ' + nameFor(cur);
        btn.setAttribute('aria-label', 'Node shape, currently ' + nameFor(cur) + '. Click to cycle.');
    }
    btn.addEventListener('click', function () {
        var cur = K.nodeStyle ? K.nodeStyle() : 'flat', idx = 0;
        for (var i = 0; i < STYLES.length; i++) if (STYLES[i][0] === cur) idx = i;
        K.setNodeStyle(STYLES[(idx + 1) % STYLES.length][0]);
        relabel();
    });

    K.on('boot', relabel);
    relabel();
})();
