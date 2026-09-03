(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var style = document.createElement('style');
    style.textContent =
        '#search-panel{margin-top:10px;border-top:1px solid rgba(255,255,255,.1);padding-top:10px}' +
        '#search-box{width:100%;box-sizing:border-box;background:rgba(0,243,255,.06);' +
        'border:1px solid rgba(0,243,255,.3);color:#cdeeff;border-radius:4px;padding:7px;font-size:12px}' +
        '#search-filters{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px;font-size:10.5px;color:#9fb3c2}' +
        '#search-filters label{display:flex;align-items:center;gap:3px}';
    document.head.appendChild(style);

    var panel = document.createElement('div');
    panel.id = 'search-panel';
    panel.innerHTML = '<div class="hud-subtitle">Search / filter</div>' +
        '<input id="search-box" type="text" placeholder="node name..." aria-label="Search nodes">' +
        '<div id="search-filters"></div>';
    var hud = K.hudPanel();
    if (hud) hud.appendChild(panel);
    var box = panel.querySelector('#search-box');
    var filt = panel.querySelector('#search-filters');

    var STATUSES = ['ok', 'out', 'down', 'unknown'];
    var active = { ok: true, out: true, down: true, unknown: true };
    STATUSES.forEach(function (s) {
        var label = document.createElement('label');
        label.innerHTML = '<input type="checkbox" checked aria-label="show ' + s + '"> ' + s;
        filt.appendChild(label);
        label.querySelector('input').addEventListener('change', function (e) {
            active[s] = e.target.checked;
            apply();
        });
    });

    function apply() {
        var q = box.value.trim().toLowerCase();
        K.nodes().forEach(function (o) {
            var d = o.data;
            var match = (!q || d.name.toLowerCase().indexOf(q) >= 0) && !!active[d.status];
            o.mesh.visible = match;
            o.filtered = !match;
        });
    }

    box.addEventListener('input', apply);
    box.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter') return;
        var q = box.value.trim().toLowerCase();
        var hit = K.nodes().filter(function (o) {
            return o.mesh.visible && o.data.name.toLowerCase().indexOf(q) >= 0;
        })[0];
        if (hit) K.focusNode(hit);
    });

    K.on('build', function () { apply(); });
})();
