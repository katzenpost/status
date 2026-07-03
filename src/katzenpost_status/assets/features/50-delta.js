(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var style = document.createElement('style');
    style.textContent =
        '#delta-panel{margin-top:10px;border-top:1px solid rgba(255,255,255,.1);' +
        'padding-top:10px;font-size:11px;color:#9fb3c2}' +
        '#delta-list{max-height:120px;overflow-y:auto}#delta-list div{margin:2px 0}';
    document.head.appendChild(style);

    var panel = document.createElement('div');
    panel.id = 'delta-panel';
    panel.innerHTML = '<div class="hud-subtitle">Recent status changes</div>' +
        '<div id="delta-list"><div style="color:#59707f">none yet</div></div>';
    var hud = K.hudPanel();
    if (hud) hud.appendChild(panel);
    var list = panel.querySelector('#delta-list');

    var prev = {};
    var first = true;

    K.on('data', function (d) {
        if (!d || !d.nodes) return;
        var changes = [];
        d.nodes.forEach(function (n) {
            var key = n.name + '|' + n.type;
            var was = prev[key];
            if (was !== undefined && was !== n.status) changes.push({ n: n, from: was, to: n.status });
            prev[key] = n.status;
        });
        if (first) { first = false; return; }
        if (!changes.length) return;
        list.innerHTML = '';
        changes.forEach(function (c) {
            if (c.n._obj) c.n._obj.flash(0xffffff);
            list.innerHTML +=
                '<div><span style="color:' + K.hex6(K.statusColor(c.to)) + '">' +
                K.esc(c.n.name) + '</span> ' + K.esc(c.from) + ' -&gt; ' + K.esc(c.to) + '</div>';
        });
    });
})();
