(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    var style = document.createElement('style');
    style.textContent =
        '#a11y-panel{margin-top:10px;border-top:1px solid rgba(255,255,255,.1);padding-top:10px}' +
        '#a11y-list{max-height:190px;overflow-y:auto;display:flex;flex-direction:column;gap:3px}' +
        '#a11y-list button{display:flex;align-items:center;gap:6px;width:100%;text-align:left;' +
        'font-size:11px;padding:5px 7px;min-height:0}' +
        '#a11y-list .s{width:8px;height:8px;border-radius:2px;flex:0 0 auto}';
    document.head.appendChild(style);

    var panel = document.createElement('div');
    panel.id = 'a11y-panel';
    panel.innerHTML =
        '<div class="hud-subtitle" style="display:flex;align-items:center;justify-content:space-between">' +
        '<span>Nodes (Tab / Enter)</span>' +
        '<select id="a11y-sort" aria-label="Sort nodes" style="background:rgba(255,180,84,.06);' +
        'border:1px solid rgba(255,180,84,.3);color:#f0c98a;font-size:10px;border-radius:4px;padding:2px">' +
        '<option value="name">name</option><option value="status">status</option>' +
        '<option value="latency">latency</option></select></div>' +
        '<div id="a11y-list" role="list" aria-label="Network nodes"></div>';
    var hud = K.hudPanel();
    if (hud) hud.appendChild(panel);
    var list = panel.querySelector('#a11y-list');
    var sortSel = panel.querySelector('#a11y-sort');
    var lastData = null;

    var SRANK = { down: 0, out: 1, unknown: 2, ok: 3 };
    function sorted(nodes) {
        var mode = sortSel.value;
        return nodes.slice().sort(function (a, b) {
            if (mode === 'status') {
                var d = (SRANK[a.status] || 9) - (SRANK[b.status] || 9);
                return d || a.name.localeCompare(b.name);
            }
            if (mode === 'latency') {   // slowest first; unmeasured last
                var la = a.latency_ms == null ? -1 : a.latency_ms, lb = b.latency_ms == null ? -1 : b.latency_ms;
                return lb - la || a.name.localeCompare(b.name);
            }
            return (a.name + a.type).localeCompare(b.name + b.type);
        });
    }
    sortSel.addEventListener('change', function () { if (lastData) render(lastData); });

    function render(data) {
        if (!data || !data.nodes) return;
        lastData = data;
        list.innerHTML = '';
        sorted(data.nodes).forEach(function (n) {
            var role = (n.type === 'out' ? (n.role || 'node') : n.type);
            var lat = (n.latency_ms != null) ? ' ' + n.latency_ms + ' ms' : '';
            var btn = document.createElement('button');
            btn.setAttribute('role', 'listitem');
            btn.setAttribute('aria-label', n.name + ' ' + role + ' ' + n.status + lat);
            btn.innerHTML =
                '<span class="s" style="background:' + K.hex6(K.statusColor(n.status)) + '"></span>' +
                '<span>' + K.esc(n.name) + '</span>' +
                '<span style="margin-left:auto;color:#7b8e9d">' + K.esc(n.status) + '</span>';
            btn.addEventListener('click', function () { if (n._obj) K.focusNode(n._obj); });
            list.appendChild(btn);
        });
    }

    K.on('build', function (data) { render(data); });

    function selfFetch() {
        var url = window.KATZEN_DATA_URL;
        if (!url) return;
        fetch(url + (url.indexOf('?') >= 0 ? '&' : '?') + 'a11y=' + Date.now(), { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) { if (d && !list.childNodes.length) render(d); })
            .catch(function () { /* the 3D view, if present, still renders it */ });
    }
    selfFetch();
    setInterval(function () { if (!list.childNodes.length) selfFetch(); },
        (window.KATZEN_POLL_SECONDS || 60) * 1000);
})();
