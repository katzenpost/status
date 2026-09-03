(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var showing = false;
    var btn = document.createElement('button');
    btn.id = 'upstreams-btn';
    btn.style.cssText = 'width:100%;margin-bottom:12px';
    btn.textContent = 'Shared upstreams';
    var anchor = document.getElementById('stats-btn') || document.getElementById('link-btn');
    if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(btn, anchor.nextSibling);
    else { var hud = K.hudPanel(); if (hud) hud.insertBefore(btn, hud.firstChild); }
    btn.addEventListener('click', function () { showing = true; render(); });

    function isLocal(ip) {
        return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^127\./.test(ip) || /^169\.254\./.test(ip)
            || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
            || /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip);   // CGNAT 100.64/10
    }

    function buildHtml() {
        var ns = K.nodes(), agg = {}, withPath = 0;
        ns.forEach(function (o) {
            var hops = o.data.hops || [];
            if (hops.length) withPath++;
            var seen = {};
            hops.forEach(function (h) {
                var ip = h.ip;
                if (!ip || ip === '*' || h.hop <= 2 || isLocal(ip)) return;   // skip monitor egress + private
                if (seen[ip]) return; seen[ip] = 1;                            // count each path once per hop IP
                var a = agg[ip] || (agg[ip] = { n: 0, asn: h.asn || '', net: h.net || '' });
                a.n++;
                if (!a.asn && h.asn) { a.asn = h.asn; a.net = h.net || ''; }
            });
        });
        var rows = Object.keys(agg).map(function (ip) { return { ip: ip, a: agg[ip] }; })
            .filter(function (r) { return r.a.n >= 2; })
            .sort(function (x, y) { return y.a.n - x.a.n; });
        if (!rows.length) return '<p style="color:#7b8e9d">No shared upstream hops yet (needs traceroute data on multiple nodes).</p>';
        var html = '<p style="font-size:10.5px;color:#7b8e9d">Hops on multiple node traceroutes (monitor egress + private hops excluded). A shared upstream is a shared failure/observation domain.</p>';
        rows.slice(0, 20).forEach(function (r) {
            var asn = r.a.asn ? ' <span style="color:#7b8e9d">' + K.esc(r.a.asn + (r.a.net ? ' ' + r.a.net : '')) + '</span>' : '';
            html += '<p style="font-size:11px;margin:2px 0">' + K.esc(r.ip) + asn
                + ' <span style="color:#7b8e9d">on</span> <b>' + r.a.n + '</b> / ' + withPath + '</p>';
        });
        return html;
    }
    function render() {
        var box = document.getElementById('node-info');
        if (!box) return;
        box.style.display = 'block';
        box.style.borderColor = K.hex6(0x8338ec);
        document.getElementById('info-title').innerText = 'Shared upstreams';
        document.getElementById('info-body').innerHTML = buildHtml();
    }
    function renderSoon() { if (showing) setTimeout(render, 0); }
    K.on('data', renderSoon);
    K.on('build', renderSoon);
    K.on('node', function () { showing = false; });
    K.on('boot', function () { if (/upstreams/.test(location.hash + location.search)) showing = true; });
})();
