(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var showing = false;
    var HL = 0x00e0a0;   // highlight colour for a stats-driven selection

    var btn = document.createElement('button');
    btn.id = 'stats-btn';
    btn.style.cssText = 'width:100%;margin-bottom:12px';
    btn.textContent = 'Network stats';
    var link = document.getElementById('link-btn');
    if (link && link.parentNode) link.parentNode.insertBefore(btn, link.nextSibling);
    else { var hud = K.hudPanel(); if (hud) hud.insertBefore(btn, hud.firstChild); }
    btn.addEventListener('click', function () { showing = true; render(); });

    function tally(items) {
        var m = {};
        items.forEach(function (k) { if (k != null && k !== '') m[k] = (m[k] || 0) + 1; });
        return Object.keys(m).map(function (k) { return [k, m[k]]; })
            .sort(function (a, b) { return b[1] - a[1]; });
    }
    function country(o) {
        var g = o.data.geo;
        if (!g || !g.label) return 'Unknown';
        var p = String(g.label).split(',');
        var last = p[p.length - 1];
        return (last == null ? '' : String(last).trim().replace(/^The\s+/i, '')) || 'Unknown';
    }
    function layerKey(o) { return o.data.layer == null ? '?' : String(o.data.layer); }
    function asKey(o) { return o.data.asn ? (o.data.asn + (o.data.net ? ' ' + o.data.net : '')) : ''; }
    function median(xs) {
        if (!xs.length) return null;
        var s = xs.slice().sort(function (a, b) { return a - b; }), n = s.length;
        return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
    }
    function isExpiring(o) {
        var d = K.data() || {}, mke = ((o.data.details || {}).mixkey_epochs) || [];
        return typeof d.epoch === 'number' && mke.length > 0 && Math.max.apply(null, mke) <= d.epoch;
    }
    function nodesMatching(kind, val) {
        return K.nodes().filter(function (o) {
            switch (kind) {
                case 'status': return o.data.status === val;
                case 'role': return o.data.type === val;
                case 'layer': return layerKey(o) === val;
                case 'country': return country(o) === val;
                case 'as': return asKey(o) === val;
                case 'version': return ((o.data.details || {}).version || '?') === val;
                case 'expiring': return isExpiring(o);
                default: return false;
            }
        });
    }
    function topShare(nodes, keyfn) {
        var m = {}, top = null, tn = 0, tot = 0;
        nodes.forEach(function (o) { var k = keyfn(o); if (!k || k === 'Unknown') return; tot++; m[k] = (m[k] || 0) + 1; if (m[k] > tn) { tn = m[k]; top = k; } });
        return { key: top, n: tn, total: tot };
    }

    function row(label, value) {
        return '<p><span style="color:#7b8e9d">' + K.esc(label) + ':</span> ' + value + '</p>';
    }
    function crow(kind, val, label, count, dotColor) {
        var dot = dotColor ? '<span style="display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;background:'
            + dotColor + '"></span>' : '';
        return '<p class="stat-row" data-kind="' + kind + '" data-val="' + K.esc(String(val))
            + '" style="cursor:pointer" title="Highlight on the map">' + dot
            + '<span style="color:#7b8e9d">' + K.esc(label) + ':</span> ' + count + '</p>';
    }
    function head(t) { return '<p style="margin-top:6px;color:#7b8e9d">' + t + '</p>'; }

    function buildHtml() {
        var ns = K.nodes();
        if (!ns.length) return '<p style="color:#7b8e9d">No data yet.</p>';
        var STAT = { ok: 'in consensus, reachable', out: 'reachable, not in consensus', down: 'down', unknown: 'address unknown' };
        var html = row('Nodes', ns.length) + '<p style="font-size:10px;color:#59707f">click a row to highlight those nodes</p>';

        html += head('By status');
        tally(ns.map(function (o) { return o.data.status; })).forEach(function (kv) {
            html += crow('status', kv[0], STAT[kv[0]] || kv[0], kv[1], K.hex6(K.statusColor(kv[0])));
        });

        var expiring = ns.filter(isExpiring);
        if (expiring.length) html += crow('expiring', '', 'Mix key expiring (drops next epoch)', expiring.length, '#ffaa00');

        html += head('By role');
        tally(ns.map(function (o) { return o.data.type; })).forEach(function (kv) { html += crow('role', kv[0], kv[0], kv[1]); });
        var mix = ns.filter(function (o) { return o.data.type === 'mix'; });
        if (mix.length) {
            tally(mix.map(layerKey)).sort(function (a, b) {
                var x = a[0] === '?' ? Infinity : +a[0], y = b[0] === '?' ? Infinity : +b[0]; return x - y;
            }).forEach(function (kv) { html += crow('layer', kv[0], 'mix layer ' + kv[0], kv[1]); });
        }

        html += head('By country');
        tally(ns.map(country)).forEach(function (kv) { html += crow('country', kv[0], kv[0], kv[1]); });

        var byAs = tally(ns.map(asKey));
        if (byAs.length) {
            html += head('By AS / operator');
            byAs.forEach(function (kv) { html += crow('as', kv[0], kv[0], kv[1]); });
        }

        var byVer = tally(ns.map(function (o) { return (o.data.details || {}).version || ''; }));
        if (byVer.length > 1) {
            html += head('By version');
            byVer.forEach(function (kv) { html += crow('version', kv[0], kv[0], kv[1]); });
        }

        var warns = [];
        var layers = {};
        mix.forEach(function (o) { (layers[layerKey(o)] || (layers[layerKey(o)] = [])).push(o); });
        Object.keys(layers).sort().forEach(function (L) {
            [['AS', asKey], ['country', country]].forEach(function (kf) {
                var t = topShare(layers[L], kf[1]);
                if (t.total >= 2 && t.n / t.total > 0.5) {
                    warns.push('L' + L + ': ' + t.n + '/' + t.total + ' in one ' + kf[0] + ' (' + K.esc(t.key) + ')');
                }
            });
        });
        if (warns.length) {
            html += '<p style="margin-top:8px;color:#ffaa00">Diversity / choke points</p>';
            warns.forEach(function (w) { html += '<p style="font-size:10.5px;color:#ffcf80">' + w + '</p>'; });
        }

        var lat = ns.map(function (o) { return o.data.latency_ms; }).filter(function (x) { return x != null; });
        if (lat.length) {
            html += head('Traceroute latency (ms)');
            html += row('min / median / max', Math.round(Math.min.apply(null, lat)) + ' / ' + Math.round(median(lat)) + ' / ' + Math.round(Math.max.apply(null, lat)));
            html += '<canvas id="lat-hist" width="248" height="42" style="width:100%;height:42px;display:block;margin-top:2px"></canvas>' +
                '<div style="display:flex;justify-content:space-between;font-size:9px;color:#59707f"><span>0</span><span>200+ ms</span></div>';
        }
        html += '<p style="margin-top:6px"></p>' + row('Modelled traffic', Math.round(K.trafficRate()) + ' packets/s');
        return html;
    }

    function drawLatHist() {
        var cv = document.getElementById('lat-hist');
        if (!cv) return;
        var g = cv.getContext('2d'), W = cv.width, H = cv.height;
        g.clearRect(0, 0, W, H);
        var lat = K.nodes().map(function (o) { return o.data.latency_ms; }).filter(function (x) { return x != null; });
        if (!lat.length) return;
        var BINS = 10, MAXMS = 200, bwms = MAXMS / BINS, bins = [];
        for (var i = 0; i < BINS; i++) bins.push(0);
        lat.forEach(function (v) { bins[Math.min(BINS - 1, Math.floor(v / bwms))]++; });
        var max = Math.max.apply(null, bins) || 1, gap = 2, bw = (W - (BINS - 1) * gap) / BINS;
        bins.forEach(function (c, i) {
            var h = (c / max) * (H - 2), x = i * (bw + gap), y = H - h;
            g.fillStyle = K.hex6(K.latencyColor((i + 0.5) * bwms));
            g.fillRect(x, y, bw, h);
        });
    }

    function render() {
        var box = document.getElementById('node-info');
        if (!box) return;
        box.style.display = 'block';
        box.style.borderColor = K.hex6(HL);
        document.getElementById('info-title').innerText = 'Network stats';
        document.getElementById('info-body').innerHTML = buildHtml();
        drawLatHist();
    }

    var body = document.getElementById('info-body');
    if (body) body.addEventListener('click', function (e) {
        var r = e.target.closest ? e.target.closest('.stat-row') : null;
        if (!r) return;
        var nodes = nodesMatching(r.getAttribute('data-kind'), r.getAttribute('data-val'));
        if (nodes.length) { K.highlightSelection(nodes, HL); K.frameNodes(nodes); }
    });

    function renderSoon() { if (showing) setTimeout(render, 0); }
    K.on('data', renderSoon);
    K.on('build', renderSoon);
    K.on('node', function () { showing = false; });
    K.on('boot', function () { if (/stats/.test(location.hash + location.search)) showing = true; });
})();
