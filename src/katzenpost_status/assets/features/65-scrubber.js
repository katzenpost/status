(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var histBase = '', index = [], pos = -1;
    function base() { return (K.dataUrl() || '').replace(/\.data\.json(\?.*)?$/, '-history/'); }

    var wrap = document.createElement('div');
    wrap.id = 'scrubber';
    wrap.style.cssText = 'margin:0 0 12px;display:none';
    wrap.innerHTML = '<div class="hud-subtitle">Epoch history</div>' +
        '<div style="display:flex;gap:6px;margin-top:4px">' +
        '<button id="hist-prev" style="flex:1">&lt; prev</button>' +
        '<button id="hist-next" style="flex:1">next &gt;</button>' +
        '<button id="hist-live" style="flex:1">Live</button></div>' +
        '<canvas id="hist-spark" width="248" height="30" style="width:100%;height:30px;margin-top:6px;display:block"></canvas>' +
        '<div id="hist-diff" style="font-size:10px;color:#9fb3c2;margin-top:4px;line-height:1.5"></div>';
    var hud = K.hudPanel();
    var anchor = document.getElementById('hud-title');
    if (hud) { if (anchor) hud.insertBefore(wrap, anchor); else hud.appendChild(wrap); }

    function renderDiff(i) {
        var el = document.getElementById('hist-diff'), cur = index[i], prev = i > 0 ? index[i - 1] : null;
        if (!prev) { el.textContent = 'epoch #' + cur.epoch + ' (oldest kept)'; return; }
        var pk = {};
        prev.nodes.forEach(function (n) { pk[n.name + '|' + n.type] = 1; });
        var ck = {};
        cur.nodes.forEach(function (n) { ck[n.name + '|' + n.type] = 1; });
        var joined = cur.nodes.filter(function (n) { return !pk[n.name + '|' + n.type]; }).map(function (n) { return n.name; });
        var left = prev.nodes.filter(function (n) { return !ck[n.name + '|' + n.type]; }).map(function (n) { return n.name; });
        var s = 'epoch #' + cur.epoch;
        function frag(sign, arr) { return ' | ' + sign + arr.length + ' (' + arr.slice(0, 3).join(', ') + (arr.length > 3 ? '...' : '') + ')'; }
        if (joined.length) s += frag('+', joined);
        if (left.length) s += frag('-', left);
        if (!joined.length && !left.length) s += ' | same node set';
        el.textContent = s;
    }

    function loadEpoch(i) {
        if (i < 0 || i >= index.length) return;
        pos = i;
        var e = index[i];
        fetch(histBase + e.file + '?ts=' + (e.generated_at || ''), { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (!data) return;
                K.replay(data);
                if (window.KATZEN_EPOCH_LABEL) window.KATZEN_EPOCH_LABEL('Viewing epoch #' + e.epoch + ' (historical)');
                renderDiff(i);
            })
            .catch(function () { });
    }
    function live() {
        pos = -1;
        if (window.KATZEN_EPOCH_LABEL) window.KATZEN_EPOCH_LABEL(null);
        K.goLive();
        document.getElementById('hist-diff').textContent = '';
    }

    function drawSpark() {
        var cv = document.getElementById('hist-spark'), g = cv.getContext('2d');
        var W = cv.width, H = cv.height;
        g.clearRect(0, 0, W, H);
        if (index.length < 2) return;
        var max = 1;
        index.forEach(function (e) { var c = e.counts || {}; max = Math.max(max, c.total || 0); });
        var series = [['ok', '#00f3ff'], ['out', '#ffaa00'], ['down', '#ff2d6b']];
        var stepX = W / (index.length - 1);
        series.forEach(function (s) {
            g.beginPath();
            index.forEach(function (e, i) {
                var by = (e.counts || {}).by_status || {};
                var v = by[s[0]] || 0, x = i * stepX, y = H - 2 - (v / max) * (H - 4);
                if (i === 0) g.moveTo(x, y); else g.lineTo(x, y);
            });
            g.strokeStyle = s[1]; g.lineWidth = 1.5; g.stroke();
        });
    }

    function fetchIndex() {
        histBase = base();
        fetch(histBase + 'index.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (idx) {
                if (!idx || !idx.length) return;
                index = idx.filter(function (e) { return e && e.epoch; });
                if (index.length < 2) return;   // need more than one epoch to scrub
                wrap.style.display = 'block';
                drawSpark();
            })
            .catch(function () { /* no history yet: stay hidden */ });
    }

    document.getElementById('hist-prev').addEventListener('click', function () {
        loadEpoch(pos < 0 ? Math.max(0, index.length - 2) : Math.max(0, pos - 1));
    });
    document.getElementById('hist-next').addEventListener('click', function () {
        if (pos < 0) return;
        if (pos + 1 >= index.length) live(); else loadEpoch(pos + 1);
    });
    document.getElementById('hist-live').addEventListener('click', live);
    K.on('boot', fetchIndex);
    K.on('data', function () { if (!K.isHistory()) fetchIndex(); });
})();
