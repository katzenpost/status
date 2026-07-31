(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var N = 40, FLAP = 4, LSKEY = 'katzen-reach-hist';

    function load() {
        try {
            var o = JSON.parse(localStorage.getItem(LSKEY) || '{}');
            if (!o || typeof o !== 'object') return {};
            Object.keys(o).forEach(function (k) {
                if (!Array.isArray(o[k]) || (o[k].length && typeof o[k][0] !== 'object')) delete o[k];
            });
            return o;
        } catch (e) { return {}; }
    }
    function save() { try { localStorage.setItem(LSKEY, JSON.stringify(hist)); } catch (e) { /* full/disabled */ } }
    function flaps(arr) { var f = 0; for (var i = 1; i < arr.length; i++) if (arr[i].r !== arr[i - 1].r) f++; return f; }
    var hist = load();

    K.on('data', function (d) {
        if (!d || !d.nodes || K.isHistory()) return;   // don't record while replaying old snapshots
        var t = d.generated_at || '';
        d.nodes.forEach(function (n) {
            var key = n.name + '|' + n.type, arr = hist[key] || (hist[key] = []);
            if (arr.length && arr[arr.length - 1].t === t) return;   // dedupe same snapshot
            arr.push({ t: t, r: n.reachable ? 1 : 0 });
            if (arr.length > N) arr.shift();
        });
        save();
    });

    K.on('node', function (obj) {
        if (!obj) return;   // null = deselected
        var body = document.getElementById('info-body');
        if (!body) return;
        var arr = hist[obj.data.name + '|' + obj.data.type] || [], nf = flaps(arr);
        var p = document.createElement('p');
        var lbl = 'Reachability (' + arr.length + ' samples' + (nf ? ', ' + nf + ' flaps' : '') + '):';
        p.innerHTML = '<span style="color:' + (nf >= FLAP ? '#ffaa00' : '#7b8e9d') + '">' + lbl + '</span> ';
        var c = document.createElement('canvas');
        c.width = 120; c.height = 16; c.style.verticalAlign = 'middle';
        var ctx = c.getContext('2d');
        ctx.fillStyle = 'rgba(255,255,255,0.06)'; ctx.fillRect(0, 0, 120, 16);
        var bw = arr.length ? 120 / arr.length : 120;
        arr.forEach(function (s, i) { ctx.fillStyle = s.r ? '#00f3ff' : '#ff2d6b'; ctx.fillRect(i * bw, 0, Math.max(1, bw - 0.5), 16); });
        p.appendChild(c);
        if (nf >= FLAP) {
            var w = document.createElement('span');
            w.style.cssText = 'color:#ffaa00;margin-left:6px;font-size:10px';
            w.textContent = 'flapping';
            p.appendChild(w);
        }
        body.appendChild(p);
    });
})();
