(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;

    var HUESBASE = [0x5b8ff9, 0x61ddaa, 0xf6bd16, 0x7262fd,
                    0x78d3f8, 0x9661bc, 0xf6903d, 0xff99c3];
    function HUEAT(i) {
        var b = HUESBASE[((i % HUESBASE.length) + HUESBASE.length) % HUESBASE.length];
        return (K.themeColor && K.hex6) ? K.hex6(K.themeColor(b)) : '#' + ('000000' + b.toString(16)).slice(-6);
    }
    var BG = '#030508', AMBER = '#ffb454', LABEL = '#9fb3c2', MUTED = '#7b8e9d';
    var PAD_T = 104, MARGIN = 16;   // PAD_T clears the title, caption and top controls

    var el = document.createElement('div');
    el.id = 'treemap-overlay';
    el.style.cssText = 'position:fixed;inset:0;z-index:25;display:none;background:#030508;' +
        'box-sizing:border-box;padding:env(safe-area-inset-top) env(safe-area-inset-right) ' +
        'env(safe-area-inset-bottom) calc(env(safe-area-inset-left) + 60px)';
    var canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    el.appendChild(canvas);
    var tip = document.createElement('div');
    tip.style.cssText = 'position:fixed;z-index:26;display:none;pointer-events:none;' +
        'background:rgba(8,12,20,0.95);border:1px solid rgba(255,180,84,0.4);color:#cdd6df;' +
        'font:11px/1.4 monospace;padding:5px 8px;border-radius:5px';
    el.appendChild(tip);
    document.body.appendChild(el);
    var ctx = canvas.getContext('2d');

    var tiles = [];   // hit-test records: {x,y,w,h,asn,net,count,color}

    function groupsNow() {
        var objs = (K.nodes && K.nodes()) || [];
        var map = {}, order = [];
        objs.forEach(function (o) {
            var d = o && o.data ? o.data : null;
            if (!d) return;
            var asn = d.asn || '';           // viz.py writes '' (not undefined) when unknown
            var key = asn ? asn : 'unknown';
            if (!map[key]) { map[key] = { asn: asn, net: '', count: 0 }; order.push(key); }
            map[key].count += 1;
            if (!map[key].net && d.net) map[key].net = d.net;
        });
        var list = order.map(function (k) { return map[k]; });
        list.sort(function (a, b) {
            return b.count - a.count || (a.asn || 'unknown').localeCompare(b.asn || 'unknown');
        });
        return list;
    }

    function worst(row, length) {
        var sum = 0, max = 0, min = Infinity, i;
        for (i = 0; i < row.length; i++) {
            var a = row[i].area;
            sum += a; if (a > max) max = a; if (a < min) min = a;
        }
        if (sum <= 0) return Infinity;
        var s2 = sum * sum, l2 = length * length;
        return Math.max(l2 * max / s2, s2 / (l2 * min));
    }

    function layoutRow(row, rect) {
        var sum = 0, i;
        for (i = 0; i < row.length; i++) sum += row[i].area;
        if (sum <= 0) return;
        if (rect.w >= rect.h) {
            var rw = sum / rect.h, ry = rect.y;
            for (i = 0; i < row.length; i++) {
                var rh = row[i].area / rw;
                row[i].rect = { x: rect.x, y: ry, w: rw, h: rh };
                ry += rh;
            }
            rect.x += rw; rect.w -= rw;
        } else {
            var rh2 = sum / rect.w, rx = rect.x;
            for (i = 0; i < row.length; i++) {
                var rw2 = row[i].area / rh2;
                row[i].rect = { x: rx, y: rect.y, w: rw2, h: rh2 };
                rx += rw2;
            }
            rect.y += rh2; rect.h -= rh2;
        }
    }

    function squarify(items, x, y, w, h) {
        var rect = { x: x, y: y, w: w, h: h };
        var remaining = items.slice();
        var row = [];
        while (remaining.length > 0) {
            var c = remaining[0];
            var length = Math.min(rect.w, rect.h);
            if (length <= 0) { remaining.shift(); continue; }
            if (row.length === 0 || worst(row, length) >= worst(row.concat([c]), length)) {
                row.push(c); remaining.shift();
            } else {
                layoutRow(row, rect); row = [];
            }
        }
        if (row.length) layoutRow(row, rect);   // flush the last row
    }

    function draw() {
        if (!ctx) return;
        var dpr = Math.min(window.devicePixelRatio || 1, 2);
        var W = el.clientWidth || window.innerWidth, H = el.clientHeight || window.innerHeight;
        canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, W, H); ctx.fillStyle = BG; ctx.fillRect(0, 0, W, H);

        var groups = groupsNow();
        var total = 0, i;
        for (i = 0; i < groups.length; i++) total += groups[i].count;

        ctx.fillStyle = AMBER; ctx.font = 'bold 14px monospace'; ctx.textBaseline = 'top';
        ctx.textAlign = 'left';
        ctx.fillText('AS / operator share (' + total + ' nodes, ' + groups.length + ' operators)', MARGIN, 16);
        ctx.fillStyle = MUTED; ctx.font = '11px monospace';
        ctx.fillText('larger tile = more nodes in that AS; operator concentration weakens anonymity', MARGIN, 38);

        var cx = MARGIN, cy = PAD_T, cw = W - 2 * MARGIN, ch = H - PAD_T - MARGIN;
        tiles = [];
        if (!groups.length || total <= 0 || cw <= 0 || ch <= 0) {
            ctx.fillStyle = MUTED; ctx.font = '12px monospace';
            ctx.fillText('No nodes yet.', MARGIN, PAD_T);
            return;
        }

        var scale = (cw * ch) / total;
        var items = groups.map(function (g) { return { g: g, area: g.count * scale }; });
        squarify(items, cx, cy, cw, ch);

        items.forEach(function (it, idx) {
            var r = it.rect; if (!r) return;
            var g = it.g, color = HUEAT(idx);
            ctx.fillStyle = color;
            ctx.fillRect(r.x + 1, r.y + 1, Math.max(0, r.w - 2), Math.max(0, r.h - 2));
            tiles.push({ x: r.x, y: r.y, w: r.w, h: r.h, asn: g.asn, net: g.net, count: g.count });

            var name = g.asn ? g.asn : 'unknown';
            var lines = [name, g.count + (g.count === 1 ? ' node' : ' nodes')];
            ctx.font = '11px monospace'; ctx.textBaseline = 'top'; ctx.textAlign = 'left';
            var lh = 13, tx = r.x + 6, ty = r.y + 5;
            for (var li = 0; li < lines.length; li++) {
                var s = lines[li];
                if (ctx.measureText(s).width > r.w - 10) continue;
                if (ty + lh > r.y + r.h - 2) break;
                ctx.fillStyle = li === 0 ? '#0b0f14' : 'rgba(6,9,14,0.85)';
                ctx.fillText(s, tx, ty);
                ty += lh;
            }
        });
    }

    canvas.addEventListener('pointermove', function (ev) {
        var rect = canvas.getBoundingClientRect();
        var mx = ev.clientX - rect.left, my = ev.clientY - rect.top, hit = null;
        for (var i = 0; i < tiles.length; i++) {
            var t = tiles[i];
            if (mx >= t.x && mx <= t.x + t.w && my >= t.y && my <= t.y + t.h) { hit = t; break; }
        }
        if (!hit) { tip.style.display = 'none'; return; }
        var name = hit.asn ? hit.asn : 'unknown';
        tip.textContent = name + (hit.net ? '  ' + hit.net : '') + '  -  ' +
            hit.count + (hit.count === 1 ? ' node' : ' nodes');
        tip.style.display = 'block';
        tip.style.left = Math.min(ev.clientX + 12, window.innerWidth - tip.offsetWidth - 8) + 'px';
        tip.style.top = (ev.clientY + 12) + 'px';
    });
    canvas.addEventListener('pointerleave', function () { tip.style.display = 'none'; });

    window.KATZEN_OVERLAYS = window.KATZEN_OVERLAYS || [];
    window.KATZEN_OVERLAYS.push({
        id: 'treemap', name: 'AS share', el: el,
        onShow: function () { draw(); },
        onHide: function () { }
    });
    function redrawIfShown() { if (el.style.display !== 'none') draw(); }
    window.addEventListener('resize', redrawIfShown);
    if (K.on) K.on('theme', redrawIfShown);
    if (window.visualViewport) window.visualViewport.addEventListener('resize', redrawIfShown);
})();
