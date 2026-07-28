(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;

    function noop() { }

    function statusHex(s) {
        try { return K.hex6(K.statusColor(s)); } catch (e) { return '#00f3ff'; }
    }

    function activate() {
        var dataUrl = window.KATZEN_DATA_URL;
        var container = document.getElementById('canvas-container');
        if (!dataUrl || !container) return;

        ['view-buttons', 'labels-toggle', 'consensus-btn', 'link-btn'].forEach(function (id) {
            var el = document.getElementById(id); if (el) el.style.display = 'none';
        });
        var leg = document.querySelector('#hud-panel .legend');
        if (leg) leg.style.display = 'none';

        var canvas = document.createElement('canvas');
        canvas.id = 'fallback2d';
        canvas.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;display:block;touch-action:none';
        container.appendChild(canvas);
        var ctx = canvas.getContext('2d');
        if (!ctx) return;

        var land = null;        // [[ [lon,lat], ... ], ...]
        var DATA = null;
        var lastGen = null;
        var hit = [];           // [{x,y,r,node}] in CSS pixels, for tap testing
        var cssW = 0, cssH = 0;

        var view = { s: 1, x: 0, y: 0 };
        var MINS = 1, MAXS = 12;
        function baseX(lon) { return (lon + 180) / 360 * cssW; }
        function baseY(lat) { return (90 - lat) / 180 * cssH; }
        function projX(lon) { return baseX(lon) * view.s + view.x; }
        function projY(lat) { return baseY(lat) * view.s + view.y; }

        function clampView() {
            if (view.s < MINS) view.s = MINS;
            if (view.s > MAXS) view.s = MAXS;
            var w = cssW * view.s, h = cssH * view.s;
            var minX = cssW - w, minY = cssH - h;   // <= 0
            if (view.x > 0) view.x = 0; if (view.x < minX) view.x = minX;
            if (view.y > 0) view.y = 0; if (view.y < minY) view.y = minY;
        }
        function zoomAt(px, py, factor) {
            var ns = view.s * factor;
            if (ns < MINS) ns = MINS; if (ns > MAXS) ns = MAXS;
            var k = ns / view.s;
            view.x = px - (px - view.x) * k;
            view.y = py - (py - view.y) * k;
            view.s = ns;
            clampView(); draw();
        }
        function resetView() { view.s = 1; view.x = 0; view.y = 0; draw(); }

        function resize() {
            var dpr = Math.min(window.devicePixelRatio || 1, 2);
            cssW = container.clientWidth || window.innerWidth;
            cssH = container.clientHeight || window.innerHeight;
            canvas.width = Math.round(cssW * dpr);
            canvas.height = Math.round(cssH * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);   // draw in CSS pixels
            clampView();
            draw();
        }

        function drawGraticule() {
            ctx.strokeStyle = 'rgba(80,110,140,0.14)';
            ctx.lineWidth = 1;
            var lon, lat;
            for (lon = -150; lon <= 150; lon += 30) {
                ctx.beginPath(); ctx.moveTo(projX(lon), 0); ctx.lineTo(projX(lon), cssH); ctx.stroke();
            }
            for (lat = -60; lat <= 60; lat += 30) {
                ctx.beginPath(); ctx.moveTo(0, projY(lat)); ctx.lineTo(cssW, projY(lat)); ctx.stroke();
            }
        }

        function drawLand() {
            if (!land) return;
            ctx.strokeStyle = 'rgba(90,130,160,0.35)';
            ctx.lineWidth = 1;
            land.forEach(function (ring) {
                ctx.beginPath();
                for (var i = 0; i < ring.length; i++) {
                    var x = projX(ring[i][0]), y = projY(ring[i][1]);
                    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
                }
                ctx.stroke();
            });
        }

        function draw() {
            if (!ctx) return;
            ctx.clearRect(0, 0, cssW, cssH);
            ctx.fillStyle = '#030508';
            ctx.fillRect(0, 0, cssW, cssH);
            drawGraticule();
            drawLand();

            hit = [];
            var ns = (DATA && DATA.nodes) || [];
            ns.forEach(function (n) {
                var g = n.geo;
                if (!g || typeof g.lat !== 'number') return;
                var x = projX(g.lon), y = projY(g.lat), r = 5;
                var col = statusHex(n.status);
                ctx.beginPath(); ctx.arc(x, y, r + 3, 0, Math.PI * 2);
                ctx.fillStyle = 'rgba(0,0,0,0.55)'; ctx.fill();     // halo for contrast
                ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
                ctx.fillStyle = col; ctx.fill();
                ctx.lineWidth = 1; ctx.strokeStyle = 'rgba(255,255,255,0.5)'; ctx.stroke();
                hit.push({ x: x, y: y, r: r + 6, node: n });
            });
            ctx.font = '10px monospace';
            ctx.textBaseline = 'middle';
            hit.forEach(function (h) {
                var name = h.node.name || '';
                ctx.fillStyle = 'rgba(0,0,0,0.6)';
                var tw = ctx.measureText(name).width;
                ctx.fillRect(h.x + 8, h.y - 6, tw + 4, 12);
                ctx.fillStyle = '#cdd6df';
                ctx.fillText(name, h.x + 10, h.y);
            });

            drawLegend();
            var mapped = hit.length, total = ns.length;
            if (total && mapped < total) {
                ctx.fillStyle = '#7b8e9d'; ctx.font = '10px monospace'; ctx.textBaseline = 'bottom';
                ctx.fillText((total - mapped) + ' node(s) without a location - see the list', 12, cssH - 10);
            }
        }

        function drawLegend() {
            var items = [['ok', 'in consensus'], ['out', 'reachable, not in consensus'],
                ['down', 'down'], ['unknown', 'address unknown']];
            ctx.font = '10px monospace'; ctx.textBaseline = 'middle';
            var x = 12, y = 16;
            ctx.fillStyle = '#9fb3c2'; ctx.fillText('Katzenpost mixnet (2D fallback)', x, y);
            items.forEach(function (it, i) {
                var yy = y + 16 + i * 14;
                ctx.beginPath(); ctx.arc(x + 4, yy, 4, 0, Math.PI * 2);
                ctx.fillStyle = statusHex(it[0]); ctx.fill();
                ctx.fillStyle = '#8ba0b0'; ctx.fillText(it[1], x + 14, yy);
            });
        }

        function showInfo(n) {
            var box = document.getElementById('node-info');
            var title = document.getElementById('info-title');
            var body = document.getElementById('info-body');
            if (!box || !title || !body) return;
            var role = (n.type === 'out' ? (n.role || 'node') : n.type);
            var rows = [];
            function add(label, val) {
                if (val === undefined || val === null || val === '') return;
                rows.push('<p><span style="color:#7b8e9d">' + K.esc(label) + ':</span> ' + K.esc(String(val)) + '</p>');
            }
            add('Role', role);
            add('Status', n.status);
            if (n.geo && n.geo.label) add('Location', n.geo.label);
            if (n.asn) add('AS', n.asn + (n.net ? ' ' + n.net : ''));
            if (n.latency_ms != null) add('Latency', n.latency_ms + ' ms');
            if (n.layer != null) add('Mix layer', n.layer);
            if (n.details && n.details.version) add('Version', n.details.version);
            title.textContent = n.name || 'Node';
            body.innerHTML = rows.join('');
            box.style.display = 'block';
        }

        function selectAt(mx, my) {
            var best = null, bestD = 1e9;
            hit.forEach(function (h) {
                var d = (h.x - mx) * (h.x - mx) + (h.y - my) * (h.y - my);
                if (d < bestD && d <= (h.r + 6) * (h.r + 6)) { bestD = d; best = h.node; }
            });
            if (best) showInfo(best);
            else { var box = document.getElementById('node-info'); if (box) box.style.display = 'none'; }
        }

        var pts = {};                 // active pointerId -> {x, y}
        var moved = false, startX = 0, startY = 0, pinchDist = 0;
        function localXY(ev) {
            var rect = canvas.getBoundingClientRect();
            return { x: ev.clientX - rect.left, y: ev.clientY - rect.top };
        }
        function activeList() { return Object.keys(pts).map(function (k) { return pts[k]; }); }

        canvas.addEventListener('pointerdown', function (ev) {
            canvas.setPointerCapture && canvas.setPointerCapture(ev.pointerId);
            var p = localXY(ev); pts[ev.pointerId] = p;
            var n = activeList();
            if (n.length === 1) { moved = false; startX = p.x; startY = p.y; }
            else if (n.length === 2) {
                pinchDist = Math.hypot(n[0].x - n[1].x, n[0].y - n[1].y);
            }
        });
        canvas.addEventListener('pointermove', function (ev) {
            if (!pts[ev.pointerId]) return;
            var prev = pts[ev.pointerId], p = localXY(ev);
            pts[ev.pointerId] = p;
            var n = activeList();
            if (n.length >= 2) {
                var a = n[0], b = n[1];
                var dist = Math.hypot(a.x - b.x, a.y - b.y);
                var midX = (a.x + b.x) / 2, midY = (a.y + b.y) / 2;
                if (pinchDist > 0 && dist > 0) zoomAt(midX, midY, dist / pinchDist);
                pinchDist = dist; moved = true;
            } else {
                view.x += p.x - prev.x; view.y += p.y - prev.y;
                if (Math.abs(p.x - startX) + Math.abs(p.y - startY) > 6) moved = true;
                clampView(); draw();
            }
        });
        var lastTapT = 0, lastTapX = 0, lastTapY = 0;
        function endPointer(ev) {
            if (!pts[ev.pointerId]) return;
            var p = pts[ev.pointerId];
            delete pts[ev.pointerId];
            if (Object.keys(pts).length === 0 && !moved) {
                var now = (window.performance && performance.now) ? performance.now() : +new Date();
                if (now - lastTapT < 320 && Math.abs(p.x - lastTapX) < 24 && Math.abs(p.y - lastTapY) < 24) {
                    resetView(); lastTapT = 0;
                } else {
                    selectAt(p.x, p.y);
                    lastTapT = now; lastTapX = p.x; lastTapY = p.y;
                }
            }
            pinchDist = 0;
        }
        canvas.addEventListener('pointerup', endPointer);
        canvas.addEventListener('pointercancel', endPointer);

        canvas.addEventListener('wheel', function (ev) {
            ev.preventDefault();
            var p = localXY(ev);
            zoomAt(p.x, p.y, ev.deltaY < 0 ? 1.15 : 1 / 1.15);
        }, { passive: false });
        canvas.addEventListener('dblclick', function () { resetView(); });
        // iOS Safari ignores user-scalable=no and pinch-zooms the whole page,
        // which was stealing the map's pinch gesture. Swallow the non-standard
        // gesture events so our pointer-based pinch (zoomAt) drives the zoom.
        ['gesturestart', 'gesturechange', 'gestureend'].forEach(function (t) {
            canvas.addEventListener(t, function (ev) { ev.preventDefault(); }, { passive: false });
        });

        function updateMeta() {
            var m = document.getElementById('hud-meta');
            if (!m || !DATA) return;
            var parts = [];
            if (DATA.epoch != null) parts.push('Epoch ' + DATA.epoch);
            parts.push(((DATA.nodes || []).length) + ' nodes');
            m.textContent = parts.join('  -  ');
        }

        function applyData(d) {
            if (!d) return;
            if (d.generated_at && lastGen && d.generated_at <= lastGen) return;
            DATA = d; lastGen = d.generated_at || lastGen;
            draw();
            updateMeta();
        }
        function fetchData() {
            fetch(dataUrl + (dataUrl.indexOf('?') >= 0 ? '&' : '?') + 'ts=' + Date.now(), { cache: 'no-store' })
                .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
                .then(applyData).catch(noop);
        }

        fetch('katzenpost-viz/earth/land-110m.geo.json', { cache: 'force-cache' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (j) { if (j && j.rings) { land = j.rings; draw(); } })
            .catch(noop);

        window.addEventListener('resize', resize);
        if (window.visualViewport) window.visualViewport.addEventListener('resize', resize);
        resize();
        fetchData();
        var secs = window.KATZEN_POLL_SECONDS || 60;
        if (secs > 0) setInterval(fetchData, secs * 1000);

        var ls = document.getElementById('load-status');
        if (ls) {
            ls.textContent = '';
            var msg = document.createElement('span');
            msg.textContent = 'WebGL is blocked (Lockdown Mode?) - 2D map. ' +
                'Tap a node for details; pinch or scroll to zoom, drag to pan, double-tap to reset.';
            var x = document.createElement('button');
            x.textContent = 'Close x';
            x.setAttribute('aria-label', 'Dismiss lockdown notice');
            x.style.cssText = 'margin-left:12px;background:rgba(255,180,84,.16);' +
                'border:1px solid rgba(255,180,84,.55);color:#ffb454;border-radius:6px;' +
                'cursor:pointer;font:inherit;padding:6px 12px;min-height:32px;line-height:1';
            x.addEventListener('click', function () { ls.textContent = ''; ls.style.display = 'none'; });
            ls.appendChild(msg); ls.appendChild(x);
        }
    }

    K.on('boot', function () { if (window.KATZEN_NO_WEBGL) activate(); });
})();
