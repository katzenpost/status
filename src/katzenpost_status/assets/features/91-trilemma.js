(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    var hud = document.getElementById('hud-panel');
    if (!hud) return;
    if (window.KATZEN_DELAY == null) window.KATZEN_DELAY = 2;
    if (window.KATZEN_COVER == null) window.KATZEN_COVER = 0;

    var PRESETS = [
        { n: 'Tor-like free route', lat: 0.05, bw: 0.05 },
        { n: 'Loopix (light cover)', lat: 0.28, bw: 0.32 },
        { n: 'Loopix (heavy cover)', lat: 0.30, bw: 0.9 },
        { n: 'Stop-and-Go mix', lat: 0.75, bw: 0.12 },
        { n: 'Timed mix', lat: 0.62, bw: 0.1 },
        { n: 'Threshold pool cascade', lat: 0.95, bw: 0.06 },
        { n: 'DC-net', lat: 0.1, bw: 1.0 }
    ];

    function mk(tag, css, txt) { var e = document.createElement(tag); if (css) e.style.cssText = css; if (txt != null) e.textContent = txt; return e; }
    function col(a) { try { return '#' + ('000000' + (K.themeColor ? K.themeColor(a) : a).toString(16)).slice(-6); } catch (e) { return '#' + ('000000' + a.toString(16)).slice(-6); } }

    var box = mk('div', 'margin-top:12px;padding-top:10px;border-top:1px solid rgba(255,180,84,0.25)');
    box.appendChild(mk('div', 'font-size:11px;font-weight:700;color:#ffb454;letter-spacing:1px;margin-bottom:6px', 'ANONYMITY TRILEMMA'));

    var canvas = mk('canvas', 'display:block;width:100%;height:120px;margin-bottom:4px');
    canvas.width = 248; canvas.height = 120;
    var ctx = canvas.getContext('2d');
    box.appendChild(canvas);

    var stratEl = mk('div', 'font-size:10px;color:#9fb3c2;margin-bottom:4px');
    box.appendChild(stratEl);

    function bar(label, cc) {
        var row = mk('div', 'display:grid;grid-template-columns:78px 1fr 34px;gap:6px;align-items:center;font-size:10px;color:#9fb3c2;margin:2px 0');
        row.appendChild(mk('span', null, label));
        var track = mk('div', 'height:8px;background:rgba(255,255,255,0.08);border-radius:4px;overflow:hidden');
        var fill = mk('div', 'height:100%;border-radius:4px;background:' + col(cc)); track.appendChild(fill);
        var val = mk('span', 'text-align:right;color:#ffb454');
        row.appendChild(track); row.appendChild(val); box.appendChild(row);
        return { fill: fill, val: val };
    }
    var bA = bar('Anonymity', 0x9b5de5);

    function slider(label, css) {
        var row = mk('div', 'display:grid;grid-template-columns:78px 1fr 34px;gap:6px;align-items:center;font-size:10px;color:#9fb3c2;margin:4px 0');
        row.appendChild(mk('span', null, label));
        var s = mk('input', 'flex:1;min-width:0;accent-color:#ffb454;cursor:pointer');
        s.type = 'range'; s.min = '0'; s.max = '1'; s.step = '0.01'; s.setAttribute('aria-label', label);
        var val = mk('span', 'text-align:right;color:#ffb454');
        row.appendChild(s); row.appendChild(val); box.appendChild(row);
        return { s: s, val: val };
    }
    var latC = slider('Latency budget');
    var bwC = slider('Bandwidth budget');

    var params = mk('div', 'font-size:10px;color:#9fb3c2;margin-top:6px;line-height:1.5;white-space:pre-wrap');
    box.appendChild(params);

    var presetSel = mk('select', 'width:100%;margin-top:6px;background:rgba(8,12,20,0.9);border:1px solid rgba(255,180,84,0.4);color:#ffb454;border-radius:6px;font:11px/1 monospace;padding:4px 6px;cursor:pointer');
    presetSel.appendChild(mk('option', null, 'Preset: classical design...'));
    PRESETS.forEach(function (p, i) { var o = mk('option', null, p.n); o.value = String(i); presetSel.appendChild(o); });
    box.appendChild(presetSel);

    function strategy(lat, bw) {
        if (lat < 0.2 && bw < 0.2) return 'FIFO, no mixing (weak)';
        if (lat >= 0.6 && bw < 0.35) return 'Threshold / pool batch, shuffle + flush';
        if (lat >= 0.45) return 'Stop-and-Go: per-packet exponential delay';
        if (bw >= 0.45) return 'Poisson mix + loop/drop cover (Loopix)';
        return 'Poisson (continuous-time) mix';
    }

    function draw(A, lat, bw) {
        var w = canvas.width, h = canvas.height, pad = 18;
        ctx.clearRect(0, 0, w, h);
        var top = [w / 2, pad], bl = [pad + 8, h - pad], br = [w - pad - 8, h - pad];
        ctx.strokeStyle = col(0xffb454); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.moveTo(top[0], top[1]); ctx.lineTo(bl[0], bl[1]); ctx.lineTo(br[0], br[1]); ctx.closePath(); ctx.stroke();
        ctx.fillStyle = '#9fb3c2'; ctx.font = '8px monospace';
        ctx.textAlign = 'center'; ctx.fillText('Anonymity', top[0], top[1] - 5);
        ctx.textAlign = 'left'; ctx.fillText('Low latency', 2, h - 4);
        ctx.textAlign = 'right'; ctx.fillText('Low bandwidth', w - 2, h - 4);
        var wa = A, wl = 1 - lat, wb = 1 - bw, s = wa + wl + wb || 1;
        wa /= s; wl /= s; wb /= s;
        var px = wa * top[0] + wl * bl[0] + wb * br[0], py = wa * top[1] + wl * bl[1] + wb * br[1];
        ctx.fillStyle = col(0x00f3ff);
        ctx.beginPath(); ctx.arc(px, py, 4.5, 0, 6.2832); ctx.fill();
    }

    function apply() {
        var lat = +latC.s.value, bw = +bwC.s.value;
        var delay = 0.2 + lat * 3.6;
        var A = lat + bw - lat * bw;
        window.KATZEN_DELAY = delay;
        window.KATZEN_COVER = bw;
        latC.val.textContent = Math.round(lat * 100) + '%';
        bwC.val.textContent = Math.round(bw * 100) + '%';
        bA.fill.style.width = Math.round(A * 100) + '%'; bA.val.textContent = Math.round(A * 100) + '%';
        stratEl.textContent = 'Shuffle: ' + strategy(lat, bw);
        var d = K.data() || {}, mu = (d.parameters && d.parameters.Mu) || 0.001;
        var effMu = mu / delay, loop = (0.0005 + bw * 0.03), drop = (bw * 0.02);
        params.textContent =
            'Mean mix delay  ' + delay.toFixed(2) + 'x  (Mu ' + effMu.toPrecision(2) + ')\n' +
            'Cover traffic   ' + Math.round(bw * 100) + '%  (lambdaL ' + loop.toPrecision(2) + ', lambdaD ' + drop.toPrecision(2) + ')';
        draw(A, lat, bw);
    }
    latC.s.addEventListener('input', function () { presetSel.value = ''; apply(); });
    bwC.s.addEventListener('input', function () { presetSel.value = ''; apply(); });
    presetSel.addEventListener('change', function () {
        var i = parseInt(presetSel.value, 10);
        if (isNaN(i)) return;
        latC.s.value = String(PRESETS[i].lat); bwC.s.value = String(PRESETS[i].bw); apply();
    });
    if (K.on) { K.on('theme', apply); K.on('data', apply); }
    hud.appendChild(box);
    latC.s.value = '0.5'; bwC.s.value = '0.32';
    apply();
})();
