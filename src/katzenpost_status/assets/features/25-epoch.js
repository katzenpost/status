(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var STALE_MS = 30 * 60 * 1000;   // ~2x the generator cadence
    var histLabel = null;

    var line = document.createElement('div');
    line.id = 'epoch-line';
    line.style.cssText = 'font-size:10.5px;color:#9fb3c2;margin:-4px 0 10px;line-height:1.5';
    var meta = document.getElementById('hud-meta');
    if (meta && meta.parentNode) meta.parentNode.insertBefore(line, meta.nextSibling);

    var banner = document.createElement('div');
    banner.id = 'stale-banner';
    banner.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:35;' +
        'background:rgba(60,10,20,0.92);border:1px solid #ff2d6b;color:#ffd0dc;' +
        'font:12px "Courier New",monospace;padding:6px 30px 6px 14px;border-radius:6px;display:none;' +
        'text-shadow:0 0 6px rgba(255,45,107,0.6)';
    var bannerText = document.createElement('span');
    var bannerX = document.createElement('button');
    bannerX.textContent = 'x'; bannerX.setAttribute('aria-label', 'Dismiss');
    bannerX.style.cssText = 'position:absolute;top:3px;right:8px;background:none;border:none;' +
        'color:#ffd0dc;cursor:pointer;font:12px monospace';
    var dismissedGen = null;
    bannerX.addEventListener('click', function () { dismissedGen = lastGen; banner.style.display = 'none'; });
    banner.appendChild(bannerText); banner.appendChild(bannerX);
    document.body.appendChild(banner);
    var lastGen = null;

    function fmt(ms) {
        if (ms < 0) ms = 0;
        var s = Math.floor(ms / 1000), m = Math.floor(s / 60);
        s = s % 60;
        return m + ':' + (s < 10 ? '0' : '') + s;
    }
    function tick() {
        if (histLabel) { line.textContent = histLabel; banner.style.display = 'none'; return; }
        var d = K.data() || {};
        if (d.epoch) {
            var end = d.epoch_end ? Date.parse(d.epoch_end) : null;
            line.textContent = 'Epoch #' + d.epoch + (end ? '  next in ' + fmt(end - Date.now()) : '');
        } else {
            line.textContent = 'No consensus';
        }
        var gen = d.generated_at ? Date.parse(d.generated_at) : null;
        lastGen = gen;
        var age = gen ? (Date.now() - gen) : 0;
        if (gen && age > STALE_MS && gen !== dismissedGen) {
            bannerText.textContent = 'Stale data - last update ' + Math.round(age / 60000) + ' min ago';
            banner.style.display = 'block';
        } else {
            banner.style.display = 'none';
        }
    }
    K.on('data', tick);
    K.on('build', tick);
    K.on('boot', function () { setInterval(tick, 1000); tick(); });

    window.KATZEN_EPOCH_LABEL = function (label) { histLabel = label; tick(); };
})();
