(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K) return;
    if (window.KATZEN_NO_WEBGL) return;  // 3D view only; hidden in the 2D fallback

    var style = document.createElement('style');
    style.textContent =
        '#traffic-panel{margin-top:10px;border-top:1px solid rgba(255,255,255,.1);' +
        'padding-top:10px;font-size:11px;color:#9fb3c2}' +
        '#traffic-panel .bar{height:6px;border-radius:3px;background:rgba(255,255,255,.08);' +
        'margin:2px 0 6px;overflow:hidden}' +
        '#traffic-panel .bar>span{display:block;height:100%}';
    document.head.appendChild(style);

    var panel = document.createElement('div');
    panel.id = 'traffic-panel';
    panel.innerHTML = '<div class="hud-subtitle">Traffic</div>' +
        '<div id="tp-flight">Packets in flight: 0</div><div id="tp-bars"></div>';
    var hud = K.hudPanel();
    if (hud) hud.appendChild(panel);
    var flight = panel.querySelector('#tp-flight');
    var bars = panel.querySelector('#tp-bars');

    var TYPES = [
        ['Real (λP)', 'LambdaP', 0x00f3ff],
        ['Client loop (λL)', 'LambdaL', 0xffaa00],
        ['Drop decoy (λD)', 'LambdaD', 0xff00aa],
        ['Mix loop (λM)', 'LambdaM', 0x8338ec],
        ['Gateway loop (λG)', 'LambdaG', 0x00ff88]
    ];

    K.on('data', function (d) {
        var P = (d && d.parameters) || {};
        var max = 0;
        TYPES.forEach(function (t) { var v = P[t[1]]; if (typeof v === 'number' && v > max) max = v; });
        var html = '';
        TYPES.forEach(function (t) {
            var v = P[t[1]];
            if (v == null) return;
            var pct = max > 0 ? Math.round(100 * v / max) : 0;
            html += '<div>' + t[0] + ': ' + v + '</div>' +
                '<div class="bar"><span style="width:' + pct + '%;background:' + K.hex6(t[2]) + '"></span></div>';
        });
        bars.innerHTML = html || '<div style="color:#59707f">no traffic parameters in consensus</div>';
    });

    var acc = 0;
    K.on('frame', function (dt) {
        acc += dt;
        if (acc < 0.5) return;
        acc = 0;
        var n = K.packets() ? K.packets().length : 0;
        var tr = K.trafficRate ? Math.round(K.trafficRate()) : null;
        flight.textContent = 'Packets in flight: ' + n +
            (tr != null ? ' (target ~' + tr + '/s from rates)' : '');
    });
})();
