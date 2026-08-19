(function () {
    "use strict";
    // "Mini" mode (?mini=1): the page is embedded in a small screen (e.g. inside
    // an LCARS panel), so hide all chrome and show only the visualization.
    if (!/[?#&]mini=1/i.test(location.hash + location.search)) return;
    var s = document.createElement('style');
    s.textContent =
        '#menu-toggle,#view-select,#randomize-view,#hud-panel,#node-info,' +
        '#stale-banner,#epoch-line{display:none!important}' +
        'body{overflow:hidden}';
    (document.head || document.documentElement).appendChild(s);
})();
