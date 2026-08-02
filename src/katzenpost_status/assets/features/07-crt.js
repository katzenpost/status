(function () {
    "use strict";
    // Shared CRT-style overlay: scanlines + faint RGB phosphor + a slow sweep
    // band + a vignette. window.KATZEN_CRT(el) drops one into a positioned
    // element so it sits over that overlay's canvas.
    var css = document.createElement('style');
    css.textContent =
        '.crt-fx{position:absolute;inset:0;pointer-events:none;z-index:3;overflow:hidden;' +
        'background:repeating-linear-gradient(to bottom,rgba(0,0,0,0.34) 0px,rgba(0,0,0,0.34) 1px,rgba(0,0,0,0) 2px,rgba(0,0,0,0) 3px),' +
        'repeating-linear-gradient(to right,rgba(255,120,0,0.035) 0px,rgba(255,120,0,0.035) 1px,rgba(0,180,255,0.035) 2px,rgba(0,0,0,0) 3px);' +
        'animation:crtfxflicker 3.5s infinite steps(60)}' +
        '.crt-fx::after{content:"";position:absolute;left:0;right:0;top:-25%;height:22%;' +
        'background:linear-gradient(to bottom,rgba(255,190,120,0) 0%,rgba(255,190,120,0.06) 50%,rgba(255,190,120,0) 100%);' +
        'animation:crtfxsweep 7s linear infinite}' +
        '.crt-fx::before{content:"";position:absolute;inset:0;' +
        'background:radial-gradient(ellipse at center,rgba(0,0,0,0) 58%,rgba(0,0,0,0.5) 100%)}' +
        '@keyframes crtfxflicker{0%,100%{opacity:0.9}50%{opacity:0.78}}' +
        '@keyframes crtfxsweep{0%{top:-25%}100%{top:110%}}';
    document.head.appendChild(css);

    window.KATZEN_CRT = function (el) {
        if (!el || el.querySelector('.crt-fx')) return null;
        var d = document.createElement('div');
        d.className = 'crt-fx';
        el.appendChild(d);
        return d;
    };
})();
