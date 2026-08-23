(function () {
    "use strict";
    var K = window.KATZEN;
    if (!K || !window.KATZEN_GEO3D) return;
    var G = window.KATZEN_GEO3D;

var PAL=[0x2ec4b6,0x4d8bf0,0x9b5de5,0xff5d8f,0xff8f3f,0x00d2a0,0xffd23f,0xff5d6c,0x33ccff,0x8a5bff],PI2=Math.PI*2;
function num(v,def){return (typeof v==='number'&&isFinite(v))?v:def;}
function cl(v,m){m=m||22;if(!isFinite(v))return 0;return v<-m?-m:(v>m?m:v);}
function pc(i){return PAL[((i%PAL.length)+PAL.length)%PAL.length];}
function mk(id,name,color,camZ,stel,layout){G.create({id:id,name:name,rotateSpeed:0.3,camZ:camZ||60,color:color,stellate:stel,layout:layout});}
function V3(T,x,y,z){return new T.Vector3(cl(x),cl(y),cl(z));}
function spread(d,T,fn){var ns=(d.nodes||[]),nodes=[],i;for(i=0;i<ns.length;i++){var p=fn(ns[i],i,ns.length||1,T)||new T.Vector3();nodes.push({name:ns[i].name,type:ns[i].type,pos:p});}return nodes;}
function polyEdges(L,color){var e=[],i;for(i=0;i+1<L.length;i++)e.push({a:L[i],b:L[i+1],color:(typeof color==='function')?color(i):color});return e;}
function sub(L){if(!L||L.length<2)return null;var a=(Math.random()*(L.length-1))|0,b=Math.min(L.length-1,a+2+((Math.random()*8)|0)),out=[],i;for(i=a;i<=b;i++)out.push(L[i]);return out.length>=2?out:null;}

function LP(d){var P=(d.parameters||{});return {Mu:num(P.Mu,0.001),Lp:num(P.LambdaP,0.001),Ll:num(P.LambdaL,0.0005),Ld:num(P.LambdaD,0.0005),Lm:num(P.LambdaM,0.0005),Lg:num(P.LambdaG,0.002),Lr:num(P.LambdaR,0.02)};}
function lscale(x){return 6+8*Math.log(1+x*2000)/Math.log(1+2000);}
mk('loopix-delaywheel','Exponential mix-delay wheel',0x2ec4b6,58,undefined,function(d,T){var p=LP(d),N=140,L=[],i;for(i=0;i<=N;i++){var q=(i+0.5)/(N+1),delay=-Math.log(1-q)/1,r=2+16*Math.min(1,delay/7),a=q*PI2;L.push(V3(T,r*Math.cos(a),r*Math.sin(a),3*Math.sin(a*5)));}var nodes=spread(d,T,function(n,j,tot){var a=PI2*j/tot,r=18;return V3(T,r*Math.cos(a),r*Math.sin(a),0);});return {nodes:nodes,edges:polyEdges(L,function(k){return pc((k/14)|0);}),spawn:function(){return sub(L);}};});mk('loopix-lambdaorbits','Traffic-class orbits by lambda',0x4d8bf0,60,undefined,function(d,T){var p=LP(d),cls=[['P',p.Lp,0x2ec4b6],['L',p.Ll,0x9b5de5],['D',p.Ld,0xff5d8f],['M',p.Lm,0xff8f3f],['G',p.Lg,0x00d2a0],['R',p.Lr,0xffd23f]],edges=[],rings=[],i,k;for(i=0;i<cls.length;i++){var r=lscale(cls[i][1]),ring=[];for(k=0;k<=48;k++){var a=PI2*k/48;ring.push(V3(T,r*Math.cos(a),(i-2.5)*2.4,r*Math.sin(a)));}rings.push(ring);edges=edges.concat(polyEdges(ring,cls[i][2]));}var nodes=spread(d,T,function(n,j,tot){var ring=rings[j%rings.length],pt=ring[(j*7)%ring.length];return pt.clone();});return {nodes:nodes,edges:edges,spawn:function(){return sub(rings[(Math.random()*rings.length)|0]);}};});
})();
