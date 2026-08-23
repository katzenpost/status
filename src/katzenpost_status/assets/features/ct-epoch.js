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

function EP(d){var C=(d.consensus||{});var ep=num(C.epoch,num(d.epoch,0)),gen=num(C.genesis_epoch,ep-8);return {ep:ep,gen:gen,span:Math.max(1,ep-gen)};}
function mkeys(n){return (n.details&&n.details.mixkey_epochs)||[];}
mk('epoch-timeline','Mixkey-epoch ribbons',0x2ec4b6,60,undefined,function(d,T){var e=EP(d),ns=(d.nodes||[]),edges=[],pos={};var nodes=spread(d,T,function(n,i,tot){var y=(i-(tot-1)/2)*(28/Math.max(1,tot));var ks=mkeys(n),x0=-16,x1=16;if(ks.length){var lo=Math.min.apply(null,ks),hi=Math.max.apply(null,ks);x0=cl(-16+32*((lo-e.gen)/e.span));x1=cl(-16+32*((hi-e.gen)/e.span));}var p=V3(T,(x0+x1)/2,y,0);edges.push({a:V3(T,x0,y,0),b:V3(T,x1,y,0),color:pc(i)});pos[n.name]=p;return p;});return {nodes:nodes,edges:edges};});
})();
