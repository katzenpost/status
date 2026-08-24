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

function pipeEdgesA(d,pos,color){var cols=G.columns(d),e=[],i;for(i=0;i<cols.length-1;i++){cols[i].forEach(function(a){cols[i+1].forEach(function(b){if(pos[a.name]&&pos[b.name])e.push({a:pos[a.name],b:pos[b.name],color:(typeof color==='function')?color(i):color});});});}return e;}
mk('adv-gpa','Global passive adversary',0xff5d6c,62,undefined,function(d,T){var ns=(d.nodes||[]),pos={};var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:4),x=-16+8*dp,a=PI2*i/tot;var p=V3(T,x,10*Math.sin(a),10*Math.cos(a));pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdgesA(d,pos,0xff5d6c)};});
})();
