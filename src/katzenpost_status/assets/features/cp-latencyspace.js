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

function nlayers(d){return ((d.layers||[]).length)||3;}
function depthOf(d,n){var L=nlayers(d);if(num(n.hop_count,0)>0)return n.hop_count;if(n.type==='gateway')return 0;if(n.type==='mix')return num(n.layer,0)+1;if(n.type==='service')return L+1;if(n.type==='storage')return L+2;return 0;}
function maxDepth(d){var m=1;(d.nodes||[]).forEach(function(n){var v=depthOf(d,n);if(v>m)m=v;});return m;}
function pipeEdges(d,pos){var cols=G.columns(d),e=[],i;for(i=0;i<cols.length-1;i++){cols[i].forEach(function(a){cols[i+1].forEach(function(b){if(pos[a.name]&&pos[b.name])e.push({a:pos[a.name],b:pos[b.name],color:pc(i)});});});}return e;}
mk('lat-radial','Hop-depth radial rings',0x2ec4b6,58,false,function(d,T){var ns=(d.nodes||[]),pos={},md=maxDepth(d),byd={};ns.forEach(function(n){var dp=depthOf(d,n);(byd[dp]=byd[dp]||[]).push(n);});var nodes=spread(d,T,function(n){var dp=depthOf(d,n),grp=byd[dp],idx=grp.indexOf(n),a=PI2*idx/grp.length,r=2+18*dp/md;var p=V3(T,r*Math.cos(a),r*Math.sin(a),0);pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdges(d,pos)};});mk('lat-buckets','Latency / depth buckets',0x4d8bf0,60,undefined,function(d,T){var ns=(d.nodes||[]),pos={},md=maxDepth(d);var nodes=spread(d,T,function(n,i){var dp=depthOf(d,n),lat=num(n.latency_ms,null),band=lat!=null?Math.min(4,(lat/50)|0):dp;var a=PI2*i/(ns.length||1),r=5+3*band;var p=V3(T,r*Math.cos(a),(band-2)*4,r*Math.sin(a));pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdges(d,pos)};});mk('lat-spiral','RTT-ordered spiral',0x9b5de5,60,undefined,function(d,T){var ns=(d.nodes||[]).slice().sort(function(a,b){return (num(a.latency_ms,depthOf(d,a)*100))-(num(b.latency_ms,depthOf(d,b)*100));}),pos={};var nodes=[],i;for(i=0;i<ns.length;i++){var t=ns.length<=1?0:i/(ns.length-1),a=t*PI2*3,r=3+16*t;var p=V3(T,r*Math.cos(a),(t-0.5)*16,r*Math.sin(a));pos[ns[i].name]=p;nodes.push({name:ns[i].name,type:ns[i].type,pos:p});}var e=[];for(i=0;i+1<ns.length;i++)e.push({a:pos[ns[i].name],b:pos[ns[i+1].name],color:pc(i)});return {nodes:nodes,edges:e};});mk('lat-pathbundle','Traceroute path bundles',0xff8f3f,62,undefined,function(d,T){var ns=(d.nodes||[]),pos={},md=maxDepth(d);var nodes=spread(d,T,function(n,i){var dp=depthOf(d,n),x=-18+36*dp/md,a=PI2*i/(ns.length||1);var p=V3(T,x,10*Math.sin(a),10*Math.cos(a));pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdges(d,pos)};});
})();
