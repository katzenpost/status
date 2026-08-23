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

function pipe(d,T,opt){opt=opt||{};var cols=G.columns(d),nc=cols.length,X=num(opt.X,18);var nodes=[],cp=[],ci,j;
 for(ci=0;ci<nc;ci++){var c=cols[ci],x=nc<=1?0:(-X+2*X*ci/(nc-1)),arr=[];
  for(j=0;j<c.length;j++){var n=c.length,fr=n<=1?0.5:j/(n-1),yz=opt.place?opt.place(ci,j,n,fr):[(fr-0.5)*24,0];
   var p=V3(T,x,yz[0],yz[1]);arr.push(p);nodes.push({name:c[j].name,type:c[j].type,pos:p});}
  cp.push(arr);}
 var edges=[],e,ia,ib;
 for(e=0;e<nc-1;e++){var A=cp[e],B=cp[e+1],color=opt.color!=null?opt.color:pc(e);
  if(opt.edge==='matched'){var m=Math.max(A.length,B.length);for(ia=0;ia<m&&A.length&&B.length;ia++)edges.push({a:A[ia%A.length],b:B[ia%B.length],color:color});}
  else{for(ia=0;ia<A.length;ia++)for(ib=0;ib<B.length;ib++)edges.push({a:A[ia],b:B[ib],color:color});}}
 if(opt.after)opt.after(nodes,edges,cp,T,d);
 return {nodes:nodes,edges:edges};}

function pRing(ci,j,n){var a=n<=1?0:PI2*j/n;return [11*Math.sin(a),11*Math.cos(a)];}
function pFan(ci,j,n,fr){var a=(fr-0.5)*Math.PI*0.85;return [12*Math.sin(a),0];}
function pHelix(ci,j,n,fr){var a=ci*1.05+fr*0.6;return [11*Math.sin(a),11*Math.cos(a)];}
function pStag(ci,j,n,fr){return [(fr-0.5)*24,(ci%2?5:-5)];}
mk('mix-strata','Stratified mix DAG',0x2ec4b6,62,undefined,function(d,T){return pipe(d,T,{});});mk('mix-cascade','Cascade columns',0x4d8bf0,62,undefined,function(d,T){return pipe(d,T,{edge:'matched'});});mk('mix-fanout','Layer fan-out',0x9b5de5,60,undefined,function(d,T){return pipe(d,T,{place:pFan});});mk('mix-helix','Pipeline helix',0xff8f3f,64,undefined,function(d,T){return pipe(d,T,{place:pHelix});});mk('mix-dag3d','Staggered 3D DAG',0xd2a0,62,undefined,function(d,T){return pipe(d,T,{place:pStag});});mk('mix-layerrings','Per-column layer rings',0x33ccff,60,undefined,function(d,T){return pipe(d,T,{place:pRing});});
})();
