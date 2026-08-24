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

mk('flow-field','Gateway to service flow field',0x2ec4b6,62,undefined,function(d,T){return pipe(d,T,{color:0x2ec4b6});});mk('flow-torus','Throughput torus',0x4d8bf0,60,undefined,function(d,T){var R=12,rr=5,N=800,L=[],i,loops=5;for(i=0;i<=N;i++){var t=i/N,u=t*PI2*loops,v=t*PI2;L.push(V3(T,(R+rr*Math.cos(v))*Math.cos(u),rr*Math.sin(v),(R+rr*Math.cos(v))*Math.sin(u)));}return G.curveLayout(d,T,L,0x4d8bf0);});mk('flow-congestion','Congestion height-field',0x9b5de5,62,undefined,function(d,T){return pipe(d,T,{place:function(ci,j,n,fr){return [(fr-0.5)*20,6*Math.sin(fr*PI2)*Math.sin(ci)];}});});
})();
