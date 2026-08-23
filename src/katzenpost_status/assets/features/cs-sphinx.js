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

function nhops(d){return ((d.layers||[]).length)||3;}
mk('sphinx-onion','Onion shells peeled per hop',0x2ec4b6,60,undefined,function(d,T){var H=nhops(d)+2,edges=[],shells=[],k;for(k=0;k<H;k++){var r=4+3*k,ring=[],j;for(j=0;j<=44;j++){var a=PI2*j/44;ring.push(V3(T,r*Math.cos(a),r*Math.sin(a)*0.6,r*Math.sin(a)));}shells.push(ring);edges=edges.concat(polyEdges(ring,pc(k)));}var nodes=spread(d,T,function(n,i){var s=shells[i%shells.length];return s[(i*7)%s.length].clone();});return {nodes:nodes,edges:edges,spawn:function(){return sub(shells[(Math.random()*shells.length)|0]);}};});mk('sphinx-headerpayload','Header / payload tube',0x4d8bf0,60,undefined,function(d,T){var H=nhops(d),N=400,L=[],i;for(i=0;i<=N;i++){var t=i/N,x=-18+36*t,seg=(t*H)|0;L.push(V3(T,x,2*Math.sin(t*PI2*H),0));}var edges=polyEdges(L,function(k){var t=k/(L.length-1);return t<0.6?0x4d8bf0:0xff8f3f;});return G.curveLayout(d,T,L,0x4d8bf0);});mk('sphinx-peelpath','Per-hop peel along path',0x9b5de5,62,undefined,function(d,T){var cols=G.columns(d),pos={},edges=[];var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:(nhops(d)+1)),x=-16+32*dp/(nhops(d)+1),r=8-1.2*dp,a=PI2*i/tot;var p=V3(T,x,Math.max(1,r)*Math.sin(a),Math.max(1,r)*Math.cos(a));pos[n.name]=p;return p;});var e;for(e=0;e<cols.length-1;e++)cols[e].forEach(function(a){cols[e+1].forEach(function(b){if(pos[a.name]&&pos[b.name])edges.push({a:pos[a.name],b:pos[b.name],color:pc(e)});});});return {nodes:nodes,edges:edges};});mk('sphinx-macchain','MAC verification chain',0xff5d8f,60,undefined,function(d,T){var H=nhops(d)+2,N=H*40,L=[],i;for(i=0;i<=N;i++){var t=i/N,a=t*PI2*H,r=10;L.push(V3(T,-16+32*t,r*Math.sin(a),r*Math.cos(a)*0.5));}return G.curveLayout(d,T,L,0xff5d8f);});
})();
