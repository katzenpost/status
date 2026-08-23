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

function widths(d){var L=(d.layers||[]);if(L.length)return L.map(function(a){return a.length||1;});return [2,2,2];}
function anonSet(w,k){var p=1,i;for(i=0;i<=k&&i<w.length;i++)p*=w[i];return p;}
mk('anon-setcone','Anonymity-set growth cone',0x2ec4b6,62,undefined,function(d,T){var w=widths(d),nl=w.length,pos={},edges=[];var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:nl+1),k=Math.min(nl,dp),setsz=anonSet(w,k-1),r=2+3*Math.log(1+setsz),a=PI2*i/tot,x=-16+32*dp/(nl+1);var p=V3(T,x,r*Math.sin(a),r*Math.cos(a));pos[n.name]=p;return p;});var cols=G.columns(d),e;for(e=0;e<cols.length-1;e++)cols[e].forEach(function(a){cols[e+1].forEach(function(b){if(pos[a.name]&&pos[b.name])edges.push({a:pos[a.name],b:pos[b.name],color:pc(e)});});});return {nodes:nodes,edges:edges};});mk('anon-fanout','Mixing fan-out tree',0x4d8bf0,62,undefined,function(d,T){var w=widths(d),nl=w.length,pos={},edges=[];var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:nl+1),spr=3+dp*5,a=PI2*i/tot;var p=V3(T,(dp-nl/2)*7,spr*Math.sin(a),spr*Math.cos(a));pos[n.name]=p;return p;});var cols=G.columns(d),e;for(e=0;e<cols.length-1;e++)cols[e].forEach(function(a){cols[e+1].forEach(function(b){if(pos[a.name]&&pos[b.name])edges.push({a:pos[a.name],b:pos[b.name],color:pc(e)});});});return {nodes:nodes,edges:edges};});mk('anon-entropyshells','Entropy shells (log2 set)',0x9b5de5,58,undefined,function(d,T){var w=widths(d),nl=w.length,edges=[],shells=[],k;for(k=0;k<nl;k++){var H=Math.log(anonSet(w,k))/Math.log(2),r=3+3*H,ring=[],j;for(j=0;j<=40;j++){var a=PI2*j/40;ring.push(V3(T,r*Math.cos(a),(k-nl/2)*4,r*Math.sin(a)));}shells.push(ring);edges=edges.concat(polyEdges(ring,pc(k)));}var nodes=spread(d,T,function(n,i,tot){var s=shells[i%shells.length];return s[(i*5)%s.length].clone();});return {nodes:nodes,edges:edges,spawn:function(){return sub(shells[(Math.random()*shells.length)|0]);}};});
})();
