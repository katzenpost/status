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
mk('adv-gpa','Global passive adversary',0xff5d6c,62,undefined,function(d,T){var ns=(d.nodes||[]),pos={};var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:4),x=-16+8*dp,a=PI2*i/tot;var p=V3(T,x,10*Math.sin(a),10*Math.cos(a));pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdgesA(d,pos,0xff5d6c)};});mk('adv-compromised','Compromised-fraction highlight',0xff8f3f,62,undefined,function(d,T){var ns=(d.nodes||[]),pos={};var nodes=spread(d,T,function(n,i,tot){var dp=(n.type==='gateway')?0:(n.type==='mix'?num(n.layer,0)+1:4),x=-16+8*dp,a=PI2*i/tot;var p=V3(T,x,10*Math.sin(a),10*Math.cos(a));pos[n.name]=p;return p;});return {nodes:nodes,edges:pipeEdgesA(d,pos,function(e){return ((e%3)===0)?0xff5d6c:0x2ec4b6;})};});mk('adv-timingcorr','Timing-correlation arcs',0x9b5de5,62,undefined,function(d,T){var ns=(d.nodes||[]),gw=ns.filter(function(n){return n.type==='gateway';}),svc=ns.filter(function(n){return n.type==='service';}),pos={};var nodes=spread(d,T,function(n,i,tot){var isg=n.type==='gateway',iss=n.type==='service',x=isg?-16:(iss?16:0),a=PI2*i/tot;var p=V3(T,x,10*Math.sin(a),10*Math.cos(a));pos[n.name]=p;return p;});var edges=[];gw.forEach(function(g){svc.forEach(function(s){edges.push({a:pos[g.name],b:pos[s.name],color:0x9b5de5});});});return {nodes:nodes,edges:edges,spawn:function(){if(!gw.length||!svc.length)return null;return [pos[gw[(Math.random()*gw.length)|0].name],pos[svc[(Math.random()*svc.length)|0].name]];}};});mk('adv-nminus1','n-1 attack focus',0xffd23f,60,undefined,function(d,T){var ns=(d.nodes||[]),mixes=ns.filter(function(n){return n.type==='mix';}),target=mixes[0]||ns[0],pos={},tp=V3(T,0,0,0);var nodes=spread(d,T,function(n,i,tot){if(n===target){pos[n.name]=tp;return tp;}var a=PI2*i/tot,side=(i%2)?1:-1,r=14;var p=V3(T,side*10,r*Math.sin(a)*0.7,r*Math.cos(a)*0.7);pos[n.name]=p;return p;});var edges=[];ns.forEach(function(n){if(n!==target&&pos[n.name])edges.push({a:tp,b:pos[n.name],color:(n.type==='gateway')?0x2ec4b6:0xff8f3f});});return {nodes:nodes,edges:edges,spawn:function(){var k=ns[(Math.random()*ns.length)|0];return (k&&k!==target)?[pos[k.name],tp]:null;}};});
})();
