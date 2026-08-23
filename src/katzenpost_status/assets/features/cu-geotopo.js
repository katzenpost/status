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

function hasGeo(n){return n.geo&&isFinite(n.geo.lat)&&isFinite(n.geo.lon);}
function ll2v(la,lo,r,T){var ph=(90-la)*Math.PI/180,th=(lo+180)*Math.PI/180;return V3(T,-r*Math.sin(ph)*Math.cos(th),r*Math.cos(ph),r*Math.sin(ph)*Math.sin(th));}
function ipPref(n){var a=(n.details&&n.details.addresses)||[],i,s;for(i=0;i<a.length;i++){s=a[i];var p=s.indexOf('://');if(p<0)continue;s=s.slice(p+3);if(s.charAt(0)==='[')continue;var dot=s.split('.');if(dot.length>=2&&(+dot[0])>=0&&(+dot[0])<256)return dot[0]+'.'+dot[1];}return '?';}
function arc(a,b,T,n){var out=[],i;for(i=0;i<=n;i++){var t=i/n,x=a.x+(b.x-a.x)*t,y=a.y+(b.y-a.y)*t,z=a.z+(b.z-a.z)*t,m=Math.sqrt(x*x+y*y+z*z)||1,lift=1+0.4*Math.sin(Math.PI*t),r=15*lift;out.push(V3(T,x/m*r,y/m*r,z/m*r));}return out;}
mk('geo-globe','Great-circle globe arcs',0x2ec4b6,60,undefined,function(d,T){var ns=(d.nodes||[]),pos={},idx=0;var nodes=spread(d,T,function(n,i,tot){var p;if(hasGeo(n))p=ll2v(n.geo.lat,n.geo.lon,15,T);else{var a=PI2*i/tot;p=V3(T,15*Math.cos(a),0,15*Math.sin(a));}pos[n.name]=p;return p;});var cols=G.columns(d),edges=[],e;for(e=0;e<cols.length-1;e++)cols[e].forEach(function(a){cols[e+1].forEach(function(b){if(pos[a.name]&&pos[b.name]){var A=arc(pos[a.name],pos[b.name],T,14);edges=edges.concat(polyEdges(A,pc(e)));}});});return {nodes:nodes,edges:edges};});mk('geo-countries','Country clusters',0x4d8bf0,60,undefined,function(d,T){var ns=(d.nodes||[]),groups={},order=[];ns.forEach(function(n){var c=(n.geo&&n.geo.label)?n.geo.label:'?';if(!groups[c]){groups[c]=[];order.push(c);}groups[c].push(n);});var pos={};var nodes=spread(d,T,function(n){var c=(n.geo&&n.geo.label)?n.geo.label:'?',gi=order.indexOf(c),a=PI2*gi/order.length,R=14,gp=groups[c],j=gp.indexOf(n),aa=PI2*j/gp.length,rr=4;var p=V3(T,R*Math.cos(a)+rr*Math.cos(aa),rr*Math.sin(aa),R*Math.sin(a));pos[n.name]=p;return p;});var edges=[];order.forEach(function(c,gi){var gp=groups[c],k;for(k=0;k<gp.length;k++)for(var l=k+1;l<gp.length;l++)edges.push({a:pos[gp[k].name],b:pos[gp[l].name],color:pc(gi)});});return {nodes:nodes,edges:edges};});
})();
