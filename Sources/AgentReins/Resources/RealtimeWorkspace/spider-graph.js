'use strict';
/* Layout only: node identities, transfer evidence and uncertainty stay unchanged. */
((root)=>{
 const array=value=>Array.isArray(value)?value:[];
 const slots={user:[1,0],environment:[0,0],context:[2,0],approval:[0,1],
  model:[1,2],agent:[1,2],plan:[0,2],'tool-result':[2,2],
  memory:[0,3],'next-context':[2,3],observation:[0,4],closure:[1,4],artifact:[2,4]};
 const rect=n=>({x:n.x,y:n.y,w:n.w||240,h:n.h||112});
 const overlaps=(a,b,pad=0)=>a.x<b.x+b.w+pad&&a.x+a.w+pad>b.x&&a.y<b.y+b.h+pad&&a.y+a.h+pad>b.y;
 function endpoint(a,b){
  const ac={x:a.x+a.w/2,y:a.y+a.h/2},bc={x:b.x+b.w/2,y:b.y+b.h/2};
  const dx=bc.x-ac.x,dy=bc.y-ac.y;
  if(Math.abs(dx)/(a.w/2)>=Math.abs(dy)/(a.h/2))return {x:dx>=0?a.x+a.w:a.x,y:ac.y,axis:'x'};
  return {x:ac.x,y:dy>=0?a.y+a.h:a.y,axis:'y'};
 }
 function curve(a,b){
  const start=endpoint(a,b),end=endpoint(b,a);
  let c1,c2;
  if(start.axis==='x'&&end.axis==='x'){
   const middle=(start.x+end.x)/2;c1={x:middle,y:start.y};c2={x:middle,y:end.y};
  }else if(start.axis==='y'&&end.axis==='y'){
   const middle=(start.y+end.y)/2;c1={x:start.x,y:middle};c2={x:end.x,y:middle};
  }else{
   c1=start.axis==='x'?{x:(start.x+end.x)/2,y:start.y}:{x:start.x,y:(start.y+end.y)/2};
   c2=end.axis==='x'?{x:(start.x+end.x)/2,y:end.y}:{x:end.x,y:(start.y+end.y)/2};
  }
  return {start,end,c1,c2,path:`M${start.x} ${start.y} C${c1.x} ${c1.y} ${c2.x} ${c2.y} ${end.x} ${end.y}`,
   midpoint:{x:(start.x+3*c1.x+3*c2.x+end.x)/8,y:(start.y+3*c1.y+3*c2.y+end.y)/8}};
 }
 function labelPosition(edge,route,nodes,occupied,width,height){
  // flow.js uses a 24px label hit box with a conservative 12px per character.
  const labelWidth=Math.min(240,Array.from(String(edge.label||'')).length*12+12),p=route.midpoint;
  const offsets=[];
  for(const dy of [-12,22,-42,52,-72,82,-102,112])
   for(const dx of [8,-labelWidth-8,-labelWidth/2,-labelWidth/2-50,-labelWidth/2+50])offsets.push([dx,dy]);
  for(const [dx,dy] of offsets){
   const x=Math.max(12,Math.min(width-labelWidth-12,p.x+dx)),y=Math.max(28,Math.min(height-16,p.y+dy));
   const box={x:x-5,y:y-16,w:labelWidth,h:24};
   if(!nodes.some(n=>overlaps(box,n,8))&&!occupied.some(r=>overlaps(box,r,5))){occupied.push(box);return {x,y};}
  }
  // Reserved center-column gaps remain available if several transfer labels meet.
  for(let y=28;y<height-16;y+=30)for(let x=12;x<width-labelWidth-12;x+=24){
   const box={x:x-5,y:y-16,w:labelWidth,h:24};
   if(!nodes.some(n=>overlaps(box,n,8))&&!occupied.some(r=>overlaps(box,r,5))){occupied.push(box);return {x,y};}
  }
  return {x:12,y:28};
 }
 function overview(g={}){
  if(!g.architecture){
   const source=array(g.nodes),center=source.find(n=>n.shape==='hub')||source[0],outer=source.filter(n=>n!==center),width=1360,height=650;
   const nodes=source.map(n=>{const w=n===center?240:210,h=n===center?120:84;if(n===center)return {...n,w,h,x:width/2-w/2,y:height/2-h/2};const angle=-Math.PI/2+outer.indexOf(n)*Math.PI*2/Math.max(1,outer.length);return {...n,w,h,x:width/2+525*Math.cos(angle)-w/2,y:height/2+245*Math.sin(angle)-h/2};});
   return routeOverview(g,nodes,width,height);
  }
  const locations={user:[360,8,260,64],perception:[360,88,260,64],model:[360,165,260,85],context:[738,95,245,140],plan:[55,180,245,100],direct:[386,267,208,65],reply:[758,270,205,65],action:[360,350,260,75],closure:[762,350,200,75],mcp:[142,451,118,62],api:[281,451,118,62],code:[420,451,118,62],database:[559,451,118,62],files:[698,451,118,62],external:[837,451,118,62],observation:[145,532,812,60]};
  return routeOverview(g,array(g.nodes).map(n=>{const [x,y,w,h]=locations[n.key]||[n.x,n.y,n.w,n.h];return {...n,x,y,w,h};}),1000,600);
 }
 function routeOverview(g,nodes,width,height){const byKey=new Map(nodes.map(n=>[n.key,rect(n)]));return {...g,nodes,width,height,overview:true,edges:array(g.edges).map(e=>{const from=byKey.get(e.from),to=byKey.get(e.to);if(!from||!to)return e;const route=curve(from,to);return {...e,path:route.path,x:route.midpoint.x,y:route.midpoint.y};})};}
 function layout(g={}){
  if(g.relationships){
   const source=array(g.nodes),center=source.find(n=>n.shape==='hub')||source[0],outer=source.filter(n=>n!==center),byKey=new Map();let radius=Math.max(470,outer.length*40),nodes,width,height;
   for(let attempt=0;attempt<12;attempt++){
    width=2*radius+340;height=2*radius+280;
    const cx=width/2,cy=height/2;
    nodes=source.map(n=>{if(n===center)return {...n,x:cx-(n.w||250)/2,y:cy-(n.h||140)/2};const i=outer.indexOf(n),angle=-Math.PI/2+i*2*Math.PI/Math.max(1,outer.length);return {...n,x:cx+radius*Math.cos(angle)-(n.w||230)/2,y:cy+radius*Math.sin(angle)-(n.h||112)/2};});
    if(!nodes.some((n,i)=>nodes.slice(i+1).some(other=>overlaps(rect(n),rect(other),24))))break;radius*=1.15;
   }
   nodes.forEach(n=>byKey.set(n.key,rect(n)));const labels=[];
   const edges=array(g.edges).map(e=>{const a=byKey.get(e.from),b=byKey.get(e.to);if(!a||!b)return e;const route=curve(a,b),label=e.label?labelPosition(e,route,nodes.map(rect),labels,width,height):{x:0,y:0};return {...e,path:route.path,...label};});
   return {...g,nodes,edges,width,height};
  }
  if(g.architecture){
   const locations={model:[385,400,245,170],user:[373,30,250,110],perception:[38,65,230,120],context:[735,85,245,280],plan:[35,335,240,180],direct:[705,415,240,110],reply:[735,825,245,105],action:[705,595,255,175],closure:[385,675,245,135],observation:[260,985,720,90],mcp:[280,860,105,68],api:[395,860,105,68],code:[510,860,105,68],database:[625,860,105,68],files:[140,810,125,80],external:[25,810,105,80]};
   const nodes=array(g.nodes).map(n=>{const [x,y,w,h]=locations[n.key]||[n.x,n.y,n.w,n.h];return {...n,x,y,w,h};});
   const byKey=new Map(nodes.map(n=>[n.key,rect(n)]));
   const occupied=[];
   const edges=array(g.edges).map(e=>{const a=byKey.get(e.from),b=byKey.get(e.to);if(!a||!b)return {...e};
    const ac={x:a.x+a.w/2,y:a.y+a.h/2},bc={x:b.x+b.w/2,y:b.y+b.h/2},dx=bc.x-ac.x,dy=bc.y-ac.y;
    const f=Math.min((a.w/2)/Math.abs(dx||.001),(a.h/2)/Math.abs(dy||.001)),fb=Math.min((b.w/2)/Math.abs(dx||.001),(b.h/2)/Math.abs(dy||.001));
    const sx=ac.x+dx*f,sy=ac.y+dy*f,tx=bc.x-dx*fb,ty=bc.y-dy*fb;
    const route={midpoint:{x:(sx+tx)/2,y:(sy+ty)/2}};
    const label=e.label?labelPosition(e,route,nodes.map(rect),occupied,1000,1110):{x:0,y:0};
    return {...e,path:`M${sx} ${sy}L${tx} ${ty}`,...label};});
   return {...g,nodes,edges,width:1000,height:1110};
  }

  const sourceNodes=array(g.nodes),maxWidth=Math.max(250,...sourceNodes.map(n=>n.w||240)),maxHeight=Math.max(140,...sourceNodes.map(n=>n.h||112));
  const width=Math.max(1250,maxWidth*3+160),rowGap=maxHeight+60;
  const centers=[40+maxWidth/2,width/2,width-40-maxWidth/2],positions=new Map(),used=new Set();
  const primaryTool=sourceNodes.find(n=>String(n.key).startsWith('card:'))?.key;
  const centerKey=sourceNodes.some(n=>n.key==='model')?'model':'agent';
  const known=sourceNodes.filter(n=>slots[n.key]&&!(n.key==='agent'&&centerKey==='model')||n.key===primaryTool);
  for(const n of known){
   const slot=n.key===primaryTool?[2,1]:slots[n.key],slotKey=slot.join(':');
   if(!used.has(slotKey)){positions.set(n.key,slot);used.add(slotKey);}
  }
  // Future projection nodes remain present; stable key order fills extra outer rows.
  let extra=0;
  for(const n of sourceNodes.filter(n=>!positions.has(n.key)).slice().sort((a,b)=>String(a.key).localeCompare(String(b.key)))){
   positions.set(n.key,[extra%3,5+Math.floor(extra/3)]);extra++;
  }
  const nodes=sourceNodes.map(n=>{const [col,row]=positions.get(n.key);return {...n,x:centers[col]-(n.w||240)/2,y:25+row*rowGap};});
  const height=Math.max(1000,...nodes.map(n=>n.y+(n.h||112)+35)),byKey=new Map(nodes.map(n=>[n.key,rect(n)]));
  const nodeRects=nodes.map(rect),labels=[];
  const edges=array(g.edges).map(e=>{
   const from=byKey.get(e.from),to=byKey.get(e.to);
   if(!from||!to)return {...e};
   const route=curve(from,to),label=labelPosition(e,route,nodeRects,labels,width,height);
   return {...e,path:route.path,...label};
  });
  return {...g,nodes,edges,objects:g.objects,currentKey:g.currentKey,width,height};
 }
 const api={layout,overview};root.AgentReinsSpiderGraph=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
