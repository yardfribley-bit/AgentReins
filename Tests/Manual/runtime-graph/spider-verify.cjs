'use strict';
const assert=require('node:assert/strict');
const runtime=require('../../../Sources/AgentReins/Resources/RealtimeWorkspace/runtime-graph.js');
const spider=require('../../../Sources/AgentReins/Resources/RealtimeWorkspace/spider-graph.js');
const intersects=(a,b)=>a.x<b.x+b.w&&a.x+a.w>b.x&&a.y<b.y+b.h&&a.y+a.h>b.y;
const near=(a,b)=>Math.abs(a-b)<.001;
function onBoundary(p,n){return p.x>=n.x-.001&&p.x<=n.x+n.w+.001&&p.y>=n.y-.001&&p.y<=n.y+n.h+.001&&(near(p.x,n.x)||near(p.x,n.x+n.w)||near(p.y,n.y)||near(p.y,n.y+n.h));}
function verify(g){
 const before=JSON.stringify(g),p=spider.layout(g);
 assert.equal(JSON.stringify(g),before,'layout mutates its source');
 assert.deepEqual(p.nodes.map(n=>n.key),g.nodes.map(n=>n.key),'node key lost');
 assert.deepEqual(p.edges.map(e=>e.key),g.edges.map(e=>e.key),'edge key lost');
 assert.strictEqual(p.objects,g.objects,'detail/evidence objects must retain identity');
 assert.equal(p.currentKey,g.currentKey);
 for(const [i,n] of p.nodes.entries()){
  assert(n.x>=0&&n.y>=0&&n.x+n.w<=p.width&&n.y+n.h<=p.height,'node outside viewport');
  for(const other of p.nodes.slice(i+1))assert(!intersects(n,other),`node overlap: ${n.key} / ${other.key}`);
 }
 const byKey=new Map(p.nodes.map(n=>[n.key,n]));
 const labels=[];
 for(const [i,e] of p.edges.entries()){
  const original=g.edges[i];assert.equal(e.from,original.from);assert.equal(e.to,original.to);
  assert.equal(e.independent,original.independent,'confirmation semantics changed');
  assert.equal(e.revision,original.revision,'evidence revision changed');
  assert.equal(e.label,original.label,'evidence label changed');
  assert(byKey.has(e.from)&&byKey.has(e.to),'edge endpoint node missing');
  const coordinates=e.path.match(/-?\d+(?:\.\d+)?/g).map(Number);
  assert.equal(coordinates.length,8,'edge must remain a single cubic path');
  assert(onBoundary({x:coordinates[0],y:coordinates[1]},byKey.get(e.from)),'start is not on source rectangle');
  assert(onBoundary({x:coordinates[6],y:coordinates[7]},byKey.get(e.to)),'end is not on destination rectangle');
  const label={x:e.x-5,y:e.y-16,w:Math.min(240,Array.from(e.label||'').length*12+12),h:24};
  assert(!p.nodes.some(n=>intersects(label,n)),`label overlaps node: ${e.key}`);
  assert(!labels.some(l=>intersects(label,l)),`labels overlap: ${e.key}`);labels.push(label);
 }
 assert.deepEqual(spider.layout(g),p,'layout must be deterministic');
 return p;
}
const tool={id:'call:search',call:'search',title:'WebSearch',detailType:'web',phase:'returned',output:'实际结果',eventIDs:['return-event']};
const task={id:'task',agent:'WorkBuddy',session:'session',turn:'turn',originalRequest:'研究开源项目',requestEventID:'human-event',lifecycleStatus:'completed',currentCardID:'end-event',cards:[tool,
 {id:'env',title:'环境',detailType:'environment',phase:'recorded'},
 {id:'plan',title:'计划',detailType:'plan',phase:'recorded'},
 {id:'memory',title:'记忆访问',detailType:'memory',phase:'recorded'},
 {id:'approval',title:'确认',detailType:'approval',phase:'waiting'},
 {id:'net',title:'网络',detailType:'network',phase:'recorded'}]};
const first={id:'request-1',structured:true,timestamp:'2026-10-09T09:00:00Z',responseID:'response-1',blocks:[{role:'user',content:task.originalRequest}],toolInstructions:JSON.stringify({tool_calls:[{id:'search',name:'WebSearch'}]})};
const next={id:'request-2',structured:true,timestamp:'2026-10-09T09:00:03Z',responseID:'response-2',blocks:[{role:'tool',content:'实际结果',callID:'search',toolEvidenceIDs:['return-event']}]};
const g=runtime.build({task,contexts:[first,next],exchangeID:first.id,artifacts:[{id:'report',name:'报告.md',exists:true}],processes:[{id:'process',agent:'WorkBuddy',active:true}]});
const p=verify(g);
assert.equal(p.nodes.length,13,'all diagram roles should exist in the comprehensive fixture');
const model=p.nodes.find(n=>n.key==='model');assert.equal(model.x+model.w/2,p.width/2,'model must be horizontally centered');
assert(p.edges.some(e=>e.key==='result-context'&&!e.independent));
verify(runtime.build({task:{...task,lifecycleStatus:'running'},contexts:[]}));
verify(runtime.build({task:null,contexts:[],processes:[]}));
const future={...g,nodes:[...g.nodes,{key:'future-detail',x:0,y:0,w:250,h:110,title:'未来证据节点'}]};
verify(future);
const compact=verify({...g,nodes:g.nodes.filter(n=>!['memory','approval','environment','plan'].includes(n.key))});
for(const n of compact.nodes){const original=p.nodes.find(old=>old.key===n.key);assert.equal(n.x,original.x);assert.equal(n.y,original.y,'optional nodes must not shift surviving nodes');}
const uncertain={...g,edges:g.edges.map((e,i)=>({...e,independent:i===0?true:e.independent}))};verify(uncertain);
const fs=require('node:fs');
const field='/private/tmp/agentreins-workbuddy-field-ui/actual-workbuddy-payload.json';
if(fs.existsSync(field)){
 const payload=JSON.parse(fs.readFileSync(field,'utf8'));
 for(const t of payload.tasks){
  const contexts=payload.contexts.filter(c=>c.agent===t.agent&&c.session===t.session&&c.turn===t.turn);
  const args={task:t,contexts,processes:payload.processes,artifacts:payload.artifacts.filter(a=>a.taskID===t.id)};
  verify(runtime.build(args));for(const c of contexts)verify(runtime.build({...args,exchangeID:c.id}));
 }
 console.log('PASS actual WorkBuddy projection: node/edge identity, evidence objects, geometry and labels preserved');
}
console.log('PASS spider graph: pure deterministic layout, all 13 roles, unknown-node retention, stable slots, center model, no rectangle/label overlap, matching edge boundaries, unchanged transfer evidence');

const relations=runtime.buildRelations({task,contexts:[first,next],exchangeID:first.id,artifacts:[{id:'report',name:'报告.md',exists:true}],processes:[{id:'process',agent:'WorkBuddy',active:true}]});
const radial=spider.layout(relations);
assert(radial.relationships);assert(!radial.architecture);
assert(radial.nodes.some(n=>n.key==='card:'+tool.id));
assert(!radial.nodes.some(n=>n.key==='approval'));
assert(!radial.nodes.some(n=>['perception','direct','mcp','api','code','database','external'].includes(n.key)));
assert(radial.objects.some(o=>o.key==='result-context'));
for(const [i,n] of radial.nodes.entries())for(const other of radial.nodes.slice(i+1))assert(!intersects(n,other),'Radial node overlap');
assert.equal(radial.nodes.find(n=>n.shape==='hub').x+radial.nodes.find(n=>n.shape==='hub').w/2,radial.width/2);
assert(radial.edges.some(e=>e.key==='call:'+tool.id&&!e.independent));
const many={...task,cards:Array.from({length:20},(_,i)=>({...tool,id:'call:tool-'+i,call:'tool-'+i,title:'工具 '+i}))};
const dense=runtime.buildRelations({task:many,contexts:[]});assert.equal(dense.shownCallCount,6);assert.equal(dense.hiddenCallCount,14);
assert.equal(dense.objects.find(o=>o.key==='other-calls').data.cards.length,14);
assert(dense.edges.filter(e=>e.key.startsWith('call:')).every(e=>e.independent),'Missing model capture must not invent a model instruction');
console.log('PASS distinct spider relations: actual tool nodes, preserved transfer details, radial hub, no empty architecture modules, collapsed calls retain all evidence');
