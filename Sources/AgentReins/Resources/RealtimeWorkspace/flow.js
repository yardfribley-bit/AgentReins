'use strict';
/* The graph renders only evidence-backed nodes supplied by the task projection. */
(()=>{
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cut=(s,n)=>esc(Array.from(String(s??'')).slice(0,n).join(''));
let lastScope=null,known=new Map(),seeded=false;
function render({scope,nodes=[],edges=[],selectedKey,currentKey,paused,onSelect}){
 if(scope!==lastScope){lastScope=scope;known=new Map();seeded=false;}
 const changed=nodes.filter(n=>known.get(n.key)!==n.revision);
 const pulse=seeded&&!paused?changed.at(-1):null;
 const pulseEdge=pulse?edges.findLast(e=>e.to===pulse.key||e.from===pulse.key):null;
 nodes.forEach(n=>known.set(n.key,n.revision));seeded=true;
 const host=document.getElementById('graph');
 host.innerHTML=`<svg viewBox="0 0 900 600" role="group" aria-label="实时任务节点与数据传递"><defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#b0a7cd"/></marker></defs>${edges.map(e=>`<g class="flow-edge ${selectedKey===e.key?'selected':''}" data-flow-edge="${esc(e.key)}" data-edge="${esc(e.key)}" role="button" tabindex="0" aria-label="${esc(e.label)}"><path class="edge-hit" d="${e.path}"/><path class="edge ${e.independent?'independent':''}" d="${e.path}" ${e.independent?'':'marker-end="url(#flow-arrow)"'}/><rect class="flow-label-hit" x="${e.x-5}" y="${e.y-13}" width="${Math.min(170,Array.from(e.label).length*9+12)}" height="19" rx="4"/><text class="edge-label" x="${e.x}" y="${e.y}">${cut(e.label,18)}</text></g>`).join('')}${pulseEdge?`<circle class="packet" r="4"><animateMotion dur="1.1s" repeatCount="1" fill="remove" path="${pulseEdge.path}"/></circle>`:''}${nodes.map(n=>`<g class="svg-node ${n.center?'center':''} ${selectedKey===n.key?'selected':''} ${currentKey===n.key?'current':''}" data-flow-node="${esc(n.key)}" role="button" tabindex="0" aria-label="${esc(n.title+'，'+n.subtitle)}" transform="translate(${n.x},${n.y})"><rect width="166" height="77" rx="9"/><text class="node-tag" x="13" y="20">${cut(n.tag,15)}</text><text class="node-name" x="13" y="43">${cut(n.title,13)}</text><text class="node-sub" x="13" y="63">${cut(n.subtitle,15)}</text></g>`).join('')}</svg>`;
 for(const el of host.querySelectorAll('[data-flow-node],[data-flow-edge]')){
  const key=el.dataset.flowNode||el.dataset.flowEdge;
  const choose=()=>onSelect(key);
  el.onclick=choose;el.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose();}};
 }
}
window.AgentReinsFlow={render};
})();
