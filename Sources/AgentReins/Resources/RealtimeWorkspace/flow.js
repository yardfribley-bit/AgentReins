'use strict';
(()=>{
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short=(s,n)=>esc(Array.from(String(s??'')).slice(0,n).join(''));
let scope=null,selection=null,frozen=null,known=new Map(),seeded=false;
const $=id=>document.getElementById(id);
function phase(t){
 if(!t)return {label:'等待新任务',node:'agent'};
 if(t.reportedComplete)return {label:'已完成 · Agent 已报告结果',node:'agent'};
 const waiting=t.cards.findLast(c=>c.tag==='等待授权 / 已阻塞');
 if(waiting)return {label:'等你确认 · '+waiting.title,node:waiting.id};
 const running=t.cards.findLast(c=>c.status==='running'&&c.kind!=='model');
 if(running)return {label:'等待 '+running.title+' 返回',node:running.id};
 const latest=t.cards.filter(c=>c.kind!=='process').at(-1);
 if(latest?.tag==='执行失败')return {label:'执行失败 · '+latest.title,node:latest.id};
 if(latest?.status==='running'||latest?.title==='Agent → 大模型')return {label:'等待大模型响应',node:'model'};
 return {label:'已收到模型返回 · 等待后续执行证据',node:'agent'};
}
function render({task:t,agent,contexts=[],processes=[],collected=[],paused,showDetail,onInspect}){
 const newScope=agent+':'+(t?.id||'none');if(scope!==newScope){scope=newScope;selection=null;frozen=null;known=new Map();seeded=false;}
 const context=contexts.filter(c=>c.agent===agent&&c.session===t?.session&&c.turn===t?.turn).at(-1);
 const cards=t?.cards||[],tools=cards.filter(c=>c.call&&['command','tool','mcp','skill','files','web'].includes(c.kind)),shownTools=tools.slice(-4);
 const processRows=processes.filter(p=>p.agent===agent),records=collected.filter(r=>r.agent===agent),stage=phase(t);
 const rows=new Map(),edges=new Map();
 function card(id,title,tag,summary,input,output,basis,eventIDs=[],extra={}){return {id,kind:'flow',title,tag,summary,input,output,basis,eventIDs,source:'本次实时采集',...extra};}
 function put(key,x,y,title,tag,summary,data){rows.set(key,{key,x,y,title,tag,summary,data});}
 put('agent',367,235,agent,stage.label,`${cards.length} 项任务证据`,card('flow-agent',agent+' 当前任务',stage.label,t?.title||'尚未采到新需求',t?.title||'未采集',cards.map(c=>`${c.tag} · ${c.title}\n${c.summary}`).join('\n\n'),'仅汇总当前任务记录；后台系统行为不自动归入任务',cards.flatMap(c=>c.eventIDs)));
 if(t)put('user',367,22,'我的需求','用户原话',t.title,card('flow-user','用户原始需求','任务起点',t.title,t.title,'输入已记录；执行进展见图中亮起的环节','当前会话 / 轮次',[]));
 if(context)put('context',40,65,'本轮上下文',`${context.fingerprints.length} 块 · ${context.characters} 字符`,context.previousID?`新增 ${context.added} · 移出 ${context.removed}`:context.coverage,card('context:'+context.id,'送给模型的上下文',context.coverage,context.previousID?`相比上次：新增 ${context.added} 块，保留 ${context.retained} 块，移出 ${context.removed} 块`:'本次已采请求；暂无可比较的上次请求',context.blocks.map(b=>`${b.label}\n${b.content}`).join('\n\n').slice(0,16000),context.response||'响应尚未按原生标识配对','请求证据 '+context.id+'；组成不等于文件来源已确认',[context.id],{contextBlocks:context.blocks,source:context.source}));
 const modelCards=cards.filter(c=>c.kind==='model');
 if(context||modelCards.length)put('model',665,65,t?.model||'大模型',context?.responseID?'模型响应已收到':'等待响应 / 核对配对',context?.toolInstructions?'已下发工具指令':context?.response||modelCards.at(-1)?.summary||'请求正文待采集',card('flow-model','Agent ↔ 大模型',context?.responseID?'原生标识已配对':'配对待确认',context?.responseBasis||'本地模型记录；完整请求可能未采到',context?.toolInstructions||context?.blocks.map(b=>`${b.label}\n${b.content}`).join('\n\n').slice(0,16000)||modelCards.at(-1)?.input||'未采集',context?.response||modelCards.at(-1)?.output||'响应未采集',context?.responseBasis||'不凭时间猜测请求响应关系',context?[context.id,...(context.responseID?[context.responseID]:[])]:modelCards.flatMap(c=>c.eventIDs),{contextBlocks:context?.blocks||[],source:context?.source||modelCards.at(-1)?.source||'未知'}));
 shownTools.forEach((c,i)=>put(c.id,665,210+i*95,c.title,c.tag,c.summary,c));
 const files=cards.filter(c=>c.kind==='files'&&!c.call),web=cards.filter(c=>c.kind==='web'&&!c.call);
 if(processRows.length)put('process',40,245,'进程观察',`${processRows.filter(p=>p.active!==false).length} 个当前可见`,'独立观察 · 任务归属待核对',card('flow-process','进程与执行器观察','独立系统证据',`${processRows.length} 个关联应用观察对象`,'父子关系按 PID + 出生身份观察',processRows.map(p=>`${p.name} · PID ${p.pid} · PPID ${p.parent}\n${p.executable}\n${p.command}`).join('\n\n'),'应用进程树不是工具执行归属；详情不强行关联任务'));
 if(files.length)put('files',40,430,'文件行为',`${files.length} 项任务记录`,files.at(-1).title,card('flow-files','本轮文件行为','已采文件证据',files.at(-1).summary,files.map(c=>c.input).join('\n\n'),files.map(c=>c.output).join('\n\n'),'工具意图与实际文件变化按各条来源核对',files.flatMap(c=>c.eventIDs)));
 if(web.length)put('web',367,490,'网络 / 网站',`${web.length} 项任务记录`,web.at(-1).title,card('flow-web','本轮网络与网站','已采网络证据',web.at(-1).summary,web.map(c=>c.input).join('\n\n'),web.map(c=>c.output).join('\n\n'),'连接不等于采到正文；关联置信度以原记录为准',web.flatMap(c=>c.eventIDs)));
 function edge(key,path,label,x,y,data,dashed=false){edges.set(key,{key,path,label,x,y,data,dashed});}
 if(t)edge('user-agent','M450 95 L450 235','用户输入',460,175,rows.get('user').data);
 if(context){edge('context-model','M206 102 Q450 200 665 102','上下文 → 模型',350,155,rows.get('context').data);if(context.responseID)edge('model-agent','M665 120 Q570 135 500 235','← 模型返回',530,180,rows.get('model').data);}
 else if(modelCards.length)edge('agent-model','M533 260 Q610 210 665 140','模型记录 · 正文覆盖待核对',555,205,rows.get('model').data,true);
 shownTools.forEach((c,i)=>{edge('call:'+c.id,`M533 272 Q595 ${240+i*55} 665 ${246+i*95}`,c.status==='running'?'调用已记录 · 等待返回':c.tag,548,241+i*65,c,c.confidence!=='confirmed');if(c.status==='returned'||c.tag==='执行失败')edge('result:'+c.id,`M665 ${265+i*95} Q590 ${285+i*55} 533 290`,'← 工具结果',550,275+i*65,{...c,title:c.title+' · 返回结果'},c.confidence!=='confirmed');});
 if(processRows.length)edge('process-agent','M206 282 L367 272','系统观察 · 非执行器确认',210,263,rows.get('process').data,true);
 if(files.length)edge('agent-files','M390 308 Q300 425 206 466','文件证据',270,405,rows.get('files').data,true);
 if(web.length)edge('agent-web','M450 308 L450 490','网络证据',462,418,rows.get('web').data,true);
 if(context){const returning=context.blocks.filter(b=>b.role==='tool');if(returning.length)edge('result-context','M380 307 Q220 390 175 138',`${returning.length} 个结果进入上下文`,160,350,card('flow-return:'+context.id,'工具结果 → 模型上下文','结果回流',`${returning.filter(b=>b.toolEvidenceIDs.length).length} 块可按调用编号追溯`,returning.map(b=>`${b.callID||'调用编号缺失'}\n${b.content}`).join('\n\n').slice(0,16000),'内容出现在实际请求中；不代表模型已采纳','同 Agent / 会话 / 调用编号；多义时不强选',[context.id],{contextBlocks:returning,source:context.source}),true);}
 const fresh=cards.filter(c=>known.get(c.id)!==JSON.stringify([c.tag,c.status,c.summary]));const animate=seeded&&!paused&&fresh.length>0;
 cards.forEach(c=>known.set(c.id,JSON.stringify([c.tag,c.status,c.summary])));seeded=true;
 const pulse=fresh.at(-1),pulseEdge=pulse?.call?edges.get((pulse.status==='returned'||pulse.tag==='执行失败'?'result:':'call:')+pulse.id):pulse?.kind==='model'?edges.get(context?.responseID?'model-agent':'context-model'):null;
 $('graph').setAttribute('viewBox','0 0 900 610');
 $('graph').innerHTML=`<defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="#a6efcd"/></marker></defs>${[...edges.values()].map(e=>`<g class="flow-link" data-flow-edge="${esc(e.key)}" tabindex="0" role="button" aria-label="${esc(e.label)}"><path class="flow-hit" d="${e.path}"/><path class="edge ${e.dashed?'dim':''} ${selection==='edge:'+e.key?'hot':''}" d="${e.path}" ${e.key.startsWith("process-")||e.key==="agent-files"||e.key==="agent-web"?"":"marker-end=\"url(#flow-arrow)\""}/><rect class="flow-label-hit" x="${e.x-5}" y="${e.y-13}" width="${Math.min(180,Array.from(e.label).length*9+10)}" height="19" rx="4"/><text class="edge-label" x="${e.x}" y="${e.y}">${short(e.label,23)}</text></g>`).join('')}${animate&&pulseEdge?`<circle class="packet" r="4"><animateMotion dur="1.2s" repeatCount="1" fill="remove" path="${pulseEdge.path}"/></circle>`:''}${[...rows.values()].map(n=>`<g class="node ${selection==='node:'+n.key?'selected':''} ${stage.node===n.key?'flow-current':''} ${n.data.tag==='执行失败'?'warn':''}" data-flow-node="${esc(n.key)}" tabindex="0" role="button" aria-label="${esc(n.title)}" transform="translate(${n.x},${n.y})"><rect width="166" height="73" rx="8"/><circle class="state-dot" cx="147" cy="17" r="3"/><text class="node-tag" x="14" y="20">${short(n.tag,13)}</text><text class="node-name" x="14" y="41">${short(n.title,13)}</text><text class="node-sub" x="14" y="59">${short(n.summary,13)}</text></g>`).join('')}`;
 function display(data){const scroll=$('detail-code').scrollTop;showDetail(data);$('detail-code').scrollTop=scroll;const old=$('flow-block-picker');old?.remove();if(data.contextBlocks?.length){const picker=document.createElement('select');picker.id='flow-block-picker';picker.className='subtle';picker.setAttribute('aria-label','选择上下文块');picker.innerHTML='<option value="">上下文组成 / 选择具体内容</option>'+data.contextBlocks.map((b,i)=>`<option value="${i}">${esc(b.label)} · ${b.change==='added'?'本次新增':b.characters+' 字符'}</option>`).join('');$('detail-type').parentNode.appendChild(picker);if(data.selectedBlock!=null)picker.value=String(data.selectedBlock);picker.onchange=()=>{if(picker.value==='')return;const b=data.contextBlocks[+picker.value];frozen={...data,selectedBlock:+picker.value,title:b.label,input:b.content,output:b.callID?`调用编号 ${b.callID}\n返回证据：${b.toolEvidenceIDs.join(', ')||'未匹配'}`:data.output,contextBlocks:data.contextBlocks};showDetail(frozen);};}$('detail-summary').textContent=data.summary+' · 当前详情固定，主图继续更新；点击其他节点切换。';}
 function select(key,data){onInspect?.();selection=key;frozen=structuredClone(data);render({task:t,agent,contexts,processes,collected,paused:true,showDetail,onInspect});}
 for(const n of $('graph').querySelectorAll('[data-flow-node]')){const act=()=>select('node:'+n.dataset.flowNode,rows.get(n.dataset.flowNode).data);n.onclick=act;n.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();act();}};}
 for(const e of $('graph').querySelectorAll('[data-flow-edge]')){const act=()=>select('edge:'+e.dataset.flowEdge,edges.get(e.dataset.flowEdge).data);e.onclick=act;e.onkeydown=k=>{if(k.key==='Enter'||k.key===' '){k.preventDefault();act();}};}
 if(!frozen){const active=rows.get(stage.node)||rows.get('agent');showDetail(active.data);}else display(frozen);
 $('task-state').textContent=stage.label;
 $('canvas-title').textContent='现在到哪一步，点开就能看';$('canvas-note').textContent='节点显示当前环节，点击连线查看传递内容与依据';
 $('callout').textContent=`现在：${stage.label}。已采：${context?context.fingerprints.length+' 个上下文块':'请求正文待采集'} · ${modelCards.length} 条模型记录 · ${tools.length} 项工具活动 · ${processRows.length} 个应用进程。${shownTools.length<tools.length?'图中展示最近4项工具，全部记录在下方进度与看板。':''}`;
 document.querySelector('.legend').innerHTML='<span><i></i>已采任务记录</span><span><i class="dashed"></i>独立观察 / 关联待核对</span>';
}
window.AgentReinsFlow={render};
})();
