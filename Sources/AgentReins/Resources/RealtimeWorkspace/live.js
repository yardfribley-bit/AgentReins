'use strict';
(()=>{
const $=id=>document.getElementById(id),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const array=v=>Array.isArray(v)?v:[],clone=v=>JSON.parse(JSON.stringify(v)),cut=(s,n=58)=>{const a=Array.from(String(s??''));return a.slice(0,n).join('')+(a.length>n?'…':'')};
const text=v=>v==null?'':typeof v==='string'?v:JSON.stringify(v,null,2),time=v=>{const d=new Date(v);return isNaN(d)?'时间未提供':d.toLocaleTimeString('zh-CN',{hour12:false});};
const stageNames=[['user','需求'],['environment','材料'],['context','上下文'],['model','模型'],['plan','调度'],['command','执行'],['mcp','服务'],['files','文件'],['network','网络'],['failure','纠偏'],['verify','验证'],['artifact','交付']];
const statuses={running:'进行中',awaiting_confirmation:'等我确认',completed:'已完成未读',stopped:'已停止 · 交付未确认',failed:'失败',cancelled:'已取消',observed:'状态待确认'};
const typeNames={user:'用户原话',context:'模型上下文',model:'模型往返',plan:'计划与调度',command:'命令执行',tool:'工具调用',mcp:'MCP',skill:'Skill',files:'文件与变更',web:'网络资源',network:'网络资源',process:'进程观察',failure:'失败与纠偏',verify:'验证结果',artifact:'交付物',environment:'材料与约束',memory:'记忆访问',transfer:'数据传递',observation:'执行现场','tool-result':'工具返回'};
let latest=normalize({}),shown=latest,view='alerts',taskID=null,following=true,paused=false,query='',agentFilter='all',collectionFilter='all',selection=null,snapshot=null,snapshotRevision='',detailTab='output',contextBlockID=null,toastTimer;
let networkQuery='',networkAgent='all',networkTask=null,networkSelected=null;
const riskState={filter:{sev:'all',rule:'all',agent:'all',q:''},selected:null,alerts:[],decisions:[],decisionsLoaded:false,transportsRequested:false};
let graphMode='architecture',subtasksExpanded=false,pendingOpenKey=null;
const hydratedTasks=new Map(),pendingTasks=new Set(),collectedCache=new Map();
let objects=new Map(),runtimeExchangeID=null,runtimeCallID=null,runtimeTaskID=null,timelineMode='tools',runtimeProjection=null;
function normalize(p){return {...p,tasks:array(p.tasks),contexts:array(p.contexts),collected:array(p.collected),processes:array(p.processes),health:array(p.health),artifacts:array(p.artifacts),readTaskIDs:array(p.readTaskIDs),ipGeolocations:array(p.ipGeolocations)};}
function primaryTasks(){return shown.tasks.filter(t=>t.isPrimaryTask!==false);}
function listTasks(){return primaryTasks().filter(t=>agentFilter==='all'||t.agent===agentFilter).sort((a,b)=>new Date(b.startedAt)-new Date(a.startedAt));}
function newest(){return listTasks()[0]?.id||null;}
function task(){return shown.tasks.find(t=>t.id===taskID)||null;}
function cards(t=task()){return array(t?.cards);}
function inputTitle(t){return t?.latestUserInput?.content||t?.originalRequest||(array(t?.inputAttachments).length?'用户附件输入 · 未附带文字':t?.title||'用户原话缺失');}
function readableTask(text){
 const raw=String(text||'').replace(/\s+/g,' ').trim();
 if(!raw)return '用户原话缺失';
 const plain=raw.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim();
 const machine=/<\s*\/?\s*(heartbeat|automation_id|automation)\b/i.test(raw);
 if(machine&&plain.length<48)return plain?('机器标记 · '+plain):'机器标记，没有用户原话';
 return plain||'机器标记，没有用户原话';
}
function taskLabel(t){return readableTask(inputTitle(t));}
function machineInput(text){return /<\s*\/?\s*(heartbeat|automation_id|automation)\b/i.test(String(text||''));}
function inputData(t){return {subagentPath:t?.subagentPath,parentSession:t?.parentSession,id:t?.requestEventID,content:t?.originalRequest,currentContent:t?.latestUserInput?.content,inputs:array(t?.userInputs),attachments:array(t?.inputAttachments),source:t?.requestSource,eventIDs:array(t?.userInputs).flatMap(i=>array(i.eventIDs)).length?array(t?.userInputs).flatMap(i=>array(i.eventIDs)):t?.requestEventID?[t.requestEventID]:array(t?.inputAttachments).flatMap(a=>array(a.eventIDs))};}
function inputDetail(d){if(d.subagentPath)return '<p class="detail-intro">这是主 Agent 委派的子任务。用户原始需求属于父任务；子任务工具和返回在当前流程中展示。</p>'+kv([['子代理',d.subagentPath],['父会话',d.parentSession]])+empty('委派正文仅在来源提供可读内容时展示，不以父任务原话代替。');const inputs=array(d.inputs);if(inputs.length)return inputs.map((i,n)=>section(`${n===0?'起始输入':'补充输入 '+n} · ${time(i.timestamp)}${n===inputs.length-1?' · 最新':''}`, (i.content?box(i.content):array(d.attachments).length?attachmentDetail(d.attachments):empty('该次输入没有文字'))+kv([['来源',i.source],['证据 ID',array(i.eventIDs).join('\n')]]) )).join('');return d.content?box(d.content):array(d.attachments).length?attachmentDetail(d.attachments):'<div class="notice">没有采到本轮用户原文。这是采集缺口，不能用任务标题或模型回复代替。</div>';}
function attachmentDetail(items){return `<p class="detail-intro">本次用户发送了附件，没有附带文字需求。</p>`+array(items).map(a=>kv([['输入类型',a.type],['原始附件路径',a.path],['采集来源',a.source],['证据 ID',array(a.eventIDs).join('\n')]])).join('');}
function taskStatus(t){return t?.lifecycleStatus||'observed';}
function read(t){return !!t?.readAt||shown.readTaskIDs.includes(t?.id);}
function state(t){return taskStatus(t)==='completed'&&read(t)?'已完成已读':statuses[taskStatus(t)]||'状态待确认';}
function current(t){return t?.currentStep||'已收到活动，任务阶段待确认';}
function cls(t){return ({running:'',awaiting_confirmation:'orange',completed:'green',stopped:'orange',failed:'red',cancelled:'',observed:'orange'})[taskStatus(t)]||'';}
function taskContexts(t=task()){return shown.contexts.filter(c=>c.agent===t?.agent&&c.session===t?.session&&c.turn===t?.turn);}
function taskArtifacts(t=task()){return shown.artifacts.filter(a=>a.taskID===t?.id);}
function detailType(c){const type=c?.detailType;return ({file:'files',network:'web',execution:'command',planning:'plan',verification:'verify',delivery:'artifact',approval:'failure',recovery:'failure'})[type]||type||c?.kind||'tool';}
function stageFor(c){return ({user:'user',command:'command',tool:'mcp',mcp:'mcp',skill:'mcp',model:'model',files:'files',web:'network',network:'network',plan:'plan',verify:'verify',failure:'failure',artifact:'artifact',environment:'environment'})[detailType(c)]||null;}
function stageRows(t=task()){
 const backend=array(t?.lifecycle?.stages);
 return stageNames.map(([id,title])=>{const s=backend.find(s=>s.id===id);if(s)return {...s,title};const cs=cards(t).filter(c=>stageFor(c)===id),n=id==='user'?(t?.originalRequest?1:0):id==='context'?taskContexts(t).length:id==='artifact'?taskArtifacts(t).length:cs.length;return {id,title,status:n?'recorded':'absent',summary:n?`${n} 项实际记录`:'本轮无对应记录',cardIDs:cs.map(c=>c.id),eventIDs:cs.flatMap(c=>array(c.eventIDs))};});
}
function box(s,mono=false,id=''){return `<div ${id?`id="${id}"`:''} class="content-box ${mono?'mono':''}">${esc(s)}</div>`;}
function section(title,body){return `<section class="detail-section"><h3>${esc(title)}</h3>${body}</section>`;}
function empty(s){return `<p class="empty compact">${esc(s)}</p>`;}
function kv(rows){return `<dl class="kv">${rows.filter(([,v])=>v!=null&&v!=='').map(([k,v])=>`<dt>${esc(k)}</dt><dd>${esc(text(v))}</dd>`).join('')}</dl>`;}
function badge(s,c=''){return `<span class="status-pill ${c}">${esc(s)}</span>`;}
function evidence(o){const d=o.data||{},t=o.task;return `<details class="technical"><summary>来源与关联依据</summary><p>${esc([d.source&&'来源：'+d.source,d.basis||d.responseBasis,t?.session&&'会话：'+t.session,t?.turn&&'轮次：'+t.turn,d.call&&'调用：'+d.call,array(d.eventIDs).length&&'证据：'+d.eventIDs.join(', '),d.id&&'记录：'+d.id].filter(Boolean).join('\n')||'该对象没有可确认的原生关联信息。')}</p></details>`;}
function recordButton(c){return `<button class="event-item" data-select="card:${esc(c.id)}"><b>${esc(c.title)}</b><small>${esc(c.tag)} · ${esc(time(c.timestamp))}</small><small>${esc(c.summary)}</small></button>`;}
function toast(s){$('toast').textContent=s;$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,3200);}
function bridge(action,fields){const handler=window.webkit?.messageHandlers?.agentreins;if(!handler){toast('此操作需要 AgentReins 原生应用；当前浏览器未连接原生通道。');return false;}handler.postMessage({action,...fields});return true;}
function selectTask(id,openKey=null){pendingOpenKey=openKey;taskID=id;following=false;selection=null;snapshot=null;contextBlockID=null;detailTab='output';view='process';render();if(openKey&&objects.has(openKey)){pendingOpenKey=null;choose(openKey);}}
function revision(o){return JSON.stringify([o?.type,o?.data]);}
function object(key,type,data,t=task()){const o={key,type,data,task:t};objects.set(key,o);return o;}
function rebuildObjects(){
 objects=new Map();const t=task();
 if(t){object('agent','agent',t);object('user','user',inputData(t));
  const contexts=taskContexts();for(const c of contexts)object('context:'+c.id,'context',c);if(contexts.length)object('context','context',contexts.at(-1));
  const models=cards().filter(c=>c.kind==='model');if(models.length||contexts.length)object('model','model',{contexts,cards:models});
  for(const c of cards())object('card:'+c.id,detailType(c),c);
  for(const s of stageRows())object('stage:'+s.id,'stage',s);
  object('files','group',{stage:'files',cards:cards().filter(c=>stageFor(c)==='files')});
  object('network','group',{stage:'network',cards:cards().filter(c=>stageFor(c)==='network')});
  object('services','group',{stage:'mcp',cards:cards().filter(c=>['mcp','skill','tool'].includes(detailType(c)))});
  object('artifact','artifact',{artifacts:taskArtifacts()});
 }
 object('process','process-group',{processes:shown.processes.filter(p=>!t||p.agent===t.agent)},null);
 for(const p of shown.processes)object('process:'+p.id,'process',p,null);
 for(const r of shown.collected)object('record:'+r.id,r.kind==='network'&&r.resource?'network-record':'record',r,null);
 for(const h of shown.health)object('health:'+h.source,'health',h,null);
 for(const a of shown.artifacts)object('artifact:'+a.id,'artifact-item',a,shown.tasks.find(t=>t.id===a.taskID));
}
function choose(key){const o=objects.get(key);if(!o)return;if(document.body.classList.contains('details-collapsed')){document.body.classList.remove('details-collapsed');$('toggle-details').textContent='收起详情';}if(key.startsWith('card:')&&o.data?.id?.startsWith('call:')){runtimeCallID=o.data.id;const origin=taskContexts().find(c=>window.AgentReinsRuntimeGraph.instructionCalls(c).some(i=>i.id===o.data.call));if(origin)runtimeExchangeID=origin.id;}selection=key;snapshot=clone(o);snapshotRevision=revision(o);following=false;contextBlockID=o.type==='transfer'?o.data.preferredBlockID||null:null;detailTab='output';renderGraph();renderStages();if(view==='collection')renderCollectionDetail();else renderDetail(true);const panel=view==='collection'?$('collection-detail'):$('detail');if(panel)panel.scrollTop=0;renderTasks();}
function refreshDetail(){const o=objects.get(selection);if(!o)return;snapshot=clone(o);snapshotRevision=revision(o);if(view==='collection')renderCollectionDetail();else renderDetail(true);}
function defaultObject(){const t=task();if(taskStatus(t)==='completed'&&taskArtifacts(t).length)return objects.get('artifact');if(runtimeProjection?.currentKey&&objects.has(runtimeProjection.currentKey))return objects.get(runtimeProjection.currentKey);return objects.get(t?.currentCardID?'card:'+t.currentCardID:'')||objects.get(t?.lifecycle?.currentStageID?'stage:'+t.lifecycle.currentStageID:'')||objects.get('user')||objects.get('process');}
function renderTasks(){
 const q=query.toLowerCase(),list=listTasks().filter(t=>!q||[t.originalRequest,...array(t.userInputs).map(i=>i.content),t.title,t.agent,t.currentStep,t.searchText,...cards(t).flatMap(c=>[c.title,c.summary,c.input,c.output,c.resource?.path,c.resource?.url,c.resource?.domain,c.execution?.command]),...taskArtifacts(t).flatMap(a=>[a.name,a.path])].filter(Boolean).join('\n').toLowerCase().includes(q));
 $('task-count').textContent=primaryTasks().length;
 $('tasks').innerHTML=list.map(t=>`<div class="task-item ${t.id===taskID?'selected':''}"><button class="task-open" data-task="${esc(t.id)}" title="${esc(taskLabel(t))}"><strong>${esc(taskLabel(t))}</strong><small><span><i class="status-dot ${esc(taskStatus(t))}"></i>${esc(t.agent)} · ${esc(state(t))}</span><span>${esc(time(t.lastActivity))}</span></small><span class="task-summary">${esc(cut(current(t),70))}</span></button><button class="task-net" data-network-scope="${esc(t.id)}" title="看这次任务的外网访问">外网</button></div>`).join('')||empty(q?'没有匹配任务。可查找原话、文件路径、工具与域名。':'尚未采到带任务身份的用户任务。');
 const subtasks=shown.tasks.filter(t=>t.subagentPath&&(agentFilter==='all'||t.agent===agentFilter)&&[t.title,t.subagentPath,...cards(t).map(c=>c.title)].join(' ').toLowerCase().includes(q));
 if(subtasks.length)$('tasks').innerHTML+=`<details class="subtask-group" ${subtasksExpanded?'open':''}><summary>Agent 子任务 · ${subtasks.length}</summary>${subtasks.map(t=>`<button class="task-item ${t.id===taskID?'selected':''}" data-task="${esc(t.id)}"><strong>${esc(t.title)}</strong><small>${esc(state(t))} · ${esc(time(t.lastActivity))}</small><span class="task-summary">${esc(cut(current(t),70))}</span></button>`).join('')}</details>`;
 const childGroup=$('tasks').querySelector('.subtask-group');if(childGroup)childGroup.addEventListener('toggle',()=>{subtasksExpanded=childGroup.open;});
 $('agent-health').innerHTML=['WorkBuddy','Codex','Cursor'].map(a=>{const hs=shown.health.filter(h=>h.source.toLowerCase().includes(a.toLowerCase()));return `<button type="button" class="agent-health" data-view="collection"><b>${a}</b><span>${hs.length?esc(hs.map(h=>h.state).join(' / ')):'来源状态未提供'}</span></button>`;}).join('')+'<p>本机独立运行 · 仅实时任务<br>无任务身份的观察保留在采集现场</p>';
}
function stopExcerpt(t){const paragraphs=String(t?.nativeEndMessage||'').split(/\n\s*\n/).map(s=>s.trim()).filter(s=>s&&!/^#{1,6}\s/.test(s));return paragraphs.length?cut(paragraphs[0].replace(/\*\*/g,''),140):'执行已结束，尚无目标验证记录。点击核对最后答复与执行详情。';}
function renderHeading(){const t=task();
 if(view==='network'&&networkTask){const scoped=shown.tasks.find(x=>x.id===networkTask);$('heading').innerHTML=scoped?`<div class="heading-meta">这次任务的外网访问</div><div class="heading-row"><h1>${esc(taskLabel(scoped))}</h1><button class="task-jump" data-task="${esc(scoped.id)}">返回任务过程</button></div><p class="request">${esc(scoped.agent)} · 下面只列归到这次任务的外网访问。</p>`:`<h1>这次任务已不在列表里</h1><button class="task-jump" data-view="process">返回任务过程</button>`;return;}
 if(view!=='process'){const titles={alerts:['风险告警','这台 Mac 上的编码 agent 今天有没有做危险的事。'],network:['外网访问，追查目标和发起来源','查看 WorkBuddy、Codex、Cursor 的目标地址、位置、会话与实际证据。'],collection:['采集现场，确认数据从哪里来','应用进程、文件与网络观察独立保留；缺少任务身份的记录可以查找。'],rules:['规则','少而准的高危行为规则；默认只告警。'],coverage:['覆盖度 · 看不到什么','告警只来自看得到的部分；没有告警不等于安全。'],results:['任务结果看板','按任务归列，点击找到当前步骤、失败原因和实际交付物。']};const meta=titles[view]||titles.alerts;$('heading').innerHTML=`<div class="heading-meta">本机运行时安全 · WorkBuddy / Codex / Cursor</div><h1>${meta[0]}</h1><p class="request">${meta[1]}</p>`;return;}
 const duration=t?Math.max(0,Math.round((new Date(t.lastActivity)-new Date(t.startedAt))/1000)):null;const durationText=duration==null?'':duration>=86400?Math.floor(duration/86400)+' 天 '+Math.floor(duration%86400/3600)+' 小时':duration>=3600?Math.floor(duration/3600)+' 小时 '+Math.floor(duration%3600/60)+' 分钟':String(Math.floor(duration/60)).padStart(2,'0')+':'+String(duration%60).padStart(2,'0');
 const requestLine=t?.originalRequest?(machineInput(t.originalRequest)?'<p class="request">这条记录是心跳或自动化标记，不是用户写下的需求。原始标记可以在「查看原始输入」里看。</p>':`<p class="request"><b>起始原话：</b>${esc(readableTask(t.originalRequest))}</p>`)+(t?.latestUserInput?.content&&t.latestUserInput.content!==t.originalRequest&&!machineInput(t.latestUserInput.content)?`<p class="request latest-input"><b>最新补充：</b>${esc(readableTask(t.latestUserInput.content))}</p>`:''):t?.subagentPath?`<p class="request">Agent 委派的子任务 · ${esc(t.subagentPath)}<br>工具与执行结果属于当前子任务，用户原始需求归属父会话。</p>`:array(t?.inputAttachments).length?'<p class="request">本次输入为附件，没有附带文字需求。点击原始输入查看路径。</p>':t?'<p class="request-missing">本轮用户原话尚未采到。后续活动保留，任务起点待补齐。</p>':'<p class="request">这里将从你的原话开始，展示模型往返、执行过程与结果。</p>';
 $('heading').innerHTML=`<div class="heading-meta"><span class="agent-label">${esc(t?.agent||'等待 Agent')}</span><span>${esc(t?.model||'模型身份未采集')}</span>${t?`<span>开始 ${esc(time(t.startedAt))}</span>`:''}</div><div class="heading-row"><h1>${esc(t?taskLabel(t):'等待一个真实任务')}</h1><div class="heading-side">${t?`<button class="task-jump" data-network-scope="${esc(t.id)}">看这次任务的外网</button>`:''}${duration!=null?`<strong>${durationText}</strong>已观察跨度`:''}</div></div>${requestLine}<div class="status-line">${badge(t?state(t):'等待新任务',cls(t))}<span id="task-state">${esc(t?current(t):'等待真实采集数据')}</span>${t?`<span class="divider"></span><button class="link-button" data-select="user">查看原始输入</button>`:''}</div>${t&&taskStatus(t)==='stopped'?`<div class="stopped-callout"><strong>Agent 已停止 · 目标达成尚未确认</strong><span>${esc(stopExcerpt(t))}</span><br><button class="link-button" data-select="closure">查看停止原文与最后一步 →</button></div>`:''}`;
}
function renderStages(){const t=task(),stages=stageRows();$('stages').innerHTML=stages.map(s=>`<button data-select="stage:${esc(s.id)}" class="${t?.lifecycle?.currentStageID===s.id?'current':s.status==='returned'?'done':''}" title="${esc(s.summary)}" ${!t?'disabled':''}><span>${esc(s.title)}</span><span class="stage-count">${s.status==='absent'?'—':s.status==='running'?'进行中':s.status==='waiting'?'等待':s.status==='failed'?'失败':s.status==='returned'?'已返回':s.status==='cancelled'?'取消':'已记录'}</span></button>`).join('');}
function renderGraph(animate=false){
 const t=task();if(runtimeTaskID!==t?.id){runtimeTaskID=t?.id;runtimeExchangeID=null;runtimeCallID=null;}
 const args={task:t,contexts:taskContexts(),processes:shown.processes,artifacts:taskArtifacts(),exchangeID:runtimeExchangeID,callID:runtimeCallID,overview:window.AgentReinsFlow.isOverview(),networkObservations:shown.collected.filter(r=>r.kind==='network'&&!r.hasTaskIdentity&&r.agent===t?.agent)};const g=graphMode==='spider'?window.AgentReinsRuntimeGraph.buildRelations(args):window.AgentReinsRuntimeGraph.buildArchitecture(args);runtimeProjection=g;
 for(const o of g.objects)object(o.key,o.type,o.data);
 const chosen=g.chosen;const inChosenCycle=chosen&&g.relevant.some(c=>c.id===chosen.id);
 $('runtime-controls').innerHTML=`<label>模型请求<select id="runtime-exchange" aria-label="选择模型请求"><option value="" ${runtimeExchangeID?'':'selected'}>跟随当前步骤</option>${g.choices.map((c,i)=>`<option value="${esc(c.id)}" ${runtimeExchangeID===c.id?'selected':''}>${i+1} · ${esc(time(c.timestamp))} · ${c.structured?'实际请求':'本地片段'}${c.responseID?' · 已返回':' · 响应待配对'}</option>`).join('')}</select></label><label>工具调用<select id="runtime-call" aria-label="选择工具调用"><option value="" ${runtimeCallID?'':'selected'}>跟随当前步骤</option>${g.calls.map((c,i)=>`<option value="${esc(c.id)}" ${runtimeCallID===c.id?'selected':''}>${i+1} · ${esc(c.title)} · ${esc(c.tag)}</option>`).join('')}</select></label>${runtimeExchangeID||runtimeCallID?'<button class="link-button" data-action="follow-cycle">回到最新进展</button>':''}`;
 const layout=window.AgentReinsFlow.isOverview()?window.AgentReinsSpiderGraph.overview(g):graphMode==='spider'?window.AgentReinsSpiderGraph.layout(g):g;
 document.querySelectorAll('[data-graph-mode]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.graphMode===graphMode)));
 window.AgentReinsFlow.render({scope:t?.id||'observation',nodes:layout.nodes,edges:layout.edges,selectedKey:selection,currentKey:g.currentKey,paused,onSelect:choose,width:layout.width,height:layout.height,animate});
 $('runtime-note').innerHTML=`${g.exchange?`当前展示第 ${g.choices.indexOf(g.exchange)+1} 次${g.exchange.structured?'实际模型请求':'本地输入片段'}${chosen?`，工具 ${esc(chosen.title)}${inChosenCycle?'':'（未归属于所选请求）'}`:''}。`:g.calls.length?'模型请求未采到；原生工具调用仍可查看。':'等待模型请求或原生工具调用。'}${g.relationships?` 蜘蛛图展开 ${g.shownCallCount} 次具体调用${g.hiddenCallCount?`，其余 ${g.hiddenCallCount} 次可点开集合或时间线`:''}。`:''}${g.unlinked.length?` ${g.unlinked.length} 个调用未与模型响应配对。`:''}${chosen&&['returned','failed'].includes(chosen.phase)&&!g.next?' 这次返回是否进入下一次请求，尚未取得配对证据。':''}`;
 $('current-bar').innerHTML=`<span>${esc(t?current(t):'等待带任务身份的新记录')}</span><small>${esc(t?.statusBasis||'系统观察持续保留，尚不代表任务执行。')}</small>`;
}
function reportedWebFailure(c){return c?.title==='WebFetch'&&/^Error:\s*(?:Error:\s*)?(?:Error during web fetch|Request timed out)/i.test(c.output||'');}
function renderTimeline(){
 const all=cards(),cs=timelineMode==='tools'?window.AgentReinsRuntimeGraph.nativeCalls(task()):all,scroll=$('timeline-viewport').scrollTop;
 $('timeline-tools').classList.toggle('active',timelineMode==='tools');$('timeline-all').classList.toggle('active',timelineMode==='all');$('stage-caption').textContent=`${cs.length} 项`;
 $('timeline').innerHTML=cs.map((c,i)=>`<button class="timeline-row ${c.id===task()?.currentCardID?'current':''} ${selection==='card:'+c.id?'active':''}" data-select="card:${esc(c.id)}"><span class="time">${timelineMode==='tools'?'#'+(i+1):esc(time(c.timestamp))}</span><span class="timeline-dot ${reportedWebFailure(c)?'failed':esc(c.phase)}"></span><span class="timeline-text">${esc(c.title)}<small>${esc(cut(c.execution?.command||c.summary,110))}</small></span><span class="timeline-tag ${reportedWebFailure(c)?'output-error':''}">${reportedWebFailure(c)?'工具报告访问失败':esc(c.tag)}</span></button>`).join('')||empty(timelineMode==='tools'?'本轮尚未采到原生工具调用。其他活动可以从“全部证据”查看。':'本轮尚无执行记录。');$('timeline-viewport').scrollTop=scroll;
}
function contextDetail(d){const blocks=array(d.blocks);let b=blocks.find(b=>b.id===contextBlockID)||blocks.find(b=>b.change==='added')||blocks[0];contextBlockID=b?.id||null;return kv([['请求时间',time(d.timestamp)],['覆盖',d.coverage],['组成',`${blocks.length} 块 · ${d.characters||0} 字符`],['与上次比较',d.previousID?`新增 ${d.added} · 保留 ${d.retained} · 移出 ${d.removed}`:'没有可比较的前次请求']])+`<div class="context-block-list">${blocks.map(b=>`<button class="context-block ${b.id===contextBlockID?'active':''}" data-block="${esc(b.id)}">${esc(b.label||b.role)}<small>${esc(b.characters||b.content?.length||0)} 字符${b.change==='added'?' · 本次新增':''}${b.containsCurrentInput?' · 含本次原话':''}${b.callID?' · '+esc(b.callID):''}</small></button>`).join('')}</div>`+section(b?.label||'请求内容',b?box(b.content,true,'context-content'):empty('请求已记录，但未取得可展示的结构化正文。'))+(b?.callID?kv([['工具调用',b.callID],['回流依据',array(b.toolEvidenceIDs).join(', ')||'未匹配到唯一执行记录']]):'')+(d.truncated?'<p class="notice">当前显示为截断预览；完整请求是否已采集，请以上方“覆盖”字段为准。</p>':'')+`<button class="link-button" data-runtime-exchange="${esc(d.id)}">切换到这次模型往返 →</button>`;}
function commandDetail(c){
 const e=c.execution||{},command=e.command||c.input,tab=detailTab,chunks=array(e.chunks);
 const stream=chunks.filter(k=>tab==='output'||k.channel===tab);
 const streaming=stream.length?stream.map(k=>`<span class="${k.channel==='stderr'?'output-error':''}"><span class="output-time">${esc(time(k.timestamp))} ${esc(k.channel)}</span>  ${esc(k.text)}${k.truncated?'\n[此输出片段达到采集上限]':''}</span>`).join('\n'):null;
 const content=tab==='input'?esc(c.input):streaming||esc(tab==='stdout'?e.stdout||'尚未收到 stdout':tab==='stderr'?e.stderr||'尚未收到 stderr':e.stdout!=null||e.stderr!=null?[e.stdout,e.stderr&&'stderr:\n'+e.stderr].filter(Boolean).join('\n'):c.output||'尚未收到实际返回');
 return kv([['工作目录',e.cwd],['命令',command],['执行身份',e.executionID],['进程',e.processID!=null?`PID ${e.processID}`:c.pid!=null?`PID ${c.pid}（采集记录，执行器身份见依据）`:null],['开始',e.startAt?time(e.startAt):null],['结束',e.endAt?time(e.endAt):null]])+`<div class="tabs"><button class="${tab==='output'?'active':''}" data-tab="output">${chunks.length?'输出时间线':e.stdout!=null||e.stderr!=null?'输出流':'工具返回'}</button>${e.stdout!=null||chunks.some(k=>k.channel==='stdout')?`<button class="${tab==='stdout'?'active':''}" data-tab="stdout">stdout</button>`:''}${e.stderr!=null||chunks.some(k=>k.channel==='stderr')?`<button class="${tab==='stderr'?'active':''}" data-tab="stderr">stderr</button>`:''}<button class="${tab==='input'?'active':''}" data-tab="input">调用参数</button></div><div class="terminal"><div class="terminal-head"><span>${esc(tab==='input'?'实际参数':tab==='stdout'?'stdout':tab==='stderr'?'stderr':chunks.length?'按来源到达顺序':e.stdout!=null||e.stderr!=null?'采集输出':'实际工具返回')}</span><span>${esc(e.status||c.tag)}</span></div><pre>${content}</pre><div class="terminal-foot"><span>${e.exitCode!=null?'exit_code: '+esc(e.exitCode):'退出码未提供'}</span><span>${e.outputComplete?'来源标记输出结束':e.outputComplete===false?'输出片段，完整性待核对':'来源未声明输出完整性'}</span></div></div>${c.outputTruncated||c.inputTruncated||e.commandTruncated||e.stdoutTruncated||e.stderrTruncated?'<div class="notice">参数或输出达到预览上限，显示的是已采片段。</div>':''}${e.basis?`<p class="note">${esc(e.basis)}</p>`:''}`;
}
function ipInfo(ip,taskID){const geo=shown.ipGeolocations.find(g=>g.ip===ip),state=geo?.state||'unqueried';return kv([['IP',ip],['位置',geo?.location],['网络归属',geo?.owner],['来源',geo?.source],['查询时间',geo?.updatedAt?time(geo.updatedAt):null]])+(state==='loading'?'<p class="note">正在查询位置与归属…</p>':state==='failed'?`<p class="notice">${esc(geo.error||'查询失败')}</p>`:state==='unqueried'?'<p class="note">尚未查询 IP 位置与归属。</p>':'')+(taskID?`<button class="quiet" data-resolve-ip="${esc(ip)}" data-ip-task="${esc(taskID)}" ${state==='loading'||state==='ready'?'disabled':''}>${state==='ready'?'已取得 IP 位置与归属':state==='failed'?'重试 IP 归属查询':'查询 IP 位置与归属'}</button>`:'')+'<p class="note">主动查询仅发送这个 IP；地理归属为来源估计，并非服务器精确位置。</p>'; }
function networkDetail(c,t){
 const r=c.resource||{},url=r.url||'',addresses=array(r.addresses),type=r.evidenceType||'',intent=type==='tool_intent';let domain=r.domain;try{if(!domain&&url)domain=new URL(url).hostname;}catch{}
 const socket=r.observedRemoteHost?kv([['本地端点',r.observedLocalAddress],['连接对端',r.observedRemoteHost+(r.observedRemotePort?':'+r.observedRemotePort:'')],['TCP 状态',r.socketState],['采样时间',time(c.timestamp)],['进程',c.pid],['进程出生身份',r.processIdentity],['来源',c.source]]):empty(intent?'这条是工具目标记录，没有系统socket证据。':'此来源没有提供原始socket端点。');
 const proxy=r.proxySource?section('代理日志确认的目标',kv([['代理',r.proxySource],['目标主机',domain],['目标端口',r.remotePort],['日志时间',time(r.proxyObservedAt)],['关联依据','同一客户端端口、采样时间与进程出生身份']])+'<p class="note">域名由代理访问日志确认；网站服务器IP、HTTP路径与正文没有因此获得。</p>'):'';
 const target=intent?section('工具声明 / 执行记录中的目标',kv([['目标资源',r.requestedURL||url],['目标主机',domain],['依据',r.destinationBasis||c.basis]])+'<p class="note">这条记录说明命令的目标，不能单凭它证明已经连接或上传。</p>'):'';
 const http=r.method&&url&&!intent?section(type==='tool_report'?'工具提供的 HTTP 信息':'实际 HTTP 资源',kv([['请求',r.method+' '+url],['响应状态',r.statusCode],['内容类型',r.contentType]])):empty('本条未采HTTP方法、资源路径或正文。系统连接和代理目标仍可单独核对。');
 const relatedCall=c.call?cards(t).find(x=>x.id==='call:'+c.call):null;
 const record=shown.collected.find(x=>array(c.eventIDs).includes(x.id));
 const overview=window.AgentReinsNetwork.exchangeMarkup({agent:t?.agent,host:domain||r.remoteIP,port:r.remotePort,ip:r.remoteIP,proxy:r.proxySource,session:t?.session,call:c.call,taskID:t?.id,taskConfidence:/time window|时间窗口/i.test(r.basis||'')||!c.call?'candidate':'native',command:relatedCall?.execution?.command,tool:relatedCall?.title,evidenceType:type,networkBody:record?.networkBody});
 return overview+target+'<details class="network-raw-details"><summary>连接、代理与原始采集字段</summary>'+section('系统观测到的连接',socket)+proxy+http+section('地址归属',kv([['观测的远端 IP',r.remoteIP],['端口',r.remotePort],['已采地址',addresses.join('\n')],['地址范围',r.ipScope],['归属依据',r.geo?.source||r.geolocationSource]])+(r.remoteIP?`<div id="ip-info" data-ip="${esc(r.remoteIP)}">${ipInfo(r.remoteIP,t?.id)}</div>`:empty('网站远端IP未采到，不能把本机代理地址当成网站IP。')))+section(intent?'原始目标参数':'采集元数据',box(c.input||'此来源未提供参数',true))+(type==='http'?section('HTTP 响应 / 已采内容',box(c.output||'响应正文未采到',true)):!['socket','proxy_route','tool_intent'].includes(type)&&c.output?section('工具返回 / 已采资源',box(c.output,true)):cards(t).some(x=>x.id==='call:'+c.call)?`<button class="link-button" data-select="card:call:${esc(c.call)}">查看对应工具的执行与返回 →</button>`:'')+(r.basis?`<p class="note">${esc(r.basis)}</p>`:'')+'</details>';
}
function filesDetail(c){const r=c.resource||{},tab=detailTab;const diff=r.diff;return kv([['文件路径',r.path],['实际动作',c.title],['来源',c.source]])+`<div class="tabs"><button data-tab="output" class="${tab==='output'?'active':''}">已采内容</button><button data-tab="input" class="${tab==='input'?'active':''}">读取 / 写入参数</button>${diff?`<button data-tab="diff" class="${tab==='diff'?'active':''}">本轮 diff</button>`:''}${r.before!=null?`<button data-tab="before" class="${tab==='before'?'active':''}">变更前</button>`:''}${r.after!=null?`<button data-tab="after" class="${tab==='after'?'active':''}">变更后</button>`:''}</div>`+(tab==='diff'&&diff?`<div class="diff-content">${text(diff).split('\n').map(line=>`<span class="diff-line ${line.startsWith('+')&&!line.startsWith('+++')?'add':line.startsWith('-')&&!line.startsWith('---')?'remove':''}">${esc(line)}</span>`).join('')}</div>`:box(tab==='input'?c.input:tab==='before'?r.before:tab==='after'?r.after:c.output||'本条没有文件正文',true))+(c.outputTruncated||c.inputTruncated?'<p class="notice">当前内容为采集片段，已达到预览上限。</p>':'')+`<p class="note">${esc(r.basis||'打开句柄不等于读取全文；模型提出写入不等于文件已落盘。仅展示本轮已有证据。')}</p>`;}
function modelDetail(d){const contexts=array(d.contexts),cs=array(d.cards);return contexts.length?contexts.map((c,i)=>`<div class="message"><header><span>请求 ${i+1} · ${esc(time(c.timestamp))}</span><span>${esc(c.responseID?'响应已配对':'响应待配对')}</span></header><button class="link-button" data-context="${esc(c.id)}">查看 ${array(c.blocks).length} 个实际上下文块 →</button>${c.inputTokens!=null||c.outputTokens!=null?kv([['输入 tokens',c.inputTokens],['输出 tokens',c.outputTokens]]):''}</div>${c.response?section('模型实际返回',box(c.response)):''}${c.toolInstructions?section('下发的工具指令',box(c.toolInstructions,true)):''}${c.recordedReasoning?`<details class="technical"><summary>来源实际返回的 reasoning</summary><p>${esc(c.recordedReasoning)}</p></details>`:''}${array(c.toolSteps).length?section('模型指令与实际执行',array(c.toolSteps).map(s=>'<div class="message"><strong>'+esc(s.name)+'</strong>'+kv([['调用编号',s.callID],['执行证据',s.status]])+box(s.arguments,true)+'</div>').join('')):''}${(c.responseCharacters>16000||c.reasoningCharacters>16000||c.instructionsCharacters>16000)?'<p class="notice">此处为显示预览，原始采集正文另行保留；不能以预览长度判断采集字节数。</p>':''}<p class="note">${esc(c.responseBasis||'配对依据未提供')}</p>`).join(''):cs.map(c=>`<div class="message"><header><span>${esc(c.title)}</span><span>${esc(time(c.timestamp))}</span></header>${box(c.output||c.input||c.summary,true)}<p class="note">${esc(c.basis)}</p></div>`).join('')||empty('本轮没有可配对的模型内容。');}
function artifactDetail(items){return items.length?items.map(a=>`<div class="artifact-row"><strong>${esc(a.name)}</strong><small>${esc(a.path)}</small>${kv([['状态',a.status|| (a.exists?'文件存在已确认':'文件存在未确认')],['大小',a.sizeBytes!=null?a.sizeBytes+' bytes':null],['来源',a.source]])}${a.preview!=null?`<div class="result-preview"><pre class="artifact-preview">${esc(a.preview)}</pre></div>${a.previewTruncated?'<p class="note">内容超过预览上限。</p>':''}`:'<p class="note">当前来源没有提供内嵌内容预览。</p>'}${a.openable?`<button class="primary" data-open-artifact="${esc(a.id)}" data-artifact-task="${esc(a.taskID)}">打开实际产物 ↗</button>`:''}${a.basis?`<p class="note">${esc(a.basis)}</p>`:''}</div>`).join(''):empty('本轮尚未识别出可以核对的交付物。文件操作记录仍可从“文件”查看。');}
function toolResultDetail(c){const failure=reportedWebFailure(c)?'<div class="notice">工具报告网页访问失败。已返回工具结果，不等于成功取得网页；具体错误见下方原始返回。</div>':'';return failure+ c.execution?commandDetail(c):kv([['工具',c.title],['调用 ID',c.call],['状态',c.tag]])+section('实际返回',box(c.output||'来源未提供返回内容',true));}
function architectureTransfer(d){
 if(!d.confirmed)return empty('这条线是架构路径。本轮没有可配对的传递内容。');
 const target=d.target||{};
 if(target.blocks)return contextDetail(target);
 if(target.execution)return commandDetail(target);
 if(target.call)return toolResultDetail(target);
 if(target.response||target.toolInstructions)return modelDetail({contexts:[target],cards:[]});
 if(target.content||array(target.attachments).length)return target.content?section('接收的原始输入',box(target.content)):attachmentDetail(target.attachments);
 if(target.cards)return `<div class="event-list">${array(target.cards).map(recordButton).join('')||empty('没有关联记录')}</div>`;
 return empty('点击对应模块查看已有采集记录。');
}
function taskStateDetail(t){
 const all=cards(t),last=window.AgentReinsRuntimeGraph.nativeCalls(t).at(-1)||all.find(c=>c.id===t?.currentCardID);
 const failure=all.find(c=>c.id===t?.lastFailureCardID);
 const verification=all.filter(c=>['verify','verification'].includes(detailType(c))),as=taskArtifacts(t);
 const executionLabels={running:'进行中',stopped:'执行已停止',failed:'执行失败',cancelled:'已取消'};
 const completionLabels={unknown:'目标达成尚未确认',reported:'来源报告完成，仍需核对',verified_delivery:'交付记录与路径存在已核对（业务内容未验收）',native_goal_success:'来源提供目标验证成功事实'};
 return section('现在到哪一步',box(current(t)))+kv([['任务状态',state(t)],['执行状态',executionLabels[t?.executionState]||'来源未提供独立执行状态'],['目标达成',completionLabels[t?.completionEvidence]||'目标达成尚未确认'],['判断依据',t?.statusBasis],['原生结束时间',t?.nativeEndAt?time(t.nativeEndAt):null],['原生结束证据',t?.nativeTerminalEventID]])+
 (taskStatus(t)==='stopped'?'<div class="notice">Agent 已停止，但尚未确认完成用户目标。最后一个工具返回或进程退出均不能代替任务完成。</div>':'')+
 section('Agent 停止时的原文',t?.nativeEndMessage?box(t.nativeEndMessage):empty('来源未提供停止时的完整原文。'))+
 section('停止原因',t?.stopReason?box(t.stopReason):empty('来源未提供结构化停止原因。请核对上面的原文及最后工具返回。'))+
 section('最后一次工具执行',last?recordButton(last)+(last.execution?commandDetail(last):box(last.output||last.summary||'本条未提供返回正文',true)):empty('本轮没有可确认的最后工具调用。'))+
 (failure&&failure.id!==last?.id?section('此前的失败步骤',recordButton(failure)):'')+
 section('验证记录',verification.length?verification.map(recordButton).join(''):empty('本轮未采到验证记录。'))+
 section('实际交付物',artifactDetail(as))+`<div class="task-open-links"><button class="quiet" data-select="user">我的原话</button><button class="quiet" data-select="artifact">实际产物</button></div>`+
 (array(t?.coverage).length?section('本轮数据覆盖',coverageMarkup(t.coverage)):'');
}
function renderDetail(force=false,panel=$('detail')){
 const o=snapshot||defaultObject();if(!o)return;
 const scroll=panel.scrollTop,changed=selection&&objects.has(selection)&&revision(objects.get(selection))!==snapshotRevision;
 if(snapshot&&!force&&panel.querySelector('#detail-code')){const updated=panel.querySelector('#detail-updated');if(updated)updated.hidden=!changed;const ip=panel.querySelector('#ip-info');if(ip)ip.innerHTML=ipInfo(ip.dataset.ip,o.task?.id);return;}
 const d=o.data||{},t=o.task;let title=typeNames[o.type]||'当前任务',type=typeNames[o.type]||'任务全貌',body='';
 switch(o.type){
 case 'user':title=array(d.inputs).length>1?'用户输入 · '+d.inputs.length+' 条':array(d.attachments).length&&!d.content?'用户原始附件输入':'用户原始需求';body=inputDetail(d);break;
 case 'input-overview':title='这次任务拿到了什么';body=section('用户原始输入',inputDetail(d))+section('材料与运行环境',`<div class="event-list">${array(d.materials).map(recordButton).join('')||empty('本轮没有材料与环境记录')}</div>`);break;
 case 'context-memory':title='本轮送给模型的上下文';body=(d.exchange?contextDetail(d.exchange):empty('本次实际模型请求未采到'))+section('长期记忆访问',`<div class="event-list">${array(d.memories).map(recordButton).join('')||empty('本轮尚未观察到记忆访问；不能据此声称使用了长期记忆。')}</div>`);break;
 case 'branch':title='下一步选择依据';body=d.exchange?kv([['请求',d.exchange.id],['响应',d.exchange.responseID],['本次下发工具指令',array(d.instructions).length]])+section('模型实际返回',box(d.exchange.response||'响应尚未配对'))+section('实际工具指令',box(d.exchange.toolInstructions||'本次没有可得工具指令',true)):empty('模型实际响应未采到，不能推测分支。');break;
 case 'reply':title='模型输出';body=(d.replyText?section(t?.nativeEndMessage?'原生任务结束时的答复':d.exchange?.response?'所选模型往返的实际输出':'本地采到的实际答复（模型往返未配对）',box(d.replyText)):empty('本次模型返回未采到'))+`<p class="notice">模型回复和工具结束均不自动代表用户目标已完成。当前任务：${esc(state(t))}</p>`;break;
 case 'context':title=d.structured?'送给模型的实际上下文':'本地输入片段';body=contextDetail(d);break;
 case 'transfer':title=d.title;body=kv([['关系',d.confirmed?'原生标识已配对':'关系尚未确认'],['依据',d.basis],['证据 ID',array(d.eventIDs).join('\n')]])+(d.sourceContent?section(d.sourceLabel||'发送内容',box(d.sourceContent,true)):'')+(d.targetType==='architecture-path'?architectureTransfer(d):d.targetType==='context'?contextDetail(d.target):d.targetType==='tool-result'?toolResultDetail(d.target):d.target?.execution?commandDetail(d.target):section('实际调用参数',box(d.target?.input||'未取得参数',true))+section('实际返回',box(d.target?.output||'未取得返回',true)));break;
 case 'tool-result':title=d.title+' · 实际返回';body=toolResultDetail(d);break;
 case 'observation':title='执行现场：进程、文件与网络';body=section('系统进程观察',`<div class="process-list">${array(d.processes).map(processButton).join('')||empty('未取得应用进程记录')}</div>`)+section('文件与网络记录',`<div class="event-list">${array(d.cards).map(recordButton).join('')||empty('本轮没有对应资源记录')}</div>`);break;
 case 'model':title='Agent 与大模型的往返';body=modelDetail(d);break;
 case 'command':title=d.title||'实际命令';body=commandDetail(d);break;
 case 'files':title=d.resource?.path||d.title||'文件行为';body=filesDetail(d);break;
 case 'web':case 'network':title=d.resource?.domain||d.title||'网络资源';body=networkDetail(d,t);break;
 case 'stage':{const s=d;title=stageNames.find(([id])=>id===s.id)?.[1]||s.title;const cs=cards(t).filter(c=>array(s.cardIDs).includes(c.id)||stageFor(c)===s.id);if(s.id==='user'){body=inputDetail(inputData(t));}else if(s.id==='context'){const contexts=taskContexts(t);body=contexts.length?contexts.map(c=>`<button class="event-item" data-context="${esc(c.id)}">请求 ${esc(time(c.timestamp))}<small>${array(c.blocks).length} 块 · ${esc(c.coverage)}</small></button>`).join(''):empty('本轮没有结构化上下文记录。');}else if(s.id==='model'){body=modelDetail({contexts:taskContexts(t),cards:cs});}else if(s.id==='artifact'){body=artifactDetail(taskArtifacts(t));}else{body=`<p class="detail-intro">${esc(s.summary||'本轮无对应记录')}</p><div class="event-list">${cs.map(recordButton).join('')||empty('当前环节没有可确认的执行记录。')}</div>`;}break;}
 case 'group':{title=({files:'本轮文件与变化',network:'本轮访问的网络资源',mcp:'Skill、MCP 与工具',plan:'计划与调度',verify:'验证记录',approval:'等待你确认',environment:'材料与运行环境',memory:'实际记忆访问',command:'代码与命令',database:'数据库访问',external:'外部服务'})[d.stage]||'任务记录';body=`<div class="event-list">${array(d.cards).map(recordButton).join('')||empty('本轮尚无已确认关联记录。')}</div>${array(d.observations).length?section('同Agent独立网络观察 · 尚未归属本任务',array(d.observations).map(r=>`<button class="event-item" data-select="record:${esc(r.id)}">${esc(r.resource?.domain||r.resource?.observedRemoteHost||r.title)}<small>PID ${esc(r.pid)} · ${esc(time(r.timestamp))} · 点击查看连接与代理目标</small></button>`).join('')):''}`;break;}
 case 'process-group':title='应用进程与执行器观察';body=`<div class="process-list">${array(d.processes).map(processButton).join('')||empty('尚未发现关联应用进程。')}</div><p class="note">应用父子进程关系单独保留。执行器归属需要原生执行身份，不能只凭时间接入任务。</p>`;break;
 case 'process':title=d.name||'进程观察';body=kv([['PID',d.pid],['父 PID',d.parent],['状态',d.active===false?'已移出观察':'当前可见'],['出生身份',d.id],['可执行路径',d.executable],['命令',d.command]])+'<p class="note">本面板是系统观察，不等于某次工具调用的执行器已确认。</p>';break;
 case 'network-record':title=d.resource?.domain||d.title||'独立网络观察';body='<p class="notice">这条连接已采到，当前尚未确认它属于哪个任务或工具。</p>'+networkDetail({...d,input:d.preview||d.details,output:'',basis:d.resource?.basis},null);break;
 case 'record':title=d.title||d.op;body=kv([['来源',d.source],['类别',d.category||d.kind],['Agent',d.agent],['采集时间',d.timestamp?time(d.timestamp):null],['PID',d.pid],['任务身份',d.hasTaskIdentity?'来源提供会话 / 轮次标识':d.session?'仅会话已知，轮次未关联':'任务未关联']])+section('实际记录',box(d.summary))+section('采集详情',box(d.details||d.preview||'本条没有内容正文',true));break;
 case 'health':title=d.source;body=kv([['来源状态',d.state],['来源累计接收',d.accepted]])+box(d.detail||'来源未提供详细状态')+'<p class="note">来源累计计数覆盖本次采集管道，不等于当前任务的记录数量。</p>';break;
 case 'artifact':title='本轮交付物';body=artifactDetail(array(d.artifacts))+(t&&taskStatus(t)==='completed'&&!read(t)?`<div class="task-open-links"><button class="quiet" data-read-task="${esc(t.id)}">标记已读</button><span class="note">已读仅表示查看，不代表验收认可。</span></div>`:'')+`<div class="task-open-links"><button class="link-button" data-action="refresh-artifacts">重新核对产物状态</button></div>`;break;
 case 'artifact-item':title=d.name||'实际产物';body=artifactDetail([d]);break;
 case 'agent':title='任务是否真的完成';body=taskStateDetail(t);break;
 default:title=d.title||typeNames[o.type]||'实际工具';body=(d.summary?`<p class="detail-intro">${esc(d.summary)}</p>`:'')+section(o.type==='plan'?'实际计划 / 调度内容':'实际调用参数',box(d.input||'来源未提供参数',true))+section(o.type==='failure'?'原因 / 返回':o.type==='verify'?'实际验证返回':'实际返回',box(d.output||'尚未取得返回',true));
 }
 if(t && (o.type==='group'&&['external','network'].includes(d.stage)||d.resource?.domain||d.resource?.remoteIP||o.type==='web'||o.type==='network')) body='<button class="quiet" data-network-scope="'+esc(t.id)+'">查看此任务的外网数据交互</button>'+body;
 if(array(d.codeFindings).length)body=section('代码安全 · '+d.codeFindings.length+' 项待核查', '<p>基于本次已采代码的规则检测，不代表漏洞已确认；行号对应采集片段。</p>'+array(d.codeFindings).map(f=>'<div class="event-item"><strong>'+esc(f.title)+'</strong><p>'+esc(f.severity)+' · 第 '+esc(f.line)+' 行 · '+esc(f.ruleId)+'</p>'+box(f.evidence,true)+'</div>').join(''))+body;
 panel.innerHTML=`<div class="detail-kicker" id="detail-type">${esc(type)}</div><div class="detail-title-row"><h2 id="detail-title">${esc(title)}</h2>${d.tag?badge(d.tag):''}</div>${snapshot?'<div class="detail-controls"><span class="read-lock">已固定查看对象 · 主图继续更新</span><button class="updated" id="detail-updated" '+(changed?'':'hidden')+'>有新内容，点击更新</button><button class="link-button" data-action="follow-current">跟随当前步骤</button></div>':''}<div id="detail-code">${body}</div>${evidence(o)}`;
 panel.scrollTop=scroll;
}
function processButton(p){return `<button class="process-item ${p.active===false?'inactive':''}" data-select="process:${esc(p.id)}" style="padding-left:${Math.min(Number(p.depth)||0,8)*12}px"><b>${esc(p.name)}</b> · PID ${esc(p.pid)}<small>父 PID ${esc(p.parent)} · ${p.active===false?'已移出观察':'当前可见'}</small><small>${esc(p.executable)}</small></button>`;}
function coverageMarkup(coverage){return `<div class="coverage-grid">${array(coverage).map(c=>`<div class="coverage-cell ${esc(c.status)}">${esc(c.category)} · ${esc(c.count)}<small>${esc(c.status==='captured'?'已有记录':c.status==='partial'?'部分覆盖':'尚未采到')} · ${esc(c.detail)}</small></div>`).join('')}</div>`;}
function collectionType(r){if(r.kind==='network'||/socket|communication|ipc/.test(r.op||''))return 'network';if(r.kind==='file'||r.kind==='memory')return 'file';if((r.source||'').includes('process'))return 'process';if((r.source||'').includes('hook')||r.kind==='tool')return 'hook';if(r.kind==='model'||(r.source||'').includes('network-body'))return 'model';return 'other';}
function renderCollection(){
 const records=shown.collected,filtered=records.filter(r=>collectionFilter==='all'||collectionFilter==='unassigned'&&!r.hasTaskIdentity||collectionType(r)===collectionFilter);
 $('collection-view').innerHTML=`<div class="collection-grid">${shown.health.map(h=>`<button class="source-card ${/error|failed|degraded/i.test(h.state)?'partial':''}" data-select="health:${esc(h.source)}"><strong>${esc(h.source)}</strong><span class="source-state">${esc(h.state)}</span><span class="source-count">${esc(h.accepted)}</span><p>${esc(h.detail||'来源没有附加说明')}</p></button>`).join('')||empty('采集源健康状态尚未提供。')}</div><div class="collection-body"><section class="collection-box"><h2>应用与执行进程树</h2><div class="process-list">${shown.processes.map(processButton).join('')||empty('尚未发现应用进程。')}</div><div class="notice">进程、文件与网络独立采样，不依赖会话日志。未确认任务归属的活动继续保留。</div>${task()?section('当前选定任务的数据覆盖',coverageMarkup(task().coverage)):''}</section><section class="collection-box"><h2>最新采集记录</h2><div class="collection-toolbar"><select class="compact-select" id="collection-filter" aria-label="筛选采集记录">${[['all','全部来源'],['unassigned','任务未关联'],['model','模型正文'],['hook','工具 / Hook'],['process','进程'],['file','文件'],['network','网络 / IPC'],['other','其他']].map(([k,v])=>`<option value="${k}" ${collectionFilter===k?'selected':''}>${v}</option>`).join('')}</select><span class="hint-line">缓存 ${esc(shown.collectedCount??records.length)} 条 · 展示 ${records.length} 条 · 网络单独保留 · 待归属 ${esc(shown.unattributedCount||0)} 条</span></div><div class="collection-records">${filtered.map(r=>`<button class="collection-record" data-select="record:${esc(r.id)}">${esc(r.title||r.op)}<small>${esc(cut(r.summary,140))}</small><small>${esc(r.source)} · ${esc(r.agent)} · ${r.hasTaskIdentity?'来源提供任务标识':r.session?'会话已知 / 轮次未关联':'任务未关联'}</small></button>`).join('')||empty('当前筛选无记录。')}</div></section></div><div class="process-layout" style="margin-top:18px;display:block"><aside id="collection-detail" class="detail-panel" style="border:0"><p class="empty">点击来源、进程或记录，查看实际详情。</p></aside></div>`;
}
function boardCard(t){const as=taskArtifacts(t);return `<button class="board-card" data-board-task="${esc(t.id)}"><small>${esc(t.agent)} · ${esc(time(t.lastActivity))}</small><strong>${esc(cut(taskLabel(t),110))}</strong><p>${esc(current(t))}</p><div class="artifact-chip">${esc(taskStatus(t)==='completed'?as.length?as.map(a=>a.name).join(' · ')+' →':'完成记录已收到 · 交付物待核对':taskStatus(t)==='stopped'?'查看停止原文、最后一步与未完成事项 →':taskStatus(t)==='awaiting_confirmation'?'查看当前等待记录 →':taskStatus(t)==='failed'?'查看失败原因与执行返回 →':'定位当前步骤 →')}</div></button>`;}
function renderBoard(){const ts=listTasks(),columns=[['awaiting_confirmation','等我确认'],['running','进行中'],['stopped','已停止 · 交付未确认'],['completed','已完成未读'],['failed','失败']];$('result-screen').innerHTML=`<div class="board-summary"><span>${ts.length} 个带任务身份的任务</span><span>已识别产物 ${shown.artifacts.length} 项</span><span>工具调用显示在任务内部</span></div><div class="board">${columns.map(([status,title])=>{const list=ts.filter(t=>taskStatus(t)===status&&(status!=='completed'||!read(t)));return `<section class="board-column kanban-column" data-status="${status}"><div class="board-head"><i class="status-dot ${status}"></i>${title}<span>${list.length}</span></div>${list.map(boardCard).join('')||empty('当前没有此状态任务')}</section>`;}).join('')}</div>${[['observed','状态待确认'],['cancelled','已取消'],['read','已完成已读']].map(([status,title])=>{const list=ts.filter(t=>status==='read'?taskStatus(t)==='completed'&&read(t):taskStatus(t)===status);return `<details class="board-extra"><summary>${title} · ${list.length}</summary><div class="board-extra-list">${list.map(boardCard).join('')||empty('当前无此状态任务')}</div></details>`;}).join('')}`;}
function collectorPhrase(){
 if(paused)return '画面已暂停 · 采集继续';
 const health=array(shown.health);
 const proxy=health.find(h=>/workbuddy-network|proxy|mitm/i.test(String(h.source||'')));
 const detail=String(proxy?.detail||'');
 const proxyFailed=!!(proxy&&(/failed|error/i.test(String(proxy.state||''))||/failed to bind/i.test(detail)));
 const proxyUp=!!(proxy&&!proxyFailed&&(/healthy|degraded|running|listening/i.test(String(proxy.state||''))||(/\b18891\b/.test(detail)&&/running|listening|records received|proxy is running/i.test(detail))));
 const otherFailed=health.some(h=>h!==proxy&&/failed|error/i.test(String(h.state||'')));
 if(proxyFailed)return '代理异常';
 if(otherFailed)return '采集有异常';
 if(shown.observing||proxyUp||health.some(h=>h.state==='healthy'))return proxyUp?'代理在线 · 正在监看':'采集进行中';
 if(health.length)return '已收到采集源状态';
 return '采集未启动';
}
function ensureReviewDecisions(){
 if(riskState.decisionsLoaded)return;
 const handler=window.webkit?.messageHandlers?.agentreins;
 if(!handler){riskState.decisionsLoaded=true;return;}
 handler.postMessage({action:'loadReviewDecisions'});
 riskState.decisionsLoaded=true;
}
function requestRiskTransports(){
 if(riskState.transportsRequested)return;
 if(typeof window.agentreinsLoadLocalTransports!=='function')return;
 const handler=window.webkit?.messageHandlers?.agentreins;
 if(!handler&&location.protocol==='file:')return;
 riskState.transportsRequested=true;
 window.agentreinsLoadLocalTransports();
 // Retry once if the host ignored an early call (payload not ready yet).
 setTimeout(()=>{
  if((window.AgentReinsNetwork?.localExchanges?.()||[]).length)return;
  riskState.transportsRequested=false;
  if(typeof window.agentreinsLoadLocalTransports==='function'){
   riskState.transportsRequested=true;
   window.agentreinsLoadLocalTransports();
  }
 },1500);
}
function renderRisk(){
 const api=window.AgentReinsRisk;if(!api){$('alerts-view').innerHTML=empty('风险告警模块未加载。');return;}
 ensureReviewDecisions();
 if(view==='alerts'||view==='rules'||view==='coverage')requestRiskTransports();
 if(view==='alerts')api.renderList($('alerts-view'),shown,riskState);
 else if(view==='rules')api.renderRules($('rules-view'),shown);
 else if(view==='coverage')api.renderCoverage($('coverage-view'),shown);
 const n=(riskState.alerts||api.applyDecisions?.(api.buildAlerts(shown),riskState.decisions)||api.buildAlerts(shown)||[]).filter(a=>a.status==='todo'||a.status==='ask').length;
 const badge=$('alert-badge');if(badge){badge.hidden=!n;badge.textContent=String(n);}
}
window.agentreinsRenderRisk=()=>{if(view==='alerts'||view==='rules'||view==='coverage'){riskState.transportsRequested=true;renderRisk();}};
function render(animate=false){
 if(following)taskID=newest();if(task()?.detailsLoaded===false)requestTask(taskID);rebuildObjects();renderTasks();renderHeading();
 document.querySelectorAll('nav [data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===view));
 $('view-name').textContent=window.agentreinsCommandsOpen?'命令外联':{alerts:'风险告警',network:'外网访问',process:'任务过程',collection:'采集现场',rules:'规则',coverage:'覆盖度',results:'结果看板'}[view]||'风险告警';
 $('alerts-view').hidden=view!=='alerts';$('rules-view').hidden=view!=='rules';$('coverage-view').hidden=view!=='coverage';
 $('network-view').hidden=view!=='network';
 $('process-view').hidden=view!=='process';$('collection-view').hidden=view!=='collection';$('result-screen').hidden=view!=='results';
 if($('heading'))$('heading').hidden=['alerts','rules','coverage'].includes(view);
 $('live-label').textContent=collectorPhrase();$('pause').textContent=paused?'恢复画面':'暂停画面';
 $('follow-latest').textContent=following?'正在跟随最新任务':'跟随最新任务';
 const warning=[shown.persistenceError&&'证据保存异常：'+shown.persistenceError,shown.truncated&&'先前展示发生过容量截断；早期任务可能缺少证据，不能据此确认完整性。'].filter(Boolean).join(' · ');$('workspace-warning').hidden=!warning&&!shown.continuityNotice;$('workspace-warning').textContent=[warning,shown.continuityNotice].filter(Boolean).join(' · ');
 $('footer-state').textContent=`${shown.publishedAt?'更新 '+time(shown.publishedAt)+' · ':''}${paused?'画面固定，采集继续':'真实采集数据'} · 当前任务 ${primaryTasks().length} 个`;
 if(view==='alerts'||view==='rules'||view==='coverage')renderRisk();
 else if(view==='process'){if($('collection-detail'))$('collection-detail').innerHTML='';const vacant=!task();if($('empty-guide'))$('empty-guide').hidden=!vacant;if($('graph-screen'))$('graph-screen').hidden=vacant;if(!vacant){renderStages();renderGraph(animate);renderTimeline();renderDetail();}else{$('stages').innerHTML='';$('detail').innerHTML='';}}
 else if(view==='collection'){$('detail').innerHTML='';renderCollection();if(snapshot)renderCollectionDetail();}
 else if(view==='network')renderNetwork();
 else if(view==='results')renderBoard();
 if(view!=='alerts'&&view!=='rules'&&view!=='coverage'&&window.AgentReinsRisk){const n=window.AgentReinsRisk.buildAlerts(shown).filter(a=>a.status==='todo'||a.status==='ask').length;const badge=$('alert-badge');if(badge){badge.hidden=!n;badge.textContent=String(n);}}
 if(view==='process'&&task()?.detailsLoaded===false){$('current-bar').textContent='正在读取该任务的完整执行证据…';$('detail').innerHTML=empty('正在读取任务详情，采集继续。');}
}
function renderNetwork(){if(networkTask&&shown.tasks.find(t=>t.id===networkTask)?.detailsLoaded===false)requestTask(networkTask);const focused=document.activeElement?.id==='network-search',position=focused?document.activeElement.selectionStart:null;window.AgentReinsNetwork.render($('network-view'),shown,{agent:networkAgent,query:networkQuery,taskOnly:networkTask,selected:networkSelected,focusTask:taskID});if(focused){$('network-search').focus();$('network-search').setSelectionRange(position,position);}}
window.agentreinsRenderNetwork=()=>{if(view==='network')renderNetwork();};
function renderCollectionDetail(){const holder=$('collection-detail');if(holder&&snapshot)renderDetail(true,holder);}
addEventListener('agentreins-layout',()=>renderGraph(false));
function rememberTask(task,contexts){hydratedTasks.delete(task.id);hydratedTasks.set(task.id,{task,contexts});while(hydratedTasks.size>5)hydratedTasks.delete(hydratedTasks.keys().next().value);pendingTasks.delete(task.id);}
function sameTaskOwner(a,b){return a&&b&&['agent','session','turn'].every(k=>typeof a[k]==='string'&&a[k]===b[k]);}
function cachedTaskAhead(header,cached){return cached&&typeof cached.task.previewBaseRevision==='string'&&cached.task.previewBaseRevision===header.projectionRevision&&cached.task.projectionRevision!==header.projectionRevision;}
function cachedTaskFits(header,cached){return cached&&header.id===cached.task.id&&sameTaskOwner(header,cached.task)&&(cached.task.projectionRevision===header.projectionRevision||cachedTaskAhead(header,cached));}
function fillCachedTask(header,cached){
 if(cached.task.projectionRevision!==header.projectionRevision)return {...cached.task,detailsLoaded:true};
 return {...cached.task,...header,cards:cached.task.cards,detailsLoaded:true,previewBaseRevision:null,detailFreshness:null};
}
function receive(payload){
 const incoming=normalize(payload||{});
 if(Array.isArray(incoming.collectedOrder)){
  for(const r of incoming.collected)collectedCache.set(r.id,r);
  const order=new Set(incoming.collectedOrder);
  for(const id of collectedCache.keys())if(!order.has(id))collectedCache.delete(id);
  incoming.collected=incoming.collectedOrder.map(id=>collectedCache.get(id)).filter(Boolean);
  if(incoming.collected.length!==incoming.collectedOrder.length)bridge('refreshCollected',{});
 }else{
  collectedCache.clear();for(const r of incoming.collected)collectedCache.set(r.id,r);
 }

 const delta=incoming.detailDelta;
 if(delta){
  const t=incoming.tasks.find(t=>t.id===delta.taskID),cached=hydratedTasks.get(delta.taskID);
  if(t&&cached?.task.projectionRevision===delta.baseRevision){
   const cards=new Map(cached.task.cards.map(c=>[c.id,c])),contexts=new Map(cached.contexts.map(c=>[c.id,c]));
   for(const c of t.cards)cards.set(c.id,c);for(const c of incoming.contexts)contexts.set(c.id,c);
   t.cards=delta.cardOrder.map(id=>cards.get(id)).filter(Boolean);incoming.contexts=delta.contextOrder.map(id=>contexts.get(id)).filter(Boolean);
   if(t.cards.length!==delta.cardOrder.length||incoming.contexts.length!==delta.contextOrder.length){t.cards=[];t.detailsLoaded=false;incoming.contexts=[];bridge('selectTask',{taskID:delta.taskID});}
  }else{if(t){t.cards=[];t.detailsLoaded=false;}incoming.contexts=[];bridge('selectTask',{taskID:delta.taskID});}
 }
 for(const t of incoming.tasks)if(t.detailsLoaded!==false){const cached=hydratedTasks.get(t.id);if(!(cachedTaskFits(t,cached)&&cachedTaskAhead(t,cached)))rememberTask(t,incoming.contexts.filter(c=>c.agent===t.agent&&c.session===t.session&&c.turn===t.turn));}
 incoming.tasks=incoming.tasks.map(t=>{const cached=hydratedTasks.get(t.id);return cachedTaskFits(t,cached)&&(t.detailsLoaded===false||cachedTaskAhead(t,cached))?fillCachedTask(t,cached):t;});
 const contexts=new Map(incoming.contexts.map(c=>[c.id,c]));
 for(const t of incoming.tasks){const cached=hydratedTasks.get(t.id);if(cachedTaskFits(t,cached))for(const c of cached.contexts)if(!contexts.has(c.id))contexts.set(c.id,c);}
 incoming.contexts=[...contexts.values()];latest=incoming;
 if(paused){
  let filled=false;
  const tasks=shown.tasks.map(t=>{const cached=hydratedTasks.get(t.id);if(t.detailsLoaded===false&&cached?.task.projectionRevision===t.projectionRevision){filled=true;return {...cached.task,...t,cards:cached.task.cards,detailsLoaded:true};}return t;});
  if(filled){const oldContexts=new Map(shown.contexts.map(c=>[c.id,c]));for(const t of tasks){const cached=hydratedTasks.get(t.id);if(cached?.task.projectionRevision===t.projectionRevision)for(const c of cached.contexts)if(!oldContexts.has(c.id))oldContexts.set(c.id,c);}shown={...shown,tasks,contexts:[...oldContexts.values()]};render(false);}
  return;
 }
 shown=latest;render(true);
 if(pendingOpenKey&&objects.has(pendingOpenKey)&&task()?.detailsLoaded!==false){const key=pendingOpenKey;pendingOpenKey=null;choose(key);}
}
async function requestTask(id){
 if(!id||pendingTasks.has(id)||!latest.lazyTasks)return;
 pendingTasks.add(id);
 const handler=window.webkit?.messageHandlers?.agentreins;
 if(handler){handler.postMessage({action:'selectTask',taskID:id});return;}
 const expected=(paused?shown:latest).tasks.find(t=>t.id===id)?.projectionRevision;
 try{
  const response=await fetch('/task.json?id='+encodeURIComponent(id)+'&revision='+encodeURIComponent(expected||''),{cache:'no-store',signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw Error('任务详情暂时不可读取');
  const detail=await response.json();
  const header=(paused?shown:latest).tasks.find(t=>t.id===id);
  if(detail.task?.id!==id||header?.projectionRevision!==expected||!sameTaskOwner(header,detail.task))return;
  const contexts=array(detail.contexts);
  if(contexts.some(c=>!sameTaskOwner(c,detail.task)))throw Error('上下文与任务归属不一致');
  if(detail.task.projectionRevision!==expected){
   if(paused||detail.previewTaskExport?.state!=='ahead_of_snapshot'||detail.previewTaskExport.snapshotRevision!==expected){if(taskID===id||networkTask===id)toast(paused?'该任务已有新记录，恢复画面后可读取最新详情。':'任务详情正在同步，请稍后重试。');return;}
   detail.task={...detail.task,previewBaseRevision:expected,detailFreshness:'ahead_of_snapshot',detailsLoaded:true};
   latest={...latest,tasks:latest.tasks.map(t=>t.id===id?detail.task:t),contexts:latest.contexts.filter(c=>!sameTaskOwner(c,detail.task)).concat(contexts)};
  }
  rememberTask(detail.task,contexts);receive(latest);
 }catch(error){if(taskID===id)toast('读取任务详情失败：'+error.message);}finally{pendingTasks.delete(id);}
}
window.agentreinsReceive=receive;
window.agentreinsHostResult=result=>{
 if(result?.action==='reviewDecisions'&&Array.isArray(result.decisions)){
  riskState.decisions=result.decisions;riskState.decisionsLoaded=true;
  if(view==='alerts'||view==='rules'||view==='coverage')renderRisk();
 }
 if(result?.message)toast(result.message);
 if(view==='collection')renderCollectionDetail();else if(view==='process')renderDetail(true);
};
document.addEventListener('click',e=>{
 const el=e.target.closest('button');if(!el)return;
 if(el.hasAttribute('data-graph-focus')){window.AgentReinsFlow.focus();}
 else if(el.dataset.action==='toggle-details'){const collapsed=document.body.classList.toggle('details-collapsed');$('toggle-details').textContent=collapsed?'显示详情':'收起详情';}
 else if(el.dataset.zoom){window.AgentReinsFlow.zoom(el.dataset.zoom);}
 else if(el.dataset.view){window.agentreinsCommandsOpen=false;const audit=document.querySelector('.transport-audit');if(audit)audit.hidden=true;view=el.dataset.view;if(view==='network'){networkTask=null;riskState.transportsRequested=false;window.agentreinsLoadLocalTransports?.();}if(view==='alerts'||view==='rules'||view==='coverage')riskState.transportsRequested=false;render();}
 else if(el.dataset.graphMode){graphMode=el.dataset.graphMode;renderGraph();}
 else if(el.dataset.networkScope){networkTask=el.dataset.networkScope;taskID=networkTask;following=false;networkQuery='';networkSelected=null;view='network';if(shown.tasks.find(t=>t.id===networkTask)?.detailsLoaded===false)requestTask(networkTask);render();}
 else if(el.hasAttribute('data-network-all')){networkTask=null;renderNetwork();}
 else if(el.dataset.networkRecord){networkSelected=networkSelected===el.dataset.networkRecord?null:el.dataset.networkRecord;renderNetwork();const opened=$('network-view')?.querySelector('.network-read');if(opened)opened.scrollIntoView({block:'nearest'});}
 else if(el.dataset.networkIp){bridge('resolveNetworkIP',{recordID:el.dataset.networkId,ip:el.dataset.networkIp});}
 else if(el.dataset.networkTask){selectTask(el.dataset.networkTask);}
 else if(el.dataset.task)selectTask(el.dataset.task);
 else if(el.dataset.boardTask){const t=shown.tasks.find(t=>t.id===el.dataset.boardTask);selectTask(t.id,taskStatus(t)==='completed'?'artifact':taskStatus(t)==='stopped'?'closure':t.currentCardID?'card:'+t.currentCardID:null);}
 else if(el.dataset.timeline){timelineMode=el.dataset.timeline;renderTimeline();}
 else if(el.dataset.action==='follow-cycle'){runtimeExchangeID=null;runtimeCallID=null;selection=null;snapshot=null;render();}
 else if(el.dataset.select){choose(el.dataset.select);if(view==='collection')renderCollectionDetail();}
 else if(el.dataset.runtimeExchange){runtimeExchangeID=el.dataset.runtimeExchange;runtimeCallID=null;selection=null;snapshot=null;render();choose('model');}
 else if(el.dataset.context){const c=shown.contexts.find(c=>c.id===el.dataset.context);if(c){const o=object('context:'+c.id,'context',c);selection=o.key;snapshot=clone(o);snapshotRevision=revision(o);contextBlockID=null;renderDetail(true);}}
 else if(el.dataset.block){contextBlockID=el.dataset.block;renderDetail(true);}
 else if(el.dataset.tab){detailTab=el.dataset.tab;renderDetail(true);}
 else if(el.dataset.resolveIp){bridge('resolveIP',{taskID:el.dataset.ipTask,ip:el.dataset.resolveIp});}
 else if(el.dataset.readTask){bridge('markRead',{taskID:el.dataset.readTask});}
 else if(el.dataset.action==='refresh-artifacts'){bridge('refreshArtifacts',{});}
 else if(el.dataset.openArtifact){bridge('openArtifact',{taskID:el.dataset.artifactTask,artifactID:el.dataset.openArtifact});}
 else if(el.id==='detail-updated'){refreshDetail();}
 else if(el.dataset.action==='follow-current'){runtimeExchangeID=null;runtimeCallID=null;selection=null;snapshot=null;contextBlockID=null;render();}
 else if(el.id==='follow-latest'){runtimeExchangeID=null;runtimeCallID=null;following=true;selection=null;snapshot=null;render();}
 else if(el.id==='pause'){paused=!paused;if(!paused)shown=latest;render();}
 else if(el.dataset.riskAlert){riskState.selected=el.dataset.riskAlert;renderRisk();}
 else if(el.dataset.riskFilter){riskState.filter[el.dataset.riskFilter]=el.dataset.riskValue;riskState.selected=null;renderRisk();}
 else if(el.dataset.riskDecide){
  const api=window.AgentReinsRisk;const alert=(riskState.alerts||[]).find(a=>a.id===el.dataset.riskId)||api?.buildAlerts?.(shown)?.find(a=>a.id===el.dataset.riskId);
  if(!alert){toast('找不到这条告警');return;}
  const evidenceText=api?.evidenceTextFor?.(alert)||'';
  bridge('saveReviewDecision',{id:alert.id,state:el.dataset.riskDecide,note:'',evidenceText,evidenceCount:evidenceText.length});
  riskState.selected=alert.id;
 }
 else if(el.dataset.riskExport){
  const api=window.AgentReinsRisk;const alert=(riskState.alerts||[]).find(a=>a.id===el.dataset.riskExport);
  if(!alert||!api?.packFields){toast('找不到这条告警');return;}
  bridge('exportEvidencePack',api.packFields(alert));
 }
 else if(el.dataset.networkRecordJump){networkSelected=el.dataset.networkRecordJump||null;view='network';render();}
});
document.addEventListener('input',e=>{if(e.target.id==='network-search'){const position=e.target.selectionStart;networkQuery=e.target.value;renderNetwork();const input=$('network-search');input.focus();input.setSelectionRange(position,position);}else if(e.target.id==='risk-search'){riskState.filter.q=e.target.value;renderRisk();}});
document.addEventListener('change',e=>{if(e.target.id==='network-agent'){networkAgent=e.target.value;renderNetwork();return;}if(e.target.id==='runtime-exchange'){runtimeExchangeID=e.target.value||null;runtimeCallID=null;selection=null;snapshot=null;render();if(runtimeExchangeID&&objects.has('model'))choose('model');}else if(e.target.id==='runtime-call'){runtimeCallID=e.target.value||null;selection=null;snapshot=null;render();if(runtimeCallID)choose('card:'+runtimeCallID);}else if(e.target.id==='collection-filter'){collectionFilter=e.target.value;renderCollection();}});
$('search').oninput=e=>{query=e.target.value;renderTasks();};$('agent-filter').onchange=e=>{agentFilter=e.target.value;if(following)taskID=newest();render();};
const initialParams=new URLSearchParams(location.search),initialView=initialParams.get('view');if(['alerts','process','collection','results','network','rules','coverage'].includes(initialView))view=initialView;const initialTask=initialParams.get('task');if(view==='network'&&initialTask&&initialTask.length<=4096){networkTask=initialTask;taskID=initialTask;following=false;}render();
})();
