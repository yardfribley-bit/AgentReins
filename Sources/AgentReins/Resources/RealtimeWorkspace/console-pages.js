'use strict';
(()=>{
const list=v=>Array.isArray(v)?v:[];
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
const cut=(s,n=96)=>{const a=Array.from(String(s??''));return a.slice(0,n).join('')+(a.length>n?'…':'');};
const time=v=>{const d=new Date(v);return isNaN(d)?'—':d.toLocaleTimeString('zh-CN',{hour12:false});};
const CRED=/(\.ssh\/|\/\.aws\/|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json|\.pem$|secrets?\.)/i;

function tasksOf(payload){return list(payload?.tasks);}
function fileRows(payload){
 const rows=[];
 for(const t of tasksOf(payload)){
  for(const c of list(t.cards)){
   const kind=String(c.kind||c.detailType||'');
   const path=c.resource?.path||'';
   const diff=c.resource?.diff||'';
   const before=c.resource?.before||'';
   const after=c.resource?.after||'';
   const fileKind=/^(files|file|skill)$/.test(kind)||!!(diff||before||after);
   if(!fileKind||(!path&&!diff&&!before&&!after))continue;
   rows.push({
    id:String(c.id||path||rows.length),
    path:path||'路径未采到',
    op:c.title||kind,
    agent:t.agent||'未对上 Agent',
    session:t.session||t.id||'',
    taskId:t.id,
    call:c.call||null,
    at:c.timestamp,
    confidence:c.confidence||'unknown',
    basis:c.basis||'',
    diff,before,after,
    diffTruncated:!!c.resource?.diffTruncated,
    findings:list(c.codeFindings),
    source:'task-card'
   });
  }
 }
 for(const r of list(payload?.collected)){
  if(String(r.kind||'')!=='file')continue;
  const path=(String(r.details||'').match(/路径：(.+)/)||[])[1]||r.title||'';
  rows.push({
   id:'collected:'+String(r.id||rows.length),
   path:path||'路径未采到',
   op:r.op||r.title||'file',
   agent:r.agent||'归属未确认',
   session:r.session||'',
   taskId:null,
   call:r.call||null,
   at:r.timestamp,
   confidence:r.hasTaskIdentity?'explicit':'unknown',
   basis:r.hasTaskIdentity?'采集记录带会话和轮次':'任务未关联',
   diff:'',before:'',after:r.preview||'',
   diffTruncated:false,
   findings:[],
   source:'collected'
  });
 }
 const seen=new Set();
 return rows.filter(r=>{if(seen.has(r.id))return false;seen.add(r.id);return true;})
  .sort((a,b)=>new Date(b.at)-new Date(a.at));
}
function assocOf(row){
 const c=String(row.confidence||'');
 if(c==='explicit'||c==='confirmed')return {name:'按执行编号',kind:'by-call',note:row.basis||'来源标明了归属'};
 if(c==='inferred'||c==='candidate')return {name:'候选',kind:'candidate',note:row.basis||'不是按执行编号对上的'};
 return {name:'缺口',kind:'gap',note:row.basis||'归属没有采到'};
}
function fileAlertRows(payload){
 const files=fileRows(payload);
 const byPath=new Map(files.filter(f=>f.path).map(f=>[f.path,f]));
 const out=[];
 for(const a of list(window.AgentReinsRisk&&window.AgentReinsRisk._lastAlerts)){
  const path=a.evidence&&a.evidence.path;
  if(!path)continue;
  out.push({kind:'alert',id:a.id,rule:a.rule,title:a.title,path,agent:a.agent,at:a.timestamp,why:a.why||'',fileId:(byPath.get(path)||{}).id||null,severity:a.severity||''});
 }
 for(const f of files){
  for(const finding of f.findings){
   out.push({kind:'finding',id:'finding:'+f.id+':'+(finding.ruleId||finding.title||f.path),rule:finding.ruleId||'代码发现',title:finding.title||finding.ruleId||'代码发现',path:f.path,agent:f.agent,at:f.at,why:finding.evidence||'来自文件卡片上已有的代码发现',fileId:f.id,severity:finding.severity||''});
  }
 }
 return out;
}
function renderFiles(holder,payload,state){
 const rows=fileRows(payload);
 const selected=rows.find(r=>r.id===(state?.fileId))||null;
 const alerts=list(window.AgentReinsRisk?._lastAlerts);
 const table=rows.length?`<table class="risk-table"><thead><tr><th>路径</th><th>操作</th><th>Agent</th><th>关联</th><th>时间</th></tr></thead><tbody>${rows.map(r=>{
  const a=assocOf(r);
  const sens=CRED.test(r.path);
  return `<tr class="${selected&&selected.id===r.id?'sel':''}"><td><button type="button" class="risk-link" data-file-id="${esc(r.id)}"><b>${esc(cut(r.path,72))}</b>${sens?'<div class="t2">凭证路径 · 不因此单独生成告警</div>':''}</button></td><td>${esc(cut(r.op,40))}</td><td>${esc(r.agent)}<div class="t2">${esc(cut(r.session,24))}</div></td><td><span class="strength-${esc(a.kind)}">${esc(a.name)}</span></td><td class="mono">${esc(time(r.at))}</td></tr>`;
 }).join('')}</tbody></table>`:'<div class="risk-empty"><h2>还没有采到文件事件</h2><p>文件卡片和 kind=file 的采集记录都会出现在这里。没有记录就不画 diff，也不编 S08–S10 告警。</p></div>';
 let detail='';
 if(selected){
  const related=alerts.filter(a=>a.evidence?.path&&selected.path&&a.evidence.path===selected.path);
  const body=selected.diff?`<pre class="mono diff-view">${esc(selected.diff)}</pre>${selected.diffTruncated?'<p class="note">diff 被截断。</p>':''}`
   :(selected.before||selected.after)?`<div class="diff-pair"><section><h3>之前</h3><pre class="mono">${esc(selected.before||'未采到之前的内容')}</pre></section><section><h3>之后</h3><pre class="mono">${esc(selected.after||'未采到之后的内容')}</pre></section></div>`
   :'<p class="empty">未采到 diff。不把文件名当成内容已经核对。</p>';
  const finds=selected.findings.length?`<ul>${selected.findings.map(f=>`<li>${esc(f.ruleId||f.title||'finding')} · ${esc(f.severity||'')} · ${esc(cut(f.evidence||f.title||'',120))}</li>`).join('')}</ul>`:'<p class="note">这条记录上没有代码发现。</p>';
  detail=`<article class="risk-detail"><h2>${esc(selected.path)}</h2><p>${esc(selected.agent)} · ${esc(selected.op)} · 来源 ${esc(selected.source)} · 执行编号 ${esc(selected.call||'缺口')}</p>${body}<h3>已有发现</h3>${finds}<h3>相关告警</h3>${related.length?related.map(a=>`<button type="button" class="risk-link" data-dest-alert="${esc(a.id)}">${esc(a.rule)} · ${esc(a.title)}</button>`).join(''):'<p class="note">没有路径对得上的风险告警。S08 敏感文件、S09 批量删除、S10 工作区外写入未接入，不在这里现编。</p>'}</article>`;
 }
 const mode=state?.fileMode==='alerts'?'alerts':'list';
 const fileHits=fileAlertRows(payload);
 const alertTable=fileHits.length?`<table class="risk-table"><thead><tr><th>规则</th><th>告警</th><th>路径</th><th>Agent</th><th>时间</th></tr></thead><tbody>${fileHits.map(a=>`<tr><td>${esc(a.rule)}</td><td><button type="button" class="risk-link" ${a.kind==='alert'?`data-dest-alert="${esc(a.id)}"`:`data-file-id="${esc(a.fileId||'')}"`}><b>${esc(a.title)}</b><div class="t2">${esc(cut(a.why,90))}</div></button></td><td class="mono">${esc(cut(a.path,48))}</td><td>${esc(a.agent||'')}</td><td class="mono">${esc(time(a.at))}</td></tr>`).join('')}</tbody></table>`:'<div class="risk-empty"><h2>没有文件改动告警</h2><p>S08 敏感文件被改、S09 批量删除、S10 工作区外写入都没有检测器。这里只列出已经挂在文件路径上的风险告警，或文件卡片自带的代码发现。没有这些就不编一条。</p></div>';
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">只列已采到的文件事件</div><h1>文件改动</h1><p>有 diff 才显示 diff。凭证路径会标出来，但不会因此发明一条告警。</p></div><span class="t2">${mode==='alerts'?fileHits.length+' 条告警':rows.length+' 条改动'}</span></div><div class="risk-actions" style="margin:0 28px 10px"><button type="button" class="${mode==='list'?'primary':'quiet'}" data-file-mode="list">改动列表</button><button type="button" class="${mode==='alerts'?'primary':'quiet'}" data-file-mode="alerts">文件告警</button></div><div class="risk-main" style="margin:0 28px">${mode==='alerts'?alertTable:table}${mode==='list'?detail:''}</div>`;
}

function textOf(card){
 return String(card?.output||card?.summary||card?.input||'').trim();
}
function reasoningRows(payload){
 const rows=[];
 for(const t of tasksOf(payload)){
  const cards=list(t.cards);
  const models=cards.filter(c=>/model|plan/.test(String(c.kind||c.detailType||'')));
  const execs=cards.filter(c=>c.execution?.command||/^(command|tool)$/.test(String(c.kind||'')));
  const used=new Set();
  for(const m of models){
   const call=m.call||null;
   const matched=call?execs.filter(e=>(e.call||e.execution?.call)&&String(e.call||e.execution.call)===String(call)):[];
   matched.forEach(e=>used.add(e.id));
   rows.push({
    id:'m:'+String(m.id),
    task:t,model:m,execs:matched,
    relation:matched.length?'explicit':'gap',
    basis:matched.length?'模型记录与命令共用执行编号':(call?'这个执行编号没有对上的命令':'模型记录没有执行编号，不能对照')
   });
  }
  for(const e of execs){
   if(used.has(e.id))continue;
   rows.push({id:'e:'+String(e.id),task:t,model:null,execs:[e],relation:'gap',basis:'有主机动作，没有同一执行编号的模型输出'});
  }
 }
 return rows;
}
function alignmentVerdict(row,alerts){
 if(row.relation!=='explicit'||!row.model)return {label:'不可对照',kind:'gap',why:row.basis};
 const said=textOf(row.model);
 const call=row.model.call;
 const hit=list(alerts).find(a=>a.call&&call&&String(a.call)===String(call)&&['S02','S04','S05','S07'].includes(a.rule));
 if(hit&&/不联网|不会外联|不外联|只读取|只读|不上传/.test(said)){
  return {label:'言行不一',kind:'mismatch',why:'模型文本里有不外联或只读的说法，同一执行编号已有 '+hit.rule+'：'+(hit.title||'')};
 }
 if(said&&row.execs.length)return {label:'可对照',kind:'paired',why:'同一执行编号两边都有记录。没有结构化的矛盾，不判成一致，也不判成不一。'};
 return {label:'缺口',kind:'gap',why:row.basis};
}
function renderReason(holder,payload,state){
 const rows=reasoningRows(payload);
 const selected=rows.find(r=>r.id===state?.reasonId)||null;
 const table=rows.length?`<table class="risk-table"><thead><tr><th>时间</th><th>执行编号</th><th>模型侧已采到的文本</th><th>主机动作</th><th>关联</th></tr></thead><tbody>${rows.map(r=>{
  const call=r.model?.call||r.execs[0]?.call||'缺口';
  const said=r.model?cut(textOf(r.model),80):'未采到模型输出';
  const did=r.execs.map(e=>e.execution?.command||e.title||e.kind).filter(Boolean).join('；')||'未采到命令';
  const verdict=alignmentVerdict(r,window.AgentReinsRisk&&window.AgentReinsRisk._lastAlerts);
  return `<tr class="${selected&&selected.id===r.id?'sel':''}"><td class="mono">${esc(time(r.model?.timestamp||r.execs[0]?.timestamp))}</td><td class="mono">${esc(cut(call,18))}</td><td><button type="button" class="risk-link" data-reason-id="${esc(r.id)}">${esc(said)}</button></td><td>${esc(cut(did,80))}</td><td>${esc(verdict.label)}<div class="t2">${esc(r.basis)}</div></td></tr>`;
 }).join('')}</tbody></table>`:'<div class="risk-empty"><h2>还没有可并列的模型记录和主机动作</h2><p>本页不自动写「言行一致」或「言行不一」。对不上就保持缺口。</p></div>';
 let detail='';
 if(selected){
  const said=selected.model?textOf(selected.model):'';
  const did=selected.execs.map(e=>e.execution?.command||e.output||e.title||'').join('\n');
  const verdict=alignmentVerdict(selected,window.AgentReinsRisk&&window.AgentReinsRisk._lastAlerts);
  detail=`<article class="risk-detail"><p class="t2">${esc(selected.task.agent||'')} · 执行编号 ${esc(selected.model?.call||selected.execs[0]?.call||'缺口')}</p><h2>${esc(verdict.label)}</h2><p>${esc(verdict.why)}</p><div class="diff-pair"><section><h3>模型侧</h3><pre class="mono">${esc(said||'未采到。不用任务标题代替。')}</pre></section><section><h3>主机侧</h3><pre class="mono">${esc(did||'未采到命令或工具回传。')}</pre></section></div><p class="note">动机看不到。没有同一执行编号，或两边文本对不上一条已有告警时，保持不可对照。</p></article>`;
 }
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">同一执行编号才并列</div><h1>推理与动作</h1><p>左边是已采到的模型或计划文本，右边是同一执行编号的命令。没有编号的行标成缺口。</p></div></div><div class="risk-main" style="margin:0 28px">${table}${detail}</div>`;
}

function taskBucket(t){
 const st=t?.lifecycleStatus;
 if(st==='awaiting_confirmation')return {id:'confirm',label:'等我确认'};
 if(st==='failed')return {id:'failed',label:'失败'};
 if(st==='completed'||st==='stopped')return {id:'review',label:'待验收'};
 return null;
}
function decisionFor(decisions,taskId){
 return list(decisions).find(d=>d.id==='task:'+taskId)||null;
}
function inboxItems(payload,decisions){
 const items=[];
 for(const t of tasksOf(payload)){
  const bucket=taskBucket(t);
  if(!bucket)continue;
  items.push({task:t,bucket,decision:decisionFor(decisions,t.id)});
 }
 const order={confirm:0,review:1,failed:2};
 return items.sort((a,b)=>order[a.bucket.id]-order[b.bucket.id]||new Date(b.task.startedAt)-new Date(a.task.startedAt));
}
function evidenceItems(task){
 return list(task?.cards).slice(0,12).map(c=>{
  const a=assocOf({confidence:c.confidence,basis:c.basis});
  return {id:c.id,title:c.title||c.kind,summary:cut(c.summary||c.execution?.command||c.resource?.path||'',140),association:a.name,kind:a.kind,note:a.note,call:c.call||null};
 });
}
function evidencePack(task,decision){
 const request=task?.originalRequest||task?.latestUserInput?.content||null;
 return {
  schema:'agentreins.acceptance.v1',
  generatedAt:new Date().toISOString(),
  limits:['只包含这次任务投影里已有的字段','没有采到的原话和交付物保持 null','不是平台侧验收记录'],
  task:{id:task?.id||null,agent:task?.agent||null,session:task?.session||null,status:task?.lifecycleStatus||null,request},
  gaps:[request?null:'没有采到用户原话',list(task?.cards).length?null:'没有卡片'].filter(Boolean),
  evidence:evidenceItems(task||{}),
  decision:decision?{state:decision.state,note:decision.note||null,decidedAt:decision.decidedAt||null}:null
 };
}
function renderInbox(holder,payload,state){
 const decisions=list(state?.decisions);
 const items=inboxItems(payload,decisions);
 const open=items.filter(i=>!i.decision||i.decision.state==='needs_evidence');
 const selected=items.find(i=>i.task.id===state?.inboxId)||open[0]||items[0]||null;
 const queue=items.length?items.map(i=>{
  const done=i.decision&&i.decision.state!=='needs_evidence';
  const label=done?(i.decision.state==='accept'?'已通过':i.decision.state==='return'?'已退回':'待补证据'):i.bucket.label;
  return `<button type="button" class="inbox-item${selected&&selected.task.id===i.task.id?' on':''}" data-inbox-id="${esc(i.task.id)}"><b>${esc(cut(i.task.originalRequest||i.task.title||i.task.id,42))}</b><small>${esc(i.task.agent||'')} · ${esc(label)}</small></button>`;
 }).join(''):'<p class="empty">没有等你处理的任务。进行中的任务仍在任务过程里，这里不把它们算进队列。</p>';
 let card='';
 if(selected){
  const t=selected.task;
  const request=t.originalRequest||t.latestUserInput?.content;
  const ev=evidenceItems(t);
  const arts=list(payload?.artifacts).filter(a=>a.taskID===t.id);
  const invalid=state?.returnInvalid?' invalid':'';
  card=`<article class="risk-detail"><p class="t2">${esc(t.agent||'')} · ${esc(t.lifecycleStatus||'unknown')}</p><h2>${esc(cut(request||t.title||t.id,120))}</h2>
   ${request?'':`<p class="request-missing">没有采到这次任务的用户原话。这是采集缺口，不用模型回复代替。</p>`}
   <h3>交付物</h3>${arts.length?arts.map(a=>`<p>${esc(a.name||a.path)} · ${a.exists?'文件存在已确认':'文件存在未确认'}</p>`).join(''):'<p class="note">没有识别到交付物。不把退出码当成交付。</p>'}
   <h3>证据</h3><ul class="ev-list">${ev.length?ev.map(e=>`<li class="strength-${esc(e.kind)}"><b>${esc(e.title)}</b><span>${esc(e.association)}</span><small>${esc(e.summary)} · ${esc(e.note)}</small></li>`).join(''):'<li>没有卡片。</li>'}</ul>
   ${selected.decision&&selected.decision.state==='return'?`<div class="returned-banner"><b>已退回</b> · ${esc(selected.decision.decidedAt||'')}<p>${esc(selected.decision.note||'')}</p><button type="button" class="quiet" data-accept-undo="task:${esc(t.id)}">撤销决定</button></div>`:selected.decision?`<p class="note">已记录 ${esc(selected.decision.state==='accept'?'通过':selected.decision.state==='needs_evidence'?'补证据':selected.decision.state)} · ${esc(selected.decision.decidedAt||'')} · ${esc(selected.decision.note||'')}</p>${selected.decision.state==='accept'||selected.decision.state==='needs_evidence'?`<button type="button" class="quiet" data-accept-undo="task:${esc(t.id)}">撤销决定</button>`:''}`:''}
   <label class="risk-search">退回原因（退回时必填）<textarea id="accept-note" class="${invalid.trim()}" rows="3" placeholder="写清要退回的原因">${esc(state?.returnNote||selected.decision?.note||'')}</textarea></label>
   <div class="risk-actions">
    <button type="button" class="primary" data-accept-decide="accept" data-task-id="${esc(t.id)}">通过</button>
    <button type="button" class="quiet" data-accept-decide="return" data-task-id="${esc(t.id)}">退回</button>
    <button type="button" class="quiet" data-accept-decide="needs_evidence" data-task-id="${esc(t.id)}">补证据</button>
    <button type="button" class="quiet" data-export-task="${esc(t.id)}">导出证据包</button>
   </div>
   <p class="note">通过、退回、补证据写入本机 Review。退回没有原因时不会保存。导出的是当前投影，不是一份被签过名的证据。</p>
  </article>`;
 }
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">人的决定留在本机</div><h1>待我处理</h1><p>等我确认、待验收、失败。风险告警仍是打开后的第一页。</p></div><span class="t2">${open.length} 条未结束</span></div><div class="inbox-layout"><aside>${queue}</aside><div>${card||'<p class="empty">选左边一条。</p>'}</div></div>`;
}

const MCP_TOOLS=[
 {name:'list_agents',note:'只读。会话列表有上限，计数是全量。'},
 {name:'list_alerts',note:'只读告警。不能在这里确认或加白。'},
 {name:'get_execution',note:'一条执行的命令、目的地、下载哈希。密钥打码。'},
 {name:'list_network',note:'运输审计加进程采样。代理流量的对端 IP 不是目的域名。'},
 {name:'get_coverage',note:'覆盖和盲区。没采到就是 unknown。'},
 {name:'list_mcp_audit',note:'监督者自己的读取也进哈希链。'}
];
function renderSupervise(holder,payload,state){
 const audit=list(state?.mcpAudit);
 const rows=audit.length?audit.slice().reverse().slice(0,40).map(e=>`<tr><td>${esc(e.at||'')}</td><td>${esc(e.actor||'')}</td><td>${esc(e.tool||'')}</td><td class="mono">${esc(cut(e.hash||'',16))}</td></tr>`).join(''):'<tr><td colspan="4">还没有只读调用记录。接上 tools/agentreins-mcp/server.py 之后才会出现。</td></tr>';
 const tools=MCP_TOOLS.map(t=>`<li><b>${esc(t.name)}</b><span>${esc(t.note)}</span></li>`).join('');
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">监督者只读</div><h1>监督接入</h1><p>这里不改 Codex / Cursor 的 MCP 配置，也没有启用开关。工具清单来自随包的 server.py 契约（0.1.0），不是「当前已连接」的探测结果。</p></div></div>
 <div class="risk-covg"><section class="risk-card"><h3>随包只读工具</h3><ul class="tool-list">${tools}</ul><p class="note">写、删除、加白、验收都不在 MCP 里。那些动作只在本应用的 Review 文件。</p></section>
 <section class="risk-card"><h3>最近的监督读取</h3><p class="note">${esc(cut(state?.mcpAuditPath||'审计日志路径未提供',140))}</p><table class="risk-table"><thead><tr><th>时间</th><th>调用方</th><th>工具</th><th>hash</th></tr></thead><tbody>${rows}</tbody></table></section></div>
 <p class="note" style="margin:16px 28px">边界：被监督方看不到监督者的推理。本页不能删改证据。完整性如果校验失败，覆盖度页会写明，不在这里标成已通过。</p>`;
}
function installLabel(install){
 const src=install===undefined?(typeof window!=='undefined'?window.agentreinsInstall:null):install;
 const clean=v=>{const s=String(v??'').trim();return /^[A-Za-z0-9._-]{1,40}$/.test(s)?s:'';};
 const version=src&&typeof src==='object'?clean(src.version):'';
 const build=src&&typeof src==='object'?clean(src.build):'';
 if(version&&build)return '本机安装包 · '+version+'（'+build+'）';
 if(version)return '本机安装包 · '+version;
 if(build)return '本机安装包 · '+build;
 return '本机安装包';
}
function renderAbout(holder, install){
 const kicker=esc(installLabel(install));
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">${kicker}</div><h1>关于 AgentReins</h1><p>这台 Mac 上的 agent 安全观测。看得见主机层里已经采到的 agent 行为，并在本机确认、加白、复查。</p></div></div>
 <div class="about-body">
 <article class="risk-rc"><h3>现在能做的</h3><p>风险告警来自运输审计、内容审计，以及已经对上的文件卡片。确认、加白、已知悉，还有任务的通过和退回，都写在本机 Review，重新打开仍在。放行和阻断目前是本机处置记录，连接仍按原路径进行。证据包可以导出当前投影。监督接入提供随包的只读工具。</p></article>
 <article class="risk-rc"><h3>下一步</h3><ul class="about-next"><li>文件层 Endpoint Security 检测（S08–S10）</li><li>放行和阻断接到模型网关与 Network Extension</li><li>WebLens 接到规则</li><li>安全设置监看（S06）和组织授权范围</li></ul></article>
 </div>`;
}

window.AgentReinsConsole={
 fileRows,fileAlertRows,renderFiles,reasoningRows,alignmentVerdict,renderReason,inboxItems,evidencePack,evidenceItems,renderInbox,renderSupervise,renderAbout
};
})();
