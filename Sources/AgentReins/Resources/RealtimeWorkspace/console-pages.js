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
function diffHTML(text){
 return String(text||'').split('\n').map(line=>{
  const cls=line.startsWith('+')&&!line.startsWith('+++')?'add':line.startsWith('-')&&!line.startsWith('---')?'remove':'';
  return `<span class="diff-line ${cls}">${esc(line)}</span>`;
 }).join('');
}
function fileBody(row){
 if(row.diff)return `<pre class="mono diff-view">${diffHTML(row.diff)}</pre>`;
 if(row.before||row.after)return `<div class="diff-pair"><section><h3>之前</h3><pre class="mono">${esc(row.before||'未采到之前的内容')}</pre></section><section><h3>之后</h3><pre class="mono">${esc(row.after||'未采到之后的内容')}</pre></section></div>`;
 return '<p class="empty">未采到 diff。</p>';
}
function toolFileCards(verification){
 return list(verification&&verification.cards).filter(card=>list(card.happened).some(effect=>effect.kind==='file'||effect.kind==='credential'));
}
function unclaimedChanges(payload){
 const verification=payload&&payload.verification;
 if(verification)return list(verification.unclaimed);
 return fileRows(payload).map(row=>({id:row.id,path:row.path,diff:row.diff,before:row.before,after:row.after,timestamp:row.at,why:'这次投影没有会话日志，改动还挂不到调用上。',credential:CRED.test(row.path||'')}));
}
function renderFiles(holder,payload,state){
 const rows=fileRows(payload);
 const verification=payload&&payload.verification;
 const cards=toolFileCards(verification);
 const unclaimed=unclaimedChanges(payload);
 const selectedId=state&&state.fileId;
 const selected=unclaimed.find(row=>row.id===selectedId)||null;
 const mode=state?.fileMode==='alerts'?'alerts':'list';
 const fileHits=fileAlertRows(payload);
 const alertTable=fileHits.length?`<table class="risk-table"><thead><tr><th>规则</th><th>告警</th><th>路径</th><th>Agent</th><th>时间</th></tr></thead><tbody>${fileHits.map(a=>`<tr><td>${esc(a.rule)}</td><td><button type="button" class="risk-link" ${a.kind==='alert'?`data-dest-alert="${esc(a.id)}"`:`data-file-id="${esc(a.fileId||'')}"`}><b>${esc(a.title)}</b><div class="t2">${esc(cut(a.why,90))}</div></button></td><td class="mono">${esc(cut(a.path,48))}</td><td>${esc(a.agent||'')}</td><td class="mono">${esc(time(a.at))}</td></tr>`).join('')}</tbody></table>`:'<div class="risk-empty"><h2>没有文件改动告警</h2><p>S08 敏感文件被改、S09 批量删除、S10 工作区外写入都没有检测器。这里只列出已经挂在文件路径上的风险告警，或文件卡片自带的代码发现。没有这些就不编一条。</p></div>';
 const attached=cards.length?cards.map(card=>{
  const files=list(card.happened).filter(effect=>effect.kind==='file'||effect.kind==='credential');
  return `<article class="tc-card ${esc(card.status||'matched')}"><header class="tc-head"><b>${esc(card.toolName||'工具')}</b><span>${esc(time(card.timestamp))} · ${esc(card.status==='mismatched'?'对不上':'对上了')}</span></header><p class="t2">它调 ${esc(card.toolName||'')} ${esc(cut(card.arguments||'',120))}</p>${files.map(effect=>`<section><h3>${esc(effect.path||'文件')}${effect.credential?' · 凭证路径':''}</h3>${fileBody(effect)}</section>`).join('')}</article>`;
 }).join(''):'';
 const unclaimedHTML=unclaimed.length?`<h2 class="unclaimed-title">无人认领的改动</h2><table class="risk-table"><thead><tr><th>路径</th><th>时间</th><th>原因</th></tr></thead><tbody>${unclaimed.map(row=>`<tr class="${selected&&selected.id===row.id?'sel':''}"><td><button type="button" class="risk-link" data-file-id="${esc(row.id)}"><b>${esc(cut(row.path,72))}</b>${row.credential?'<div class="t2">凭证路径</div>':''}</button></td><td class="mono">${esc(time(row.timestamp))}</td><td>${esc(row.why||'')}</td></tr>`).join('')}</tbody></table>`:'<h2 class="unclaimed-title">无人认领的改动</h2><p class="note">没有无人认领的改动。</p>';
 let detail='';
 if(selected){
  detail=`<article class="risk-detail"><h2>${esc(selected.path)}</h2><p>${esc(selected.why||'')}</p>${fileBody(selected)}</article>`;
 }
 const listHTML=cards.length||unclaimed.length?`${attached}${unclaimedHTML}${detail}`:'<div class="risk-empty"><h2>还没有采到文件事件</h2><p>有 diff 才挂到对应的工具调用下面。没有记录就不画 diff。S08 敏感文件、S09 批量删除、S10 工作区外写入还没有检测器。</p></div>';
 const count=mode==='alerts'?fileHits.length:cards.length+unclaimed.length;
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">改动跟调用走</div><h1>文件改动</h1><p>每次 diff 挂在引起它的那次工具调用下面。对不上调用的，放在无人认领的改动。S08 敏感文件检测器还没接上，凭证路径只标出来。</p></div><span class="t2">${count} 条</span></div><div class="risk-actions" style="margin:0 28px 10px"><button type="button" class="${mode==='list'?'primary':'quiet'}" data-file-mode="list">改动列表</button><button type="button" class="${mode==='alerts'?'primary':'quiet'}" data-file-mode="alerts">文件告警</button></div><div class="risk-main" style="margin:0 28px">${mode==='alerts'?alertTable:listHTML}</div>`;
}

function joinLabel(kind){
 return { 'call-id':'按调用编号对上','time-pid':'按时间和进程树对上','time-window':'按时间窗对上' }[kind]||kind||'';
}
function happenedBlock(effect){
 const title=effect.kind==='file'||effect.kind==='credential'?(effect.path||'文件'):effect.kind==='network'?(effect.remote||'外联'):(effect.command||effect.kind||'进程');
 return `<div class="tc-effect"><b>${esc(title)}</b><span class="t2">${esc(joinLabel(effect.join))}</span>${effect.diff?`<pre class="mono diff-view">${diffHTML(effect.diff)}</pre>`:''}${(effect.before||effect.after)&&!effect.diff?fileBody(effect):''}</div>`;
}
function hostLine(effect){
 const verdict=effect.verdict==='shell-gate'?'shell 在执行前拒绝':effect.verdict==='transport-wrapper'?'PATH 入口拒绝':effect.verdict==='audit-proxy'?'审计代理拒绝':(effect.verdict||'');
 const exit=effect.exitCode==null?'退出码没采到':'退出码 '+effect.exitCode;
 const dur=effect.durationMs==null?'耗时没采到':effect.durationMs+' 毫秒';
 const binary=effect.binary?('实际程序 '+effect.binary):(effect.exitCode===126?'真实程序没有执行':'实际程序没采到');
 const pid=effect.pid?('pid '+effect.pid):'pid 没采到';
 const parents=effect.parents?('父进程 '+effect.parents):'';
 const hit=effect.credential?('凭据路径 '+(effect.path||effect.command||'')):effect.kind==='network'?('外联 '+(effect.remote||'')):effect.kind==='file'?('文件 '+(effect.path||'')):(effect.command||effect.kind||'');
 return [pid,parents,binary,verdict,hit,exit,dur].filter(Boolean).join(' · ');
}
function renderToolCard(card){
 const status=card.status==='mismatched'?'mismatched':'matched';
 const said=String(card.said||'').trim()?esc(card.said)+(card.saidTruncated?'<p class="t2">只留了开头一段。</p>':''):'<span class="t2">这次调用前面没有推理文本。</span>';
 const happened=list(card.happened);
 const result=String(card.resultExcerpt||'').trim();
 const resultLine=result?esc(result)+(card.resultTruncated?'<p class="t2">只留了开头一段。</p>':''):'<span class="t2">没有采到返回给模型的结果。</span>';
 const ack=String(card.acknowledgement||'').trim();
 const ackLine=ack?esc(ack):'<span class="t2">后面没有再说话。</span>';
 const flags=list(card.mismatches).map(item=>`<li><b>${esc(item.label)}</b> ${esc(item.detail||'')}</li>`).join('');
 const host=happened.length?happened.map(effect=>`<div class="tc-effect"><b>${esc(hostLine(effect))}</b><span class="t2">${esc(joinLabel(effect.join))}</span>${effect.diff?`<pre class="mono diff-view">${diffHTML(effect.diff)}</pre>`:''}</div>`).join(''):'<span class="t2">这个时间窗里没有对上的主机记录。</span>';
 return `<article class="tc-card ${status}"><header class="tc-head"><b class="tc-status ${status}">${status==='matched'?'对上了':'对不上'}</b><span>${esc(card.agent||'')} · 会话 ${esc(cut(card.sessionId||'',36))} · ${esc(time(card.timestamp))}</span></header><div class="tc-grid"><section><h3>模型提出</h3><p><b>${esc(card.toolName||'工具')}</b></p><pre class="mono">${esc(card.arguments||'没有参数')}</pre><p class="t2">动手前</p><pre class="mono">${said}</pre></section><section><h3>主机执行</h3>${host}</section><section><h3>模型收到</h3><p class="t2">${card.resultBytes?esc(card.resultBytes)+' 字节，只留摘录':'大小没采到'}</p><pre class="mono">${resultLine}</pre><p class="t2">下一句</p><pre class="mono">${ackLine}</pre></section></div>${flags?`<ul class="tc-flags">${flags}</ul>`:''}${card.note?`<p class="t2">${esc(card.note)}</p>`:''}</article>`;
}
function renderChecklist(item,state){
 const decisions=list(state&&state.decisions);
 const decision=item.taskId?decisions.find(row=>row.id==='task:'+item.taskId):null;
 const invalid=state&&state.returnInvalid?' invalid':'';
 const recorded=decision?`<p class="note">已记录 ${esc(decision.state==='accept'?'通过':decision.state==='return'?'已退回':decision.state)} · ${esc(decision.note||'')}</p>`:'';
 const buttons=item.taskId?`<label class="risk-search">退回原因（退回时必填）<textarea id="checklist-note" class="${invalid.trim()}" rows="2" placeholder="写清要退回的原因">${esc(state&&state.returnNote||'')}</textarea></label><div class="risk-actions"><button type="button" class="primary" data-accept-decide="accept" data-task-id="${esc(item.taskId)}" data-note-field="checklist-note">通过</button><button type="button" class="quiet" data-accept-decide="return" data-task-id="${esc(item.taskId)}" data-note-field="checklist-note">退回</button></div>`:'<p class="note">这条完成声明还没对上待我处理里的任务，通过和退回先不写。</p>';
 return `<article class="tc-check"><h3>它说做完了</h3><p>${esc(cut(item.doneText||'',180))}</p><ul class="tc-flags"><li>它说改了 ${esc(item.claimedFiles)} 个文件，主机记下 ${esc(item.actualFiles)} 个</li><li>外联 ${esc(item.egressCount)} 次</li><li>凭证 ${item.credentialsTouched?'碰到了':'没碰到'}</li><li>拦住后仍说成功 ${esc(item.blockedSuccessClaims||0)} 次</li></ul>${recorded}${buttons}</article>`;
}
function renderReason(holder,payload,state){
 const verification=payload&&payload.verification;
 const sources=list(verification&&verification.sources);
 const cards=list(verification&&verification.cards);
 const session=state&&state.sessionId;
 const shown=session?cards.filter(card=>card.sessionId===session):cards;
 const checks=list(verification&&verification.checklists).filter(item=>!session||item.sessionId===session);
 const sourceNote=sources.length?sources.map(item=>`${esc(item.agent)}：${esc(item.note||item.state)}`).join('<br>'):'这次投影没有带上会话日志。Claude Code 在 ~/.claude/projects，Codex 在 ~/.codex/sessions。';
 const sessions=[...new Set(cards.map(card=>card.sessionId).filter(Boolean))];
 const picker=sessions.length>1?`<div class="risk-actions">${sessions.map(id=>`<button type="button" class="${session===id?'primary':'quiet'}" data-verify-session="${esc(id)}">${esc(cut(id,24))}</button>`).join('')}<button type="button" class="${session?'quiet':'primary'}" data-verify-session="">全部</button></div>`:'';
 const body=shown.length?shown.map(renderToolCard).join('')+checks.map(item=>renderChecklist(item,state)).join(''):`<div class="risk-empty"><h2>还没有可核对的工具调用</h2><p>${sourceNote}</p><p>目录不在，或日志里没有工具调用时，这里是空的。</p></div>`;
 const mismatches=shown.filter(card=>card.status==='mismatched').length;
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">核得清</div><h1>推理对齐</h1><p>一条命令从上到下：模型提出、主机执行、模型收到。对不上的包括说了没做、做了没说、做的比说的多，以及说成功了其实被拦住或失败。对不上的留在这里，通过或退回进待我处理。</p></div><span class="t2">${shown.length} 次调用${mismatches?` · ${mismatches} 次对不上`:''}</span></div><div class="risk-main" style="margin:0 28px">${picker}${body}</div>`;
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
function inboxNoiseReason(task){
 const fields=[task?.originalRequest,task?.latestUserInput?.content,task?.title];
 const blob=fields.map(v=>String(v||'')).join('\n');
 if(/<\s*\/?\s*(heartbeat|automation_id|automation)\b/i.test(blob))return 'heartbeat';
 const request=String(task?.originalRequest||task?.latestUserInput?.content||'').replace(/\s+/g,' ').trim();
 const title=String(task?.title||'').replace(/\s+/g,' ').trim();
 const missing=/用户需求未采集|轮次尚未关联|没有采到这次任务的用户原话|机器标记，没有用户原话/;
 if(!request&&missing.test(title))return 'no-user-prompt';
 if(request&&missing.test(request)&&request.length<80)return 'no-user-prompt';
 return null;
}
function isTelemetrySubject(subject){
 return /telemetry/i.test(String(subject||''));
}
function gateClosed(subject,decisions,allowlist){
 if(list(allowlist).some(e=>e&&e.subject===subject&&e.actor==='user'&&String(e.reason||'').trim()))return true;
 return list(decisions).some(d=>{
  if(!d||d.subject!==subject)return false;
  if(d.state==='allowlisted'||d.state==='hard-allow'||d.state==='hard-deny')return true;
  return d.actor==='user'&&(d.action==='allow'||d.action==='deny');
 });
}
function gateInboxItems(records,decisions,allowlist){
 const items=[];
 const seen=new Set();
 for(const row of list(records)){
  if(!row||row.inbox!==true||row.heartbeat===true)continue;
  if(row.tier&&row.tier!=='keep')continue;
  if(row.action&&row.action!=='deny')continue;
  const subject=String(row.subject||'');
  if(isTelemetrySubject(subject)||row.noise==='telemetry')continue;
  if(!subject||seen.has(subject)||gateClosed(subject,decisions,allowlist))continue;
  seen.add(subject);
  const id='gate:'+subject;
  items.push({
   gate:row,
   task:{id,agent:row.agent||'监督进程树',lifecycleStatus:'hard-gate',originalRequest:row.detail||(row.kind==='credential-read'?'第一次读取凭据路径':'第一次外联到新主机'),title:subject,startedAt:row.at||''},
   bucket:{id:'gate',label:'硬门禁'},
   decision:null
  });
 }
 return items;
}
function hardGateFrom(opts,payload){
 if(opts&&Array.isArray(opts.inbox))return opts;
 if(opts&&opts.hardGate)return opts.hardGate;
 return payload?.hardGate||{};
}
function inboxItems(payload,decisions,opts){
 const wantNoise=!!(opts&&opts.noise);
 const items=[];
 for(const t of tasksOf(payload)){
  const bucket=taskBucket(t);
  if(!bucket)continue;
  const noise=inboxNoiseReason(t);
  if(wantNoise){if(!noise)continue;}
  else if(noise)continue;
  items.push({task:t,bucket,decision:decisionFor(decisions,t.id),noise:noise||null});
 }
 const gate=hardGateFrom(opts,payload);
 if(wantNoise) items.push(...telemetryNoiseItems(gate.receipts));
 else items.push(...gateInboxItems(gate.inbox,decisions,gate.allowlist));
 const order={gate:-1,confirm:0,review:1,failed:2};
 return items.sort((a,b)=>new Date(b.task.startedAt)-new Date(a.task.startedAt)||(order[a.bucket.id]??9)-(order[b.bucket.id]??9));
}
function telemetryBlob(alert){
 return [alert&&alert.sub,alert&&alert.title,alert&&alert.hostText,alert&&alert.subject,alert&&alert.destination].join(' ');
}
function homeStatus(payload, alerts){
 const rows=list(alerts).filter(a=>a&&!/telemetry/i.test(telemetryBlob(a)))
  .sort((a,b)=>new Date(b.timestamp||b.startedAt||0)-new Date(a.timestamp||a.startedAt||0));
 const cred=rows.find(a=>/凭证|凭据|credential|\.env|S01/i.test(String(a.title||'')+String(a.rule||'')+String(a.sub||'')));
 const net=rows.find(a=>/S0[247]/.test(String(a.rule||''))||/外联|访问|连到/.test(String(a.title||'')));
 const who=cred||net||rows[0]||null;
 const what=who?(cred&&who===cred?'读了凭据':'往外连了'):'';
 const line1=who?`${who.agent||'某个 Agent'} 刚刚${what}：${cut(who.title||who.sub||'细节没写清',72)}`:'还没有看到新的外联或凭据读取。';
 const blocked=!!(who&&(who.blocked===true||(who.enforcement&&who.enforcement.fired===true)||who.disposition==='已阻断'));
 const line2=!who?'没有要拦的事。':blocked?'拦住了。真实程序没有发出去。':'没拦住。这次只是记下来了。';
 const verification=payload&&payload.verification;
 const checks=list(verification&&verification.checklists);
 const unclaimed=verification?list(verification.unclaimed).filter(row=>row&&row.path):[];
 const done=checks[0];
 let line3='还没有人说做完。';
 if(done){
  line3=unclaimed.length?`它说做完了，但有 ${unclaimed.length} 处改动没人认领。`:`它说做完了。对得上的改动是 ${done.actualFiles||0} 个文件。`;
 }else if(unclaimed.length){
  line3=`还没说做完。已有 ${unclaimed.length} 处改动没挂到工具调用上。`;
 }
 const detail=[who&&(who.why||who.sub),unclaimed.slice(0,5).map(row=>row.path).join('、')].filter(Boolean).join(' ');
 return {line1,line2,line3,detail:detail||'没有更多依据。'};
}
function homeStatusHTML(payload, alerts){
 const lines=homeStatus(payload, alerts);
 return `<section class="plain-home"><p>${esc(lines.line1)}</p><p>${esc(lines.line2)}</p><p>${esc(lines.line3)}</p><button type="button" data-plain-toggle>看依据</button><div class="plain-detail" hidden><p>${esc(lines.detail)}</p></div></section>`;
}
function telemetryNoiseItems(records){
 const items=[];
 const seen=new Set();
 for(const row of list(records)){
  const subject=String(row&&row.subject||'');
  if(!isTelemetrySubject(subject)&&row?.noise!=='telemetry')continue;
  if(row.action&&row.action!=='deny')continue;
  if(!subject||seen.has(subject))continue;
  seen.add(subject);
  items.push({
   gate:row,
   task:{id:'gate:'+subject,agent:'遥测',lifecycleStatus:'hard-gate',originalRequest:'遥测域名，默认拒绝，不进待办',title:subject,startedAt:row.at||''},
   bucket:{id:'noise',label:'遥测'},
   decision:null,
   noise:'telemetry'
  });
 }
 return items;
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
 const noiseMode=state?.inboxBucket==='noise';
 const hardGate=state?.hardGate||payload?.hardGate||{};
 const items=inboxItems(payload,decisions,noiseMode?{noise:true,hardGate}:{hardGate});
 const noiseItems=inboxItems(payload,decisions,{noise:true,hardGate});
 const open=items.filter(i=>!i.decision||i.decision.state==='needs_evidence');
 const noiseOpen=noiseItems.filter(i=>!i.decision||i.decision.state==='needs_evidence').length;
 const selected=items.find(i=>i.task.id===state?.inboxId)||open[0]||items[0]||null;
 const queue=items.length?items.map(i=>{
  const done=i.decision&&i.decision.state!=='needs_evidence';
  const label=done?(i.decision.state==='accept'?'已通过':i.decision.state==='return'?'已退回':'待补证据'):i.bucket.label;
  const noiseNote=i.noise==='telemetry'?'遥测':i.noise==='heartbeat'?'心跳':'没有用户原话';
  return `<button type="button" class="inbox-item${selected&&selected.task.id===i.task.id?' on':''}" data-inbox-id="${esc(i.task.id)}"><b>${esc(cut(i.task.originalRequest||i.task.title||i.task.id,42))}</b><small>${esc(i.task.agent||'')} · ${esc(noiseMode?noiseNote+' · '+label:label)}</small></button>`;
 }).join(''):`<p class="empty">${noiseMode?'噪声桶是空的。':'没有等你验收的任务。心跳和「用户需求未采集」在「噪声」里，证据还在，没有删除。'}</p>`;
 const switcher=`<div class="inbox-switch"><button type="button" class="${noiseMode?'':'on'}" data-inbox-bucket="work">待验收 ${inboxItems(payload,decisions,{hardGate}).filter(i=>!i.decision||i.decision.state==='needs_evidence').length}</button><button type="button" class="${noiseMode?'on':''}" data-inbox-bucket="noise">噪声 ${noiseOpen}</button></div>`;
 let card='';
 if(selected&&selected.gate){
  const row=selected.gate;
  const fired=row.enforced===true&&(row.mechanism==='audit-proxy'||row.mechanism==='transport-wrapper'||row.mechanism==='shell-gate');
  const status=fired?'已阻断':'已记下，未拦截';
  const where=row.mechanism==='audit-proxy'?'审计代理':row.mechanism==='shell-gate'?'agent 的 shell':'PATH 命令入口';
  const invalid=state?.hardGateReasonInvalid?' invalid':'';
  card=`<article class="risk-detail"><p class="t2">${esc(row.kind==='credential-read'?'凭据路径':'外联')} · ${esc(row.subject||'')}</p><h2>${esc(status)}</h2>
   <p>${esc(row.detail||selected.task.originalRequest||'')}</p>
   <p class="note">${fired?`执行回执来自${esc(where)}，发生在转发或 exec 之前。`:'这条记录没有执行回执，所以不写成已经拦住。'}</p>
   <label class="risk-search">允许原因（允许时必填）<textarea id="hardgate-reason" class="${invalid.trim()}" rows="3" placeholder="写明为什么可以放行">${esc(state?.hardGateReason||'')}</textarea></label>
   <div class="risk-actions">
    <button type="button" class="primary" data-hardgate-decide="allow" data-hardgate-subject="${esc(row.subject||'')}" data-hardgate-kind="${esc(row.kind||'')}">允许</button>
    <button type="button" class="quiet" data-hardgate-decide="deny" data-hardgate-subject="${esc(row.subject||'')}" data-hardgate-kind="${esc(row.kind||'')}">保持拒绝</button>
   </div>
   <p class="note">允许会写入显式允许名单并记一条原因。拒绝不会把这条放进允许名单。心跳不会出现在这个队列。</p>
  </article>`;
 }else if(selected){
  const t=selected.task;
  const noiseBanner=selected.noise?`<p class="request-missing">${selected.noise==='telemetry'?'这是遥测域名，默认拒绝，不进待办。':selected.noise==='heartbeat'?'这是心跳或机器标记，不是要你验收的用户请求。':'没有采到用户原话，所以默认待办不列出它。'}证据还在，这里没有删除。</p>`:'';
  const request=t.originalRequest||t.latestUserInput?.content;
  const ev=evidenceItems(t);
  const arts=list(payload?.artifacts).filter(a=>a.taskID===t.id);
  const invalid=state?.returnInvalid?' invalid':'';
  card=`<article class="risk-detail"><p class="t2">${esc(t.agent||'')} · ${esc(t.lifecycleStatus||'unknown')}</p><h2>${esc(cut(request||t.title||t.id,120))}</h2>
   ${noiseBanner}
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
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">人的决定留在本机</div><h1>待我处理</h1><p>${noiseMode?'心跳和没采到用户原话的轮次。默认待办不含这些。':'等我确认、待验收、失败，以及第一次去新主机或第一次读凭据路径。心跳、「用户需求未采集」和重复外联不进默认队列。'}</p></div><span class="t2">${open.length} 条未结束</span></div>${switcher}<div class="inbox-layout"><aside>${queue}</aside><div>${card||'<p class="empty">选左边一条。</p>'}</div></div>`;
}

const MCP_TOOLS=[
 {name:'list_agents',note:'只读。会话列表有上限，计数是全量。'},
 {name:'list_alerts',note:'只读告警。不能在这里确认或加白。'},
 {name:'get_execution',note:'一条执行的命令、目的地、下载哈希。密钥打码。'},
 {name:'list_network',note:'运输审计加进程采样。代理流量的对端 IP 不是目的域名。'},
 {name:'get_coverage',note:'覆盖和盲区。没采到就是 unknown。'},
 {name:'list_mcp_audit',note:'监督者自己的读取也进哈希链。'},
 {name:'list_tool_calls',note:'只读。工具调用卡片：它说、它调、真发生。'},
 {name:'get_session_verification',note:'只读。一次会话的核对、无人认领的改动、完成核对。'}
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
function staleFilesHTML(disk){
 const rows=list(disk&&disk.stale);
 if(!rows.length)return '';
 const items=rows.map(row=>{
  const bytes=Number(row.bytes||0);
  const label=bytes>=1e9?(bytes/1e9).toFixed(1)+' GB':bytes>=1e6?Math.round(bytes/1e6)+' MB':Math.round(bytes/1024)+' KB';
  return `<li><b>${esc(row.name||row.path||'')}</b> <span class="mono">${esc(label)}</span> <button type="button" data-stale-delete="${esc(row.id||'')}">删除这份旧文件</button><div class="t2">${esc(row.reason||'')}</div></li>`;
 }).join('');
 return `<article class="risk-rc"><h3>可以清掉的旧文件</h3><p>备份、旧的重建副本和云审计暂存。点删除才会去掉。正在用的 evidence.sqlite3 不在这份名单里。</p><ul class="about-next">${items}</ul></article>`;
}
function renderAbout(holder, install, disk){
 const kicker=esc(installLabel(install));
 const bytes=Number(disk&&disk.evidenceBytes||0);
 const huge=bytes>=4*1024*1024*1024;
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">${kicker}</div><h1>关于 AgentReins</h1><p>这台 Mac 上的 agent 安全观测。首页三句话：谁刚往外连或读了凭据，拦没拦住，说做完之后到底改了什么。确认、加白、复查都在本机。</p></div></div>
 <div class="about-body">
 <article class="risk-rc"><h3>现在能做的</h3><p>看得见外联和凭据读取，拦得住的会写已阻断。已阻断只在审计代理拒绝转发、PATH 命令入口没有执行真实命令，或 agent 的 shell 在执行前拒绝凭据读取时出现。进程内 open()（例如 Read 工具读 .env 或凭据文件）写「只看见，未拦截」，没有拦住。只写了 Review、没有执行回执时，状态是「已记下，未拦截」。</p><p class="note">证据按值留。外联、凭据、策略命中和处置决定会留着。对得上工具或没人认领的文件改动会留着。待我处理的决定和理由会留着。说了没做、做了没说，只留能看清的短摘录。心跳、没采到用户原话、重复采样和整段会话副本会清掉。不会为了凑容量丢掉这些记录。</p><div class="risk-actions"><button type="button" class="primary" data-retention-clean>清理旧证据</button></div><p class="note">${huge?'这份库已经很大。自动清理停了，点上面的按钮才按小批清，不会整库压缩。':'库还不大。心跳和大块原文会按小批清掉。外联、凭据、文件改动和验收决定不动。'}</p></article>
 ${staleFilesHTML(disk)}
 <article class="risk-rc"><h3>下一步</h3><ul class="about-next"><li>文件层 Endpoint Security 检测（S08–S10）。进程内 open() 这版只看见，拦不住</li><li>Network Extension 仍未安装。绝对路径 curl、QUIC、参数里看不到目的地的 git 仍拦不住。凭据文件的绝对路径读取，在 agent 的 shell 里会在执行前拒绝</li><li>WebLens 接到规则</li><li>安全设置监看（S06）和组织授权范围</li></ul></article>
 </div>`;
}

window.AgentReinsConsole={
 fileRows,fileAlertRows,renderFiles,unclaimedChanges,renderReason,inboxItems,inboxNoiseReason,evidencePack,evidenceItems,renderInbox,renderSupervise,renderAbout,homeStatus,homeStatusHTML
};
})();
