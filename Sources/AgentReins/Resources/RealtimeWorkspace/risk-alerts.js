'use strict';
(()=>{
const list=v=>Array.isArray(v)?v:[];
/** Single mutable escape binding — renderList/detail always call through escImpl. */
let escImpl=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function esc(s){return escImpl(s);}
const cut=(s,n=72)=>{const a=Array.from(String(s??''));return a.slice(0,n).join('')+(a.length>n?'…':'')};
const time=v=>{const d=new Date(v);return isNaN(d)?'—':d.toLocaleTimeString('zh-CN',{hour12:false});};
const dayKey=v=>{const d=new Date(v);return isNaN(d)?'':d.toLocaleDateString('zh-CN');};

const RULES=[
 {id:'S01',name:'凭证读取后外联',mode:'告警',severity:'critical',
  desc:'agent 读取 ~/.ssh、~/.aws、.env、钥匙串导出文件后，同一执行编号下出现外联。',
  cond:'真实文件读取证据（resource.path）∧ 路径命中凭证清单 ∧ 同一执行编号 ∧ 目的地非白名单',
  cant:'当前没有 Endpoint Security 级文件监控；仅会话描述文本或时间窗凑出来的关联不当证据，覆盖度页标为盲区。'},
 {id:'S02',name:'出站含密钥',mode:'告警',severity:'critical',
  desc:'出站请求头或正文里出现 API Key、Token、私钥片段。命中即打码展示。',
  cond:'content_audit：credential-outbound / private-key-outbound',
  cant:'HTTPS 未经代理解密、QUIC、证书固定的请求，正文看不到。'},
 {id:'S03',name:'下载后执行',mode:'告警',severity:'critical',
  desc:'curl / wget 下载的文件在 5 分钟内被 sh、bash 或 open 真正执行（chmod +x 只改权限，不算执行）。',
  cond:'下载路径与随后执行命令对得上 ∧ Δt ≤ 300s；Correlated 仅直接父子血缘（pid+启动时间）或执行文件哈希一致；同父兄弟进程为 Inferred，除非父进程有 shell 证据（名+argv+启动时间）且同会话',
  cant:'不经命令包装的下载（如 agent 内置 fetch）只能看到网络，不知道落到哪个文件。绝对路径绕过 PATH 包装时看不到 sh/bash。'},
 {id:'S04',name:'非白名单外联',mode:'告警',severity:'high',
  desc:'git push / clone、brew tap、ssh、curl 访问白名单之外的远端或来源。',
  cond:'目的主机 ∉ 默认可信名单（github.com、registry.npmjs.org 等）',
  cant:'ssh 通道内传了什么看不到，只能看到连到了哪里。'},
 {id:'S05',name:'大体积上传',mode:'告警',severity:'high',
  desc:'单次向首次出现的域名上传超过 1 MB。',
  cond:'域名首次出现 ∧ 送出字节 > 1 MB',
  cant:'分片成多次小请求的上传，目前只按单次计，可能漏报。'},
 {id:'S06',name:'安全设置被关闭',mode:'告警',severity:'high',
  desc:'Cursor 改为自动运行全部命令、Claude Code 关闭 sandbox、Codex 切到 full-access 等。',
  cond:'监看各 agent 配置文件的关键字段变更',
  cant:'当前未接入配置文件监看；运行时临时放开（不写配置）也看不到。'},
 {id:'S07',name:'绕过审计代理',mode:'告警',severity:'high',
  desc:'命令显式 --noproxy / 自选代理，导致不经本机审计代理。',
  cond:'后端写入 auditBypass=true（前端不再自行根据参数推断）',
  cant:'不读 HTTPS_PROXY 的内置直连仍可能完全看不到；后端未打标时本页不报 S07。'}
];

const DEFAULT_ALLOW=new Set([
 'github.com','api.github.com','raw.githubusercontent.com','objects.githubusercontent.com',
 'registry.npmjs.org','registry.yarnpkg.com','pypi.org','files.pythonhosted.org',
 'crates.io','static.crates.io','proxy.golang.org','sum.golang.org',
 'cdn.jsdelivr.net','unpkg.com','homebrew.bintray.com','github.com',
 'formulae.brew.sh','ghcr.io','docker.io','registry-1.docker.io',
 'api.openai.com','api.anthropic.com','api2.cursor.sh','cursor.com','www.cursor.com',
 'chatgpt.com','claude.ai','openrouter.ai'
]);

const CRED_PATH=/(\.ssh\/|\/\.aws\/|\.env(?:\.|$)|id_rsa|id_ed25519|credentials\.json|keychain|\.pem$|secrets?\.)/i;

function hostOf(r){
 const raw=r.host||r.resource?.domain||'';
 try{if(/^https?:\/\//i.test(raw))return new URL(raw).hostname.toLowerCase();}catch{}
 return String(raw).toLowerCase().replace(/^\[|\]$/g,'').split(':')[0];
}
function bytesOut(r){return Number(r.networkBody?.requestBytes)||0;}
function auditOf(r){return r.networkBody?.securityAudit||r.securityAudit||null;}
function findingsOf(r){return list(auditOf(r)?.findings);}
function bypassed(r){
 // S07 完全以后端 auditBypass 为准，前端不再根据 --noproxy 等参数自行判断。
 return r.auditBypass===true;
}
function associationOf(a){
 // 关联强度不用「已确认」；弱关联更不能冒充已确认。
 if(a.call)return {name:'按执行编号',note:'执行编号对得上',kind:'by-call'};
 if(a.record?.taskConfidence==='candidate')return {name:'候选关联',note:'不是按执行编号对上的',kind:'candidate'};
 return {name:'缺口',note:'还没有执行编号',kind:'gap'};
}
function isAllowedHost(host){
 if(!host)return false;
 if(DEFAULT_ALLOW.has(host))return true;
 for(const a of DEFAULT_ALLOW)if(host.endsWith('.'+a))return true;
 return false;
}
function confOf(kind){
 return ({obs:{c:'obs',t:'Observed · 已观测'},cor:{c:'cor',t:'Correlated · 已关联'},inf:{c:'inf',t:'Inferred · 推断'},unk:{c:'unk',t:'Unknown · 未知'}})[kind]||{c:'unk',t:'Unknown · 未知'};
}
function sevOf(level){return ({critical:'crit',high:'high',medium:'med',low:'low'})[level]||'med';}
function sevLabel(level){return ({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW'})[level]||'MEDIUM';}

/** Seed / 测试采集：仅认显式来源标记，不再按主机名（example.com / 127.0.0.1）推断。 */
function isTestCapture(r){
 if(!r||typeof r!=='object')return false;
 if(r.testCapture===true||r.provenance==='test'||r.provenance==='seed')return true;
 const inv=r.invocation;
 if(inv&&typeof inv==='object'&&(inv.testCapture===true||inv.provenance==='test'||inv.provenance==='seed'))return true;
 const sess=String(r.session||r.codexThreadID||'');
 if(/^(seed-session|test-capture)([:._-]|$)/i.test(sess))return true;
 if(String(r.agent||'')==='__test__')return true;
 return false;
}

/** 真实文件读取证据：必须有 resource.path，不能只用工具描述文本凑。 */
function credentialReadCards(tasks){
 const out=[];
 for(const t of list(tasks)){
  for(const c of list(t.cards)){
   const path=String(c.resource?.path||'');
   if(!path||!CRED_PATH.test(path))continue;
   const kind=String(c.kind||c.detailType||'');
   const title=String(c.title||'');
   const op=String(c.op||c.action||'');
   const realRead=
    /^(file|read)$/i.test(kind)||
    /file[_-]?read|read_file|ReadFile/i.test(kind+title+op)||
    ((/^(file)$/i.test(kind)||/文件/.test(kind+title))&&/read|Read|打开|读取|cat/i.test(kind+title+op));
   if(!realRead)continue;
   out.push({task:t,card:c,path,call:c.call||c.execution?.call||(String(c.id||'').startsWith('call:')?String(c.id).slice(5):null),at:c.timestamp});
  }
 }
 return out;
}

function commandCards(tasks){
 const out=[];
 for(const t of list(tasks)){
  for(const c of list(t.cards)){
   const cmd=String(c.execution?.command||c.input||'');
   if(!cmd)continue;
   const sha=String(c.resource?.sha256||c.execution?.sha256||c.sha256||'').toLowerCase();
   out.push({
    task:t,card:c,cmd,sha,call:c.call||c.execution?.call||null,at:c.timestamp||c.execution?.startAt,
    pid:c.pid||c.execution?.pid,parentPID:c.parentPID||c.execution?.parentPID,
    parentName:c.parentName||c.execution?.parentName||null,
    parentArgv:c.parentArgv||c.execution?.parentArgv||null,
    parentStartAt:c.parentStartAt||c.execution?.parentStartAt||null,
    processStartAt:c.processStartAt||c.execution?.processStartAt||c.execution?.startAt||null,
    agent:t.agent,fromTransport:false
   });
  }
 }
 return out;
}

/** True when the command actually runs a file (sh/bash/open/direct path). chmod +x alone is NOT execution. */
function isActualExecution(cmd,tool){
 const t=String(tool||'');
 const c=String(cmd||'');
 if(/^(chmod)$/.test(t)||/^\s*chmod\b/.test(c))return false;
 if(/^(sh|bash|open)$/.test(t))return true;
 if(/\/bin\/(ba)?sh\b|\bbash\b|(?:^|[\s;|&])sh\s+|^\s*open\s+/.test(c))return true;
 // bare path / interpreter invocation without chmod
 if(/^\s*(?:\.\/|\/)[^\s]+\s*$/.test(c))return true;
 return false;
}

/** 真实运输审计里的 sh / bash / open —— 与任务卡片同等作为 S03 执行侧证据（不含 chmod）。 */
function transportExecCommands(){
 const net=window.AgentReinsNetwork;
 const locals=typeof net?.localExchanges==='function'?net.localExchanges():[];
 const out=[];
 for(const r of locals){
  if(isTestCapture(r))continue;
  const tool=String(r.tool||'');
  const args=list(r.args).map(String);
  const cmd=[tool,...args].join(' ').trim();
  if(!cmd)continue;
  if(!isActualExecution(cmd,tool))continue;
  // Skip downloaders that only wrote a file; do NOT skip sh/bash/open even if
  // projectLocal attached a downloads[] hint from a sibling curl (S03 needs them).
  if(list(r.downloads).some(d=>d&&d.path) && !/^(sh|bash|zsh|dash|open)$/.test(tool))continue;
  const sha=String(r.execSha256||r.fileResult?.sha256||r.resource?.sha256||r.sha256||'').toLowerCase();
  out.push({
   task:{agent:r.agent,session:r.session},card:null,cmd,sha,
   call:r.call||r.runID||null,at:r.startedAt||r.timestamp,
   pid:r.pid,parentPID:r.parentPID||r.launcherPID,
   parentName:r.parentName||null,parentArgv:r.parentArgv||null,parentStartAt:r.parentStartAt||null,
   processStartAt:r.processStartAt||r.startedAt||null,
   agent:r.agent,fromTransport:true,record:r
  });
 }
 return out;
}

/** Parent is a proven interactive/login shell with name + argv + start time recorded. */
function isProvenShellParent(c){
 const name=String(c.parentName||'').toLowerCase();
 const argv=String(Array.isArray(c.parentArgv)?c.parentArgv.join(' '):c.parentArgv||'');
 if(!name||!argv||!c.parentStartAt)return false;
 return /^(ba)?sh$|^zsh$|^fish$|^dash$|\/(ba)?sh$|\/zsh$/.test(name)||/\b(ba)?sh\b|\bzsh\b/.test(argv);
}

function alertId(rule,key){return rule+':'+String(key||'').replace(/[^\w.:@/-]+/g,'-').slice(0,80);}

function buildAlerts(payload){
 const net=window.AgentReinsNetwork;
 if(!net)return [];
 const rows=typeof net.rows==='function'?net.rows(payload):[];
 const locals=typeof net.localExchanges==='function'?net.localExchanges():[];
 const byCall=new Map();
 for(const r of locals)if(r.call)byCall.set(String(r.call),r);
 const exchanges=[];
 for(const r of rows){
  if(r.call&&byCall.has(String(r.call))){
   const base=byCall.get(String(r.call));
   const merged={...base,networkBody:{...(base.networkBody||{}),...(r.networkBody||{})},auditBypass:base.auditBypass??r.auditBypass};
   if(r.networkBody?.securityAudit)merged.networkBody.securityAudit=r.networkBody.securityAudit;
   byCall.set(String(r.call),merged);
  }else exchanges.push(r);
 }
 const allRaw=[...byCall.values(),...exchanges].sort((a,b)=>new Date(b.timestamp||b.startedAt)-new Date(a.timestamp||a.startedAt));
 // 「真实采集」视图：只排除显式测试/种子来源标记
 const all=allRaw.filter(r=>!isTestCapture(r));
 const alerts=[];
 const seenHosts=new Set();
 const today=dayKey(new Date());

 // chronological for first-seen domain
 const chrono=[...all].sort((a,b)=>new Date(a.timestamp||a.startedAt)-new Date(b.timestamp||b.startedAt));
 for(const r of chrono){
  const h=hostOf(r);
  const first=!h||seenHosts.has(h)?false:true;
  if(h)seenHosts.add(h);
  r.__firstHost=first;
 }

 const reads=credentialReadCards(payload.tasks);
 const cmds=[...commandCards(payload.tasks),...transportExecCommands()];

 for(const r of all){
  const host=hostOf(r);
  const when=r.timestamp||r.startedAt;
  const call=r.call||null;
  const agent=r.agent||'未对上 Agent';
  const sess=r.session||r.codexThreadID||'还没对上哪次工具调用';
  const tool=r.tool||'访问';

  for(const f of findingsOf(r)){
   if(f.rule==='credential-outbound'||f.rule==='private-key-outbound'){
    alerts.push({
     id:alertId('S02',(call||r.id)+':'+f.rule),rule:'S02',severity:'critical',confidence:'obs',
     title:f.rule==='private-key-outbound'?'出站请求含私钥片段（已打码）':'出站请求体含疑似密钥（已打码）',
     sub:`${tool} · ${host||'未知主机'} · ${f.direction==='response'?'收回':'送出'}第 ${f.characterOffset??0} 字符`,
     agent,session:sess,call,record:r,timestamp:when,status:'open',
     why:'content_audit 命中 '+f.rule+'。展示正文已打码，原始匹配文本不会写入告警。'
    });
   }
   if(f.rule==='instruction-override-inbound'){
    alerts.push({
     id:alertId('INB',(call||r.id)+':inj'),rule:'INB',severity:'high',confidence:'obs',
     title:'收回内容含提示覆盖指令',
     sub:`${tool} · ${host||'未知主机'} · 入站正文`,
     agent,session:sess,call,record:r,timestamp:when,status:'open',
     why:'content_audit 命中 instruction-override-inbound。这是入站告警，不证明本机已执行该指令。'
    });
   }
   if(f.rule==='download-execute-inbound'){
    alerts.push({
     id:alertId('S03',(call||r.id)+':pipe'),rule:'S03',severity:'critical',confidence:'obs',
     title:'收回内容含「下载后管道执行」写法',
     sub:`${tool} · ${host||'未知主机'}`,
     agent,session:sess,call,record:r,timestamp:when,status:'open',
     why:'响应正文命中 curl|bash / wget|sh 一类写法。是否真的执行了，还要看本机命令证据。'
    });
   }
  }

  if(bypassed(r)){
   alerts.push({
    id:alertId('S07',call||r.id),rule:'S07',severity:'high',confidence:'obs',
    title:'命令绕过了审计代理',
    sub:`${tool} · ${host||'目标未解析'} · 后端 auditBypass`,
    agent,session:sess,call,record:r,timestamp:when,status:'open',
    why:'后端写入了 auditBypass=true。前端不根据 --noproxy 等参数自行推断。'
   });
  }

  if(bytesOut(r)>1048576&&r.__firstHost&&host&&!isAllowedHost(host)){
   alerts.push({
    id:alertId('S05',call||r.id),rule:'S05',severity:'high',confidence:call?'cor':'obs',
    title:`向新域名上传 ${(bytesOut(r)/1048576).toFixed(1)} MB`,
    sub:`${tool} · ${host}`,
    agent,session:sess,call,record:r,timestamp:when,status:'open',
    why:'本会话视角下该域名首次出现，且单次送出超过 1 MB。'
   });
  }

  const git=r.gitOperation||{};
  const op=String(git.operation||'');
  const remote=String(git.remote||git.url||host||'');
  if((r.tool==='git'&&/push|clone|fetch/i.test(op+' '+list(r.args).join(' ')))||(r.tool==='brew'&&list(r.args).some(a=>String(a)==='tap'))||r.tool==='ssh'||(r.tool==='curl'&&host&&!isAllowedHost(host))){
   const dest=host||remote;
   if(dest&&!isAllowedHost(dest)&&!/^(127\.|localhost|::1)/i.test(dest)){
    const title=r.tool==='git'?`git ${op||'操作'} 到非白名单远端`:r.tool==='brew'?'brew 使用未在白名单的 tap':r.tool==='ssh'?`ssh 到新主机（${dest}）`:`外联非白名单主机 ${dest}`;
    alerts.push({
     id:alertId('S04',(call||r.id)+':'+dest),rule:'S04',severity:r.tool==='ssh'?'medium':'high',
     confidence:call?'obs':(/加密/.test(String(r.gap||''))?'inf':'obs'),
     title,sub:`${tool} · ${dest}`,agent,session:sess,call,record:r,timestamp:when,status:'open',
     why:r.tool==='ssh'?'只看到连到了哪里；通道内传了什么看不到。':'目的地不在默认可信名单。白名单可在本机策略里扩展（当前为内置默认）。'
    });
   }
  }

  // S03 (en_4088c393): Correlated 只来自执行前 sha256==下载 sha256（basis=exec_hash）。
  // 同父兄弟进程一律 Inferred(same_parent_shell)；不把 curl→sh 合成血缘当成 Correlated。
  const downloads=list(r.downloads).filter(d=>d&&d.path);
  for(const d of downloads){
   const fullPath=String(d.path);
   const name=fullPath.split(/[/\\]/).pop();
   const sha=d.sha256?String(d.sha256).toLowerCase():'';
   const start=new Date(when).getTime();
   if(isNaN(start))continue;
   const dlPid=r.pid;
   const dlStart=r.processStartAt||r.startedAt||when;
   const dlCall=call||'缺口';
   let best=null;
   for(const c of cmds){
    if(!c.at)continue;
    const dt=(new Date(c.at).getTime()-start)/1000;
    if(dt<0||dt>300)continue;
    if(!isActualExecution(c.cmd,c.card?.execution?.tool||c.record?.tool||(c.cmd||'').split(/\s+/)[0]))continue;
    const pathHit=c.cmd.includes(fullPath)||(name&&(new RegExp('(?:^|[\\s\'"`/=])'+name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'(?:$|[\\s\'"`;|&])')).test(c.cmd));
    if(!pathHit)continue;
    const lineageHit=!!(dlPid&&c.parentPID&&String(c.parentPID)===String(dlPid)&&dlStart&&(c.parentStartAt||c.processStartAt||c.at));
    const siblingSameParent=!!(c.parentPID&&r.parentPID&&String(c.parentPID)===String(r.parentPID||r.launcherPID)&&c.pid&&dlPid&&String(c.pid)!==String(dlPid));
    const hashHit=!!(sha&&c.sha&&c.sha===sha);
    let basis='path_only';
    if(hashHit)basis='exec_hash';
    else if(siblingSameParent)basis='same_parent_shell';
    else if(lineageHit)basis='lineage_observed';
    const confidence=basis==='exec_hash'?'cor':'inf';
    const cmdCall=c.call||'缺口';
    const rank=(confidence==='cor'?3:1)+(basis==='same_parent_shell'?1:0)+(hashHit?1:0);
    const evidence={
     downloadCall:dlCall,execCall:cmdCall,path:fullPath,basis,lineage:lineageHit,hashMatch:hashHit,
     sameParentShell:basis==='same_parent_shell',dtSec:Math.round(dt),parentPID:c.parentPID||null,downloadPID:dlPid||null,
     parentName:c.parentName||null,parentArgv:c.parentArgv||null,parentStartAt:c.parentStartAt||null,
     downloadStartAt:dlStart||null,execSha256:c.sha||null,downloadSha256:sha||null
    };
    const why=basis==='exec_hash'
      ?`分级依据 Correlated（basis=exec_hash）：执行前目标文件 SHA-256 与下载哈希一致（Δt ${Math.round(dt)}s）。下载 ${dlCall} · 命令 ${cmdCall}。`
      :basis==='same_parent_shell'
       ?`分级依据 Inferred（basis=same_parent_shell）：curl 与 sh 同属父 shell 兄弟进程（parentPID=${c.parentPID}），无执行哈希对齐（Δt ${Math.round(dt)}s）。下载 ${dlCall} · 命令 ${cmdCall}。`
       :`分级依据 Inferred（basis=${basis}）：路径「${cut(fullPath,60)}」与命令「${cut(c.cmd,80)}」（Δt ${Math.round(dt)}s）；无执行哈希。下载 ${dlCall} · 命令 ${cmdCall}。`;
    const candidate={
     id:alertId('S03',fullPath),rule:'S03',severity:'critical',confidence,basis,rank,
     title:'下载后在 5 分钟内执行',
     sub:`${name}${sha?' · SHA-256 '+sha.slice(0,12)+'…':''}`,
     agent,session:sess,call:c.call||call,record:r,execRecord:c.record||null,timestamp:c.at||when,status:'open',
     evidence,why
    };
    if(!best||candidate.rank>best.rank||(candidate.rank===best.rank&&new Date(candidate.timestamp)>=new Date(best.timestamp)))best=candidate;
   }
   if(best){
    delete best.rank;
    // Collapse by absolute path; prefer higher confidence, then most recent download writer (this `r`).
    const existing=alerts.findIndex(a=>a.rule==='S03'&&a.evidence?.path===fullPath);
    if(existing>=0){
     const prev=alerts[existing];
     const prevRank=(prev.confidence==='cor'?3:1);
     const nextRank=(best.confidence==='cor'?3:1);
     const prevWrite=new Date(prev.record?.startedAt||prev.timestamp||0).getTime();
     const nextWrite=new Date(r.startedAt||when||0).getTime();
     if(nextRank>prevRank||(nextRank===prevRank&&nextWrite>=prevWrite))alerts[existing]=best;
    }else alerts.push(best);
   }
  }
 }

 // S01: 仅真实文件读取证据 + 同一执行编号；无真实读取时不报（盲区见覆盖度）
 for(const read of reads){
  if(!read.call)continue;
  const r=all.find(x=>x.call&&String(x.call)===String(read.call));
  if(!r)continue;
  const host=hostOf(r);
  if(host&&isAllowedHost(host))continue;
  alerts.push({
   id:alertId('S01',read.call),rule:'S01',severity:'critical',confidence:'cor',
   title:`读取凭证相关路径后外联${host?' '+host:''}`,
   sub:`${cut(read.path,48)} → ${r.tool||'访问'} · 同一执行编号`,
   agent:r.agent||read.task?.agent||'未对上 Agent',session:r.session||read.task?.session||'',call:read.call,record:r,timestamp:r.timestamp||r.startedAt,status:'open',
   why:'文件读取证据来自 resource.path，并与外联共用执行编号。描述文本或无路径证据不会触发 S01。'
  });
 }

 // dedupe by id, keep newest
 const map=new Map();
 for(const a of alerts){
  if(dayKey(a.timestamp)&&dayKey(a.timestamp)!==today&&alerts.length>40)continue;
  map.set(a.id,a);
 }
 return [...map.values()].sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
}

function coverageModel(payload){
 const health=list(payload.health);
 const agents=['Cursor','Codex','WorkBuddy'];
 const chips=agents.map(a=>{
  const hs=health.filter(h=>String(h.source||'').toLowerCase().includes(a.toLowerCase()));
  if(!hs.length)return {a,level:'none',label:'来源未提供'};
  if(hs.some(h=>/failed|error/i.test(h.state)))return {a,level:'part',label:'异常'};
  if(hs.some(h=>/healthy|running|listening/i.test(h.state)))return {a,level:'full',label:'已接入'};
  return {a,level:'part',label:'部分'};
 });
 const proxy=health.find(h=>/workbuddy-network|proxy|mitm/i.test(String(h.source||'')+' '+String(h.detail||'')));
 const proxyUp=!!(proxy&&proxy.state!=='failed'&&(/healthy|degraded|running|listening/i.test(String(proxy.state||''))||/18891|proxy is running|records received/i.test(String(proxy.detail||''))));
 return {chips,proxyUp,proxyDetail:proxy?.detail||'',blind:[
  {t:'未走代理的流量',s:'不读 HTTPS_PROXY 的程序、agent 内置直连',v:'看不到，也不估算比例'},
  {t:'文件读取（S01）',s:'不经 agent 会话 / 执行编号的读文件；无 resource.path 的描述文本不算读取证据',v:'未接 Endpoint Security，不声称文件级监控；无真实读取证据时 S01 不报'},
  {t:'安全设置变更（S06）',s:'各 agent 配置文件关键字段',v:'本版未监看，规则页仅说明'},
  {t:'SSH 加密通道',s:'ssh、git over ssh 内部传输',v:'只看到连到了哪台主机'},
  {t:'证书固定 / QUIC',s:'拒绝本机根证书或走 UDP 443',v:'可能只有元数据，或完全看不到'}
 ]};
}

/** 已知悉只影响显示样式，不改变告警本身、不做验收处置。 */
function applyDecisions(alerts,decisions){
 const map=new Map(list(decisions).map(d=>[d.id,d]));
 return alerts.map(a=>{
  const d=map.get(a.id);if(!d)return a;
  const acked=d.state==='acked'||d.state==='acknowledged'||d.state==='known';
  return {...a,acked,decision:d};
 });
}
function statusLabel(a){
 if(a.acked)return '已知悉';
 return '未读';
}
function renderStats(alerts,cov){
 const crit=alerts.filter(a=>a.severity==='critical').length;
 const high=alerts.filter(a=>a.severity==='high').length;
 const unread=alerts.filter(a=>!a.acked).length;
 const chips=cov.chips.map(c=>`<span class="risk-chip ${c.level==='full'?'ok':c.level==='part'?'warn':'bad'}"><i></i>${esc(c.a)} ${esc(c.label)}</span>`).join('')
  +`<span class="risk-chip ${cov.proxyUp?'ok':'bad'}"><i></i>${cov.proxyUp?'代理在听':'未走代理流量：看不到'}</span>`;
 return `<div class="risk-stats">
  <div class="risk-stat crit"><b>${crit}</b><span>今日 Critical</span></div>
  <div class="risk-stat high"><b>${high}</b><span>今日 High</span></div>
  <div class="risk-stat ask"><b>${unread}</b><span>未读</span></div>
  <div class="risk-cov"><div class="risk-cov-t"><span>覆盖度 · 告警只来自看得到的部分</span><button type="button" data-view="coverage">看不到什么 →</button></div><div class="risk-chips">${chips}</div></div>
 </div>`;
}

function renderFilters(alerts,filter){
 const f=filter||{sev:'all',rule:'all',agent:'all',q:''};
 const agents=[...new Set(alerts.map(a=>a.agent))];
 const rules=[...new Set(alerts.map(a=>a.rule))];
 const item=(k,v,label,n)=>`<button type="button" class="risk-f ${f[k]===v?'on':''}" data-risk-filter="${k}" data-risk-value="${esc(v)}">${esc(label)}<span>${n}</span></button>`;
 return `<aside class="risk-filters">
  <h5>严重级别</h5>${item('sev','all','全部',alerts.length)}${item('sev','critical','Critical',alerts.filter(a=>a.severity==='critical').length)}${item('sev','high','High',alerts.filter(a=>a.severity==='high').length)}${item('sev','medium','Medium',alerts.filter(a=>a.severity==='medium').length)}
  <h5>命中规则</h5>${item('rule','all','全部',alerts.length)}${rules.map(r=>item('rule',r,r,alerts.filter(a=>a.rule===r).length)).join('')}
  <h5>Agent</h5>${item('agent','all','全部',alerts.length)}${agents.map(a=>item('agent',a,a,alerts.filter(x=>x.agent===a).length)).join('')}
  <label class="risk-search">搜索<input id="risk-search" value="${esc(f.q||'')}" placeholder="域名、规则、会话…"></label>
 </aside>`;
}

function rowHTML(a,selected){
 const c=confOf(a.confidence);
 const assoc=associationOf(a);
 return `<tr class="${selected===a.id?'sel':''}${a.acked?' acked':''}" data-risk-alert="${esc(a.id)}">
  <td><span class="risk-sev ${sevOf(a.severity)}">${sevLabel(a.severity)}</span></td>
  <td><button type="button" class="risk-link" data-risk-alert="${esc(a.id)}"><div class="t1">${esc(a.title)}</div><div class="t2">${esc(a.sub)}</div></button></td>
  <td class="ag"><b>${esc(a.agent)}</b><div class="t2 mono">${esc(cut(a.session,28))}</div><div class="t2 strength-${esc(assoc.kind)}">关联：${esc(assoc.name)}</div></td>
  <td><span class="risk-rule">${esc(a.rule)}</span></td>
  <td><span class="risk-conf ${c.c}">${esc(c.t)}</span></td>
  <td><span class="risk-st ${a.acked?'acked':'open'}">${esc(statusLabel(a))}</span></td>
  <td class="mono">${esc(time(a.timestamp))}</td>
 </tr>`;
}

function renderList(holder,payload,state){
 const alerts=applyDecisions(buildAlerts(payload),state.decisions||[]);
 const cov=coverageModel(payload);
 state.alerts=alerts;
 if(window.AgentReinsRisk)window.AgentReinsRisk._lastAlerts=alerts;
 const f=state.filter||{sev:'all',rule:'all',agent:'all',q:''};
 let shown=alerts.filter(a=>(f.sev==='all'||a.severity===f.sev)&&(f.rule==='all'||a.rule===f.rule)&&(f.agent==='all'||a.agent===f.agent));
 if(f.q){const q=f.q.toLowerCase();shown=shown.filter(a=>[a.title,a.sub,a.agent,a.session,a.rule,hostOf(a.record||{})].join('\n').toLowerCase().includes(q));}
 const selected=state.selected&&shown.find(a=>a.id===state.selected)||null;
 const table=shown.length?`<div class="risk-table-wrap"><table class="risk-table"><thead><tr><th>级别</th><th>告警</th><th>Agent · 会话</th><th>规则</th><th>证据可信度</th><th>状态</th><th>时间</th></tr></thead><tbody>${shown.map(a=>rowHTML(a,selected?.id)).join('')}</tbody></table>
 <div class="risk-ft"><span>可信度：Observed / Correlated / Inferred / Unknown · 关联强度：按执行编号 / 候选 / 缺口</span><span>仅真实采集 · ${shown.length} 条</span></div></div>`
  :`<div class="risk-empty"><h2>今天还没有风险告警</h2><p>没有告警不等于安全。未走代理的流量、文件级读取和配置变更仍可能是盲区。</p><ol><li>看覆盖度，确认代理是否在听。</li><li>用真实工具调用触发 S02 / S03 / S07 后再回到这里。</li></ol><button type="button" data-view="coverage">打开覆盖度</button><button type="button" data-view="network">打开外网访问</button></div>`;
 const detail=selected?renderDetail(selected,payload):'';
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">本机 · WorkBuddy / Codex / Cursor</div><h1>风险告警</h1><p>这台 Mac 上的编码 agent 今天有没有做危险的事。每条告警都能点开看送出和收回的证据。</p></div></div>
 ${renderStats(alerts,cov)}
 <div class="risk-split">${renderFilters(alerts,f)}<div class="risk-main">${table}${detail}</div></div>`;
}

function s07EvidenceMarkup(a,r){
 // S07 只陈述本条实际有的证据（auditBypass），不套用通用「flow ID / 已采流证据」文案。
 const host=hostOf(r||{});
 const args=list(r?.args).map(String).join(' ');
 return `<div class="network-verdict"><strong>后端标记 auditBypass=true</strong>
  <p>${esc(host||'目标未解析')} · 工具 ${esc(r?.tool||'—')} · 执行编号 ${esc(a.call||'缺口')}</p></div>
  <dl class="network-facts">
   <dt>证据字段</dt><dd>auditBypass=true（后端写入；前端不根据 --noproxy 自行推断）</dd>
   <dt>Agent</dt><dd>${esc(a.agent||'—')}</dd>
   <dt>会话</dt><dd>${esc(a.session||'未确认')}</dd>
   <dt>命令参数</dt><dd class="mono">${esc(cut(args,200)||'未采到')}</dd>
   <dt>开始时间</dt><dd>${esc(a.timestamp||r?.startedAt||'—')}</dd>
  </dl>
  <p class="network-notice">本条没有请求/响应流、也没有 flow ID；未采到的字段不会写成已确认证据。</p>`;
}

function renderDetail(a,payload){
 const r=a.record;
 const net=window.AgentReinsNetwork;
 let exchange='';
 if(a.rule==='S07'){
  exchange=s07EvidenceMarkup(a,r);
 }else if(r&&net?.exchangeMarkup){
  exchange=net.exchangeMarkup({
   agent:a.agent,host:hostOf(r),port:r.port||r.resource?.remotePort,ip:r.resource?.remoteIP||r.ip,
   proxy:r.proxy,session:a.session,call:a.call,taskID:r.taskID,command:list(r.args).join(' '),tool:r.tool,
   evidenceType:r.evidenceType,networkBody:r.networkBody,gap:r.gap,auditBypass:r.auditBypass
  });
 }
 const c=confOf(a.confidence);
 const assoc=associationOf(a);
 const evidenceBlock=a.evidence
  ?`<pre class="mono risk-evidence-json">${esc(JSON.stringify(a.evidence,null,2))}</pre>`
  :'';
 return `<article class="risk-detail${a.acked?' acked':''}">
  <header><span class="risk-sev ${sevOf(a.severity)}">${sevLabel(a.severity)}</span><h2>${esc(a.title)}</h2>
  <p>${esc(a.agent)} · ${esc(a.session)} · 规则 ${esc(a.rule)} · <span class="risk-conf ${c.c}">${esc(c.t)}</span> · <span class="strength-${esc(assoc.kind)}">关联 ${esc(assoc.name)}</span>（${esc(assoc.note)}）· 执行编号 ${esc(a.call||'缺口')}</p></header>
  <p class="risk-why">${esc(a.why||'')}</p>
  ${evidenceBlock}
  <div class="risk-actions">
   ${a.acked?'':`<button type="button" class="quiet" data-risk-decide="acked" data-risk-id="${esc(a.id)}">标记已知悉</button>`}
   ${a.call&&a.rule!=='S07'?`<button type="button" class="quiet" data-network-record-jump="${esc(r?.id||'')}">在外网访问中打开</button>`:''}
   <button type="button" class="quiet" data-view="network">外网访问</button>
   <button type="button" class="quiet" data-view="rules">规则说明</button>
  </div>
  ${a.acked?`<p class="note">已知悉（仅样式）· ${esc(a.decision?.decidedAt||'')} · 告警本身未改</p>`:''}
  <h3>${a.rule==='S07'?'绕过证据':'送出 / 收回'}</h3>
  ${exchange||'<p class="empty">这条告警还没有可展示的交换正文。</p>'}
  <div class="risk-gapbox"><b>证据缺口</b><br>${esc(RULES.find(x=>x.id===a.rule)?.cant||'未采到的部分不会补成已确认。')}${a.call?'':'<br>· 还没有执行编号，工具调用归属未知。'}</div>
 </article>`;
}

function renderRules(holder,payload){
 const alerts=buildAlerts(payload);
 const cards=RULES.map(r=>{
  const hit=alerts.filter(a=>a.rule===r.id).length;
  return `<div class="risk-rc"><div class="h"><span class="id">${esc(r.id)}</span><span class="nm">${esc(r.name)}</span><div class="seg"><span class="on">告警</span></div></div>
   <div class="d">${esc(r.desc)}</div><div class="cond mono">${esc(r.cond)}</div>
   <div class="m"><span><b>${hit}</b>今日命中</span><span><b>—</b>近 7 天</span></div>
   <div class="cant"><b>看不到：</b>${esc(r.cant)}</div></div>`;
 }).join('');
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">本机规则 · ${RULES.length} 条</div><h1>规则</h1><p>少而准：命中时尽量拿出送出/收回或命令证据。默认只告警；验收流已撤掉。</p></div></div>
 <div class="risk-rules">${cards}</div>
 <p class="note" style="margin:16px 28px">S01 无真实文件读取证据时不报。S03 按路径/进程血缘/时间窗关联（执行编号可不同）。S06 本版未监看配置文件。S07 只认后端 auditBypass=true。</p>`;
}

function renderCoverage(holder,payload,riskState){
 const cov=coverageModel(payload);
 const rows=cov.chips.map(c=>`<tr><td><b>${esc(c.a)}</b></td><td><span class="risk-lvl ${esc(c.level)}">${esc(c.label)}</span></td><td colspan="3" class="t2">以采集源健康状态为准；会话/工具调用是否齐全见外网访问页的关联强度。</td></tr>`).join('');
 const blind=cov.blind.map(b=>`<tr><td><b>${esc(b.t)}</b><div class="t2">${esc(b.s)}</div></td><td>${esc(b.v)}</td></tr>`).join('');
 const audit=Array.isArray(riskState?.mcpAudit)?riskState.mcpAudit:[];
 const auditRows=audit.length
  ?audit.slice().reverse().map(e=>`<tr><td>${esc(e.at||'')}</td><td>${esc(e.actor||'')}</td><td><b>${esc(e.tool||'')}</b></td><td class="t2 mono">${esc(cut(e.argsDigest||'',16))}</td><td class="t2 mono">${esc(cut(e.hash||'',12))}</td></tr>`).join('')
  :`<tr><td colspan="5" class="t2">尚无 Codex/supervisor 只读调用记录。配置 tools/agentreins-mcp/server.py 后会出现哈希链审计。</td></tr>`;
 const auditPath=esc(cut(riskState?.mcpAuditPath||'~/Library/Application Support/AgentGuard/mcp-supervisor-audit.jsonl',120));
 holder.innerHTML=`<div class="risk-ph"><div><div class="k">告警只来自看得到的部分</div><h1>覆盖度 · 看不到什么</h1><p>没有告警不等于安全。下面写清盲区。</p></div></div>
 <div class="risk-stats cov-only">
  <div class="risk-stat"><b class="${cov.proxyUp?'ok':''}">${cov.proxyUp?'在听':'未确认'}</b><span>审计代理 18891</span></div>
  <div class="risk-stat"><b>S01</b><span>文件读 · 盲区（无 ES）</span></div>
  <div class="risk-stat"><b>S06</b><span>配置监看 · 未接入</span></div>
  <div class="risk-stat"><b>看不到</b><span>未走代理流量 · 不估算</span></div>
 </div>
 <div class="risk-covg">
  <section class="risk-card"><h3>Agent 接入情况</h3><table class="risk-table"><thead><tr><th>Agent</th><th>接入</th><th>说明</th></tr></thead><tbody>${rows}</tbody></table>
  <p class="note">代理 ${cov.proxyUp?'在线':'状态未确认'} · ${esc(cut(cov.proxyDetail,120)||'127.0.0.1:18891')}</p></section>
  <section class="risk-card"><h3>盲区</h3><table class="risk-table"><thead><tr><th>盲区</th><th>现在能看到多少</th></tr></thead><tbody>${blind}</tbody></table></section>
  <section class="risk-card"><h3>Supervisor MCP 只读审计</h3>
   <p class="note">Codex 经 stdio MCP 的每次只读查询会追加哈希链日志（本页只展示，不可改写）。路径：${auditPath}</p>
   <table class="risk-table"><thead><tr><th>时间</th><th>调用方</th><th>工具</th><th>参数摘要</th><th>hash</th></tr></thead><tbody>${auditRows}</tbody></table>
  </section>
 </div>`;
}

function evidenceTextFor(a){
 const r=a.record||{};
 const body=r.networkBody||{};
 return [
  'rule='+a.rule,'title='+a.title,'agent='+a.agent,'session='+a.session,'call='+(a.call||''),
  'why='+(a.why||''),'host='+hostOf(r),'args='+list(r.args).join(' '),
  'request='+String(body.request||'').slice(0,8000),'response='+String(body.response||'').slice(0,8000),
  'audit='+JSON.stringify(auditOf(r)||{})
 ].join('\n');
}
function packFields(a){
 return {
  id:a.id,title:a.title,summary:a.sub||a.why||'',rule:a.rule,agent:a.agent,session:a.session||'',
  call:a.call||null,state:a.decision?.state||null,note:a.decision?.note||null,
  decidedAt:a.decision?.decidedAt||null,evidenceText:evidenceTextFor(a)
 };
}
window.AgentReinsRisk={
 RULES,buildAlerts,applyDecisions,renderList,renderRules,renderCoverage,coverageModel,packFields,evidenceTextFor,associationOf,bypassed,isTestCapture,isActualExecution,isProvenShellParent,
 get esc(){return escImpl;},
 set esc(fn){escImpl=typeof fn==='function'?fn:escImpl;},
 _lastAlerts:[]
};
})();
