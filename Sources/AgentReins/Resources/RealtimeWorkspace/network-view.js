'use strict';
(()=>{
 const list=v=>Array.isArray(v)?v:[],esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 function scope(host){
  host=String(host||'').toLowerCase().replace(/^\[|\]$/g,'');
  if(!host)return 'unknown';
  const a=host.split('.').map(Number);
  if(a.length===4&&a.every(n=>Number.isInteger(n)&&n>=0&&n<=255))return a[0]===0||a[0]===10||a[0]===127||a[0]>=224||a[0]===169&&a[1]===254||a[0]===172&&a[1]>=16&&a[1]<=31||a[0]===192&&a[1]===168||a[0]===100&&a[1]>=64&&a[1]<=127?'local':'public';
  if(host.includes(':')){if(host.startsWith('::ffff:'))return scope(host.slice(7))==='local'?'local':'unknown';if(host==='::'||host==='::1'||/^f[cd]|^fe[89ab]|^ff/.test(host))return 'local';return /^[23][0-9a-f]{0,3}:/.test(host)&&!host.startsWith('2001:db8:')?'public':'unknown';}
  return 'unknown';
 }
 function agentTransport(record){
  return record&&record.captureMode==='agent-path'&&['Codex','WorkBuddy','Cursor'].includes(record.agent)&&/^[A-Za-z0-9._+-]{1,32}$/.test(record.tool||'');
 }
 let localRuns=[],capturedBodies=[];
 function setLocalTransports(records){localRuns=list(records).filter(agentTransport);}
 function setCapturedBodies(records){capturedBodies=list(records);}
 function hostToken(value){
  const s=String(value||'').trim();
  const m=s.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?(\[[^\]]+\]|[A-Za-z0-9.-]+)/i);
  return m?m[1].replace(/^\[|\]$/g,''):'';
 }
 function loopbackHost(value){
  const host=hostToken(value).toLowerCase();
  if(!host)return false;
  if(host==='localhost'||host==='::1')return true;
  const v4=host.match(/^(\d+)\.\d+\.\d+\.\d+$/);
  return !!(v4&&v4[1]==='127');
 }
 function externalDetail(value){
  const text=String(value||'').trim();
  if(!text||loopbackHost(text)||/目标未|未从命令解析|未采到/.test(text))return null;
  return text;
 }
 function invocationArgs(run){
  const saved=list(run.args).map(arg=>String(arg)).filter(Boolean);
  if(saved.length)return saved.slice(0,40);
  const sent=list(run.blocks).find(block=>block.direction==='send'&&block.textPreview&&!list(block.http).length);
  const text=String(sent?.textPreview||'').trim();
  if(!text||/[\n\r]/.test(text))return [];
  return text.split(' ').filter(Boolean).slice(0,40);
 }
 function flagValue(args,name){
  for(let index=0;index<args.length;index++){
   const arg=args[index];
   if(arg===name&&args[index+1]&&!args[index+1].startsWith('-'))return args[index+1];
   if(arg.startsWith(name+'='))return arg.slice(name.length+1);
  }
  return '';
 }
 function askedDestination(run){
  const args=invocationArgs(run);
  const output=new Set(['-O','--output-document','-o','--output','-P','--directory-prefix']);
  const urls=[]; const peers=[];
  args.forEach((arg,index)=>{
   if(arg.startsWith('-')||output.has(args[index-1]))return;
   if(/:\/\//.test(arg))urls.push(arg);
   else if(arg.includes('@')||/^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/.test(arg)||/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+(?::\d{1,5})?$/.test(arg))peers.push(arg);
  });
  if(urls[0]||peers[0])return urls[0]||peers[0];
  if(run.tool==='gh'){
   const host=flagValue(args,'--hostname');
   const repo=flagValue(args,'--repo')||flagValue(args,'-R');
   if(host&&repo)return host+'/'+repo;
   if(host)return host;
   if(repo)return 'github.com/'+repo.replace(/^\//,'');
   if(args.includes('api'))return 'api.github.com';
  }
  return null;
 }
 function hostsFromBlocks(blocks){
  const found=[];
  for(const b of blocks){
   for(const line of list(b.http)){
    const host=String(line).match(/^host:\s*(\S+)/i);
    if(host)found.push(host[1]);
    const absolute=String(line).match(/^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+(https?:\/\/\S+)/i);
    if(absolute)found.push(absolute[1]);
   }
   const preview=String(b.textPreview||'');
   const hostLine=preview.match(/(?:^|\n)>?\s*Host:\s*(\S+)/);
   if(hostLine)found.push(hostLine[1]);
  }
  return found.map(externalDetail).find(Boolean)||null;
 }
 function projectLocal(records){
  return list(records).filter(agentTransport).map(run=>{
   const tunnel=(run.connections||[]).find(c=>c.kind==='proxyTunnel');
   const connected=(run.connections||[]).find(c=>c.kind==='connected');
   const blocks=list(run.blocks);
   const tunnelHost=externalDetail(tunnel?.detail?.[0]);
   const connectedHost=externalDetail(connected?.detail?.[0]);
   const headerHost=hostsFromBlocks(blocks);
   const askedRaw=askedDestination(run);
   const asked=externalDetail(askedRaw);
   // 显式访问本机回环仍保留（不再被当成「无外连」丢掉）；代理隧道里的 127.0.0.1 仍不当作站点。
   const askedLoopback=(!asked&&askedRaw&&loopbackHost(askedRaw))?hostToken(askedRaw):null;
   const connectedLoopback=(!connectedHost&&connected&&loopbackHost(connected.detail?.[0])&&!tunnelHost)?hostToken(connected.detail?.[0]):null;
   const formula=list(run.formulas).find(Boolean);
   const recordedReal=run.realDestination||run.destinationHost||null;
   const target=recordedReal||tunnelHost||headerHost||connectedHost||asked||askedLoopback||connectedLoopback||(run.tool==='brew'&&formula?'Homebrew':null);
   // 127.0.0.1 is the local proxy or a local port, never the external site.
   const proxied=!!tunnelHost||(!!(connected&&loopbackHost(connected.detail?.[0]))&&!!headerHost)||!!run.transportPeer;
   const transportPeer=run.transportPeer||(proxied&&connected&&loopbackHost(connected.detail?.[0])?hostToken(connected.detail[0]):null);
   const destinationSource=run.destinationSource||(recordedReal?'proxy_observed':headerHost?'proxy_observed':asked?'argv_parsed':null);
   const side=direction=>blocks.filter(b=>b.direction===direction);
   const hideLine=line=>/^(?:>|<)?\s*(authorization|cookie|set-cookie|proxy-authorization)\s*:/i.test(String(line).trim())||/connection established/i.test(String(line));
   const text=items=>items.map(b=>{
    const http=list(b.http).filter(line=>!hideLine(line));
    const preview=String(b.textPreview||'').split('\n').filter(line=>!hideLine(line)).join('\n');
    return [http.join('\n'),preview].filter(Boolean).join('\n');
   }).filter(Boolean).join('\n\n');
   const bytes=items=>items.filter(b=>b.kind==='data').reduce((n,b)=>n+(Number(b.observedBytes)||0),0);
   const sent=side('send'),received=side('receive');
   const names=list(run.outboundFiles).filter(Boolean);
   const invocation=invocationArgs(run);
   const downloads=list(run.downloads).filter(item=>item&&typeof item==='object');
   // en_d595e9da: never promote sh/bash exec fileResult into downloads[] — that made
   // downloadCall/downloadPID point at the exec record instead of curl.
   const isExecTool=/^(sh|bash|zsh|dash|open|chmod)$/.test(String(run.tool||''));
   const fallback=(!isExecTool&&run.fileResult&&typeof run.fileResult==='object')?[run.fileResult]:[];
   const downloadRecords=(downloads.length?downloads:fallback).filter(item=>item.path&&item.path!=='/dev/null');
   const downloaded=downloadRecords.map(item=>String(item.path).split(/[/\\]/).pop()).filter(name=>name&&name!=='null');
   const request=[names.length?'外传文件名\n'+names.join('\n'):'',downloaded.length?'下载文件名\n'+downloaded.join('\n'):'',text(sent)].filter(Boolean).join('\n\n');
   const statusLine=received.flatMap(block=>list(block.http).map(String)).filter(line=>/^HTTP\//.test(line)&&!/connection established/i.test(line)).pop();
   const statusMatch=statusLine&&statusLine.match(/\s(\d{3})\b/);
   // chmod/sh/bash/open 无外连主机，仍保留为本地执行证据（S03）
   const isLocalExec=/^(chmod|sh|bash|open)$/.test(String(run.tool||''));
   if(!target&&!isLocalExec&&!downloadRecords.length)return null;
   const host=target||(isLocalExec?'local-exec':null);
   return {id:'local-transport:'+(run.runID||run.startedAt+':'+run.pid),agent:run.agent,tool:run.tool,args:invocation,connections:list(run.connections),timestamp:run.startedAt,startedAt:run.startedAt,processStartAt:run.processStartAt||run.startedAt||null,host,realDestination:target&&!loopbackHost(target)?target:recordedReal||null,transportPeer,destinationSource,pid:run.pid,parentPID:run.parentPID||run.launcherPID||null,parentName:run.parentName||null,parentArgv:run.parentArgv||null,parentStartAt:run.parentStartAt||null,launcherPID:run.launcherPID||null,runID:run.runID,provenance:run.provenance,testCapture:run.testCapture===true,accessKind:isLocalExec?'local-exec':'local-tool',route:proxied?'proxied':'direct',source:'agentsight:local-transport',evidenceType:isLocalExec?'local_tool_exec':'local_tool_exchange',session:run.session||run.codexThreadID||null,codexThreadID:run.codexThreadID||null,call:run.call||run.runID||null,exitCode:run.exitCode,gap:run.gap||null,auditBypass:run.auditBypass===true?true:run.auditBypass===false?false:undefined,sha256:run.sha256||run.fileResult?.sha256||null,proxy:proxied?'本机代理':null,outboundFiles:names,downloadedFiles:downloaded,downloads:downloadRecords,formulas:list(run.formulas),gitOperation:run.gitOperation||null,fileResult:run.fileResult||null,networkBody:{flow:'local:'+(run.runID||run.pid),request:request||null,response:text(received)||null,requestBytes:bytes(sent),responseBytes:bytes(received),requestTruncated:sent.some(b=>b.previewTruncated),responseTruncated:received.some(b=>b.previewTruncated),responseComplete:run.exitCode===0,requestComplete:sent.length>0||names.length>0||downloaded.length>0,responseStatus:statusMatch?Number(statusMatch[1]):undefined,securityAudit:run.securityAudit||null},taskTitle:isLocalExec?(run.tool+' 本地执行'):(run.tool==='git'?'Git '+(run.gitOperation?.operation||'操作'):run.tool+' 访问')};
  }).filter(Boolean);
 }
 function localExchanges(){return projectLocal(localRuns);}
 function rawLocalTransports(){return list(localRuns);}
 function foldCapturedIntoCalls(locals,exchanges){
  const byCall=new Map();
  for(const row of locals) if(row.call) byCall.set(String(row.call),row);
  return exchanges.filter(row=>{
   const call=row.call&&byCall.get(String(row.call));
   if(!call) return true;
   const body=row.networkBody||{};
   if(!call.subrequests) call.subrequests=[];
   call.subrequests.push({id:row.id,host:row.host,url:row.url,networkBody:body});
   if(call.subrequests.length===1){
    const local=call.networkBody;
    if(body.response && (!local.response || String(body.response).length>String(local.response).length)) local.response=body.response;
    if(body.request && (!local.request || String(body.request).length>String(local.request).length)) local.request=body.request;
    if(body.responseStatus && !local.responseStatus) local.responseStatus=body.responseStatus;
   }
   if(call.traceAudit===undefined) call.traceAudit=call.networkBody.securityAudit||null;
   if(body.securityAudit){
    call.proxyAudit=mergeAudit(call.proxyAudit, body.securityAudit);
    call.networkBody.securityAudit=mergeAudit(call.traceAudit, call.proxyAudit, 'overlap');
   }
   return false;
  });
 }
 function cardObject(card){
  try{const value=JSON.parse(card&&card.input||'');if(value&&typeof value==='object'&&!Array.isArray(value))return value;}catch{}
  return {};
 }
 function shellText(card){
  const recorded=card&&card.execution&&card.execution.command;
  if(typeof recorded==='string'&&recorded.trim())return recorded.trim();
  const raw=cardObject(card).command||cardObject(card).cmd||cardObject(card).shell_command;
  return typeof raw==='string'?raw.trim():'';
 }
 function splitCommand(text){
  const parts=[];
  const pattern=/"([^"]*)"|'([^']*)'|(\S+)/g;
  let match;while((match=pattern.exec(text)))parts.push(match[1]??match[2]??match[3]);
  return parts;
 }
 function cardResult(card){
  const text=String(card&&card.output||'');
  if(!text||text==='结果尚未采集'||text==='正文未采集')return null;
  return text;
 }
 function cardExit(card){
  const recorded=card&&card.execution;
  if(recorded&&recorded.exitCode!=null&&recorded.exitCode!=='')return recorded.exitCode;
  if(card&&(card.phase==='failed'||card.status==='attention'))return 1;
  if(card&&(card.phase==='returned'||card.status==='returned'))return 0;
  return null;
 }
 function commandKey(tool,args){return String(tool||'')+' '+list(args).map(arg=>String(arg)).join(' ');}
 function remoteCardVisit(task,card){
  const title=String(card.title||'');
  if(card.kind!=='web'&&!/fetch|search|browse/i.test(title))return null;
  const query=cardObject(card);
  const url=[query.url,query.website,query.link,query.uri].find(value=>typeof value==='string'&&/^https?:\/\//i.test(value))||'';
  const search=[query.query,query.search_term,query.searchTerm,query.q].find(value=>typeof value==='string'&&value.trim())||'';
  const prompt=typeof query.prompt==='string'?query.prompt:'';
  const where=url||search||prompt;
  if(!where||loopbackHost(where))return null;
  const name=/search/i.test(title)&&!/fetch/i.test(title)?'搜索':title||'远程访问工具';
  const failed=card.phase==='failed'||card.status==='attention';
  return {id:'task-tool:'+card.id,agent:task.agent,tool:name,args:[],accessKind:'remote-tool',accessHop:'remote-tool',host:where,url:url||null,timestamp:card.timestamp,startedAt:card.timestamp,session:task.session,turn:task.turn,taskID:task.id,call:card.call||null,connections:[],source:'task-tool',requestObject:query,exitCode:failed?1:null,networkBody:{flow:'task-tool:'+card.id,request:JSON.stringify(query),response:cardResult(card),requestComplete:true,responseComplete:cardResult(card)!=null,responseStatus:failed?502:undefined}};
 }
 function commandCardVisit(task,card){
  const title=String(card.title||'');
  if(card.kind!=='command'&&!/terminal|shell|bash/i.test(title))return null;
  const text=shellText(card);
  const mentions=(text.match(/\b(curl|wget|brew|git|gh|ssh|scp|sftp|rsync)\b/g)||[]);
  if(/[\n;]/.test(text)&&mentions.length>1)return null;
  const parts=splitCommand(text);
  const tool=String(parts[0]||'').split('/').pop();
  if(!['curl','wget','brew','git','gh','ssh','scp','sftp','rsync'].includes(tool))return null;
  const args=parts.slice(1);
  const operation=tool==='git'?args.find(arg=>!arg.startsWith('-')):null;
  const run={captureMode:'agent-path',agent:task.agent,tool,args,startedAt:card.timestamp,pid:card.pid||0,exitCode:cardExit(card),runID:'card-'+card.id,session:task.session,gitOperation:operation?{operation}:null,outboundFiles:[],connections:[],blocks:[{direction:'send',kind:'data',textPreview:shellText(card)},cardResult(card)?{direction:'receive',kind:'data',textPreview:String(cardResult(card)).slice(0,4000)}:null].filter(Boolean)};
  const projected=projectLocal([run])[0];
  if(!projected)return null;
  projected.id='task-tool:'+card.id;
  projected.call=card.call||null;
  projected.taskID=task.id;
  projected.turn=task.turn;
  return projected;
 }
 function taskToolVisits(task){
  const seen=new Set();
  const visits=[];
  for(const card of list(task&&task.cards)){
   const visit=remoteCardVisit(task,card)||commandCardVisit(task,card);
   if(!visit)continue;
   const key=visit.accessKind==='remote-tool'?visit.tool+'\0'+visit.host:commandKey(visit.tool,visit.args);
   if(seen.has(key))continue;
   seen.add(key);
   const transport=localExchanges().find(record=>record.agent===task.agent&&record.session&&record.session===task.session&&commandKey(record.tool,record.args)===commandKey(visit.tool,visit.args));
   if(transport){transport.taskID=task.id;transport.turn=task.turn;visits.push(transport);continue;}
   visits.push(visit);
  }
  return visits;
 }
 function delegatedTarget(object){
  if(!object||typeof object!=='object')return null;
  for(const key of ['url','query','search_term','searchTerm','q','target','website','link','uri','prompt'])if(typeof object[key]==='string'&&object[key])return object[key];
  return null;
 }
 function accessHop(r){
  const service=String(r.serviceURL||'');
  const host=String(r.host||'');
  if(r.accessHop==='model'||service.includes('/chat/completions'))return {kind:'model',localParty:r.agent||'本机',remoteParty:service||host||'模型服务',notice:'这是本机与模型服务的上下文交换，不是访问工具与网站的交互。'};
  if(r.accessHop==='remote-tool'||/\/agenttool\/|\/v2\/videos\//i.test(service))return {kind:'remote-tool',localParty:r.agent||'本机',remoteParty:service||host||'远程访问工具',delegated:delegatedTarget(r.requestObject),notice:'这是本机与远程访问工具之间的交互。工具再到网站的那一段不在本机，下面的正文不是网站原始 HTTP。'};
  if(r.accessKind==='local-tool'||r.accessHop==='local-target'||r.source==='agentsight:local-transport'||(r.source==='agentsight:workbuddy-network-body'&&host))return {kind:'local-tool',localParty:(r.agent||'本机')+' 的本机 '+(r.tool||'网络客户端'),remoteParty:host||'访问目标未采到',notice:r.route==='proxied'?'本次经过代理。下面是本机访问工具与访问目标之间的数据，不是和代理本身的握手。':'本次是本机访问工具直连访问目标。下面是该工具实际发出和收到的数据。'};
  return {kind:'unclassified',localParty:r.agent||'本机',remoteParty:host||service||'对端未采到',notice:'尚未确认这是远程访问工具还是本机访问工具。没有正文就不能判断交互内容。'};
 }
 function redact(value){
  const keys=/^(authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)$/i;
  const scrub=text=>String(text).replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+/gi,'Bearer [已隐藏凭据]').replace(/\b(?:sk-proj-|sk-or-v1-|ghp_)[A-Za-z0-9_-]{20,}/g,'[已隐藏凭据]').replace(/([?&](?:api[_-]?key|access[_-]?token|token|password)=)[^&\s"']*/gi,'$1[已隐藏凭据]');
  const walk=(v,depth=0)=>{
   if(depth>24)return '[深层数据已隐藏]';
   if(Array.isArray(v))return v.map(x=>walk(x,depth+1));
   if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,keys.test(k)?'[已隐藏凭据]':walk(x,depth+1)]));
   if(typeof v==='string'){try{if(/^[{[]/.test(v.trim()))return JSON.stringify(walk(JSON.parse(v),depth+1));}catch{}return scrub(v);}
   return v;
  };
  const original=String(value||'');try{return JSON.stringify(walk(JSON.parse(original)),null,2);}catch{}
  return scrub(original).replace(/("(?:authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)"\s*:\s*")[^"\n]*("|$)/gi,'$1[已隐藏凭据]$2');
 }
 function exchangeMarkup(r){
  const body=r.networkBody||{},intent=r.evidenceType==='tool_intent';
  const request=body.request!=null?`<p>已采 HTTPS 请求正文 · ${esc(body.requestBytes)} 字节${body.requestTruncated?' · 当前预览截断，完整证据保留':''}</p><pre>${esc(redact(body.request))}</pre>`:intent?'<p>只有工具参数；尚未证明这些数据已发送到网站。</p>':'<p>请求正文未采到，不能据此判断没有发送数据。</p>';
  const response=body.response!=null?`<p>${body.responseRepresentation==='parsed_model_output'?'已解析模型输出（不是原始 HTTP 响应字节）':'已采响应正文'}${body.responseTruncated?' · 当前预览截断':''}</p><pre>${esc(redact(body.response))}</pre>`:body.toolInstructions||body.reasoning?'<p>已采模型响应中的工具指令或推理内容；未取得文本回答。</p>':'<p>响应数据未采到；TCP 建立或代理目标记录不能证明网页访问成功。</p>';
  const instructions=body.toolInstructions?'<h4>模型返回的工具指令（未证明执行；预览最多 16000 字符）</h4><pre>'+esc(redact(body.toolInstructions))+'</pre>':'';
  const reasoning=body.reasoning?'<details><summary>已采模型推理输出</summary><pre>'+esc(redact(body.reasoning))+'</pre></details>':'';
  const boundary=body.responseComplete!=null?'<p>响应边界：'+(body.responseComplete?'已确认接收完成':'未确认完整，可能仍在传输或中断')+'</p>':'';
  let requestedSite;try{const q=JSON.parse(body.request||'{}');if(typeof q.url==='string'&&/^https?:\/\//i.test(q.url))requestedSite=q.url;}catch{}
  const siteNotice=requestedSite&&r.host==='copilot.tencent.com'?'<p class="network-notice">以下正文来自 WorkBuddy 工具服务。网址是 Agent 提交给工具服务的访问目标；当前连接 IP 属于工具服务，未证明网站服务器 IP。</p>':'';
  const association=r.taskConfidence==='candidate'?'候选任务，具体调用未确认':r.taskID?'来源会话/轮次匹配':'会话未确认';
  return `<div class="network-verdict"><strong>${intent?'访问意图，未证实发送':body.flow?'已采请求/响应流证据':'已观察连接，网站交互尚未完整采到'}</strong><p>${esc(r.host||'目标未采到')}${r.port?':'+esc(r.port):''} · ${esc(association)}</p></div><div class="network-route"><span>${esc(r.agent||'Agent')}</span><b>→</b><span>${esc(r.proxy||'直接连接／路径未确认')}</span><b>→</b><span>${esc(r.host||'目标未知')}</span></div>${siteNotice}<dl class="network-facts">${requestedSite?'<dt>提交的访问目标</dt><dd>'+esc(redact(requestedSite))+'</dd>':''}${r.url?'<dt>请求网址</dt><dd>'+esc(redact(r.url))+'</dd>':''}${r.serviceURL?'<dt>工具服务地址</dt><dd>'+esc(r.serviceURL)+'</dd>':''}<dt>实际连接对端 IP</dt><dd>${esc(r.ip||'未采到；不以本机代理 IP 代替')}</dd><dt>会话</dt><dd>${esc(r.session||'未确认')}</dd><dt>工具调用</dt><dd>${esc(r.call||'未确认')}</dd><dt>触发来源</dt><dd>${esc(redact(r.command||r.tool||'未确认'))}</dd><dt>交互配对</dt><dd>${body.flow?'同一原生 HTTPS flow ID':'尚未取得可配对的请求/响应流'}</dd></dl><section><h3>Agent 发出了什么</h3>${request}</section><section><h3>对方返回了什么</h3>${boundary}${response}${instructions}${reasoning}</section><p class="network-notice">常见凭据字段默认隐藏；工具报告、解析输出和原始网络正文分别标注，不以网站当前内容代替当次响应。</p>`;
 }
 function rows(payload){
  // Selected task details retain previously collected evidence beyond the live window.
  const archived=list(payload.tasks).flatMap(t=>list(t.cards).filter(c=>c.kind==='network'||c.networkBody).map(c=>({...c,agent:t.agent,session:t.session,turn:t.turn,details:c.input,preview:c.output})));
  const byID=new Map(archived.map(r=>[r.id,r]));
  for(const r of list(payload.collected))byID.set(r.id,r);
  for(const r of capturedBodies)if(!byID.has(r.id))byID.set(r.id,r);
  const candidates=[...byID.values()].filter(r=>(r.kind==='network'||r.networkBody)&&['Codex','WorkBuddy','Cursor'].includes(r.agent));
  const groups=new Map();
  for(const r of candidates.slice().sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp))){
   const key=r.networkBody?.flow?'flow:'+r.networkBody.flow:r.id,old=groups.get(key);
   if(!old){groups.set(key,{...r,requestRecord:r.networkBody?.request!=null?r:null});continue;}
   const body={...old.networkBody};
   if(r.networkBody?.request!=null)for(const k of ['request','requestBytes','requestTruncated'])body[k]=r.networkBody[k];
   if(r.networkBody?.response!=null)for(const k of ['response','responseBytes','responseTruncated','responseRepresentation'])body[k]=r.networkBody[k];
   for(const k of ['toolInstructions','reasoning','responseComplete','requestComplete','requestHeaders','responseHeaders','responseStatus','transportError','securityAudit','wireRequest','wireResponse'])if(r.networkBody?.[k]!=null)body[k]=r.networkBody[k];
   groups.set(key,{...r,resource:{...old.resource,...r.resource},networkBody:body,requestRecord:old.requestRecord||(r.networkBody?.request!=null?r:null)});
  }
  return [...groups.values()].map(r=>{
   const capturedURL=(String(r.details||'')+' '+String(r.preview||'')).match(/"websiteURL"\s*:\s*("(?:[^"\\]|\\.)*")/);
   let websiteURL;try{websiteURL=capturedURL?JSON.parse(capturedURL[1]):null;}catch{}
   const transport=r.requestRecord||r;
   let requestObject;try{requestObject=JSON.parse(r.networkBody?.request||'{}');}catch{}
   const pathMatch=String(transport.details||'').match(/"requestPath"\s*:\s*"([^"\n]+)"/);
   const serviceURL=r.source==='agentsight:workbuddy-network-body'&&transport.resource?.domain==='copilot.tencent.com'?'https://copilot.tencent.com'+(pathMatch?.[1]||new URL(transport.resource?.url||'https://copilot.tencent.com').pathname):null;
   const d=r.resource||{},ip=d.remoteIP||'',host=serviceURL?'copilot.tencent.com':d.domain||d.observedRemoteHost||ip||'';
   const classification=scope(ip||host);
   const task=list(payload.tasks).find(t=>t.agent===r.agent&&t.session===r.session&&r.turn&&t.turn===r.turn);
   const calls=task&&r.call?list(task.cards).filter(c=>c.call===r.call):[];
   const callCard=calls.find(c=>c.id==='call:'+r.call);
   const command=calls.find(c=>c.execution?.command)?.execution.command;
   const process=list(payload.processes).find(p=>String(p.pid)===String(r.pid));
   const geo=list(payload.ipGeolocations).find(g=>g.ip===ip);
   return {id:r.id,agent:r.agent,timestamp:r.timestamp,host,ip,port:d.remotePort||d.observedRemotePort,classification,
    location:geo?.location||d.location||'',geoState:geo?.state||'unqueried',taskID:task?.id,taskTitle:task?.title,
    taskConfidence:/time window|time-window|时间窗口|single active tool|unique exact native tool parameters|same HTTPS flow/i.test(transport.resource?.basis||d.basis||'')||!r.call?'candidate':'native',session:r.session,turn:r.turn,call:r.call,command:command||'',processCommand:process?.command||'',pid:r.pid,
    method:d.method,url:websiteURL&&websiteURL!=='not captured'?websiteURL:d.requestedURL||d.url,proxy:d.proxySource,proxyHost:d.observedRemoteHost,proxyPort:d.observedRemotePort,local:d.observedLocalAddress,state:d.socketState,
    serviceURL,requestedSite:requestObject?.url,requestObject,startedAt:transport.timestamp,networkBody:r.networkBody,evidenceType:d.evidenceType||'unknown',tool:callCard?.title||'',toolResult:callCard?.output||'',source:r.source,basis:d.destinationBasis||d.basis,details:r.details||r.preview||'',record:r};
  }).filter(r=>r.classification!=='local').sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));
 }
 function journeys(records){
  const groups=new Map();
  for(const r of records.filter(r=>r.networkBody?.flow)){
   // Only native task + call identity groups multiple exchanges. Unconfirmed flows stay separate.
   const confirmed=r.taskID&&r.taskConfidence==='native'&&r.call;
   const key=confirmed?r.taskID+':'+r.call:r.networkBody.flow;
   if(!groups.has(key))groups.set(key,{key,title:confirmed?r.taskTitle:(r.requestObject?.url?'访问 '+r.requestObject.url:r.requestObject?.query?'搜索：'+r.requestObject.query:r.serviceURL?.includes('/chat/completions')?'WorkBuddy 与模型的数据交换':'工具数据交换'),call:confirmed?r.call:null,records:[]});
   groups.get(key).records.push(r);
  }
  return [...groups.values()].map(g=>({...g,records:g.records.sort((a,b)=>new Date(a.startedAt)-new Date(b.startedAt))}));
 }
 function parseBody(text){try{return JSON.parse(text||'{}');}catch{const wrapped=String(text||'').match(/^[A-Za-z_][\w.]*\s*\(([\s\S]*)\)\s*$/);if(wrapped){try{return JSON.parse(wrapped[1]);}catch{}}return null;}}
 function stepTitle(r){
  if(r.requestObject?.url)return '访问 '+r.requestObject.url;
  if(r.requestObject?.query)return '搜索：'+r.requestObject.query;
  return r.serviceURL?.includes('/chat/completions')?'请求模型处理上下文':r.tool||'外网访问';
 }
 function journeyMarkup(records,selected){
  return '<aside class="network-journeys"><h2>访问过程</h2>'+journeys(records).map(g=>'<section class="network-journey">'+(g.call?'<small>工具调用 · '+esc(g.call)+'</small>':'<small>所属任务尚未确认</small>')+g.records.map((r,i)=>{
   const b=r.networkBody,result=parseBody(b.response);
   const summary=result?.title?'返回“'+result.title+'”':Array.isArray(result?.results)?'返回 '+result.results.length+' 条搜索结果':b.response?'已返回内容':b.toolInstructions?'返回工具指令':'尚未采到返回';
   return '<button class="network-round" data-network-record="'+esc(r.id)+'" aria-pressed="'+(selected===r.id)+'"><strong>'+esc(stepTitle(r))+'</strong><small>'+esc(r.startedAt?new Date(r.startedAt).toLocaleTimeString('zh-CN',{hour12:false}):'时间未采到')+(g.records.length>1?' · 第 '+(i+1)+' 轮':'')+'</small><span>'+esc(summary)+'</span></button>';
  }).join('')+'</section>').join('')+'</aside>';
 }
 function connectionMarkup(r){
  const states={SYN_SENT:'正在尝试连接，尚未确认建立',ESTABLISHED:'TCP 连接已建立，不能据此确认请求成功',CLOSE_WAIT:'对端已关闭连接',TIME_WAIT:'连接关闭后的等待状态'};
  return '<h2>连接观察</h2><p>'+esc(states[r.state]||'连接状态未确认')+'</p><dl class="network-facts"><dt>观察到的目标</dt><dd>'+esc(r.host||'未采到')+':'+esc(r.port||'未知')+'</dd><dt>TCP 状态</dt><dd>'+esc(r.state||'未提供')+'</dd><dt>数据来源</dt><dd>'+esc(r.source||'未提供')+'</dd><dt>任务归属</dt><dd>'+esc(r.taskConfidence==='candidate'?'时间窗口等线索推断，尚未证实属于本次调用':'来源记录关联')+'</dd></dl>'+(r.proxy?'<p>代理：'+esc(r.proxy)+' · '+esc(r.proxyHost||'')+':'+esc(r.proxyPort||'')+'</p>':'')+'<p class="network-notice">该记录来自连接采样，不包含请求与返回正文，也不代表一轮工具交互。此连接尚未关联正文采集记录。</p><details><summary>关联依据</summary><pre>'+esc(redact(r.record?.resource?.basis||r.basis||'未提供'))+'</pre></details>';
 }
 function bodyDownload(record,label){
  if(!record||!/^\/agent-body\?key=[a-f0-9]{64}&side=(request|response)$/.test(record.downloadURL||''))return '';
  return '<p><a href="'+esc(record.downloadURL)+'">下载'+esc(label)+'</a> · '+esc(record.bytes)+' 字节 · '+(record.complete?'源记录确认完整':'完整性未确认')+'</p><details><summary>正文 SHA256</summary><code>'+esc(record.sha256)+'</code></details>';
 }
 function coverage(b={}){
  const sent=b.request!=null,returned=b.response!=null||b.toolInstructions!=null;
  return sent&&returned?'请求与返回已采到':sent?'请求已采到 · 返回尚未采到':returned?'返回已采到 · 请求尚未采到':'已观察连接 · 正文未采到';
 }
 function securityMarkup(r){
  const a=r.networkBody?.securityAudit;
  if(!a)return '<section class="network-next"><h3>安全审计</h3><p>此记录尚无内容检测结果，不能判断安全。</p></section>';
  const labels={'credential-outbound':'发送正文疑似包含访问凭据','private-key-outbound':'发送正文包含私钥标记','instruction-override-inbound':'返回内容含覆盖指令的可疑文本','download-execute-inbound':'返回内容含下载后执行命令'};
  return '<section class="network-next"><h3>安全审计 · '+(a.findings?.length?'需人工核查':'已检测，未命中当前规则')+'</h3>'+list(a.findings).map(f=>'<p><strong>'+esc(f.label||labels[f.rule]||f.rule)+'</strong><br>'+esc(f.direction==='request'?'发送正文':'返回正文')+' · '+esc(f.count)+' 处命中 · 首次位于字符 '+esc(f.characterOffset)+'<br><small>规则：'+esc(f.rule)+'；依据：正文模式匹配，尚未确认泄露、攻击或执行。</small><br>'+esc(f.recommendation||(/credential|private-key/.test(f.rule)?'如为有效密钥，请撤销或轮换，并检查使用记录':'核对任务意图，谨慎执行返回内容中的指令'))+'</p>').join('')+'<p>实际接收方：'+esc(a.destinationHost||r.host||'未采到')+' · '+esc(a.destinationPolicy==='approved'?'符合用户配置的接收方名单（不等于安全认证）':a.destinationPolicy==='unapproved'?'不在用户配置的接收方名单内':'尚未配置接收方名单')+'</p>'+(a.policyError?'<p>'+esc(a.policyError)+'</p>':'')+'<p class="network-notice">检查范围：已采解码正文；不含未采流量。发送 '+esc(a.requestBytesInspected)+' 字节，返回 '+esc(a.responseBytesInspected??'尚未检查')+' 字节。未命中不代表安全；示例代码和引用文本也可能命中。</p><small>规则版本：'+esc(a.version)+' · 证据流：'+esc(r.networkBody.flow)+'</small></section>';
 }
 function resourceBrief(r){
  const q=r.requestObject||{},b=r.networkBody||{};
  if(r.accessKind==='local-tool'){
   const names=list(r.outboundFiles);
   const out=names.length?'外传 '+names.slice(0,3).join('、'):(r.host||'目标未采到');
   return '带出 '+out+' · '+(r.exitCode===0?'命令完成':'命令未成功');
  }
  const out=q.url||q.query||(b.request!=null?String(b.request).replace(/\s+/g,' ').slice(0,72):'未采到');
  const back=b.response!=null?String(b.response).replace(/\s+/g,' ').slice(0,72):(b.toolInstructions?'工具指令':'未采到');
  return '带出 '+out+' · 带回 '+back;
 }
 function networkBehavior(r){
  if(r.tool!=='git')return true;
  const op=r.gitOperation?.operation;
  return ['push','fetch','pull','clone','ls-remote'].includes(op)||r.route==='proxied'||list(r.outboundFiles).length>0||list(r.downloadedFiles).length>0;
 }
 function showOnAccessPage(r){
  const blob=[r.serviceURL,r.details,r.host,r.url].join(' ');
  if(/galileotelemetry|\/v1\/metrics|\/v1\/traces|\/console\/as\/conversations|\/v3\/config|\/edge-cloud\/credentials|\/ocp\/api\//.test(blob))return false;
  const kind=accessHop(r).kind;
  return kind==='remote-tool'||kind==='model'||kind==='local-tool';
 }
 function taskExchangeMarkup(r){
  const b=r.networkBody||{},q=r.requestObject||{},model=r.serviceURL?.includes('/chat/completions');
  const hop=accessHop(r);
  const remoteTool=hop.kind==='remote-tool';
  const localTool=hop.kind==='local-tool';
  const text=v=>esc(redact(v));
  const outbound=b.request!=null?(b.request===''?'本次带出去的正文为空':String(b.request)):'带出去的资源未采到，不能判断发送了哪些内容';
  const inbound=b.response!=null?(b.response||'本次带回来的正文为空'):(b.toolInstructions||'带回来的资源未采到');
  const association=r.taskConfidence==='native'?'来源任务与调用标识匹配':/unique exact native tool parameters/.test(r.record?.requestRecord?.resource?.basis||r.basis||'')?'工具参数唯一匹配，属于推断关联':'候选任务关联，尚未确认具体调用';
  const field=(label,value)=>'<dt>'+label+'</dt><dd>'+text(value)+'</dd>';
  const outNote=localTool?'本机工具发给访问目标的内容。':remoteTool?'本机发给远程访问工具的内容。':'本机发送出去的内容。';
  const inNote=localTool?'访问目标返回给本机工具的内容。':remoteTool?'远程访问工具返回给本机的内容，不是网站原始 HTTP。':model?'模型服务返回给本机的内容。':'对端返回给本机的内容。';
  const uploaded=list(r.outboundFiles),downloaded=list(r.downloadedFiles),taken=[...new Set([q.url,q.query,q.prompt,hop.delegated].filter(Boolean))].join('\n');
  const outFacts=[field('怎么交互',(localTool?(r.route==='proxied'?'经过代理访问 ':'直连访问 '):'')+(localTool?r.host:r.serviceURL||r.host||'目标未采到')),field('上传的文件',uploaded.length?uploaded.join('\n'):'无文件'),field('下载的文件',downloaded.length?downloaded.join('\n'):'无文件'),taken?field('带走的内容',taken):'',field('字节',b.request!=null?String(b.requestBytes??'未知'):'未采到')].join('');
  const inFacts=[field('字节',b.response!=null?String(b.responseBytes??'未知'):'未采到'),field('HTTP 状态',b.responseStatus??'未采到')].join('');
  const parties=text(hop.localParty)+' → '+text(hop.remoteParty);
  return '<h2>'+text(localTool?r.taskTitle||stepTitle(r):stepTitle(r))+'</h2><p class="network-resource-lead">'+(localTool?'本机访问工具与访问目标。':'')+'下面是这次外网访问带出去的资源，以及带回来的资源。</p><div class="network-exchange-pair"><section class="network-out"><h3>带出去的资源</h3><p>'+outNote+'</p><dl class="network-facts">'+outFacts+'</dl><pre class="network-readable">'+text(outbound)+'</pre>'+(b.requestTruncated?'<small>预览截断，已采内容仍在本机。</small>':'')+bodyDownload(b.wireRequest,'本机发送的 HTTP 正文')+'</section><section class="network-in"><h3>带回来的资源</h3><p>'+inNote+'</p><dl class="network-facts">'+inFacts+'</dl><pre class="network-readable">'+text(inbound)+'</pre>'+(b.responseTruncated?'<small>预览截断，已采内容仍在本机。</small>':'')+bodyDownload(b.wireResponse,'带回来的 HTTP 正文')+'</section></div><p class="network-notice">'+text(hop.notice)+'</p>'+securityMarkup(r)+(b.transportError?'<p>传输错误：'+text(b.transportError)+'</p>':'')+(localTool&&r.gap?'<p>'+text(r.gap)+'</p>':'')+'<details><summary>连接与归属</summary><div class="network-route"><strong>'+parties+'</strong></div><dl class="network-facts">'+field(localTool?'访问目标':remoteTool?'远程访问工具':'实际服务地址',localTool?r.host:r.serviceURL||r.host||'未采到')+field('连接对端 IP',r.ip||'未采到')+field('采集来源',r.source||'未提供')+field('交互标识',b.flow||'未提供')+field('工具调用标识',r.call||'未确认')+field('关联方式',association)+'</dl><p>请求结束：'+(b.requestComplete===true?'已确认':b.requestComplete===false?'未确认':'未采到')+' · '+(b.responseComplete===true?'响应结束已确认':b.responseComplete===false?'响应完整性未确认':'未取得响应结束标记')+'。</p><h4>请求头</h4><pre>'+text(b.requestHeaders!=null?JSON.stringify(b.requestHeaders,null,2):'未采到')+'</pre><h4>响应头</h4><pre>'+text(b.responseHeaders!=null?JSON.stringify(b.responseHeaders,null,2):'未采到')+'</pre></details>';
 }
 function matchedTask(r,tasks){
  if(r.taskID){const hit=list(tasks).find(t=>t.id===r.taskID);if(hit)return hit;}
  return list(tasks).find(t=>t.agent===r.agent&&t.session&&(t.session===r.session||t.session===r.codexThreadID))||null;
 }
 function plainTask(text){
  const raw=String(text||'');
  const plain=raw.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim();
  if(/<\s*\/?\s*(heartbeat|automation_id|automation)\b/i.test(raw)&&plain.length<48)return plain?('机器标记 · '+plain):'机器标记，没有用户原话';
  return plain||raw;
 }
 function visitSite(record){
  return siteKey(httpURL(record))||siteKey(record.url)||siteKey(record.host);
 }
 function siteKey(value){
  const match=String(value||'').match(/^https?:\/\/([^\/\s:?#]+)(?::\d+)?([^?#\s]*)?/i);
  if(!match||loopbackHost(match[1]))return '';
  const path=(match[2]||'/').replace(/\/+$/,'')||'/';
  return match[1].toLowerCase()+path;
 }
 function urlsOf(task){
  const chunks=[];
  for(const card of list(task&&task.cards))chunks.push(card.input,card.output,card.summary,card.title,card.resource&&card.resource.url);
  return [...chunks.filter(Boolean).join('\n').matchAll(/https?:\/\/[^\s"'<>\\)\]]+/g)].map(item=>item[0]);
 }
 function httpURL(r){
  const query=r.requestObject||{};
  for(const value of [query.url,r.url])if(typeof value==='string'&&/^https?:\/\//i.test(value))return value;
  const host=hostToken(r.host);
  if(!host||loopbackHost(host))return '';
  let path='';
  try{const detail=JSON.parse(r.details||'{}');if(typeof detail.requestPath==='string')path=detail.requestPath.split('?')[0];}catch{}
  if(!path)return '';
  return 'https://'+host+(path.startsWith('/')?path:'/'+path);
 }
 function taskForVisit(r,tasks){
  const known=matchedTask(r,tasks);
  if(known)return {task:known,basis:'session'};
  if(r.taskID)return null;
  const key=siteKey(httpURL(r));
  if(!key)return null;
  const hits=list(tasks).filter(task=>urlsOf(task).some(url=>siteKey(url)===key));
  return hits.length===1?{task:hits[0],basis:'url'}:null;
 }
 function taskNameOf(r,tasks){
  const linked=taskForVisit(r,tasks);
  const title=linked&&(linked.task.latestUserInput?.content||linked.task.originalRequest||linked.task.title);
  if(title)return plainTask(title);
  if(r.accessKind!=='local-tool'&&r.taskTitle)return plainTask(r.taskTitle);
  return '尚未归入任务';
 }
 function remoteToolName(r){
  const service=String(r.serviceURL||'');
  if(/webfetch/i.test(service))return 'WebFetch';
  if(/search/i.test(service))return '搜索';
  if(/\/v2\/videos\//i.test(service))return '视频生成';
  const tail=service.split('/').filter(Boolean).pop();
  return tail||'远程访问工具';
 }
 function whereOf(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool'&&hop.delegated)return hop.delegated;
  const page=httpURL(r);
  if(page)return page;
  const query=r.requestObject||{};
  if(typeof query.query==='string'&&query.query)return query.query;
  if(typeof query.prompt==='string'&&query.prompt)return query.prompt;
  return r.host||r.serviceURL||'目标未采到';
 }
 function viaOf(r){
  if(r.accessKind==='local-tool'){
   const name=r.tool==='git'?('Git '+(r.gitOperation?.operation||'操作')):(r.tool||'本机工具');
   return name+' · '+(r.route==='proxied'?'经本机代理':'直连');
  }
  const hop=accessHop(r);
  const verb=r.method?' · '+r.method:'';
  const status=Number(r.networkBody?.responseStatus)>=100?' · HTTP '+r.networkBody.responseStatus:'';
  if(hop.kind==='model')return '模型接口';
  if(hop.kind==='remote-tool')return '远程访问工具'+(r.tool?' · '+r.tool:'')+verb+status;
  if(hop.kind==='local-tool')return '网页抓取'+verb+status;
  return (r.tool||'访问')+' · '+(r.serviceURL||r.host||'方式未采到');
 }
 function shownExchange(value){
  const lines=String(redact(value)||'').split('\n').map(s=>s.trim()).filter(line=>line&&line!=='外传文件名'&&line!=='下载文件名'&&!line.startsWith('* ')&&!/^(?:>|<)?\s*(authorization|cookie|set-cookie|proxy-authorization)\s*:/i.test(line)&&!/^CONNECT\s/i.test(line)&&!/connection established/i.test(line));
  if(!lines.length)return '未采到';
  const text=lines.slice(0,12).join('\n');
  return text.length>520?text.slice(0,520)+'…':text;
 }
 function readablePreview(value){
  const raw=String(value||'');
  if(/<!doctype html|<html[\s>]/i.test(raw)){
   const title=raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
   const name=title?title[1].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim():'';
   const plain=raw.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/\s+/g,' ').trim();
   const lead=plain.slice(0,180);
   return (name?'网页《'+name+'》':'网页')+(lead?'\n'+lead:'');
  }
  return shownExchange(raw);
 }
 function presentExchange(value,complete){
  if(value==null)return '未采到';
  if(String(value).trim()==='')return complete===true?'正文为空':'未采到';
  return readablePreview(value);
 }
 const auditLabels={'credential-outbound':'发送正文疑似包含访问凭据','private-key-outbound':'发送正文包含私钥标记','instruction-override-inbound':'返回内容含覆盖指令的可疑文本','download-execute-inbound':'返回内容含下载后执行命令'};
 function builtinFindings(request, response){
  const rules=[
   ['credential-outbound','request',/(?:sk-(?:proj-|or-v1-)[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})/g],
   ['private-key-outbound','request',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
   ['instruction-override-inbound','response',/ignore (?:all |the )?(?:previous|prior|system) instructions|忽略(?:之前|上述|系统)(?:的)?(?:指令|规则)/gi],
   ['download-execute-inbound','response',/(?:curl|wget)[^\r\n]{0,400}\|\s*(?:bash|sh)\b/gi]
  ];
  const texts={request, response};
  const findings=[];
  for(const [rule, direction, pattern] of rules){
   pattern.lastIndex=0;
   let count=0, first=null, match;
   const text=texts[direction]||'';
   while((match=pattern.exec(text))){
    count+=1;
    if(first==null) first=match.index;
    if(!match[0]) pattern.lastIndex+=1;
   }
   if(count) findings.push({rule, direction, count, characterOffset:first, basis:'captured_body_pattern', status:'needs_review'});
  }
  return findings;
 }
 function mergeAudit(left, right, overlap){
  if(!left) return right;
  if(!right) return left;
  const findings=[];
  const seen=new Map();
  for(const item of [...list(left.findings), ...list(right.findings)]){
   const key=(item.rule||'')+'|'+(item.direction||'');
   const previous=seen.get(key);
   if(!previous){
    const copy=Object.assign({}, item);
    seen.set(key, copy);
    findings.push(copy);
    continue;
   }
   const count=Number(item.count)||1;
   previous.count=overlap==='overlap'?Math.max(Number(previous.count)||1, count):(Number(previous.count)||1)+count;
   const offsets=[previous.characterOffset, item.characterOffset].filter(value=>value!=null);
   if(offsets.length) previous.characterOffset=Math.min(...offsets);
  }
  const verdict=left.verdict==='audit_error'||right.verdict==='audit_error'?'audit_error':(findings.length?'review':(right.verdict||left.verdict||'no_rule_match'));
  return Object.assign({}, left, right, {findings, verdict});
 }
 function agentAudit(r){
  if(/加密/.test(String(r.gap||''))) return {verdict:'no_body', findings:[], scope:'no_plaintext'};
  const body=r.networkBody||{};
  const request=String(body.request||'').replace(/^.*X-AgentReins-Call:.*$/gim,'').trim();
  const response=String(body.response||'').replace(/^.*X-AgentReins-Call:.*$/gim,'').trim();
  const stored=body.securityAudit&&typeof body.securityAudit==='object'?body.securityAudit:null;
  if(stored&&stored.verdict==='audit_error') return Object.assign({}, stored, {findings:list(stored.findings)});
  const fresh=(request||response)?builtinFindings(request, response):[];
  const merged=mergeAudit(stored, {findings:fresh, destinationHost:stored?.destinationHost||r.host||null});
  const findings=list(merged.findings);
  if(findings.length) return Object.assign({}, merged, {findings, verdict:'review'});
  const truncated=stored?stored.inspectionTruncated===true:(body.requestTruncated||body.responseTruncated);
  if(truncated) return Object.assign({}, merged, {findings:[], verdict:'truncated', requestBytesInspected:stored?.requestBytesInspected??String(body.request||'').length});
  if(!request&&!response) return {verdict:'no_body', findings:[], scope:'no_plaintext', destinationHost:r.host||null};
  return Object.assign({}, merged, {findings:[], verdict:'no_rule_match'});
 }
 function destinationSentence(audit){
  const host=audit.destinationHost||'';
  if(audit.destinationPolicy==='approved') return '接收方'+(host?' '+host:'')+' 在你配置的名单里。';
  if(audit.destinationPolicy==='unapproved') return '接收方'+(host?' '+host:'')+' 不在你配置的名单里。';
  if(audit.destinationPolicy==='not_configured') return '还没配置接收方。';
  return '';
 }
 function securityLine(r){
  const audit=agentAudit(r);
  const who='这次 '+(r.tool||'工具')+' 发往 '+showWhere(r)+'。';
  if(audit.verdict==='audit_error') return '<p class="network-notice">'+esc(who+'这次审计没跑成。')+'</p>';
  if(audit.verdict==='no_body') return '<p class="network-notice">'+esc(who+'这次没有正文可查。')+'</p>';
  if(audit.verdict==='truncated') return '<p class="network-notice">'+esc(who+'只看了前 '+(audit.requestBytesInspected||0)+' 字节，没有命中。')+'</p>';
  const dest=destinationSentence(audit);
  const findings=list(audit.findings);
  if(!findings.length) return '<p class="network-notice">'+esc(who+'这次正文按现有规则看过，没有命中。'+dest)+'</p>';
  const items=findings.map(item=>{
   const name=item.label||auditLabels[item.rule]||item.rule;
   const side=item.direction==='response'?'收回':'送出';
   const advice=item.recommendation||(/credential|private-key|secret/.test(String(item.rule))?'如为有效密钥，请撤销或轮换。':'核对是不是这次任务要的内容。');
   return name+'。'+side+'里 '+(item.count||1)+' 处，第一次在第 '+(item.characterOffset??0)+' 个字符。'+advice;
  }).join('');
  return '<p class="network-notice">需核查。'+esc(who+items+dest)+'</p>';
 }
 function showWhere(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '远程访问工具';
  if(hop.kind==='model')return '模型服务';
  return String(whereOf(r)||'').replace(/:(?:443|80)$/,'');
 }
 function protocolOf(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '工具调用';
  if(hop.kind==='model')return '模型';
  if(/加密/.test(String(r.gap||'')))return '加密通道';
  const blob=[r.networkBody?.request,r.networkBody?.response].join('\n');
  const lines=blob.split('\n').map(line=>line.trim()).filter(line=>line&&!/^CONNECT\s/i.test(line)&&!/connection established/i.test(line));
  const version=lines.join('\n').match(/HTTP\/(\d+(?:\.\d+)?)/i);
  if(version)return 'HTTP/'+version[1].replace(/\.0$/,'');
  if(r.tool==='brew'||list(r.formulas).length||list(r.downloads).length)return '安装包';
  return '连接';
 }
 function responseText(r){
  const body=r.networkBody||{};
  return String(body.response!=null?body.response:body.toolInstructions||'');
 }
 function tlsFailureText(raw){
  return /error setting certificate|certificate verify failed|SSL certificate problem|alert certificate unknown/i.test(String(raw||''));
 }
 function curlDiagText(r){
  return responseText(r).split('\n').filter(line=>/^\*\s|curl:\s*\(/.test(line.trim())).join('\n');
 }
 function readableText(raw){
  return String(raw||'').split('\n').filter(line=>!/certificate verify ok|error setting certificate|certificate verify failed|SSL certificate problem|CAfile:/i.test(line)).join('\n').trim();
 }
 function tlsFailed(r){
  const exit=r.exitCode!=null&&r.exitCode!==''?Number(r.exitCode):null;
  const status=Number(r.networkBody?.responseStatus);
  if(exit===0&&Number.isFinite(status)&&status>=100)return false;
  if(exit===60||exit===77||exit===58)return true;
  if(exit===35)return false;
  if(exit!=null&&exit!==0)return tlsFailureText(curlDiagText(r));
  return false;
 }
 function tlsHandshakeFailed(r){
  const exit=r.exitCode!=null&&r.exitCode!==''?Number(r.exitCode):null;
  return exit===35;
 }
 function bypassedAudit(r){
  if(r.auditBypass===true)return true;
  if(r.auditBypass===false)return false;
  if(/绕过|bypass/i.test(String(r.gap||'')))return true;
  const args=list(r.args).map(String);
  if(args.some(a=>a==='--noproxy'||a==='--no-proxy'||a.startsWith('--noproxy=')||a.startsWith('--socks')))return true;
  const inline=args.find(a=>/^(?:-x|--proxy|--preproxy)=/.test(a));
  const flag=args.findIndex(a=>a==='-x'||a==='--proxy'||a==='--preproxy');
  const value=inline?inline.split('=').slice(1).join('='):(flag>=0?args[flag+1]:'');
  if(value&&!/127\.0\.0\.1:(18891|18893)/.test(value))return true;
  return args.some(a=>/^http\.proxy=/.test(a)&&!/127\.0\.0\.1:(18891|18893)/.test(a));
 }
 function associationStrength(r){
  if(r.call)return {name:'已确认',note:'执行编号对得上'};
  if(r.taskConfidence==='candidate')return {name:'候选关联',note:'不是按执行编号对上的'};
  if(r.accessKind==='local-tool')return {name:'缺口',note:'还没有执行编号'};
  return {name:'说明',note:'这条记录本身'};
 }
 function headRequest(r){
  const args=list(r.args).map(String);
  if(args.includes('-I')||args.includes('--head'))return true;
  if(args.some(arg=>/^-[A-Za-z]*I[A-Za-z]*$/.test(arg)))return true;
  return /^HEAD$/i.test(String(r.method||''))||/\bHEAD\s+\//.test(String(r.networkBody?.request||''));
 }
 function broughtPhrase(r){
  const raw=responseText(r);
  // Only curl diagnostic lines count as TLS failures; body text that mentions
  // "SSL certificate problem" (docs, troubleshooting pages) must still render.
  if(tlsFailureText(curlDiagText(r)))return '';
  if(/<!doctype html|<html[\s>]/i.test(raw)){
   const title=raw.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
   const name=title?title[1].replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim():'';
   return name?'网页《'+name+'》':'一个网页';
  }
  const lines=raw.split('\n').map(line=>line.trim()).filter(line=>line&&!/^HTTP\//i.test(line)&&!/^CONNECT\s/i.test(line)&&!/connection established/i.test(line)&&!/certificate verify ok|error setting certificate|certificate verify failed/i.test(line)&&!/^(?:>|<)?\s*(host|user-agent|accept|content-type|content-length|date|server|cache-control|pragma|age|cf-|alt-svc|allow|last-modified|accept-ranges)\s*:/i.test(line)&&!line.startsWith('* ')&&line!=='外传文件名'&&line!=='下载文件名'&&!/^(curl|git|wget|gh|ssh|scp|sftp|rsync)\b/.test(line));
  const text=lines.join(' ').replace(/\s+/g,' ').trim();
  if(text.length<2)return '';
  if(/^[{[]/.test(text)){
   try{
    const value=JSON.parse(text);
    const title=value&&(value.title||(Array.isArray(value.results)&&value.results[0]&&value.results[0].title));
    if(title)return String(title).slice(0,32);
   }catch{}
   return '';
  }
  return text.length>32?text.slice(0,32)+'…':text;
 }
 function askCell(r){
  const files=list(r.outboundFiles).filter(Boolean);
  if(files.length)return files.join('、');
  const query=r.requestObject||{};
  const prompt=typeof query.prompt==='string'?query.prompt:'';
  const where=showWhere(r);
  if(prompt&&prompt!==where)return prompt;
  if(headRequest(r))return '只要头信息';
  return '—';
 }
 function verdict(r){
  const text=connectionVerdict(r);
  const review=list(agentAudit(r).findings).length?text+' · 需核查':text;
  return bypassedAudit(r)?review+' · 绕过了审计代理':review;
 }
 function connectionVerdict(r){
  const status=Number(r.networkBody?.responseStatus);
  const exit=r.exitCode!=null&&r.exitCode!==''?Number(r.exitCode):null;
  const back=broughtPhrase(r);
  const files=list(r.outboundFiles).filter(Boolean);
  const saved=list(r.downloads).filter(item=>item&&(item.state==='verified'||item.bytes!=null||item.state==='tooLarge'));
  const savedNames=saved.map(item=>String(item.path||'').split(/[/\\]/).pop()).filter(Boolean);
  if(tlsFailed(r))return '证书没配好';
  if(tlsHandshakeFailed(r))return 'TLS 握手失败';
  if(/加密/.test(String(r.gap||'')))return '看不到通道里的内容';
  if(status>=400)return '对方返回 '+status;
  if(r.accessKind==='remote-tool'||accessHop(r).kind==='remote-tool'){
   if(callFailed(r)&&!back)return '工具没有带回内容';
   if(back)return '收回了 '+(back.startsWith('网页')?back:back);
   if(responseText(r).trim())return '收回了一段结果';
   return '工具做了这次访问';
  }
  if(savedNames.length)return '下载了 '+savedNames.join('、');
  if(status>=200&&status<400&&exit!=null&&exit!==0)return '网站回了 '+status+'，命令失败';
  if(files.length&&exit===0)return '带走了 '+files.join('、');
  if(callFailed(r)&&!(status>=100))return '没连上';
  if(headRequest(r)&&(status>=200&&status<400||exit===0))return '只要了头信息';
  if(status>=200&&status<300||exit===0)return '通了';
  return '没完成';
 }
 function connectionBrief(r){
  const status=Number(r.networkBody?.responseStatus);
  if(r.accessKind==='remote-tool'&&!externalConnections(r).length)return '工具代办';
  if(tlsFailed(r)||tlsHandshakeFailed(r))return '没完成';
  if(callFailed(r)&&!(status>=100))return '没通';
  if(status>=400)return '通到了';
  return '通了';
 }
 function externalConnections(r){
  return list(r.connections).filter(item=>externalDetail(list(item.detail).join(' ')));
 }
 function connectionLine(r){
  const rows=externalConnections(r);
  const count=kind=>rows.filter(item=>item.kind===kind).length;
  const attempts=count('attempt'),connected=count('connected'),reused=count('reuse'),tunneled=count('proxyTunnel');
  const closed=count('closed')+rows.filter(item=>item.kind==='connectionState'&&String((item.detail||[])[2]||'')==='closed').length;
  const status=Number(r.networkBody?.responseStatus);
  const httpReached=status>=100&&!connected&&!tunneled&&!reused;
  const parts=[];
  if(attempts)parts.push((httpReached?'连通 ':'尝试 ')+attempts+' 次');
  if(connected)parts.push('连通 '+connected+' 次');
  if(tunneled)parts.push('经代理连通 '+tunneled+' 次');
  if(reused)parts.push('复用 '+reused+' 次');
  const missed=Math.max(0,attempts-(connected+reused+tunneled));
  if(missed&&!(status>=100))parts.push('未连通 '+missed+' 次');
  if(closed)parts.push('关闭 '+closed+' 次');
  if(/加密/.test(String(r.gap||'')))parts.push('通道加密，没有明文');
  if(status>=100)parts.push('HTTP '+status);
  if(r.accessKind==='remote-tool'&&!rows.length)return parts.concat('远程工具访问，本机没有这次连接').join('，');
  if(r.exitCode!=null&&r.exitCode!=='')parts.push('命令退出 '+r.exitCode);
  if(parts.length)return parts.join('，');
  if(r.route==='proxied')return '经本机代理发出，追踪里没有分开的连接次数';
  return '这次没有留下连接次数';
 }
 function callFailed(r){
  const status=Number(r.networkBody?.responseStatus);
  if(status>=400)return true;
  if(r.exitCode!=null&&r.exitCode!==''&&Number(r.exitCode)!==0)return true;
  const rows=externalConnections(r);
  const attempts=rows.filter(item=>item.kind==='attempt').length;
  const reached=rows.filter(item=>item.kind==='connected'||item.kind==='reuse'||item.kind==='proxyTunnel').length;
  return attempts>0&&reached===0;
 }
 function matchedToolCard(r,tasks){
  const key=siteKey(httpURL(r));
  const linked=key&&taskForVisit(r,tasks);
  if(!linked)return null;
  return list(linked.task.cards).find(card=>urlsOf({cards:[card]}).some(url=>siteKey(url)===key)&&card.title)||null;
 }
 function toolName(r,tasks){
  if(r.tool==='git')return 'Git '+(r.gitOperation?.operation||'操作');
  if(r.tool)return r.tool;
  const card=matchedToolCard(r,tasks);
  if(card)return card.title;
  const hop=accessHop(r);
  if(hop.kind==='local-tool')return r.method?String(r.method):'网页抓取';
  if(hop.kind==='remote-tool')return remoteToolName(r);
  if(hop.kind==='model')return '模型接口';
  return '工具未确认';
 }
 function parameterText(r,tasks){
  const args=list(r.args).map(arg=>String(arg)).filter(Boolean);
  if(args.length){
   const names=list(r.outboundFiles);
   const command=(r.tool?r.tool+' ':'')+args.join(' ');
   return (names.length?command+' · '+names.join('、'):command).slice(0,500);
  }
  const hop=accessHop(r);
  if(hop.kind==='remote-tool'){
   const query=r.requestObject||{};
   const service=String(r.serviceURL||'').replace(/^https?:\/\//,'');
   const prompt=typeof query.prompt==='string'&&query.prompt!==hop.delegated?query.prompt:'';
   return [hop.delegated,prompt,service].filter(Boolean).join(' · ').slice(0,500);
  }
  const page=httpURL(r);
  if(r.method&&page)return r.method+' '+page;
  const card=matchedToolCard(r,tasks);
  if(card){
   const body=String(card.input||'').replace(/\s+/g,' ').trim();
   return (card.title+(body?' '+body:'')).slice(0,500);
  }
  const preview=String(r.networkBody?.request||'').split('\n').map(line=>line.trim()).find(line=>line&&line!=='外传文件名'&&line!=='下载文件名');
  if(preview)return preview.slice(0,240);
  return '这次记录没有留下工具参数';
 }
 function rollupMarkup(records,tasks){
  const groups=new Map();
  for(const record of records){
   const name=toolName(record,tasks);
   const dest=hostToken(whereOf(record))||whereOf(record);
   const task=taskNameOf(record,tasks);
   const key=[task,name,dest].join('\0');
   const group=groups.get(key)||{task,name,dest,calls:0,failed:0,attempts:0};
   group.calls+=1;
   if(callFailed(record))group.failed+=1;
   group.attempts+=externalConnections(record).filter(item=>item.kind==='attempt').length;
   groups.set(key,group);
  }
  const repeated=[...groups.values()].filter(group=>group.calls>1);
  if(!repeated.length)return '';
  return '<section class="network-rollup"><h3>重复访问</h3>'+repeated.map(group=>'<p>'+esc(redact(group.name+' 去了 '+group.dest+' '+group.calls+' 次'+(group.failed?'，'+group.failed+' 次没成':'')))+'</p>').join('')+'</section>';
 }
 function behaviorArticle(r,payload){
  const b=r.networkBody||{};
  const up=list(r.outboundFiles),down=list(r.downloadedFiles);
  const sent=String(b.request||'').replace(/外传文件名\n[\s\S]*?(?:\n\n|$)/,'').replace(/下载文件名\n[\s\S]*?(?:\n\n|$)/,'').trim();
  const when=r.startedAt?new Date(r.startedAt).toLocaleString('zh-CN',{hour12:false}):'时间未采到';
  const files=(label,names)=>names.length?'<p>'+label+'：'+esc(redact(names.join('、')))+'</p>':'';
  const link=taskForVisit(r,payload.tasks);
  const basis=link&&link.basis==='url'?'<p class="network-notice">归入依据：这次网址与该任务里记录的网址一致。</p>':'';
  return '<article class="network-behavior"><header><h3>任务：'+esc(redact(taskNameOf(r,payload.tasks)))+'</h3><small>'+esc((r.agent||'')+' · '+when)+'</small></header><dl class="network-facts"><dt>访问了哪里</dt><dd>'+esc(redact(whereOf(r)))+'</dd><dt>通过什么</dt><dd>'+esc(viaOf(r))+'</dd><dt>工具</dt><dd>'+esc(redact(toolName(r,payload.tasks)))+'</dd><dt>调用参数</dt><dd>'+esc(redact(parameterText(r,payload.tasks)))+'</dd><dt>连接</dt><dd>'+esc(connectionLine(r))+'</dd></dl><h4>交换的数据</h4><div class="network-exchange-pair"><section class="network-out"><h3>发出</h3>'+files('上传文件',up)+'<pre class="network-readable">'+esc(presentExchange(sent===''?b.request:sent,b.requestComplete))+'</pre></section><section class="network-in"><h3>返回</h3>'+files('下载文件',down)+'<pre class="network-readable">'+esc(presentExchange(b.response!=null?b.response:b.toolInstructions,b.response!=null?b.responseComplete:b.toolInstructions!=null))+'</pre></section></div>'+securityLine(r)+basis+'</article>';
 }
 function attemptCount(r){
  const attempts=externalConnections(r).filter(item=>item.kind==='attempt').length;
  if(attempts)return attempts;
  if(externalConnections(r).some(item=>item.kind==='connected'||item.kind==='proxyTunnel'||item.kind==='reuse'))return 1;
  if(Number(r.networkBody?.responseStatus)>=100||(r.exitCode!=null&&r.exitCode!==''))return 1;
  return 0;
 }
 function resultLabel(r){
  if(callFailed(r))return '失败';
  const status=Number(r.networkBody?.responseStatus);
  if(status>=100)return 'HTTP '+status;
  if(r.exitCode!=null&&r.exitCode!==''&&Number(r.exitCode)===0)return '完成';
  if(r.accessKind==='remote-tool'&&r.networkBody?.response)return '完成';
  return '已记录';
 }
 function clock(r){
  const value=r.startedAt||r.timestamp;
  return value?new Date(value).toLocaleTimeString('zh-CN',{hour12:false}):'时间未采到';
 }
 function statsMarkup(records){
  const failed=records.filter(callFailed).length;
  const attempts=records.reduce((sum,record)=>sum+attemptCount(record),0);
  return '<div class="network-stats"><div><strong>'+records.length+'</strong><span>出去了</span></div><div'+(failed?' class="is-fail"':'')+'><strong>'+failed+'</strong><span>没成</span></div></div>';
 }
 function readableExchange(value){
  const raw=readableText(value);
  if(!raw.trim()||tlsFailureText(value))return '';
  const text=readablePreview(raw).replace(/^(?:网页《[^》]*》|网页)\n?/,'').replace(/^.*X-AgentReins-Call:.*$/gim,'').trim();
  return text==='未采到'?'':text;
 }
 function sentView(r){
  const hop=accessHop(r);
  const query=r.requestObject||{};
  if(hop.kind==='remote-tool'){
   const bits=[query.url,query.website,query.query,query.search_term,query.searchTerm,query.q,query.prompt].filter(value=>typeof value==='string'&&value.trim());
   return bits.length?[...new Set(bits)].join('\n'):'没有送出正文。';
  }
  if(hop.kind==='model'){
   const text=readableExchange(r.networkBody?.request);
   return text||'没有送出正文。';
  }
  const files=list(r.outboundFiles).filter(Boolean);
  if(files.length)return '要送出 '+files.join('、');
  const formulas=list(r.formulas).filter(Boolean);
  if(formulas.length)return '要安装 '+formulas.join('、');
  if(headRequest(r))return '没有送出正文。';
  const text=readableExchange(r.networkBody?.request);
  const body=String(text||'').split('\n').map(line=>line.trim()).filter(line=>line&&line!=='外传文件名'&&line!=='下载文件名'&&!/^(curl|wget|git|gh|brew|ssh|scp|sftp|rsync)\b/.test(line)).join('\n');
  return body||'没有送出正文。';
 }
 function sentLabel(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '交给工具';
  if(list(r.formulas).length)return '交给 Homebrew';
  const method=String(r.method||r.networkBody?.request||'').match(/\b(GET|HEAD|POST|PUT|PATCH|DELETE)\b/i);
  return method?method[1].toUpperCase():'请求';
 }
 function downloadLines(r){
  return list(r.downloads).map(item=>{
   const name=String(item.path||'').split(/[/\\]/).pop()||'未命名文件';
   if(item.state==='unavailable')return '预期下载 '+name+'，文件没有留下。';
   const bytes=item.bytes!=null?item.bytes+' 字节':'大小未采到';
   const hash=item.sha256?'sha256 '+String(item.sha256).slice(0,16)+'…':(item.state==='tooLarge'?'文件较大，未计算校验':'校验未采到');
   return '下载了 '+name+'\n'+bytes+'\n'+hash;
  }).filter(Boolean);
 }
 function backView(r){
  if(tlsFailed(r))return '证书没有通过。';
  if(tlsHandshakeFailed(r))return 'TLS 握手失败。';
  if(/加密/.test(String(r.gap||'')))return '通道里的正文没采到。';
  const files=downloadLines(r);
  const hop=accessHop(r);
  const raw=readableText(responseText(r));
  const text=/<!doctype html|<html[\s>]/i.test(raw)?readablePreview(raw):readableExchange(raw);
  if(hop.kind==='remote-tool')return text||'工具没有带回内容。';
  if(headRequest(r))return '没有正文。只收回了头信息。';
  const status=Number(r.networkBody?.responseStatus);
  if(status>=400)return '对方返回 '+status+'。'+(text?'\n'+text:'');
  if(files.length)return files.join('\n\n');
  if(text)return text;
  return '没有采到响应正文。';
 }
 function backLabel(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '工具返回';
  if(list(r.downloads).length)return '下载的文件';
  const status=Number(r.networkBody?.responseStatus);
  return status>=100?String(status):'收回';
 }
 function relationLine(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '本机和远程工具之间的交互。工具自己再去网站的那一段不在本机。';
  if(hop.kind==='model')return '本机和模型服务之间的交互。';
  const call=r.call?'这次执行就是这次工具调用。':'还没对上哪次工具调用。';
  return '本机 '+(r.tool||'工具')+' 和 '+showWhere(r)+' 之间的交互。'+call;
 }
 function protocolRaw(r){
  const blob=[r.networkBody?.request,r.networkBody?.response].filter(value=>value!=null).join('\n');
  const lines=blob.split('\n').map(line=>line.trim()).filter(line=>line&&!/connection established/i.test(line)&&!/^CONNECT\s/i.test(line)&&!/certificate verify ok|error setting certificate|certificate verify failed|SSL certificate problem|CAfile:/i.test(line)&&!/^(?:>|<)?\s*(authorization|cookie|set-cookie|proxy-authorization)\s*:/i.test(line)&&(/^(?:GET|HEAD|POST|PUT|PATCH|DELETE)\s/i.test(line)||/^HTTP\//i.test(line)||/^(?:>|<)?\s*host:/i.test(line)));
  const files=downloadLines(r);
  return [...lines.slice(0,12),...files].join('\n')||'没有留下协议行。';
 }
 function exchangePair(record){
  return '<div class="network-exchange-pair"><section class="network-out"><h3>送出</h3><p>'+esc(sentLabel(record))+'</p><pre class="network-readable">'+esc(redact(sentView(record)))+'</pre></section><section class="network-in"><h3>收回</h3><p>'+esc(backLabel(record))+'</p><pre class="network-readable">'+esc(redact(backView(record)))+'</pre></section></div>';
 }
 function exchangeMarkupFor(r,tasks){
  const subs=list(r.subrequests);
  const pairs=subs.length>1?subs.map((sub,index)=>'<h4>第 '+(index+1)+' 次</h4>'+exchangePair(Object.assign({}, r, {networkBody:sub.networkBody,host:sub.host||r.host,url:sub.url||r.url}))).join(''):exchangePair(r);
  const strength=associationStrength(r);
  const bypass=bypassedAudit(r)?'<p class="network-notice">这次命令直接连接，绕过了审计代理。</p>':'';
  return '<section class="network-read"><h3>'+esc(toolName(r,tasks)+' · '+showWhere(r))+'</h3><p>'+esc(relationLine(r))+'</p><p class="strength-'+esc(strength.name)+'">'+esc(strength.name)+' · '+esc(strength.note)+'</p>'+bypass+pairs+'<details><summary>协议原文</summary><pre class="network-readable">'+esc(redact(protocolRaw(r)))+'</pre></details>'+securityLine(r)+'</section>';
 }
 function tableMarkup(records,tasks,{all=false,selected=null}={}){
  const headers=all?['任务','时间','谁','去了哪里','协议','结果','']:['时间','谁','去了哪里','协议','结果',''];
  const body=records.map(record=>{
   const open=selected===record.id;
   const cells=[esc(redact(taskNameOf(record,tasks))),esc(clock(record)),esc(redact(toolName(record,tasks))),esc(redact(showWhere(record))),esc(protocolOf(record)),esc(verdict(record)),'<button type="button" data-network-record="'+esc(record.id)+'" aria-pressed="'+open+'">'+(open?'收起':'打开')+'</button>'];
   const row='<tr'+(callFailed(record)?' class="is-fail"':'')+'>'+(all?cells:cells.slice(1)).map(cell=>'<td>'+cell+'</td>').join('')+'</tr>';
   const detail=open?'<tr class="network-read-row"><td colspan="'+headers.length+'">'+exchangeMarkupFor(record,tasks)+'</td></tr>':'';
   return row+detail;
  }).join('');
  return '<div class="network-table-wrap"><table class="network-table"><thead><tr>'+headers.map(header=>'<th>'+header+'</th>').join('')+'</tr></thead><tbody>'+body+'</tbody></table></div>';
 }
 function render(holder,payload,{agent='all',query='',taskOnly=null,selected=null,focusTask=null}={}){
  const allRows=rows(payload),q=query.toLowerCase();
  const activeTask=list(payload.tasks).find(task=>task.id===taskOnly);
  if(activeTask?.detailsLoaded===false){holder.innerHTML='<header><button data-network-all>返回任务列表</button><h2>'+esc(redact(activeTask.title))+'</h2></header><p>正在读取此任务的网络交互记录…</p>';return;}
  const matches=record=>{
   if(!q)return true;
   const blob=[taskNameOf(record,payload.tasks),record.agent,toolName(record,payload.tasks),parameterText(record,payload.tasks),whereOf(record),connectionLine(record),record.networkBody?.request,record.networkBody?.response].join('\n').toLowerCase();
   return blob.includes(q);
  };
  let records,title,note,showAll;
  if(!activeTask){
   const locals=localExchanges().filter(record=>(agent==='all'||record.agent===agent)&&networkBehavior(record));
   const exchanges=foldCapturedIntoCalls(locals,allRows.filter(record=>record.networkBody?.flow&&showOnAccessPage(record)&&(agent==='all'||record.agent===agent)));
   records=[...locals,...exchanges].sort((a,b)=>new Date(b.startedAt||b.timestamp)-new Date(a.startedAt||a.timestamp)).filter(matches).slice(0,40);
   title='全部外网访问';
   note='还没归进任务的，也列在这里。';
   showAll=true;
  }else{
   const taskLocals=localExchanges().filter(record=>record.agent===activeTask.agent&&activeTask.session&&(record.session===activeTask.session||record.codexThreadID===activeTask.session)&&networkBehavior(record));
   const taskExchanges=foldCapturedIntoCalls(taskLocals,allRows.filter(record=>record.networkBody?.flow&&showOnAccessPage(record)&&(record.taskID===activeTask.id||taskForVisit(record,[activeTask])?.task)));
   const covered=new Set([...taskLocals,...taskExchanges].map(record=>visitSite(record)?toolName(record,[activeTask])+'\0'+visitSite(record):'').filter(Boolean));
   const toolVisits=taskToolVisits(activeTask).filter(record=>{const site=visitSite(record);return networkBehavior(record)&&!(site&&covered.has(toolName(record,[activeTask])+'\0'+site));});
   const byID=new Map();
   for(const record of [...toolVisits,...taskLocals,...taskExchanges])if(!byID.has(record.id))byID.set(record.id,record);
   records=[...byID.values()].sort((a,b)=>new Date(a.startedAt||a.timestamp)-new Date(b.startedAt||b.timestamp)).filter(matches).slice(0,40);
   const fullTitle=plainTask(activeTask.originalRequest||activeTask.title||'这次任务');
   title=fullTitle.length>42?fullTitle.slice(0,42)+'…':fullTitle;
   note=activeTask.agent;
   showAll=false;
  }
  const current=selected?records.find(record=>record.id===selected):null;
  const taskPill=activeTask?'<button type="button" aria-pressed="true">这次任务</button>':(focusTask?'<button type="button" data-network-scope="'+esc(focusTask)+'">这次任务</button>':'');
  const allPill=activeTask?'<button type="button" data-network-all>全部外网访问</button>':'<button type="button" aria-pressed="true">全部外网访问</button>';
  const back=activeTask?'<button type="button" data-task="'+esc(activeTask.id)+'">返回任务过程</button>':'';
  holder.innerHTML='<div class="network-scope-switch">'+taskPill+allPill+'</div><header class="network-task-bar">'+back+'<h2>'+esc(redact(title))+'</h2><p>'+esc(redact(note))+'</p></header>'+statsMarkup(records)+rollupMarkup(records,payload.tasks)+(records.length?tableMarkup(records,payload.tasks,{all:showAll,selected:current?.id}):'<p>'+(activeTask?'这次任务还没有归上的外网访问。':'还没有采到外网访问。')+'</p>');
 }
 window.AgentReinsNetwork={rows,scope,render,redact,exchangeMarkup,journeys,taskExchangeMarkup,coverage,connectionMarkup,securityMarkup,accessHop,projectLocal,setLocalTransports,setCapturedBodies,localExchanges,rawLocalTransports,bypassedAudit,tlsFailed,tlsHandshakeFailed};
})();
