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
 let socketLedger={connections:[],coverage:{state:'not_loaded'},keychain:null};
 function setSocketLedger(value){socketLedger=value&&typeof value==='object'?{connections:list(value.connections),coverage:value.coverage&&typeof value.coverage==='object'?value.coverage:{},keychain:value.keychain&&typeof value.keychain==='object'?value.keychain:null}:{connections:[],coverage:{state:'not_loaded'},keychain:null};}
 function socketLedgerData(){return {connections:socketLedger.connections.slice(),coverage:Object.assign({},socketLedger.coverage),keychain:socketLedger.keychain?Object.assign({},socketLedger.keychain):null};}
 const socketSourceLabel={proxy_observed:'代理路由日志按本机端口+时间对上 · Correlated',argv_parsed:'命令参数中的主机，正向解析到同一 IP · Correlated',dns_inferred:'反向 DNS 推断 · Inferred',socket_sampled:'只有对端 IP · Observed',proxy_unjoined:'走了代理，真实目的地未对上 · Unknown',local:'本机服务'};
 function socketTime(value){if(value==null||value==='')return '未采到';const d=new Date(value);return isNaN(d)?'时间无法解析：'+String(value):d.toLocaleTimeString('zh-CN',{hour12:false});}
 // Raw per-process connection list (the destination view above groups the same rows).
 function socketLedgerMarkup(agent='all',{collapsed=false}={}){
  const cov=socketLedger.coverage||{};
  if(cov.state==='not_loaded')return '';
  if(cov.state==='not_running'||(!socketLedger.connections.length&&cov.state!=='sampling'))return '<section class="socket-ledger"><h3>按进程采样的全部连接</h3><p class="network-notice">'+esc(cov.state==='tampered'?'连接台账校验失败：采样记录不能当证据。':cov.state==='stopped'?'按进程连接采样已停止：agent 直连外网的新流量看不到。':'按进程连接采样没有运行：现在只看得到走审计代理或审计入口的访问，agent 直连外网的流量看不到。')+'</p></section>';
  const all=socketLedger.connections.filter(r=>agent==='all'||r.agent===agent);
  const shown=all.filter(r=>r.scope!=='loopback'||r.viaProxy);
  const direct=shown.filter(r=>r.viaProxy===false&&r.scope==='public').length;
  const p95=cov.measurementConfidence==='Observed'&&cov.observedCycleSecondsP95!=null?'实测采样周期 p95 '+cov.observedCycleSecondsP95+' 秒':'实测采样周期 Unknown（样本不足）';
  const state=cov.state==='sampling'?'':cov.state==='stopped'?'采样已停止，以下是历史记录。':cov.state==='tampered'?'台账校验失败，以下记录按 Unknown 处理。':'';
  const body=shown.slice(0,60).map(r=>'<tr><td>'+esc(r.agent)+'</td><td>'+esc(r.processName||'进程')+' · PID '+esc(r.pid)+'<br><small>父进程 '+esc(r.ppid)+'</small></td><td>'+esc(r.protocol)+'</td><td><b>'+esc(r.realDestination||'未知')+'</b><br><small>'+esc(socketSourceLabel[r.destinationSource]||r.destinationSource||'未提供')+'</small></td><td>'+esc(r.transportPeer||r.remoteAddress)+'</td><td>'+(r.viaProxy?'走代理':'<b>未走代理</b>')+'</td><td>'+esc(r.state||'未提供')+'</td><td>'+esc(socketTime(r.firstSeen))+' → '+esc(socketTime(r.lastSeen))+'<br><small>'+esc(r.sampleCount)+' 次采样</small></td><td>'+esc(r.ledgerIntegrity==='tampered'?'Unknown':(r.evidence||'Observed'))+'</td></tr>').join('');
  const inner='<p class="network-notice">'+esc(state+p95+'，最近一次 '+socketTime(cov.lastSampleAt)+'。共 '+shown.length+' 条，其中未走代理的外网连接 '+direct+' 条。短于采样间隔的连接会漏掉；经系统解析器的 DNS 查询看不到；不含正文。')+'</p>'+(shown.length?'<div class="network-table-wrap"><table class="network-table"><thead><tr><th>Agent</th><th>进程</th><th>协议</th><th>真实目的地</th><th>实际对端</th><th>代理</th><th>状态</th><th>首次 → 最近</th><th>证据</th></tr></thead><tbody>'+body+'</tbody></table></div>':'<p>采样在运行，暂未看到 agent 的外网连接。</p>');
  return collapsed?'<details class="socket-ledger"><summary>按进程采样的原始连接（'+esc(shown.length)+' 条）</summary>'+inner+'</details>':'<section class="socket-ledger"><h3>按进程采样的全部连接 · 不论是否走代理</h3>'+inner+'</section>';
 }
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
 function loopbackPeer(value){
  const text=String(value||'');
  if(!text||!loopbackHost(text))return '';
  const host=hostToken(text);
  const port=text.match(/:(\d{2,5})/)||text.match(/\bport (\d{2,5})\b/);
  return port&&host?host+':'+port[1]:host;
 }
 function projectLocal(records){
  return list(records).filter(agentTransport).map(run=>{
   const tunnel=(run.connections||[]).find(c=>c.kind==='proxyTunnel');
   const connected=(run.connections||[]).find(c=>c.kind==='connected');
   const attempt=(run.connections||[]).find(c=>c.kind==='attempt');
   const blocks=list(run.blocks);
   const tunnelHost=externalDetail(tunnel?.detail?.[0]);
   const connectedHost=externalDetail(connected?.detail?.[0]);
   const headerHost=hostsFromBlocks(blocks);
   const askedRaw=askedDestination(run);
   const asked=externalDetail(askedRaw);
   // 显式访问本机回环仍保留（不再被当成「无外连」丢掉）；代理隧道里的 127.0.0.1 仍不当作站点。
   const askedLoopback=(!asked&&askedRaw&&loopbackHost(askedRaw))?hostToken(askedRaw):null;
   const connectedLoopback=(!connectedHost&&connected&&loopbackHost(connected.detail?.[0])&&!tunnelHost)?hostToken(connected.detail?.[0]):null;
   const attemptPeer=loopbackPeer(attempt&&attempt.detail&&attempt.detail[0]);
   const recordedPeer=loopbackPeer(run.transportPeer);
   const formula=list(run.formulas).find(Boolean);
   const recordedReal=run.realDestination&&!loopbackHost(run.realDestination)?run.realDestination:(run.destinationHost&&!loopbackHost(run.destinationHost)?run.destinationHost:null);
   const failedExit=run.exitCode!=null&&run.exitCode!==''&&Number(run.exitCode)!==0;
   const invocation=invocationArgs(run);
   const argvURL=invocation.find(arg=>/^https?:\/\//i.test(String(arg)))||'';
   let target=recordedReal||tunnelHost||headerHost||connectedHost||asked||askedLoopback||connectedLoopback||attemptPeer||(run.tool==='brew'&&formula?'Homebrew':null);
   // A failed loopback / peer-only attempt is evidence. Name the URL or the peer; do not drop it
   // because curl never reached "Connected" and the only address is 127.0.0.1.
   if(failedExit&&(argvURL&&loopbackHost(argvURL)||attemptPeer||recordedPeer||askedLoopback)&&loopbackHost(target||argvURL||attemptPeer||recordedPeer||askedLoopback)){
    target=(argvURL&&loopbackHost(argvURL)?argvURL:'')||attemptPeer||recordedPeer||target;
   }
   if(!target&&failedExit&&(attemptPeer||recordedPeer))target=attemptPeer||recordedPeer;
   // 127.0.0.1 is the local proxy or a local port, never the external site.
   const proxied=!!tunnelHost||(!!(connected&&loopbackHost(connected.detail?.[0]))&&!!headerHost)||!!run.transportPeer;
   const transportPeer=run.transportPeer||(proxied&&connected&&loopbackHost(connected.detail?.[0])?hostToken(connected.detail[0]):null)||(failedExit?attemptPeer||recordedPeer||null:null);
   let destinationSource=run.destinationSource||(recordedReal?'proxy_observed':headerHost?'proxy_observed':asked?'argv_parsed':null);
   if(!destinationSource&&failedExit&&loopbackHost(target)&&!recordedReal)destinationSource='transport_peer_only';
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
   const downloads=list(run.downloads).filter(item=>item&&typeof item==='object');
   // en_d595e9da: never promote sh/bash exec fileResult into downloads[] — that made
   // downloadCall/downloadPID point at the exec record instead of curl.
   const isExecTool=/^(sh|bash|zsh|dash|open|chmod)$/.test(String(run.tool||''));
   const fallback=(!isExecTool&&run.fileResult&&typeof run.fileResult==='object')?[run.fileResult]:[];
   const downloadRecords=(downloads.length?downloads:fallback).filter(item=>item.path&&item.path!=='/dev/null');
   const downloaded=downloadRecords.map(item=>String(item.path).split(/[/\\]/).pop()).filter(name=>name&&name!=='null');
   let request=[names.length?'外传文件名\n'+names.join('\n'):'',downloaded.length?'下载文件名\n'+downloaded.join('\n'):'',text(sent)].filter(Boolean).join('\n\n');
   if(argvURL&&!request.includes(argvURL))request=[argvURL,request].filter(Boolean).join('\n');
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
 function normalizeCmd(value){return String(value||'').replace(/\s+/g,' ').trim();}
 function parentBlob(run){
  const argv=run&&run.parentArgv;
  if(Array.isArray(argv))return normalizeCmd(argv.join(' '));
  return normalizeCmd(argv);
 }
 function argvURLs(run){return list(run&&run.args).map(String).filter(arg=>/^https?:\/\//i.test(arg));}
 // Child curls under one agent shell. A parent exit code of 0 must not hide them.
 function shellChildAttempts(task, card){
  const command=normalizeCmd(shellText(card));
  const title=String(card&&card.title||'');
  const shell=card&&(card.kind==='command'||/^(bash|shell|exec_command|terminal|commandexecution|zsh|sh)$/i.test(title)||/terminal|shell|\bbash\b/i.test(title));
  if(!shell||command.length<12)return [];
  const agent=task&&task.agent;
  const session=task&&task.session;
  const shellPID=card.execution&&card.execution.processID;
  const runs=rawLocalTransports().filter(run=>{
   if(agent&&run.agent&&run.agent!==agent)return false;
   const owner=run.session||run.codexThreadID;
   if(session&&owner&&owner!==session)return false;
   return true;
  });
  const strong=[],urlHits=[];
  for(const run of runs){
   const parent=parentBlob(run);
   if((command.length>=24&&parent.includes(command))||(shellPID!=null&&shellPID!==''&&String(run.parentPID)===String(shellPID))){strong.push(run);continue;}
   if(argvURLs(run).some(url=>command.includes(url)))urlHits.push(run);
  }
  const pids=new Set(strong.map(run=>run.parentPID).filter(pid=>pid!=null&&pid!==''));
  // $i in a for-loop is not the expanded URL. Same parent shell as a literal hit still counts.
  if(/[\n;]|&&|\bfor\b|\bwhile\b/.test(command))for(const run of urlHits)if(run.parentPID!=null&&run.parentPID!=='')pids.add(run.parentPID);
  const linked=runs.filter(run=>strong.includes(run)||urlHits.includes(run)||(pids.size&&pids.has(run.parentPID)));
  const byID=new Map();
  for(const run of linked){
   const id=String(run.call||run.runID||'');
   if(!id||byID.has(id))continue;
   byID.set(id,run);
  }
  return [...byID.values()].sort((a,b)=>String(a.startedAt||'').localeCompare(String(b.startedAt||'')));
 }
 function shellChildMarkup(task, card){
  const rows=shellChildAttempts(task, card);
  if(!rows.length)return '';
  const failed=rows.filter(run=>run.exitCode!=null&&run.exitCode!==''&&Number(run.exitCode)!==0);
  const items=rows.map(run=>{
   const exit=run.exitCode!=null&&run.exitCode!==''?run.exitCode:'未提供';
   const url=argvURLs(run)[0]||'';
   const peer=run.transportPeer||loopbackPeer(list(run.connections).map(c=>c&&c.detail&&c.detail[0]).find(Boolean))||'对端未采到';
   const dest=run.realDestination&&!loopbackHost(run.realDestination)?run.realDestination:(url&&!loopbackHost(url)?hostToken(url):'');
   const id=run.call||run.runID||'';
   const bad=run.exitCode!=null&&run.exitCode!==''&&Number(run.exitCode)!==0;
   return '<li'+(bad?' class="is-fail"':'')+'>'+esc(run.tool||'命令')+' · 退出码 '+esc(exit)+' · '+(dest?esc(dest):'目的地未解析')+' · 对端 '+esc(peer)+(url?' · '+esc(url):'')+' · 执行编号 '+esc(id)+'</li>';
  }).join('');
  return '<section class="shell-children"><h3>同一次 shell 的子命令</h3><p>父命令退出码不能盖住这些尝试。'+esc(failed.length)+' 次未成功，共 '+esc(rows.length)+' 次已审计。</p><ul>'+items+'</ul></section>';
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
 // ESC-MUTATION-REGION-START (tools/mutate_esc_calls.cjs + Tests/Manual/network/test_xss_network_views.cjs)
 // ---------------------------------------------------------------------------------------------
 // 外网访问 (phase 2): one destination-grouped view over BOTH sources — proxy/command records and the
 // per-process socket ledger (proxied or not) — plus a connection map and a destination detail.
 // Prototype table: 任务｜时间｜谁｜去了哪里｜协议｜结果｜关联｜内容审计. 结果 comes only from structured
 // fields (HTTP status, TLS check outcome, exit code); 关联 and 内容审计 are their own columns.
 const TABLE_HEADERS=['任务','时间','谁','去了哪里','协议','结果','关联','内容审计'];
 function insecureFlag(r){return list(r.args).map(String).some(a=>a==='--insecure'||a==='--no-check-certificate'||/^-[A-Za-z]*k[A-Za-z]*$/.test(a));}
 // HTTPS judged from structured fields only: URL scheme (record or command argument), port 443 on the connection.
 function httpsLike(r){return /^https:/i.test(String(httpURL(r)||r.url||''))||list(r.args).some(a=>/^https:\/\//i.test(String(a)))||String(r.port||r.resource?.remotePort||'')==='443'||/:443(?:$|\/)/.test(String(r.host||''))||list(r.connections).some(c=>list(c&&c.detail).some(d=>/:443$/.test(String(d))));}
 function exitOf(r){return r.exitCode!=null&&r.exitCode!==''&&Number.isFinite(Number(r.exitCode))?Number(r.exitCode):null;}
 function resultCell(r){
  const parts=[],status=Number(r.networkBody?.responseStatus),exit=exitOf(r);
  if(Number.isFinite(status)&&status>=100)parts.push('HTTP '+status);
  if(exit===60||exit===77||exit===58)parts.push('TLS 校验失败（退出码 '+exit+'）');
  else if(exit===35)parts.push('TLS 握手失败（退出码 35）');
  else if(Number.isFinite(status)&&status>=100&&httpsLike(r))parts.push(insecureFlag(r)?'TLS 未校验（-k / --insecure）':'TLS 校验通过');
  if(exit!=null&&![0,35,58,60,77].includes(exit))parts.push('退出码 '+exit);
  else if(exit===0&&!(status>=100))parts.push('退出码 0');
  if(/加密/.test(String(r.gap||'')))parts.push('加密通道');
  if(bypassedAudit(r))parts.push('直接连接，绕过了审计代理');
  // Structured transfer facts from the capture (git push file list, verified downloads) — not body text.
  const files=list(r.outboundFiles).filter(Boolean);
  if(files.length&&exit===0)parts.push('带走了 '+files.join('、'));
  const saved=list(r.downloads).filter(item=>item&&(item.state==='verified'||item.bytes!=null||item.state==='tooLarge')).map(item=>String(item.path||'').split(/[/\\]/).pop()).filter(Boolean);
  if(saved.length)parts.push('下载了 '+saved.join('、'));
  if(!parts.length)parts.push(accessHop(r).kind==='remote-tool'?'工具调用 · 没有状态码':'没有状态码或退出码');
  return parts.join(' · ');
 }
 function associationCell(r){
  if(r.call)return '执行编号已对上';
  if(r.taskConfidence==='candidate')return '候选关联（按时间窗，没有执行编号）';
  if(bypassedAudit(r)&&list(r.args).map(String).some(a=>/^(?:-x|--proxy|--preproxy|--noproxy|--no-proxy|--socks)/.test(a)||/^http\.proxy=/.test(a)))return '没有执行编号（命令自带代理参数）';
  if(r.accessKind==='local-tool')return '没有执行编号';
  return '没有执行编号（只有这条记录本身）';
 }
 function auditCell(r){
  if(bypassedAudit(r))return '没有审计（流量没经过代理）';
  const audit=agentAudit(r),findings=list(audit.findings);
  if(audit.verdict==='audit_error')return '审计没跑成';
  if(findings.length)return '命中 '+findings.length+' 条：'+findings.map(item=>item.label||auditLabels[item.rule]||item.rule).join('、');
  if(audit.verdict==='no_body')return /加密/.test(String(r.gap||''))?'没有审计（加密通道，看不到正文）':'没有正文可查';
  if(audit.verdict==='truncated')return '只查了前 '+(audit.requestBytesInspected||0)+' 字节，没有命中';
  return '没有命中规则';
 }
 function socketPublic(s){return s.scope==='public'||(s.scope==null&&scope(s.remoteAddress)==='public');}
 function socketDestination(s){return String(s.realDestination||'')||String(s.remoteAddress||'')||'目的地未采到';}
 function socketEvidence(s){return s.ledgerIntegrity==='tampered'?'Unknown':String(s.destinationEvidence||s.evidence||'Unknown');}
 function socketWhen(s){return s.firstSeen&&s.lastSeen&&s.firstSeen!==s.lastSeen?socketTime(s.firstSeen)+' → '+socketTime(s.lastSeen):socketTime(s.lastSeen||s.firstSeen);}
 function socketCells(s){
  const dest=socketDestination(s),peer=s.remoteAddress&&s.remoteAddress!==dest?'（'+s.remoteAddress+'）':'';
  return ['未归属任务（按进程采样）',socketWhen(s),(s.agent||'Agent 未确认')+' · '+(s.processName||'进程')+' · PID '+(s.pid??'?'),dest+peer+(s.remotePort?':'+s.remotePort:''),(s.protocol||'连接'),
   '连接 '+(s.state||'状态未采到')+' · '+(s.viaProxy?'经审计代理':'未走代理（直连）'),
   '没有执行编号（按进程采样）· '+(socketSourceLabel[s.destinationSource]||s.destinationSource||'目的地来源未提供')+(s.ledgerIntegrity==='tampered'?' · 台账校验失败':''),
   s.viaProxy?'经代理：正文审计见同一目的地的代理记录':'没有审计（流量没经过代理）'];
 }
 function rowCells(record,tasks){return [taskNameOf(record,tasks),clock(record),toolName(record,tasks)+(record.agent?' · '+record.agent:''),showWhere(record),protocolOf(record),resultCell(record),associationCell(record),auditCell(record)];}
 function tableRows(records,tasks,{selected=null,sockets=[]}={}){
  const recordRows=records.map(record=>{
   const open=selected===record.id,cells=rowCells(record,tasks);
   const tds=cells.map((cell,i)=>i===3?'<td><button type="button" class="network-open" data-network-record="'+esc(record.id)+'" aria-pressed="'+open+'">'+esc(redact(cell))+'</button></td>':'<td>'+esc(redact(cell))+'</td>').join('');
   const row='<tr'+(callFailed(record)?' class="is-fail"':bypassedAudit(record)?' class="is-bypass"':'')+'>'+tds+'</tr>';
   return row+(open?'<tr class="network-read-row"><td colspan="'+TABLE_HEADERS.length+'">'+exchangeMarkupFor(record,tasks)+'</td></tr>':'');
  }).join('');
  const socketRows=list(sockets).map(s=>'<tr class="is-socket'+(s.viaProxy===false&&socketPublic(s)?' is-bypass':'')+'">'+socketCells(s).map(cell=>'<td>'+esc(redact(cell))+'</td>').join('')+'</tr>').join('');
  return recordRows+socketRows;
 }
 function tableMarkup(records,tasks,{selected=null,sockets=[]}={}){
  return '<div class="network-table-wrap"><table class="network-table network-table-8"><thead><tr>'+TABLE_HEADERS.map(header=>'<th>'+header+'</th>').join('')+'</tr></thead><tbody>'+tableRows(records,tasks,{selected,sockets})+'</tbody></table></div>';
 }
 // --- destinations -----------------------------------------------------------------------------
 function hostOfText(value){
  const s=String(value||'').trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i,'').replace(/^[^@\s/]+@/,'');
  return hostToken(s).toLowerCase();
 }
 const FAILED_LOOPBACK='本机回环 · 未成功';
 function attemptFailed(r){
  const exit=r.exitCode!=null&&r.exitCode!==''?Number(r.exitCode):null;
  return exit!=null&&exit!==0;
 }
 function recordDestination(r){
  const hop=accessHop(r);
  if(hop.kind==='remote-tool')return '远程访问工具';
  if(hop.kind==='model')return '模型服务';
  const key=hostOfText(httpURL(r)||r.host||whereOf(r))||'目的地未采到';
  const loop=loopbackHost(key)||/^127\./.test(key)||key==='::1';
  const peerOnly=r.destinationSource==='transport_peer_only'&&!r.realDestination;
  // Failed loopback / destination-null attempts stay on the destination page. Successful local services do not.
  if(attemptFailed(r)&&(loop||peerOnly))return FAILED_LOOPBACK;
  return key;
 }
 const UNJOINED='经代理（真实目的地未对上）';
 function ipLiteral(key){return scope(key)!=='unknown';}
 function allowFn(){return typeof window.AgentReinsRisk?.isAllowedHost==='function'?window.AgentReinsRisk.isAllowedHost:null;}
 function destinationGroups(records,sockets){
  const groups=new Map(),byIP=new Map();
  const group=key=>{if(!groups.has(key))groups.set(key,{key,records:[],sockets:[],agents:new Set(),ips:new Set(),ports:new Set(),first:null,last:null});return groups.get(key);};
  const stamp=(g,value)=>{const t=new Date(value).getTime();if(!Number.isFinite(t))return;if(g.first==null||t<g.first)g.first=t;if(g.last==null||t>g.last)g.last=t;};
  for(const r of records){
   const g=group(recordDestination(r));g.records.push(r);if(r.agent)g.agents.add(r.agent);
   const ip=r.ip||r.resource?.remoteIP;if(ip){g.ips.add(String(ip));if(!ipLiteral(g.key))byIP.set(String(ip),g.key);}
   const port=r.port||r.resource?.remotePort;if(port)g.ports.add(String(port));
   stamp(g,r.startedAt||r.timestamp);
  }
  for(const s of sockets){
   const named=s.realDestination&&!ipLiteral(String(s.realDestination))?hostOfText(s.realDestination):'';
   const key=named||(s.viaProxy&&s.scope==='loopback'&&!s.realDestination?UNJOINED:byIP.get(String(s.remoteAddress||s.realDestination||''))||String(s.realDestination||s.remoteAddress||'目的地未采到').toLowerCase());
   const g=group(key);g.sockets.push(s);if(s.agent)g.agents.add(s.agent);if(s.remoteAddress)g.ips.add(String(s.remoteAddress));if(s.remotePort)g.ports.add(String(s.remotePort));
   stamp(g,s.firstSeen);stamp(g,s.lastSeen);
  }
  const allow=allowFn();
  for(const g of groups.values()){
   const special=g.key==='远程访问工具'||g.key==='模型服务'||g.key==='目的地未采到'||g.key===UNJOINED||g.key===FAILED_LOOPBACK;
   g.local=!special&&(loopbackHost(g.key)||scope(g.key)==='local');
   g.ipOnly=!special&&ipLiteral(g.key);
   g.allowed=!special&&!g.local&&!!(allow&&allow(g.key));
   g.allowKnown=!!allow;
   g.bypass=g.records.some(bypassedAudit)||g.sockets.some(s=>s.viaProxy===false&&socketPublic(s));
   g.nonAllowed=!special&&!g.local&&!!allow&&!g.allowed;
   g.sensitive=g.records.filter(r=>list(agentAudit(r).findings).length).length;
   g.failed=g.records.filter(callFailed).length;
   g.tampered=g.sockets.some(s=>s.ledgerIntegrity==='tampered');
   g.suspicious=g.bypass||g.sensitive>0||(g.nonAllowed&&!g.ipOnly);
   g.verdict=g.local?'内网':g.suspicious?'可疑':g.nonAllowed?'待核（只有 IP）':g.allowed?'白名单':special?'说明':'未判定';
  }
  // Loopback is not 外网 (local services). Agent-attributed failures aimed at loopback stay visible.
  return [...groups.values()].filter(g=>{
   const loop=loopbackHost(g.key)||/^127\./.test(g.key)||g.key==='::1';
   if(!loop)return true;
   return g.records.some(attemptFailed);
  }).sort((a,b)=>(b.suspicious-a.suspicious)||((b.last||0)-(a.last||0)));
 }
 function evidenceSummary(g){
  const counts=new Map();
  const add=label=>counts.set(label,(counts.get(label)||0)+1);
  for(const r of g.records)add(r.call?'Observed（执行编号）':r.taskConfidence==='candidate'?'Inferred（时间窗）':'Observed（单条记录）');
  for(const s of g.sockets)add(socketEvidence(s)+'（采样）');
  return [...counts].map(([label,n])=>label+' ×'+n).join(' · ')||'Unknown';
 }
 function flagChips(g){
  const chips=[];
  if(g.local)chips.push(['local','内网']);
  if(g.bypass)chips.push(['bad','绕过代理']);
  if(g.nonAllowed)chips.push(['bad',g.ipOnly?'非白名单 · 只有 IP':'非白名单']);
  if(g.sensitive)chips.push(['bad','出站含敏感内容 ×'+g.sensitive]);
  if(g.allowed)chips.push(['ok','白名单']);
  if(!g.allowKnown&&!g.local)chips.push(['unk','白名单未加载']);
  if(g.tampered)chips.push(['unk','台账校验失败']);
  // Chip texts are fixed strings (plus integer counts), never captured data.
  return chips.map(([cls,text])=>'<span class="dest-chip '+cls+'">'+text+'</span>').join('');
 }
 function stampText(t){return t==null?'时间未采到':new Date(t).toLocaleString('zh-CN',{hour12:false});}
 // Socket sampling coverage, stated as measured — shared by this page and the 首页 banner.
 function socketCoverageSummary(){
  const cov=socketLedger.coverage||{},key=socketLedger.keychain||{},integ=cov.integrity||{};
  const p95=cov.measurementConfidence==='Observed'&&cov.observedCycleSecondsP95!=null?cov.observedCycleSecondsP95:null;
  return {state:cov.state||'not_loaded',p95,p95Text:p95!=null?'实测周期 p95 '+p95+' 秒':'实测周期：Unknown（样本不足）',
   misses:cov.measurementConfidence==='Observed'?cov.missesShorterThanSeconds:null,failures:cov.failures??0,lastFailure:cov.lastFailure||null,
   staleSeconds:cov.staleSeconds,lastSampleAt:cov.lastSampleAt||null,integrity:integ.state||'unknown',integrityReason:integ.reason||'',
   keyState:key.state||'unknown',keyHelper:key.helper||null,keyReason:key.reason||'',connections:socketLedger.connections.length};
 }
 const integrityText={verified:'台账已签名并校验通过',unsigned:'台账未签名',unverifiable:'台账已签名，但本机读不到密钥，无法校验',tampered:'台账校验失败（按篡改处理）',missing:'没有台账'};
 const stateText={sampling:'按进程采样运行中',stopped:'采样已停止',not_running:'采样没有运行',tampered:'台账校验失败',not_loaded:'尚未读取采样台账'};
 function coverageLine(){
  const c=socketCoverageSummary();
  if(c.state==='not_loaded')return '';
  const parts=[stateText[c.state]||c.state];
  if(c.state==='stopped'&&c.staleSeconds!=null)parts.push('最近一次在 '+c.staleSeconds+' 秒前');
  parts.push(c.p95Text);
  if(c.misses!=null)parts.push('短于 '+c.misses+' 秒的连接可能漏掉');
  parts.push('失败 '+c.failures+' 次');
  parts.push(integrityText[c.integrity]||('台账：'+c.integrity));
  if(c.keyState==='key_unavailable')parts.push('完整性密钥不可用（'+(c.keyHelper||'原因未知')+'）');
  return '<p class="network-notice socket-coverage-line">'+esc(parts.join(' · '))+'</p>';
 }
 function destinationsMarkup(groups,tasks,{selected=null,perGroup=6}={}){
  if(!groups.length)return '<p class="network-empty">还没有采到外网访问。</p>';
  const body=groups.map(g=>{
   const header='<tr class="dest-group'+(g.suspicious?' is-suspicious':'')+'"><td colspan="'+TABLE_HEADERS.length+'"><button type="button" class="dest-name" data-network-destination="'+esc(g.key)+'">'+esc(redact(g.key))+'</button> '+flagChips(g)+'<span class="dest-meta">'+esc([...g.agents].join('、')||'Agent 未确认')+' · '+g.records.length+' 次请求 · '+g.sockets.length+' 条采样连接 · '+stampText(g.first)+' → '+stampText(g.last)+' · 判定 '+g.verdict+' · 可信度 '+esc(evidenceSummary(g))+'</span></td></tr>';
   const recs=g.records.slice(0,perGroup),socks=g.sockets.slice(0,Math.max(0,perGroup-recs.length));
   const more=g.records.length+g.sockets.length-recs.length-socks.length;
   return header+tableRows(recs,tasks,{selected,sockets:socks})+(more>0?'<tr class="dest-more"><td colspan="'+TABLE_HEADERS.length+'"><button type="button" data-network-destination="'+esc(g.key)+'">另有 '+more+' 条 · 打开目的地详情</button></td></tr>':'');
  }).join('');
  return '<div class="network-table-wrap"><table class="network-table network-table-8"><thead><tr>'+TABLE_HEADERS.map(h=>'<th>'+h+'</th>').join('')+'</tr></thead><tbody>'+body+'</tbody></table></div>';
 }
 function destinationStats(groups){
  const n=f=>groups.filter(f).length;
  const reqs=groups.reduce((s,g)=>s+g.records.length,0),socks=groups.reduce((s,g)=>s+g.sockets.length,0);
  // Counts and fixed labels only.
  const card=(value,label,cls)=>'<div'+(cls?' class="'+cls+'"':'')+'><strong>'+value+'</strong><span>'+label+'</span></div>';
  return '<div class="network-stats dest-stats">'+card(groups.length,'目的地')+card(n(g=>g.nonAllowed),'非白名单',n(g=>g.nonAllowed)?'is-fail':'')+card(n(g=>g.bypass),'绕过代理',n(g=>g.bypass)?'is-fail':'')+card(n(g=>g.sensitive),'出站含敏感内容',n(g=>g.sensitive)?'is-fail':'')+card(reqs+' / '+socks,'请求 / 采样连接')+'</div>';
 }
 // --- connection map (agent → process → destination) ---------------------------------------------
 function mapModel(groups,tasks){
  const agents=new Map(),procs=new Map(),dests=new Map(),edges=new Map();
  const edge=(from,to,kind,label)=>{const k=from+'\u0000'+to;const e=edges.get(k)||{from,to,kinds:new Set(),labels:new Set(),n:0};e.kinds.add(kind);if(label)e.labels.add(label);e.n+=1;edges.set(k,e);};
  for(const g of groups){
   const dkind=g.bypass?'bypass':g.nonAllowed||g.sensitive?'nonallow':g.local?'local':'allow';
   dests.set('d:'+g.key,{id:'d:'+g.key,label:g.key,kind:dkind,group:g});
   const link=(agent,proc,kind,label)=>{
    const a='a:'+agent,p='p:'+agent+'\u0000'+proc;
    agents.set(a,{id:a,label:agent});procs.set(p,{id:p,label:proc,agent});
    edge(a,p,'allow','');edge(p,'d:'+g.key,kind,label);
   };
   for(const r of g.records)link(r.agent||'Agent 未确认',toolName(r,tasks),bypassedAudit(r)?'bypass':dkind==='bypass'?(g.nonAllowed?'nonallow':'allow'):dkind,clock(r)+' '+resultCell(r));
   for(const s of g.sockets)link(s.agent||'Agent 未确认',s.processName||'进程',s.viaProxy===false&&socketPublic(s)?'bypass':dkind==='bypass'?(g.nonAllowed?'nonallow':'allow'):dkind,socketWhen(s)+' '+(s.protocol||'')+' '+(s.viaProxy?'经代理':'直连'));
  }
  return {agents:[...agents.values()],procs:[...procs.values()],dests:[...dests.values()],edges:[...edges.values()]};
 }
 function mapMarkup(groups,tasks,{suspicious=false}={}){
  if(!groups.length)return '<p class="network-empty">还没有采到外网访问，地图为空。</p>';
  const m=mapModel(groups,tasks),ROW=44,TOP=30;
  const pos=new Map();
  const place=(nodes,x)=>nodes.forEach((n,i)=>pos.set(n.id,{x,y:TOP+i*ROW+ROW/2}));
  place(m.agents,0);place(m.procs,1);place(m.dests,2);
  const rows=Math.max(m.agents.length,m.procs.length,m.dests.length),H=TOP+rows*ROW+10;
  const X=[220,390,610,780];
  const rank={bypass:3,nonallow:2,local:0,allow:1};
  const lines=m.edges.map(e=>{
   const a=pos.get(e.from),b=pos.get(e.to);if(!a||!b)return '';
   const kind=[...e.kinds].sort((p,q)=>rank[q]-rank[p])[0];
   const x1=a.x===0?X[0]:X[2],x2=b.x===1?X[1]:X[3];
   const dim=suspicious&&!(kind==='bypass'||kind==='nonallow');
   const title=[...e.labels].slice(0,6).join('\n')||(e.n+' 条');
   return '<path class="map-edge '+kind+(dim?' dim':'')+'" d="M'+x1+' '+a.y+' C'+(x1+80)+' '+a.y+' '+(x2-80)+' '+b.y+' '+x2+' '+b.y+'" vector-effect="non-scaling-stroke"><title>'+esc(redact(title))+'</title></path>';
  }).join('');
  const col=(nodes,cls,render)=>'<div class="map-col '+cls+'">'+nodes.map((n,i)=>'<div class="map-node" style="top:'+(TOP+i*ROW)+'px">'+render(n)+'</div>').join('')+'</div>';
  const agentsCol=col(m.agents,'map-agents',n=>'<span class="map-label agent">'+esc(redact(n.label))+'</span>');
  const procsCol=col(m.procs,'map-procs',n=>'<span class="map-label proc">'+esc(redact(n.label))+'<small>'+esc(redact(n.agent))+'</small></span>');
  const destsCol=col(m.dests,'map-dests',n=>'<button type="button" class="map-label dest '+n.kind+(suspicious&&!(n.group.suspicious||n.group.nonAllowed)?' dim':'')+'" data-network-destination="'+esc(n.label)+'" title="'+n.group.verdict+' · '+n.group.records.length+' 次请求 · '+n.group.sockets.length+' 条采样连接">'+esc(redact(n.label))+'</button>');
  const legend='<div class="map-legend"><span class="allow">白名单 / 已知</span><span class="nonallow">非白名单或含敏感内容</span><span class="bypass">绕过代理（直连）</span><span class="local">内网</span></div>';
  const filter='<div class="map-filter" role="group" aria-label="连线筛选"><button type="button" data-network-map-filter="all" aria-pressed="'+!suspicious+'">全部连线</button><button type="button" data-network-map-filter="suspicious" aria-pressed="'+suspicious+'">突出可疑</button></div>';
  return '<section class="network-map">'+filter+legend+'<div class="map-heads"><span>AGENT</span><span>进程 / 命令</span><span>目的地</span></div><div class="map-canvas" style="height:'+H+'px"><svg class="map-svg" viewBox="0 0 1000 '+H+'" preserveAspectRatio="none" aria-hidden="true">'+lines+'</svg>'+agentsCol+procsCol+destsCol+'</div><p class="network-notice">连线来自同一份数据：经代理或审计入口的请求，加上按进程采样到的连接。悬停连线可看时间与结果。</p></section>';
 }
 // --- destination detail (mockup 13) --------------------------------------------------------------
 function sizeText(n){const v=Number(n);if(!Number.isFinite(v)||v<=0)return null;return v>=1048576?(v/1048576).toFixed(1)+' MB':v>=1024?(v/1024).toFixed(1)+' KB':v+' B';}
 function destinationDetailMarkup(g,tasks,alerts){
  const timeline=[...g.records.map(r=>({t:new Date(r.startedAt||r.timestamp).getTime(),cells:[clock(r),r.call||'没有执行编号',(r.agent||'Agent 未确认')+' · '+toolName(r,tasks),[r.method,httpURL(r)||list(r.args).join(' ')||showWhere(r)].filter(Boolean).join(' '),[sizeText(r.networkBody?.requestBytes)&&'送出 '+sizeText(r.networkBody.requestBytes),sizeText(r.networkBody?.responseBytes)&&'收回 '+sizeText(r.networkBody.responseBytes)].filter(Boolean).join(' · ')||'未计量',resultCell(r)+' · '+auditCell(r)+' · '+(r.call?'Observed':'Inferred')]})),
   ...g.sockets.map(s=>({t:new Date(s.lastSeen||s.firstSeen).getTime(),cells:[socketWhen(s),'按进程采样',(s.agent||'Agent 未确认')+' · '+(s.processName||'进程')+' · PID '+(s.pid??'?'),(s.protocol||'连接')+' '+(s.remoteAddress||'')+(s.remotePort?':'+s.remotePort:'')+' · '+(s.state||'状态未采到')+' · '+(s.viaProxy?'经代理':'直连'),'未计量（采样不含字节数）',(s.viaProxy?'经审计代理':'绕过审计代理')+' · '+socketEvidence(s)+'（'+(socketSourceLabel[s.destinationSource]||s.destinationSource||'来源未提供')+'）']}))].sort((a,b)=>(b.t||0)-(a.t||0));
  const tl='<table class="network-table"><thead><tr><th>时间</th><th>执行</th><th>Agent · 进程</th><th>请求 · 命令</th><th>大小</th><th>结果 · 可信度</th></tr></thead><tbody>'+timeline.slice(0,80).map(row=>'<tr>'+row.cells.map(c=>'<td>'+esc(redact(c))+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  const sent=g.records.reduce((s,r)=>s+(Number(r.networkBody?.requestBytes)||0),0),back=g.records.reduce((s,r)=>s+(Number(r.networkBody?.responseBytes)||0),0);
  const reasons=[];
  if(g.bypass)reasons.push(g.sockets.some(s=>s.viaProxy===false&&socketPublic(s))?'按进程采样看到 agent 进程直接连到这个公网地址（viaProxy=false），没经过审计代理，正文没有审计。':'命令绕过了审计代理（后端 auditBypass 或命令自带代理参数）。');
  if(g.nonAllowed)reasons.push(g.ipOnly?'只有对端 IP，没有可核对的主机名；不在默认可信名单。':'目的地不在默认可信名单。');
  if(g.sensitive)reasons.push('有 '+g.sensitive+' 次请求的正文命中内容审计规则（见时间线“结果 · 可信度”列）。');
  if(g.tampered)reasons.push('连接台账校验失败：这些采样记录按 Unknown 处理。');
  // Reasons are fixed sentences (plus integer counts).
  const why=reasons.length?'<ul>'+reasons.map(x=>'<li>'+x+'</li>').join('')+'</ul>':'<p>'+(g.allowed?'目的地在默认可信名单内，没有发现绕过代理或敏感内容。':g.local?'这是内网 / 本机地址。':'没有命中可疑条件。')+'</p>';
  const sources=[...new Set(g.sockets.map(s=>socketSourceLabel[s.destinationSource]||s.destinationSource).filter(Boolean))];
  // TLS outcomes are fixed phrases from resultCell (exit codes are numbers).
  const tls=[...new Set(g.records.map(resultCell).filter(t=>/TLS/.test(t)).map(t=>t.split(' · ').filter(x=>/^TLS /.test(x)).join(' · ')))].filter(Boolean);
  const card='<dl class="network-facts"><dt>IP</dt><dd>'+esc([...g.ips].join('、')||'未采到')+'</dd><dt>端口</dt><dd>'+esc([...g.ports].join('、')||'未采到')+'</dd><dt>主机名来源</dt><dd>'+esc(sources.join('；')||(g.records.length?'请求本身（URL / Host / 命令参数）':'未采到'))+'</dd><dt>TLS</dt><dd>'+(tls.join('；')||'没有结构化 TLS 结果')+'</dd><dt>DNS</dt><dd>系统解析器发出的 DNS 查询看不到；只有命令参数或反向解析能给出主机名。</dd></dl>';
  const related=list(alerts).filter(a=>a&&(String(a.destination||'')===g.key||(a.record&&recordDestination(a.record)===g.key)));
  const rel=related.length?'<ul class="dest-alerts">'+related.map(a=>'<li><button type="button" class="risk-link" data-view="alerts" data-dest-alert="'+esc(a.id)+'">'+esc(a.rule)+' · '+esc(a.title)+'</button></li>').join('')+'</ul>':'<p>没有关联告警。</p>';
  return '<section class="destination-detail"><header class="network-task-bar"><button type="button" data-network-destination-back>返回目的地列表</button><h2>'+esc(redact(g.key))+'</h2><p>'+flagChips(g)+' 判定 '+g.verdict+' · '+esc([...g.agents].join('、')||'Agent 未确认')+' · 首次 '+stampText(g.first)+' · 最近 '+stampText(g.last)+'</p></header>'
   +'<div class="dest-grid"><section class="risk-card"><h3>请求时间线</h3>'+tl+'</section>'
   +'<section class="risk-card"><h3>送出 / 收回</h3><p>'+(sizeText(sent)||'未计量')+' 送出 · '+(sizeText(back)||'未计量')+' 收回（只计经代理或审计入口、带正文的请求；按进程采样的连接不含字节数）</p></section>'
   +'<section class="risk-card"><h3>为什么判为'+(g.suspicious?'可疑':g.verdict)+'</h3>'+why+'</section>'
   +'<section class="risk-card"><h3>DNS · IP · TLS</h3>'+card+'</section>'
   +'<section class="risk-card"><h3>关联告警</h3>'+rel+'</section>'
   +'<section class="risk-card"><h3>处置</h3><p>AgentReins 只观察、不拦截。本版没有一键“加入白名单 / 拦截”；可信名单目前是内置默认名单。</p></section></div></section>';
 }
 function socketsFor(agent,q){
  return socketLedger.connections.filter(s=>(agent==='all'||s.agent===agent)&&(s.scope!=='loopback'||s.viaProxy)).filter(s=>!q||[s.agent,s.processName,s.realDestination,s.remoteAddress,s.protocol].join('\n').toLowerCase().includes(q));
 }
 function render(holder,payload,{agent='all',query='',taskOnly=null,selected=null,focusTask=null,mode='list',destination=null,suspicious=false,alerts=null}={}){
  const allRows=rows(payload),q=query.toLowerCase();
  const activeTask=list(payload.tasks).find(task=>task.id===taskOnly);
  if(activeTask?.detailsLoaded===false){holder.innerHTML='<header><button data-network-all>返回任务列表</button><h2>'+esc(redact(activeTask.title))+'</h2></header><p>正在读取此任务的网络交互记录…</p>';return;}
  const matches=record=>{
   if(!q)return true;
   const blob=[taskNameOf(record,payload.tasks),record.agent,toolName(record,payload.tasks),parameterText(record,payload.tasks),whereOf(record),connectionLine(record),record.networkBody?.request,record.networkBody?.response].join('\n').toLowerCase();
   return blob.includes(q);
  };
  const taskPill=activeTask?'<button type="button" aria-pressed="true">这次任务</button>':(focusTask?'<button type="button" data-network-scope="'+esc(focusTask)+'">这次任务</button>':'');
  const allPill=activeTask?'<button type="button" data-network-all>全部外网访问</button>':'<button type="button" aria-pressed="true">全部外网访问</button>';
  if(activeTask){
   const taskLocals=localExchanges().filter(record=>record.agent===activeTask.agent&&activeTask.session&&(record.session===activeTask.session||record.codexThreadID===activeTask.session)&&networkBehavior(record));
   const taskExchanges=foldCapturedIntoCalls(taskLocals,allRows.filter(record=>record.networkBody?.flow&&showOnAccessPage(record)&&(record.taskID===activeTask.id||taskForVisit(record,[activeTask])?.task)));
   const covered=new Set([...taskLocals,...taskExchanges].map(record=>visitSite(record)?toolName(record,[activeTask])+'\0'+visitSite(record):'').filter(Boolean));
   const toolVisits=taskToolVisits(activeTask).filter(record=>{const site=visitSite(record);return networkBehavior(record)&&!(site&&covered.has(toolName(record,[activeTask])+'\0'+site));});
   const byID=new Map();
   for(const record of [...toolVisits,...taskLocals,...taskExchanges])if(!byID.has(record.id))byID.set(record.id,record);
   const records=[...byID.values()].sort((a,b)=>new Date(a.startedAt||a.timestamp)-new Date(b.startedAt||b.timestamp)).filter(matches).slice(0,40);
   const fullTitle=plainTask(activeTask.originalRequest||activeTask.title||'这次任务');
   const title=fullTitle.length>42?fullTitle.slice(0,42)+'…':fullTitle;
   const current=selected?records.find(record=>record.id===selected):null;
   holder.innerHTML='<div class="network-scope-switch">'+taskPill+allPill+'</div><header class="network-task-bar"><button type="button" data-task="'+esc(activeTask.id)+'">返回任务过程</button><h2>'+esc(redact(title))+'</h2><p>'+esc(redact(activeTask.agent))+'</p></header>'+statsMarkup(records)+rollupMarkup(records,payload.tasks)+(records.length?tableMarkup(records,payload.tasks,{selected:current?.id}):'<p>这次任务还没有归上的外网访问。</p>');
   return;
  }
  const locals=localExchanges().filter(record=>(agent==='all'||record.agent===agent)&&networkBehavior(record));
  const exchanges=foldCapturedIntoCalls(locals,allRows.filter(record=>record.networkBody?.flow&&showOnAccessPage(record)&&(agent==='all'||record.agent===agent)));
  const records=[...locals,...exchanges].sort((a,b)=>new Date(b.startedAt||b.timestamp)-new Date(a.startedAt||a.timestamp)).filter(matches).slice(0,400);
  const groups=destinationGroups(records,socketsFor(agent,q));
  const current=selected?records.find(record=>record.id===selected):null;
  const focus=destination!=null?groups.find(g=>g.key===destination):null;
  if(focus){holder.innerHTML='<div class="network-scope-switch">'+taskPill+allPill+'</div>'+destinationDetailMarkup(focus,payload.tasks,(alerts&&alerts.length?alerts:window.AgentReinsRisk?.buildAlerts?.(payload))||[]);return;}
  const agents=[...new Set([...records.map(r=>r.agent),...socketLedger.connections.map(s=>s.agent)].filter(Boolean))].sort();
  const agentPills='<div class="network-agent-pills" role="group" aria-label="按 Agent 筛选">'+['all',...agents].map(a=>'<button type="button" data-network-agent-pill="'+esc(a)+'" aria-pressed="'+(agent===a)+'">'+esc(a==='all'?'全部 Agent':a)+'</button>').join('')+'</div>';
  const modes='<div class="network-mode" role="group" aria-label="展示方式"><button type="button" data-network-mode="list" aria-pressed="'+(mode!=='map')+'">列表</button><button type="button" data-network-mode="map" aria-pressed="'+(mode==='map')+'">地图</button></div>';
  const search='<input id="network-search" class="network-search" value="'+esc(query)+'" placeholder="搜索目的地、进程、命令…" aria-label="搜索外网访问">';
  holder.innerHTML='<div class="network-scope-switch">'+taskPill+allPill+'</div><header class="network-task-bar"><h2>外网访问 · 按目的地</h2><p>每个 AI agent 实际连到了哪里：经审计代理的请求，加上按进程采样到的全部连接（不论是否走代理）。</p></header>'
   +'<div class="network-toolbar">'+agentPills+modes+search+'</div>'+coverageLine()+destinationStats(groups)
   +(mode==='map'?mapMarkup(groups,payload.tasks,{suspicious}):destinationsMarkup(groups,payload.tasks,{selected:current?.id}))
   +socketLedgerMarkup(agent,{collapsed:true});
 }
 // ESC-MUTATION-REGION-END
 window.AgentReinsNetwork={rows,scope,render,redact,exchangeMarkup,journeys,taskExchangeMarkup,coverage,connectionMarkup,securityMarkup,accessHop,projectLocal,setLocalTransports,setCapturedBodies,setSocketLedger,socketLedgerMarkup,socketLedgerData,socketCoverageSummary,destinationGroups,resultCell,associationCell,auditCell,mapMarkup,destinationDetailMarkup,localExchanges,rawLocalTransports,shellChildAttempts,shellChildMarkup,bypassedAudit,tlsFailed,tlsHandshakeFailed};
})();
