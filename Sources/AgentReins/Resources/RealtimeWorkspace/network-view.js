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
  const candidates=[...byID.values()].filter(r=>(r.kind==='network'||r.networkBody)&&['Codex','WorkBuddy'].includes(r.agent));
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
 function taskExchangeMarkup(r){
  const b=r.networkBody||{},q=r.requestObject||{},a=parseBody(b.response),model=r.serviceURL?.includes('/chat/completions');
  const remoteTool=!!r.serviceURL&&/\/(webfetch|search)(?:[/?]|$)/i.test(r.serviceURL);
  const tool=remoteTool?(r.serviceURL.includes('/webfetch')?'WebFetch':'Search'):model?'模型服务':r.tool||'外部服务';
  const text=v=>esc(redact(v));
  const sent=q.url?'网站：'+q.url+(q.prompt?'\n提取要求：'+q.prompt:''):q.query?'搜索条件：'+q.query:Array.isArray(q.messages)?'对话上下文：'+q.messages.length+' 条消息':b.request!=null?(b.request===''?'本次请求正文为空':b.requestTruncated?'已采到请求正文；当前预览截断，请查看已采内容':String(b.request)):'请求正文未采到，不能判断发送了哪些内容';
  const response=a?.title?'标题：'+a.title+(a.content?'\n'+String(a.content).slice(0,1600):''):Array.isArray(a?.results)?a.results.slice(0,10).map(x=>[x.title,x.url,x.snippet||x.description].filter(Boolean).join('\n')).join('\n\n'):b.response!=null?(b.response||'本次返回正文为空'):b.toolInstructions||'返回正文未采到';
  const association=r.taskConfidence==='native'?'来源任务与调用标识匹配':/unique exact native tool parameters/.test(r.record?.requestRecord?.resource?.basis||r.basis||'')?'工具参数唯一匹配，属于推断关联':'候选任务关联，尚未确认具体调用';
  const field=(label,value)=>'<dt>'+label+'</dt><dd>'+text(value)+'</dd>';
  const pane=(title,summary,raw,bytes,truncated,note,wire)=>'<section><h3>'+title+'</h3><p>'+note+'</p><pre class="network-readable">'+text(summary)+'</pre><small>'+(raw!=null?'已采正文 '+text(bytes??'未知')+' 字节':'正文未采到')+(truncated?' · 预览截断':'')+'</small><details><summary>查看展示内容</summary><pre>'+text(raw??'正文未采到')+'</pre></details>'+bodyDownload(wire,title.startsWith('发送')?'本机发送的 HTTP 正文':'服务返回的已采 HTTP 正文（未解析）')+'</section>';
  return '<h2>'+text(stepTitle(r))+'</h2><p>'+text(coverage(b))+'</p><h3>本机与谁通信</h3><div class="network-route"><strong>'+text(r.agent)+' → '+(r.proxy?text(r.proxy)+'（'+text(r.proxyHost||'本机代理')+':'+text(r.proxyPort||'端口未知')+'） → ':'')+text(r.serviceURL||r.host||'服务地址未采到')+'</strong></div><dl class="network-facts">'+field('实际服务地址',r.serviceURL||r.host||'未采到')+field('连接对端 IP',r.ip||'未采到')+(q.url?field('委托访问的网站',q.url):'')+'</dl>'+(remoteTool?'<p class="network-notice">本机将访问要求交给远程工具。下面展示本机与工具服务的交互；工具到网站这一段没有服务端采集数据。</p>':'')+'<div class="network-exchange-pair">'+pane('发送 → '+tool,sent,b.request,b.requestBytes,b.requestTruncated,'本机发送的内容',b.wireRequest)+pane('返回 ← '+tool,response,b.response??b.toolInstructions,b.responseBytes,b.responseTruncated,model?'已解析模型输出，字节数不代表原始 HTTP 响应':remoteTool?'工具服务返回的内容，不是网站原始 HTTP 响应':'对方返回的内容',b.wireResponse)+'</div>'+securityMarkup(r)+'<p class="network-notice">'+(b.responseComplete===true?'响应结束已确认':b.responseComplete===false?'响应完整性未确认': '未取得响应结束标记')+'。</p>'+ (b.transportError?'<p>传输错误：'+text(b.transportError)+'</p>':'')+'<details><summary>协议字段与完整性</summary><p>请求结束：'+(b.requestComplete===true?'已确认':b.requestComplete===false?'未确认':'未采到')+' · HTTP 状态：'+text(b.responseStatus??'未采到')+'</p><h4>请求头</h4><pre>'+text(b.requestHeaders!=null?JSON.stringify(b.requestHeaders,null,2):'未采到')+'</pre><h4>响应头</h4><pre>'+text(b.responseHeaders!=null?JSON.stringify(b.responseHeaders,null,2):'未采到')+'</pre></details><details><summary>数据来源与关联依据</summary><dl class="network-facts">'+field('采集来源',r.source||'未提供')+field('请求记录',r.record?.requestRecord?.id||'未提供')+field('当前记录',r.id||'未提供')+field('交互标识',b.flow||'未提供')+field('工具调用标识',r.call||'未确认')+field('关联方式',association)+field('依据',r.basis||'未提供')+'</dl></details>';
 }
 function render(holder,payload,{agent='all',query='',taskOnly=null,selected=null}={}){
  const openDetails=holder.querySelectorAll?Array.from(holder.querySelectorAll('details[open]')).map(d=>d.querySelector('summary')?.textContent):[];
  const previousKey=holder._networkDetailKey;
  const all=rows(payload),q=query.toLowerCase();
  const activeTask=list(payload.tasks).find(t=>t.id===taskOnly);
  if(activeTask?.detailsLoaded===false){holder.innerHTML='<header><button data-network-all>返回任务列表</button><h2>'+esc(redact(activeTask.title))+'</h2></header><p>正在读取此任务的网络交互记录…</p>';return;}
  if(!activeTask){
   const tasks=list(payload.tasks).filter(t=>['WorkBuddy','Codex'].includes(t.agent)&&(agent==='all'||t.agent===agent)&&(!q||String(t.title||'').toLowerCase().includes(q))&&!String(t.session||'').startsWith('workbuddy-network:'));
   const counted=tasks.map(t=>({task:t,records:all.filter(r=>r.taskID===t.id&&r.evidenceType!=='tool_intent')}));
   const visible=counted.filter(x=>x.records.length).sort((a,b)=>b.records.filter(r=>r.networkBody?.flow).length-a.records.filter(r=>r.networkBody?.flow).length);
   holder.innerHTML='<h2>选择任务，查看外网访问过程</h2><p>以下任务有已采网络证据；连接观察不等于已取得请求正文。</p>'+visible.map(({task:t,records})=>'<button class="network-round" data-network-scope="'+esc(t.id)+'"><strong>'+esc(redact(t.title||'未命名任务'))+'</strong><small>'+esc(t.agent)+'</small><span>'+records.filter(r=>r.networkBody?.flow).length+' 次数据交互 · '+records.filter(r=>!r.networkBody?.flow).length+' 条连接观察</span></button>').join('')+(visible.length?'':'<p>当前没有已关联任务的网络证据，不能判断没有外联。</p>')+'<p>'+counted.filter(x=>!x.records.length).length+' 个任务尚无已关联网络证据。</p>';
   return;
  }
  const nativeCards=list(activeTask.cards).filter(c=>c.call&&c.id==='call:'+c.call);
  // Network observations drive this view; local calls and destination intent are not network events.
  const taskEvents=all.filter(r=>r.taskID===activeTask.id&&r.evidenceType!=='tool_intent'&&scope(r.ip||r.host)!=='local');
  const connections=taskEvents.filter(r=>!r.networkBody?.flow);
  const stepRecords=taskEvents.filter(r=>r.networkBody?.flow).map(r=>{
   const c=r.call?nativeCards.find(c=>c.call===r.call):null;
   return c?{...r,tool:c.title,toolResult:c.output}:r;
  });
  stepRecords.sort((a,b)=>new Date(a.startedAt)-new Date(b.startedAt));
  const unassociated=all.filter(r=>r.agent===activeTask.agent&&r.evidenceType!=='tool_intent'&&!r.taskID);
  const unassociatedSelection=unassociated.find(r=>r.id===selected);
  const chosen=unassociatedSelection||stepRecords.find(r=>r.id===selected)||connections.find(r=>r.id===selected)||stepRecords.find(r=>r.serviceURL&&/\/(webfetch|search)/.test(r.serviceURL))||stepRecords[0]||connections[0];
  const steps=new Map();
  for(const r of stepRecords){const key=(r.taskConfidence==='native'&&r.call)||r.networkBody?.flow||r.id;if(!steps.has(key))steps.set(key,[]);steps.get(key).push(r);}
  const connectionList=connections.length?'<details open><summary>连接观察（'+connections.length+' 条采样，不计为交互轮次）</summary>'+connections.map(r=>'<button class="network-round" data-network-record="'+esc(r.id)+'" aria-pressed="'+(chosen?.id===r.id)+'"><strong>'+esc(r.host||'目标未采到')+'</strong><span>'+esc(r.state==='SYN_SENT'?'连接尝试':r.state||'状态未采到')+'</span></button>').join('')+'</details>':'';
  const taskSidebar='<aside class="network-journeys"><h2>任务访问步骤</h2>'+[...steps.values()].map((group,index)=>'<section class="network-journey"><h3>'+esc((index+1)+'. '+redact(stepTitle(group[0])))+'</h3>'+group.map((r,i)=>'<button class="network-round" data-network-record="'+esc(r.id)+'" aria-pressed="'+(chosen?.id===r.id)+'"><strong>'+esc(group.length>1?'交互 '+(i+1):r.tool||'查看交互')+'</strong><small>'+esc(r.startedAt?new Date(r.startedAt).toLocaleTimeString('zh-CN',{hour12:false}):'时间未采到')+'</small><span>'+esc(coverage(r.networkBody))+'</span></button>').join('')+'</section>').join('')+connectionList+'</aside>';
  holder.innerHTML='<header><button data-network-all>返回任务列表</button><h2>'+esc(redact(activeTask.title))+'</h2><p>'+esc(activeTask.agent)+' · 任务过程 / 外部服务与外网安全</p>'+(activeTask.detailFreshness==='ahead_of_snapshot'?'<p class="network-warning">已显示该任务更新的已采详情，任务列表仍在同步。</p>':'')+'</header><div class="network-workspace">'+taskSidebar+'<section class="network-evidence">'+(chosen?((unassociatedSelection?'<p class="network-warning">待关联证据：属于同一应用，尚未确认属于当前任务，不计入本任务步骤。</p>':'')+(chosen.networkBody?.flow?taskExchangeMarkup(chosen):connectionMarkup(chosen))):'<p>该任务尚未采到已关联的外网网络事件，无法据此判断是否访问外网或是否安全。</p><button data-network-all>查看已有网络证据的任务</button>')+'</section></div><details><summary>待关联交互（同应用，未确认属于此任务）</summary>'+journeyMarkup(unassociated,selected)+'</details>';
  const detailKey=activeTask.id+':'+(chosen?.id||'');
  if(previousKey===detailKey&&holder.querySelectorAll)for(const d of holder.querySelectorAll('details'))if(openDetails.includes(d.querySelector('summary')?.textContent))d.open=true;
  holder._networkDetailKey=detailKey;
  return;
 }
 window.AgentReinsNetwork={rows,scope,render,redact,exchangeMarkup,journeys,taskExchangeMarkup,coverage,connectionMarkup,securityMarkup};
})();
