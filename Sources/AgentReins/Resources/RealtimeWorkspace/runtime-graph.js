'use strict';
/* A runtime diagram is a projection of evidence, never an invented execution plan. */
((root)=>{
 const arr=v=>Array.isArray(v)?v:[],cut=(s,n=32)=>{const a=Array.from(String(s??''));return a.slice(0,n).join('')+(a.length>n?'…':'');};
 const nativeCalls=t=>arr(t?.cards).filter(c=>c.call&&c.id?.startsWith('call:'));
 function instructionCalls(exchange){
  if(!exchange?.toolInstructions)return [];
  try{
   const result=JSON.parse(exchange.toolInstructions),calls=arr(result.tool_calls||result);
   return calls.map(c=>({id:c.id||c.call_id,name:c.name||c.function?.name,arguments:c.arguments||c.function?.arguments})).filter(c=>c.id);
  }catch{return [];}
 }
 function externalServices(task){return arr(task?.cards).flatMap(c=>{
  const command=String(c.execution?.command||''),match=command.match(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*(?:[^\s]*\/)?git\s+(push|fetch|pull|clone|ls-remote)\b/);
  const requested=c.source==='tool-intent'&&c.resource?.requestedURL,domain=c.resource?.domain||String(c.execution?.stderr||c.execution?.stdout||'').match(/(?:^|\n)To\s+https?:\/\/([^/\s]+)/)?.[1];
  if(!match&&!requested)return [];
  if(!match&&!/^(?:github\.com|api\.github\.com|gitlab\.com|gitee\.com)$/.test(domain||''))return [];
  const service=/github\.com$/.test(domain||'')?'GitHub':/gitlab\.com$/.test(domain||'')?'GitLab':/gitee\.com$/.test(domain||'')?'Gitee':'Git 远端服务';
  const action=match?({push:'推送代码',fetch:'读取远端变更',pull:'拉取代码',clone:'克隆仓库','ls-remote':'查询远端分支'})[match[1]]:'工具声明的服务目标';
  return [{...c,title:service+' · '+action}];
 });}
 function returned(c){return ['returned','failed'].includes(c?.phase);}
 function build({task:t,contexts=[],processes=[],artifacts=[],exchangeID=null,callID=null}){
  const nodes=[],edges=[],objects=[],calls=nativeCalls(t),exchanges=arr(contexts).slice().sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  const instructionIndex=new Map(exchanges.map(e=>[e.id,instructionCalls(e)])),allIssuedIDs=new Set([...instructionIndex.values()].flat().map(i=>i.id));
  const full=exchanges.filter(c=>c.structured),choices=full.length?full:exchanges;
  const nativeCurrent=calls.find(c=>c.id===t?.currentCardID)||(['completed','stopped','failed','cancelled'].includes(t?.lifecycleStatus)?calls.at(-1):null);
  const origin=!exchangeID&&nativeCurrent?choices.find(c=>(instructionIndex.get(c.id)||[]).some(i=>i.id===nativeCurrent.call)):null;
  const exchange=choices.find(c=>c.id===exchangeID)||origin||choices.at(-1)||null;
  const instructions=instructionIndex.get(exchange?.id)||[],issuedIDs=new Set(instructions.map(c=>c.id));
  const issued=calls.filter(c=>issuedIDs.has(c.call));
  // Missing HTTPS capture must not make a native call disappear. It stays visible
  // in a separate lane with an explicit unconfirmed model relationship.
  const unlinked=calls.filter(c=>!allIssuedIDs.has(c.call));
  const relevant=exchange?(issued.length?issued:!exchange.responseID?unlinked:[]):calls;
  const requested=calls.find(c=>c.id===callID);
  const liveCall=t?.lifecycleStatus==='running'?calls.find(c=>c.id===t.currentCardID&&['running','waiting'].includes(c.phase)):null;
  const currentCall=!exchangeID&&!callID?calls.find(c=>c.id===t?.currentCardID)||(['completed','stopped','failed','cancelled'].includes(t?.lifecycleStatus)?calls.at(-1):null):null;
  const chosen=requested||liveCall||currentCall||relevant.find(c=>['running','waiting'].includes(c.phase))||relevant.at(-1)||unlinked.at(-1)||calls.at(-1)||null;
  const matched=!!chosen&&issuedIDs.has(chosen.call);
  const next=chosen&&returned(chosen)?exchanges.find(e=>e.id!==exchange?.id&&(!exchange||new Date(e.timestamp)>=new Date(exchange.timestamp))&&arr(e.blocks).some(b=>b.role==='tool'&&b.callID===chosen.call&&arr(b.toolEvidenceIDs).some(id=>arr(chosen.eventIDs).includes(id)))):null;
  function node(key,x,y,w,h,title,tag,subtitle,tone,type,data,phase='recorded'){
   nodes.push({key,x,y,w,h,title,tag,subtitle,tone,phase,revision:JSON.stringify([data?.id,phase,data?.eventIDs,data?.responseID,data?.output,data?.execution?.chunks?.length,data?.status])});
   objects.push({key,type,data});return key;
  }
  function edge(key,from,to,path,label,x,y,type,data,confirmed=true,basis='',eventIDs=[]){
   edges.push({key,from,to,path,label,x,y,independent:!confirmed,revision:JSON.stringify(eventIDs)});
   objects.push({key,type:'transfer',data:{title:label,from,to,basis,confirmed,eventIDs,targetType:type,target:data}});
  }
  const hasOriginal=!!t?.originalRequest,attachments=arr(t?.inputAttachments),hasInput=hasOriginal||attachments.length>0;
  if(t)node('user',355,22,240,84,attachments.length&&!hasOriginal?'原始附件输入':'我的需求',hasOriginal?'用户原话':attachments.length?'用户附件已采集':'需求原文缺失',hasOriginal?cut(t.latestUserInput?.content||t.originalRequest,27):attachments.length?'本次没有附带文字': '后续活动不能代替你的原话','input','user',{id:t.requestEventID,content:t.originalRequest,currentContent:t.latestUserInput?.content,inputs:arr(t.userInputs),attachments,source:t.requestSource,eventIDs:arr(t.userInputs).flatMap(i=>arr(i.eventIDs)).length?arr(t.userInputs).flatMap(i=>arr(i.eventIDs)):t.requestEventID?[t.requestEventID]:attachments.flatMap(a=>arr(a.eventIDs))},hasInput?'returned':'missing');
  if(exchange){
   node('context',720,136,250,103,'本轮上下文',exchange.structured?'实际模型请求':'本地消息片段',`${arr(exchange.blocks).length} 个内容块 · ${exchange.characters||0} 字符`,'context','context',exchange,exchange.truncated?'partial':'recorded');
   node('model',355,164,240,112,t?.model||'大模型',`请求 ${choices.indexOf(exchange)+1} / ${choices.length}`,exchange.responseID?(instructions.length?`已返回 ${instructions.length} 条工具指令`:'模型响应已采集'):'模型响应尚未配对','model','model',{contexts:[exchange],cards:[]},exchange.responseID?'returned':'running');
   edge('context-model','context','model','M720 181 C670 181 650 210 595 210','送入模型',622,185,'context',exchange,true,'来源记录中的同一次模型请求',[exchange.id]);
   const originals=arr(exchange.blocks).filter(b=>b.role==='user');
   const containsOriginal=hasOriginal&&originals.some(b=>b.containsCurrentInput||String(b.content||'').includes(t.originalRequest));
   if(containsOriginal)edge('user-context','user','context','M595 64 C685 64 650 156 720 156','原话在请求中',622,99,'context',exchange,true,'请求中的 user 内容块包含本轮已采用户原文',[t.requestEventID,exchange.id]);
  }else if(t){
   const models=arr(t.cards).filter(c=>c.kind==='model'&&c.detailType!=='user');
   if(models.length)node('model',355,164,240,112,t.model||'大模型','本地模型活动','完整请求与响应关系尚未取得','model','model',{contexts:[],cards:models},'partial');
  }
  const materials=arr(t?.cards).filter(c=>['environment','context'].includes(c.detailType||c.kind)&&c.title!=='codex.attachment');
  if(materials.length)node('environment',35,24,235,104,'材料与运行环境','实际上下文记录',`${materials.length} 项材料 / 环境证据`,'input','group',{stage:'environment',cards:materials},'recorded');
  const memories=arr(t?.cards).filter(c=>(c.detailType||c.kind)==='memory');
  if(memories.length)node('memory',35,440,235,97,'记忆访问','已采记忆记录',cut(memories.at(-1).summary,27),'context','group',{stage:'memory',cards:memories},'recorded');
  const plans=arr(t?.cards).filter(c=>['plan','planning'].includes(c.detailType||c.kind));
  if(plans.length)node('plan',35,328,235,94,'计划与调度','已采调度记录',`${plans.length} 条计划 / 工具指令记录`,'plan','group',{stage:'plan',cards:plans},plans.at(-1).phase);
  const approvals=arr(t?.cards).filter(c=>c.phase==='waiting'||c.detailType==='approval');
  if(approvals.length)node('approval',35,150,235,106,'等待你确认','实际确认点',cut(approvals.at(-1).summary,27),'approval','group',{stage:'approval',cards:approvals},'waiting');
  if(chosen){
   node('card:'+chosen.id,355,371,240,112,chosen.title,(chosen.execution?.status==='requested'?'调用已提交':'工具执行')+' · '+(calls.indexOf(chosen)+1),cut(chosen.execution?.command||chosen.summary,29),'action',chosen.detailType||chosen.kind,chosen,chosen.execution?.status==='requested'?'pending':chosen.phase);
   if(nodes.some(n=>n.key==='model'))edge('call:'+chosen.id,'model','card:'+chosen.id,'M475 276 L475 371',matched?'模型下发指令':'本轮调用 · 请求未关联',matched?490:480,326,chosen.detailType||chosen.kind,chosen,matched,matched?'模型响应 tool_calls.id 与原生工具 call ID 完全相同':'本轮原生调用已采到，但没有模型响应与调用 ID 的配对证据',[exchange?.responseID,...arr(chosen.eventIDs)].filter(Boolean));
   if(returned(chosen)){
    node('tool-result',720,372,250,111,'工具返回',chosen.phase==='failed'?'执行失败':chosen.phase==='cancelled'?'已取消':'实际返回已采集',chosen.execution?.exitCode!=null?`退出码 ${chosen.execution.exitCode} · ${cut(chosen.execution.stdout||chosen.execution.stderr||chosen.summary,21)}`:cut(chosen.output,29),'result','tool-result',chosen,chosen.phase);
    edge('tool-return','card:'+chosen.id,'tool-result','M595 425 L720 425','调用结果',622,412,'tool-result',chosen,true,'同 Agent、会话、轮次与调用 ID 的原生返回',arr(chosen.eventIDs));
    if(next){
     node('next-context',720,562,250,102,'结果进入下一次请求','工具结果回流',`匹配调用 ID · ${arr(next.blocks).length} 个内容块`,'context','context',next,'returned');
     edge('result-context','tool-result','next-context','M845 483 L845 562','回到模型上下文',856,532,'context',next,true,'下一次实际请求的 tool 块包含相同 call ID，且关联到此调用返回证据',arr(next.blocks).flatMap(b=>b.callID===chosen.call?arr(b.toolEvidenceIDs):[]));
    }
   }
  }
  for(const o of objects.filter(o=>o.type==='transfer')){
   if(o.key==='result-context'&&next&&chosen){o.data.preferredBlockID=arr(next.blocks).find(b=>b.role==='tool'&&b.callID===chosen.call)?.id;o.data.sourceContent=chosen.output;o.data.sourceLabel='工具实际返回';}
   if(o.key==='call:'+chosen?.id&&matched){const instruction=instructions.find(i=>i.id===chosen.call);o.data.sourceContent=instruction?.arguments;o.data.sourceLabel='模型下发的实际参数';}
   if(o.key==='user-context')o.data.preferredBlockID=arr(exchange?.blocks).find(b=>b.role==='user'&&String(b.content||'').includes(t.originalRequest))?.id;
  }
  const terminal=['completed','stopped','failed','cancelled'].includes(t?.lifecycleStatus),verified=arr(t?.cards).filter(c=>['verify','verification'].includes(c.detailType||c.kind));
  if(terminal||verified.length){
   node('closure',355,594,240,104,terminal?'任务收尾':'验证步骤',t?.lifecycleStatus==='completed'?'已确认交付':t?.lifecycleStatus==='stopped'?'已停止 · 交付未确认':t?.lifecycleStatus==='failed'?'任务失败':t?.lifecycleStatus==='cancelled'?'任务已取消':'已采验证记录',cut(t?.statusBasis||verified.at(-1)?.summary,30),t?.lifecycleStatus==='failed'?'failure':'closure',terminal?'agent':'group',terminal?t:{stage:'verify',cards:verified},t?.lifecycleStatus==='failed'?'failed':t?.lifecycleStatus==='stopped'?'stopped':terminal?'returned':'recorded');
  }
  if(artifacts.length)node('artifact',720,next?718:594,250,104,'实际交付物',`${artifacts.length} 项产物`,cut(artifacts.map(a=>a.name).join('、'),27),'artifact','artifact',{artifacts},artifacts.every(a=>a.exists)?'returned':'partial');
  const resourceCards=arr(t?.cards).filter(c=>['files','web','network'].includes(c.detailType||c.kind));
  const ps=arr(processes).filter(p=>!t||p.agent===t.agent);
  if(resourceCards.length||ps.length)node('observation',35,558,235,140,'执行现场','独立观察与资源证据',`${ps.filter(p=>p.active!==false).length} 个进程 · ${resourceCards.length} 项文件 / 网络记录`,'observe','observation',{cards:resourceCards,processes:ps},'recorded');
  if(!t)node('agent',355,230,240,112,'等待用户任务','采集仍在运行','无归属记录保留在采集现场','observe','agent',null,'recorded');
  let currentKey=terminal?'closure':t?.currentCardID&&nodes.some(n=>n.key==='card:'+t.currentCardID)?'card:'+t.currentCardID:t?.lifecycleStatus==='awaiting_confirmation'&&approvals.length?'approval':!exchange?.responseID&&exchange?'model':chosen&&!returned(chosen)?'card:'+chosen.id:null;
  return {nodes,edges,objects,currentKey,width:1000,height:Math.max(740,...nodes.map(n=>n.y+n.h+20)),exchange,choices,calls,relevant,chosen,next,unlinked,instructions};
 }

 // The approved architecture stays visible. A visible scaffold is not capture evidence:
 // missing modules and unpaired paths remain explicitly grey/dashed.
 function buildArchitecture(input){
  const g=build(input),t=input.task,cards=arr(t?.cards),exchange=g.exchange,chosen=g.chosen;
  const source=new Map(g.objects.map(o=>[o.key,o]));
  const nodes=[],objects=[],edges=[];
  const kind=c=>c.detailType||c.kind;
  const materials=cards.filter(c=>['environment','context'].includes(kind(c))&&c.title!=='codex.attachment');
  const plans=cards.filter(c=>['plan','planning'].includes(kind(c)));
  const memories=cards.filter(c=>kind(c)==='memory');
  const files=cards.filter(c=>['file','files'].includes(kind(c)));
  const network=cards.filter(c=>['web','network'].includes(kind(c))||c.resource?.evidenceType==='http');
  const observations=arr(input.networkObservations);
  const apiCalls=network.filter(c=>c.resource?.method&&c.resource?.url&&c.resource?.evidenceType!=='tool_intent');
  const services=cards.filter(c=>['mcp','skill'].includes(kind(c)));
  const commands=cards.filter(c=>kind(c)==='command'||c.execution);
  const databases=cards.filter(c=>kind(c)==='database'||c.resource?.kind==='database');
  const external=externalServices(t).concat(cards.filter(c=>kind(c)==='external'||c.resource?.kind==='external'));
  const verified=cards.filter(c=>['verify','verification'].includes(kind(c)));
  const replyCards=cards.filter(c=>kind(c)==='model'&&c.phase==='returned'&&!c.call);
  const replyText=t?.nativeEndMessage||exchange?.response||replyCards.at(-1)?.output;
  const inputData=source.get('user')?.data||{content:t?.originalRequest,attachments:arr(t?.inputAttachments)};
  const haveInput=!!inputData.content||inputData.attachments?.length>0;
  const terminal=['completed','stopped','failed','cancelled'].includes(t?.lifecycleStatus);
  const missing='本轮未采到记录';
  function add(key,x,y,w,h,title,tag,subtitle,tone,type,data,phase='missing',inner=[],shape=''){
   nodes.push({key,x,y,w,h,title,tag,subtitle,tone,type,phase,inner,shape,alias:key==='action'&&chosen?'card:'+chosen.id:null,
    revision:JSON.stringify([data?.id,phase,data?.eventIDs,data?.responseID,data?.execution?.chunks?.length])});
   objects.push({key,type,data});
  }
  add('user',345,30,280,104,'用户输入 / 原始任务',haveInput?arr(t?.userInputs).length>1?`${arr(t.userInputs).length} 条用户输入 · 点击展开`:'任务起点':'原始输入缺失',haveInput?cut(inputData.currentContent||inputData.content||'本次输入为附件，没有附带文字',40):'后续活动不能代替用户原话','input','user',inputData,haveInput?'returned':'missing');
  add('perception',345,180,280,120,'感知 / 输入内容','输入',`${arr(t?.inputAttachments).length} 个附件 · ${materials.length} 项环境材料`,'input','input-overview',{materials,attachments:arr(t?.inputAttachments),content:t?.originalRequest,inputs:arr(t?.userInputs)},haveInput||materials.length?'recorded':'missing');
  add('model',345,395,280,160,'推理引擎 / 大语言模型',exchange?`推理 · 第 ${g.choices.indexOf(exchange)+1} 次模型往返`:'模型往返未采到',t?.model||'模型身份未提供','model','model',{contexts:exchange?[exchange]:[],cards:cards.filter(c=>kind(c)==='model')},exchange?.responseID?'returned':exchange?'running':'missing',[
   ['本次模型返回',exchange?.response?cut(exchange.response,32):'响应尚未配对'],['下发指令',g.instructions.length?g.instructions.map(i=>i.name||i.id).join(' · '):'本次未采到工具指令']]);
  add('context',735,240,245,283,'上下文与记忆','记忆 / 上下文',exchange?`${arr(exchange.blocks).length} 个内容块 · ${exchange.characters||0} 字符`:'实际请求上下文未采到','context','context-memory',{exchange,memories},exchange||memories.length?'recorded':'missing',[
   ['短期：本次请求上下文',exchange?`${arr(exchange.blocks).length} 块 · 点击核对内容`:'本轮实际请求未采到'],['长期记忆访问',memories.length?`${memories.length} 项真实访问`:'本轮尚未采到']]);
  add('plan',90,625,245,180,'规划与调度','规划',plans.length?`${plans.length} 项实际计划记录`:'没有计划记录，不补写模板','plan','group',{stage:'plan',cards:plans},plans.length?'recorded':'missing',plans.slice(-3).map(c=>[c.title,cut(c.output||c.input||c.summary,27)]));
  const branch=g.instructions.length?'已下发工具指令':exchange?.responseID?'响应已收到 · 需核对回答':'等待模型实际返回';
  add('direct',382,603,205,135,'能否直接回答？','判断',branch,'decision','branch',{exchange,instructions:g.instructions,chosen},exchange?.responseID?'recorded':'missing',[],'diamond');
  add('reply',755,630,210,92,'回复 / 输出','模型输出',replyText?cut(replyText,25):'本轮返回未采到','input','reply',{exchange,cards:replyCards,replyText},replyText?'recorded':'missing');
  add('action',345,837,280,175,'工具执行 / 行动层',chosen?`执行 · ${chosen.title}`:'执行',chosen?cut(chosen.execution?.command||chosen.summary,38):'本轮原生工具调用未采到','action',chosen?(chosen.detailType||chosen.kind):'group',chosen||{stage:'command',cards:[]},chosen?(chosen.execution?.status==='requested'?'pending':chosen.phase):'missing',chosen?[[chosen.tag||chosen.phase,cut(chosen.output||chosen.execution?.stdout||'点击查看参数与完整执行过程',35)]]:[]);
  const labels={running:'进行中',stopped:'已停止 · 交付未确认',completed:'已完成',failed:'失败',cancelled:'已取消',observed:'状态待确认',awaiting_confirmation:'等待执行'};
  add('closure',764,840,200,145,'目标完成？','任务状态',labels[t?.lifecycleStatus]||'状态待确认','decision','agent',t||{},t?.lifecycleStatus==='failed'?'failed':t?.lifecycleStatus==='stopped'?'stopped':t?.lifecycleStatus==='completed'?'returned':'recorded',[],'diamond');
  [['mcp','MCP / Skill',services,'mcp'],['api','API / 网络',network,'network'],['code','代码 / 命令',commands,'command'],['database','数据库',databases,'database'],['files','文件系统',files,'files'],['external','外部服务',external,'external']].forEach(([key,title,items,stage],i)=>
   add(key,143+i*139,1090,118,70,title,key==='api'&&(items.length||observations.length)?`${apiCalls.length} HTTP · ${network.length} 关联 / ${observations.length} 独立`:items.length?`${items.length} 项真实记录`:missing,'','resource','group',{stage,cards:items,observations:key==='api'?observations:[]},items.length||key==='api'&&observations.length?'recorded':'missing',[],'resource'));
  const ps=arr(input.processes).filter(p=>!t||p.agent===t.agent);
  add('observation',145,1240,812,88,'可观测层','观测','调用关联 · 进程 · 文件 · 网络 · 终端输出 · 延迟与用量','observe','observation',{cards:[...files,...network],processes:ps,coverage:arr(t?.coverage)},ps.length||files.length||network.length?'recorded':'missing',[],'observe');
  function route(key,from,to,path,label,x,y,confirmed=false,basis='',target=null,sourceContent=null,eventIDs=[]){
   const proof=confirmed&&arr(eventIDs).filter(Boolean).length>0;
   edges.push({key,from,to,path,label,x,y,independent:!proof,revision:proof?JSON.stringify(eventIDs):'[]'});
   objects.push({key,type:'transfer',data:{title:label||`${from} → ${to}`,from,to,confirmed:proof,basis:proof?basis:'仅为架构路径；未取得可配对的本轮证据',eventIDs:proof?eventIDs:[],targetType:'architecture-path',target,sourceContent}});
  }
  const original=source.get('user-context')?.data,call=source.get('call:'+chosen?.id)?.data,back=source.get('result-context')?.data;
  route('input-perception','user','perception','M485 134L485 180','输入',502,161,haveInput,'同一任务的实际输入',inputData,inputData.content,arr(inputData.eventIDs));
  route('perception-model','perception','model','M485 300L485 395','材料与上下文',502,350,!!original,'实际请求中的 user 块包含本轮原话',exchange,t?.originalRequest,original?.eventIDs);
  route('context-model','context','model','M735 370C682 370 700 438 625 438','实际请求',643,391,!!exchange,'同一次实际模型请求',exchange,null,exchange?[exchange.id]:[]);
  route('model-context','model','context','M625 505C686 505 675 481 735 481','上下文更新',653,528,!!back,back?.basis,g.next,chosen?.output,back?.eventIDs);
  route('model-direct','model','direct','M485 555L485 603','',0,0,!!exchange?.responseID,'模型响应记录',exchange,exchange?.response,exchange?.responseID?[exchange.responseID]:[]);
  route('direct-reply','direct','reply','M587 670L755 670','是',657,654,!!exchange?.responseID&&g.instructions.length===0,'实际模型返回没有下发工具调用',exchange,exchange?.response,exchange?.responseID?[exchange.responseID]:[]);
  route('direct-plan','direct','plan','M382 670L335 670','否',348,654);
  route('plan-action','plan','action','M213 805C213 885 296 913 345 913','调度',275,865);
  route('direct-action','direct','action','M485 738L485 837','下发指令',502,790,!!call?.confirmed,call?.basis,chosen,call?.sourceContent,call?.eventIDs);
  route('result-model','action','model','M625 927C706 927 695 471 625 471','结果返回模型',650,751,!!back,back?.basis,g.next,chosen?.output,back?.eventIDs);
  route('action-goal','action','closure','M625 939L764 939','结果',683,922,!!chosen&&returned(chosen),'原生调用返回与同一任务状态分开核对',chosen,chosen?.output,arr(chosen?.eventIDs));
  route('goal-model','closure','model','M864 840C864 740 705 658 625 534','继续',722,788,!!back,back?.basis,g.next,chosen?.output,back?.eventIDs);
  route('goal-reply','closure','reply','M864 840L864 722','交付',905,780,t?.lifecycleStatus==='completed'&&!!t?.nativeTerminalEventID,'明确交付证据与原生结束分开核对',t,t?.nativeEndMessage,[t?.nativeTerminalEventID,...cards.filter(c=>c.title==='present_files').flatMap(c=>arr(c.eventIDs))].filter(Boolean));
  ['mcp','api','code','database','files','external'].forEach((key,i)=>{const target=objects.find(o=>o.key===key)?.data;
   const same=!!chosen&&arr(target?.cards).some(c=>c.id===chosen.id||arr(c.eventIDs).some(id=>arr(chosen.eventIDs).includes(id)));
   route('resource-'+key,'action',key,`M485 1012C485 1050 ${202+i*139} 1037 ${202+i*139} 1090`,'',0,0,same,'同调用记录或共同原始证据 ID',target,null,same?arr(chosen.eventIDs):[]);
  });
  route('observability','observation','action','M145 1284C116 1284 130 1040 345 990','观测',152,1198);
  return {...g,nodes,edges,objects,width:1000,height:1340,currentKey:terminal?'closure':g.currentKey?.startsWith('card:')?'action':g.currentKey==='model'?'model':null,architecture:true};
 }
 // Preserve the original evidence relation view independently of the fixed architecture.
 function buildRelations(input){
  const g=build(input),t=input.task,nodes=g.nodes.filter(n=>!n.key.startsWith('card:')&&n.key!=='approval'),edges=g.edges.filter(e=>nodes.some(n=>n.key===e.from)&&nodes.some(n=>n.key===e.to)),objects=g.objects.filter(o=>nodes.some(n=>n.key===o.key)||edges.some(e=>e.key===o.key));
  let hub=nodes.find(n=>n.key==='model'||n.key==='agent');
  if(!hub){hub={key:'agent',w:250,h:140,title:t?.agent||'Agent',tag:'原生任务与调用',subtitle:'完整模型请求关系尚未取得',tone:'model',phase:'recorded'};nodes.push(hub);objects.push({key:'agent',type:'agent',data:t});}
  hub.shape='hub';
  const selected=g.chosen,shown=input.overview?(selected?[selected]:g.calls.slice(-1)):g.calls.slice(-6);if(selected&&!shown.some(c=>c.id===selected.id)){shown.pop();shown.push(selected);}shown.sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp));
  function add(key,title,tag,subtitle,tone,type,data,phase='recorded'){nodes.push({key,w:230,h:112,title,tag,subtitle,tone,phase,revision:JSON.stringify([data?.id,data?.eventIDs,phase,data?.output])});objects.push({key,type,data});}
  function relation(key,from,to,label,targetType,target,confirmed,basis,eventIDs=[],sourceContent=null){edges.push({key,from,to,label,independent:!confirmed,revision:JSON.stringify(eventIDs)});objects.push({key,type:'transfer',data:{title:label,from,to,targetType,target,confirmed,basis,eventIDs,sourceContent}});}
  for(const c of shown){const key='card:'+c.id;add(key,`${c.title} · #${g.calls.indexOf(c)+1}`,c.tag||c.phase,cut(c.execution?.command||c.input||c.summary,40),'action',c.detailType||c.kind,c,c.execution?.status==='requested'?'pending':c.phase);
   const issuer=g.choices.find(e=>instructionCalls(e).some(i=>i.id===c.call)),instruction=issuer&&instructionCalls(issuer).find(i=>i.id===c.call);
   relation('call:'+c.id,hub.key,key,issuer?`请求 ${g.choices.indexOf(issuer)+1} 下发`:'原生调用 · 模型关系未确认',c.detailType||c.kind,c,!!issuer,issuer?'模型响应指令 ID 与原生调用 ID 相同':'已采原生调用；没有模型指令配对证据',[issuer?.responseID,...arr(c.eventIDs)].filter(Boolean),instruction?.arguments);
  }
  const hidden=g.calls.filter(c=>!shown.some(s=>s.id===c.id));
  if(hidden.length){add('other-calls',`其余 ${hidden.length} 次工具调用`,'展开完整调用列表','时间线与下拉框保留全部调用','action','group',{stage:'mcp',cards:hidden});relation('other-call-observations',hub.key,'other-calls','同轮调用记录','group',{stage:'mcp',cards:hidden},false,'折叠的原生调用集合，不推断某次模型下发关系');}
  for(const [key,kind,title] of [['files','files','文件'],['network','network','网络资源']]){const items=arr(t?.cards).filter(c=>key==='files'?['files','file'].includes(c.detailType||c.kind):['web','network'].includes(c.detailType||c.kind));if(!items.length)continue;
   const recent=items.at(-1),resource=recent.resource;add(key,`${title} · ${cut(resource?.domain||resource?.path?.split('/').at(-1)||resource?.remoteIP||recent.title,20)}`,`${items.length} 项实际记录`,cut(resource?.url||resource?.path||recent.summary,40),key==='files'?'action':'context','group',{stage:kind,cards:items});
   const origin=shown.find(c=>arr(c.eventIDs).some(id=>arr(recent.eventIDs).includes(id)));
   relation('resource-'+key,origin?'card:'+origin.id:hub.key,key,origin?'同一调用的资源':'独立资源观察','group',{stage:kind,cards:items},!!origin,origin?'资源与工具记录含相同原始证据 ID':'同轮观察已保留，不能据此推断具体调用关系',origin?arr(recent.eventIDs):[]);
  }
  const observations=arr(input.networkObservations);
  if(observations.length){add('network-observations',`独立网络观察 · ${observations.length} 条`,'未确认任务归属','可点开原始连接与代理目标','context','group',{stage:'network',cards:[],observations});relation('independent-network-observations',hub.key,'network-observations','同Agent独立观察','group',{stage:'network',cards:[],observations},false,'采到系统连接；没有据此推断它属于当前任务');}
  if(selected&&nodes.some(n=>n.key==='tool-result'))relation('tool-return','card:'+selected.id,'tool-result','实际返回','tool-result',selected,true,'相同原生调用 ID 的返回',arr(selected.eventIDs));
  // Context, plan and observations keep source objects; structural spokes stay dashed.
  for(const n of nodes)if(n.key!==hub.key&&!edges.some(e=>e.from===n.key||e.to===n.key))relation('observed-'+n.key,hub.key,n.key,'同轮记录',objects.find(o=>o.key===n.key)?.type,objects.find(o=>o.key===n.key)?.data,false,'记录属于此原生轮次；未取得进一步因果关系');
  return {...g,nodes,edges,objects,currentKey:g.currentKey,relationships:true,shownCallCount:shown.length,hiddenCallCount:hidden.length};
 }
 const api={build,buildArchitecture,buildRelations,nativeCalls,instructionCalls,externalServices};root.AgentReinsRuntimeGraph=api;
 if(typeof module!=='undefined')module.exports=api;
})(typeof window==='undefined'?globalThis:window);
