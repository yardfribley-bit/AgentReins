'use strict';
// Explicit opt-in Node HTTP/1 adapter; not a universal TLS interceptor.
const fs=require('node:fs'), crypto=require('node:crypto');
const output=process.env.AGENTREINS_PLAINTEXT_OUTPUT;
if(output && process.env.AGENTREINS_PLAINTEXT_AGENT && !globalThis[Symbol.for('agentreins.http.probe')]) {
 globalThis[Symbol.for('agentreins.http.probe')]=true;
 const cap=1024*1024, agent=process.env.AGENTREINS_PLAINTEXT_AGENT;
 let fd;try{fd=fs.openSync(output,fs.constants.O_CREAT|fs.constants.O_APPEND|fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);}catch{}
 const redact=h=>Object.fromEntries(Object.entries(h||{}).map(([k,v])=>[k,/authorization|cookie|api.?key|token|secret/i.test(k)?'[REDACTED]':v]));
 function record(value){if(fd===undefined)return;try{fs.writeSync(fd,JSON.stringify({schemaVersion:1,source:'node-http-plaintext',agent,pid:process.pid,ppid:process.ppid,observedAt:new Date().toISOString(),...value})+'\n');}catch{try{fs.closeSync(fd);}catch{}fd=undefined;}}
 function collector(){let bytes=0, kept=0, parts=[],hash=crypto.createHash('sha256');return {add(chunk,encoding){if(chunk==null)return;try{const b=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk,typeof encoding==='string'?encoding:undefined);bytes+=b.length;hash.update(b);const n=Math.min(cap-kept,b.length);if(n>0){parts.push(Buffer.from(b.subarray(0,n)));kept+=n;}}catch{}},finish(){return {observedBytes:bytes,capturedBytes:kept,truncated:bytes>kept,bodyBase64:Buffer.concat(parts).toString('base64'),sha256:hash.digest('hex')};}};}
 for(const [name,scheme] of [['node:http','http:'],['node:https','https:']]) {
  const mod=require(name),original=mod.request;
  mod.request=function(...args){
   const req=Reflect.apply(original,this,args),flow=crypto.randomUUID(),sent=collector();
   let requestDone=false;
   function finishRequest(complete){if(requestDone)return;requestDone=true;record({flow,stage:'request',complete,scheme,host:req.getHeader('host'),method:req.method,path:req.path,headers:redact(req.getHeaders()),...sent.finish()});}
   const write=req.write,end=req.end;
   req.write=function(chunk,encoding,...rest){sent.add(chunk,encoding);return Reflect.apply(write,this,[chunk,encoding,...rest]);};
   req.end=function(chunk,encoding,...rest){if(typeof chunk!=='function')sent.add(chunk,encoding);return Reflect.apply(end,this,[chunk,encoding,...rest]);};
   req.once('finish',()=>finishRequest(true));
   req.once('close',()=>finishRequest(false));
   // Wrap emit instead of installing a data listener: preserve consumer flow control.
   req.prependOnceListener('response',res=>{
    const received=collector(),emit=res.emit,push=res.push;let done=false;
    // Capture buffers before consumer setEncoding converts them into strings.
    res.push=function(chunk,encoding){received.add(chunk,encoding);return Reflect.apply(push,this,[chunk,encoding]);};
    function finish(complete,error){if(done)return;done=true;record({flow,stage:'response',complete,scheme,host:req.getHeader('host'),path:req.path,method:req.method,status:res.statusCode,headers:redact(res.headers),error,...received.finish()});}
    res.emit=function(event,...values){if(event==='end')finish(res.complete===true);if(event==='aborted')finish(false,'aborted');if(event==='error')finish(false,'response_error');if(event==='close')finish(false,'closed_before_end');return Reflect.apply(emit,this,[event,...values]);};
   });
   // Observe errors without adding an error listener (which changes Node semantics).
   const emit=req.emit;
   req.emit=function(event,...values){if(event==='error'){finishRequest(false);record({flow,stage:'error',complete:false,error:'request_error',errorCode:typeof values[0]?.code==='string'?values[0].code:'unknown'});}return Reflect.apply(emit,this,[event,...values]);};
   return req;
  };
  mod.get=function(...args){const req=mod.request(...args);req.end();return req;};
 }
 record({stage:'ready',coverage:'node_http1_only',limitations:['fetch_undici_not_covered','http2_not_covered','native_tls_not_covered','body_limit_1MiB','synchronous_local_journal']});
}
