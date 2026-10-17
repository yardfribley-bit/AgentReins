const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'agentreins-probe-'));
process.env.AGENTREINS_PLAINTEXT_OUTPUT=path.join(dir,'capture.jsonl');
process.env.AGENTREINS_PLAINTEXT_AGENT='fixture';
require('./node-http.cjs');
const http=require('node:http');
(async()=>{
 const server=http.createServer((req,res)=>{let data='';req.on('data',b=>data+=b);req.on('end',()=>{res.write('reply:');res.end(data);});});
 try {
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const body='中文-test',response=await new Promise((resolve,reject)=>{const req=http.request({host:'127.0.0.1',port:server.address().port,method:'POST',headers:{Authorization:'fixture-secret'}},res=>{let data='';res.on('data',b=>data+=b);res.on('end',()=>resolve(data));});req.on('error',reject);req.write('中文');req.end('-test');});
 assert.equal(response,'reply:'+body);
 const rows=fs.readFileSync(process.env.AGENTREINS_PLAINTEXT_OUTPUT,'utf8').trim().split('\n').map(JSON.parse);
 const request=rows.find(r=>r.stage==='request'),reply=rows.find(r=>r.stage==='response');
 assert.equal(request.flow,reply.flow);assert.equal(request.complete,true);assert.equal(reply.complete,true);
 assert.equal(Buffer.from(request.bodyBase64,'base64').toString(),body);
 assert.equal(Buffer.from(reply.bodyBase64,'base64').toString(),response);
 assert.equal(request.sha256,crypto.createHash('sha256').update(body).digest('hex'));
 assert.equal(request.headers.authorization,'[REDACTED]');
 console.log('PASS real loopback HTTP: chunked request/response, exact bytes/hash, pairing, completion, header redaction');
 } finally {server.close();fs.rmSync(dir,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
