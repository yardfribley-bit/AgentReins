'use strict';
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{execFileSync}=require('node:child_process');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'agentreins-coverage-'));
process.env.AGENTREINS_PLAINTEXT_OUTPUT=path.join(dir,'capture.jsonl');process.env.AGENTREINS_PLAINTEXT_AGENT='fixture';
require('./node-http.cjs');
const http=require('node:http'),https=require('node:https');
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const rows=()=>fs.readFileSync(process.env.AGENTREINS_PLAINTEXT_OUTPUT,'utf8').trim().split('\n').map(JSON.parse);
const pair=p=>{const req=rows().find(r=>r.path===p);assert(req,'request '+p);const res=rows().filter(r=>r.flow===req.flow&&r.stage==='response');assert.equal(res.length,1);return [req,res[0]];};
let checks=0;const pass=s=>{checks++;console.log('PASS '+s);};
const payload=Buffer.from([0,255,254,128,65]);
function handler(req,res){const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{if(req.url==='/abort'){res.writeHead(200,{'content-length':100});res.write('partial');setTimeout(()=>res.destroy(),20);return;}res.setHeader('Set-Cookie','fixture-cookie');if(req.url==='/binary'||req.url==='/readable'){res.end(payload);return;}res.end(Buffer.concat(chunks));});}
function send(server,p,body=Buffer.from('中文'),mode='data',secure=false){return new Promise((resolve,reject)=>{const mod=secure?https:http;const req=mod.request({host:'127.0.0.1',port:server.address().port,path:p,method:'POST',...(secure?{ca:fs.readFileSync(path.join(dir,'cert.pem')),servername:'localhost'}:{})},res=>{const chunks=[];res.on('error',e=>p==='/abort'?resolve(Buffer.concat(chunks)):reject(e));if(mode==='readable')res.on('readable',()=>{let b;while((b=res.read())!==null)chunks.push(b);});else{if(mode==='encoded')res.setEncoding('latin1');res.on('data',b=>chunks.push(Buffer.isBuffer(b)?b:Buffer.from(b,'latin1')));}res.on('end',()=>resolve(Buffer.concat(chunks)));});req.on('error',reject);req.end(body);});}
(async()=>{let plain,tls;try{
 execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(dir,'key.pem'),'-out',path.join(dir,'cert.pem'),'-days','1','-subj','/CN=localhost'],{stdio:'ignore'});
 plain=http.createServer(handler);tls=https.createServer({key:fs.readFileSync(path.join(dir,'key.pem')),cert:fs.readFileSync(path.join(dir,'cert.pem'))},handler);
 await Promise.all([plain,tls].map(s=>new Promise((resolve,reject)=>{s.once('error',reject);s.listen(0,'127.0.0.1',resolve);})));
 const body=Buffer.from('加密前请求');assert.deepEqual(await send(tls,'/tls',body,'data',true),body);let [a,b]=pair('/tls');assert.equal(a.scheme,'https:');assert.equal(a.sha256,hash(body));assert.equal(b.sha256,hash(body));assert(b.complete);assert.equal(b.headers['set-cookie'],'[REDACTED]');pass('HTTPS verified certificate, request/response bytes and redaction');
 await Promise.all(Array.from({length:16},(_,i)=>send(plain,'/parallel-'+i,Buffer.from('body-'+i))));for(let i=0;i<16;i++){const [q,r]=pair('/parallel-'+i);assert.equal(r.sha256,hash(Buffer.from('body-'+i)));assert(q.complete&&r.complete);}pass('16 concurrent flows remain paired');
 const large=Buffer.alloc(1024*1024+71,97);assert.deepEqual(await send(plain,'/large',large),large);for(const r of pair('/large')){assert(r.truncated);assert.equal(r.capturedBytes,1024*1024);assert.equal(r.observedBytes,large.length);assert.equal(r.sha256,hash(large));}pass('body cap explicit; transport unchanged; full observed hash');
 await send(plain,'/abort');assert.equal(pair('/abort')[1].complete,false);pass('aborted response never marked complete');
 assert.deepEqual(await send(plain,'/readable',Buffer.alloc(0),'readable'),payload);assert.equal(pair('/readable')[1].sha256,hash(payload));pass('readable/read consumption captured');
 assert.deepEqual(await send(plain,'/binary',Buffer.alloc(0),'encoded'),payload);assert.equal(pair('/binary')[1].sha256,hash(payload));pass('setEncoding does not corrupt raw bytes');
 console.log('Completed '+checks+' groups');
 }finally{for(const s of [plain,tls])if(s){s.closeAllConnections();await new Promise(r=>s.close(r));}fs.rmSync(dir,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1;});
