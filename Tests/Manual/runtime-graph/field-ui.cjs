const fs=require('fs'),assert=require('assert'),path=require('path');const repo=path.resolve(__dirname,'../../..');const output=process.env.AGENTREINS_QA_OUTPUT||'/private/tmp/agentreins-runtime-field-ui';fs.mkdirSync(output,{recursive:true});if(!process.env.AGENTREINS_FIELD_PAYLOAD)throw Error('Set AGENTREINS_FIELD_PAYLOAD to a private actual captured JSON payload; no source fixture is substituted.');
const {chromium}=require(process.env.AGENTREINS_PLAYWRIGHT||'playwright');
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.AGENTREINS_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 const page=await browser.newPage({viewport:{width:1680,height:1180}}),errors=[],requests=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(/^https?:/.test(r.url()))requests.push(r.url())});
 await page.goto('file://'+repo+'/Sources/AgentReins/Resources/RealtimeWorkspace/index.html');
 const payload=JSON.parse(fs.readFileSync(process.env.AGENTREINS_FIELD_PAYLOAD,'utf8'));
 const task=payload.tasks[0],cs=payload.contexts.filter(c=>c.agent===task.agent&&c.session===task.session&&c.turn===task.turn);
 const calls=task.cards.filter(c=>c.id.startsWith('call:'));
 await page.evaluate(p=>window.agentreinsReceive(p),payload);
 assert((await page.locator('#heading .request').first().textContent()).includes(task.originalRequest));
 assert.equal(await page.locator('#runtime-exchange option').count(),cs.length+1);
 assert.equal(await page.locator('#timeline .timeline-row').count(),calls.length);
 assert.equal(await page.locator('[data-flow-node=closure]').count(),1);
 assert.equal(await page.locator('[data-flow-node=observation]').count(),1);
 await page.locator('#runtime-exchange').selectOption(cs[0].id);
 assert((await page.locator('#detail-title').textContent()).includes('模型'));
 const web=calls.find(c=>c.title==='WebSearch');
 await page.locator('#runtime-call').selectOption(web.id);
 assert.equal(await page.locator('[data-flow-edge=result-model]').count(),1);
 await page.locator('[data-flow-edge=result-model] .ar-edge-hit').click();
 assert((await page.locator('#detail-code').textContent()).includes('原生标识已配对'));
 assert((await page.locator('#detail-code').textContent()).includes(web.call));
 await page.screenshot({path:path.join(output,'flow.png'),fullPage:true});
 await page.locator('[data-runtime-exchange]').click();
 assert.equal(await page.locator('#runtime-exchange').inputValue(),cs[1].id);
 for(const call of calls.filter(c=>c.title==='Bash')){
  await page.locator('#runtime-call').selectOption(call.id);
  assert((await page.locator('.terminal pre').textContent()).includes(call.execution.stdout.slice(0,30)));
  assert((await page.locator('.terminal-foot').textContent()).includes('exit_code: 0'));
 }
 await page.screenshot({path:path.join(output,'command.png'),fullPage:true});
 await page.locator('[data-select=artifact]').first().click();
 assert((await page.locator('.artifact-preview').textContent()).includes('REA'));
 await page.screenshot({path:path.join(output,'delivery.png'),fullPage:true});
 // Exactly the same captured payload can refresh without changing a frozen reader.
 const before=await page.locator('#detail-code').textContent();const start=performance.now();
 const samples=[];const count=Number(process.env.AGENTREINS_REFRESH_COUNT||20),interval=Number(process.env.AGENTREINS_REFRESH_INTERVAL_MS||0);
 for(let i=0;i<count;i++){samples.push(await page.evaluate(p=>{const start=performance.now();window.agentreinsReceive(p);return performance.now()-start},payload));if(interval)await page.waitForTimeout(interval);}
 samples.sort((a,b)=>a-b);
 const elapsed=performance.now()-start;
 assert.equal(await page.locator('#detail-code').textContent(),before);
 assert(!await page.locator('#detail-updated').isVisible());
 assert.deepEqual(errors,[]);assert.deepEqual(requests,[]);
 console.log(JSON.stringify({passed:true,actualCalls:calls.length,actualRequests:cs.length,matchedToolReturn:true,artifactWithNetwork:true,refreshes:count,intervalMs:interval,elapsedMs:Math.round(elapsed),renderP50Ms:Math.round(samples[Math.floor(samples.length*.5)]),renderP95Ms:Math.round(samples[Math.min(samples.length-1,Math.floor(samples.length*.95))]),renderMaxMs:Math.round(samples.at(-1)),note:'Actual captured snapshot replay; not a currently running WorkBuddy task'},null,2));
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
