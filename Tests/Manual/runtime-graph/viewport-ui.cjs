const fs=require('fs'),path=require('path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.AGENTREINS_PLAYWRIGHT||'playwright');
const root=process.env.AGENTREINS_CODEX_INPUT_FIELD_DIR;if(!root)throw Error('Actual field payload required');
(async()=>{const payload=JSON.parse(fs.readFileSync(path.join(root,'actual-codex-input-payload.json'),'utf8'));
const browser=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
const page=await browser.newPage({viewport:{width:1366,height:768}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
await page.goto('file://'+path.resolve(__dirname,'../../../Sources/AgentReins/Resources/RealtimeWorkspace/index.html'));
await page.evaluate(p=>window.agentreinsReceive(p),payload);
assert.equal(await page.locator('#graph-scale').textContent(),'85%');assert(await page.locator('[data-zoom=readable]').getAttribute('aria-pressed')==='true');assert(await page.locator('#graph-nav [data-nav-node]').count()===16);
await page.locator('#toggle-details').click();assert(!(await page.locator('#detail').isVisible()));await page.locator('#toggle-details').click();assert(await page.locator('#detail').isVisible());
await page.locator('details.canvas-tools').evaluate(el=>{el.open=true});
for(const [width,height] of [[1366,768],[1680,900],[1024,768]]){
 await page.setViewportSize({width,height});
 await page.locator('[data-zoom=fit]').click();assert(parseInt(await page.locator('#graph-scale').textContent())>=35,'Overview uses compact layout instead of a tiny portrait thumbnail');
 const positions=await page.evaluate(()=>{const viewport=document.getElementById('graph-viewport').getBoundingClientRect();return {pageHeight:document.documentElement.scrollHeight,windowHeight:innerHeight,viewport,nodes:[...document.querySelectorAll('[data-flow-node]')].map(n=>({key:n.dataset.flowNode,rect:n.getBoundingClientRect().toJSON()}))};});
 assert(positions.pageHeight<=positions.windowHeight+1,'Desktop page fits viewport');
 assert.equal(positions.nodes.length,16);assert(await page.evaluate(()=>[...document.querySelectorAll('#graph .ar-node strong')].every(e=>e.scrollHeight<=e.clientHeight+1)),'Overview title is not clipped');
 const box=await page.locator('#graph-viewport').boundingBox();
 for(const {key,rect} of positions.nodes){assert(rect.top>=box.y-1&&rect.bottom<=box.y+box.height+1,'Node fully visible: '+key);assert(rect.left>=box.x-1&&rect.right<=box.x+box.width+1,'Node width visible: '+key);}
 await page.locator('[data-flow-node=user]').click();assert((await page.locator('#detail-code').textContent()).includes('修复 这个问题'));
 await page.screenshot({path:path.join(root,`fit-${width}x${height}.png`),fullPage:true});
}
await page.locator('[data-zoom=actual]').click();assert.equal(await page.locator('#graph-scale').textContent(),'100%');
assert(await page.evaluate(()=>document.getElementById('graph-viewport').scrollHeight>document.getElementById('graph-viewport').clientHeight));
await page.locator('[data-zoom=out]').click();assert.equal(await page.locator('#graph-scale').textContent(),'83%');
await page.locator('[data-zoom=in]').click();assert.equal(await page.locator('#graph-scale').textContent(),'100%');
await page.locator('[data-zoom=fit]').click();
const detail=await page.locator('#detail-code').textContent();await page.locator('[data-graph-mode=spider]').click();assert.equal(await page.locator('#detail-code').textContent(),detail);
await page.screenshot({path:path.join(root,'fit-spider.png'),fullPage:true});
await page.locator('[data-zoom=readable]').click();assert.equal(await page.locator('#graph-scale').textContent(),'85%');await page.screenshot({path:path.join(root,'readable-spider.png'),fullPage:true});
await page.setViewportSize({width:390,height:844});await page.locator('[data-mobile-node=user]').click();assert((await page.locator('#detail-code').textContent()).includes('修复 这个问题'));
assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert.deepEqual(errors,[]);
console.log(JSON.stringify({passed:true,desktopViewports:3,all16NodesFit:true,zoomOut:true,zoomIn:true,actualSize:true,independentInspector:true,mobile:true}));await browser.close();})().catch(e=>{console.error(e);process.exit(1)});
