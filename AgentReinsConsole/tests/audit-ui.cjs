const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

test('audit UI: explicit demo, evidence tabs, empty/error states, paging and literal evidence', async () => {
  const browser = await chromium.launch({ headless: true, channel: process.env.AUDIT_BROWSER_CHANNEL || "chrome" });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    let payload = null;
    let status = 503;
    const requests = [];
    await page.route('http://127.0.0.1:8899/**', async route => {
      const url = new URL(route.request().url());
      if (url.pathname.startsWith('/api/')) {
        requests.push(url.search);
        return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(payload || {}) });
      }
      const name = url.pathname.endsWith('.css') ? 'audit.css' : url.pathname.endsWith('.js') ? 'audit.js' : 'index.html';
      await route.fulfill({ contentType: name.endsWith('.css') ? 'text/css' : name.endsWith('.js') ? 'text/javascript' : 'text/html', body: fs.readFileSync(path.join(__dirname, '../public', name)) });
    });
    await page.goto('http://127.0.0.1:8899/');
    await page.locator('#ara-load-status').filter({ hasText: '尚未接通' }).waitFor();
    assert.equal(await page.locator('.case').count(), 0);
    await page.locator('#ara-mode-toggle').click();
    assert.equal(await page.locator('.case').count(), 3);
    await page.locator('.tabs [data-tab="memory"]').click();
    assert.match(await page.locator('#ara-evidence').innerText(), /ops-memory/);
    await page.locator('.tabs [data-tab="relay"]').click();
    assert.match(await page.locator('#ara-evidence').innerText(), /entry_ip_only/);
    await page.locator('.case').nth(1).click();
    assert.match(await page.locator('#ara-conclusion').innerText(), /尚不能认定已外发/);
    await page.locator('.case').first().click();
    await page.locator('.tabs [data-tab="request"]').click();
    fs.mkdirSync('/private/tmp/agentreins-audit-ui', { recursive: true });
    await page.screenshot({ path: '/private/tmp/agentreins-audit-ui/desktop.png', fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.screenshot({ path: '/private/tmp/agentreins-audit-ui/mobile.png', fullPage: true });
    status = 200; payload = { schemaVersion: 1, items: [], nextCursor: null };
    await page.locator('#ara-mode-toggle').click();
    await page.locator('#ara-load-status').filter({ hasText: '暂无审计记录' }).waitFor();
    assert.equal(await page.locator('.case').count(), 0);
    const view = { facts: [['依据', '<script>window.pwned=1</script>']], raw: { content: '<img src=x onerror=alert(1)>' } };
    const record = Object.fromEntries(['title','who','summary','process','data','send','target','conclusion','limit','receipt'].map(key => [key, 'test-' + key]));
    record.views = { request: view, memory: view, relay: view, process: view };
    payload = { schemaVersion: 1, items: [{ id: 'case-1', record }], nextCursor: 'next-20' };
    await page.locator('#ara-retry').click();
    await page.locator('.case').waitFor();
    assert.equal(await page.locator('#ara-reviewed').isVisible(), false);
    assert.match(await page.locator('#ara-json').textContent(), /"simulation": false/);
    assert.equal(await page.locator('#ara-facts script').count(), 0);
    payload = { schemaVersion: 1, items: [{ id: 'case-2', record }], nextCursor: null };
    await page.locator('#ara-more').click();
    await page.waitForFunction(() => document.querySelectorAll('.case').length === 2);
    assert.match(requests.at(-1), /cursor=next-20/);
    status = 403;
    await page.locator('#ara-retry').click();
    await page.locator('#ara-load-status').filter({ hasText: '没有审计查看权限' }).waitFor();
    assert.deepEqual(errors, []);
  } finally { await browser.close(); }
});

test('incremental refresh adds WorkBuddy, preserves open evidence, and updates on click', async () => {
  const browser = await chromium.launch({ headless: true, channel: 'chrome' });
  try {
    const page = await browser.newPage();
    await page.clock.install();
    const record = Object.fromEntries(['title','who','summary','process','data','send','target','conclusion','limit','receipt'].map(k=>[k, 'test-'+k]));
    record.who = 'employee · Office Mac · 192.168.1.11';
    const view = {facts:[['依据','原文']],raw:{content:'original'}};
    const full = {...record,views:{request:view,memory:view,relay:view,process:view}};
    let changed = false, detailReads = 0, updates = 0;
    await page.route('http://127.0.0.1:8899/**', async route => {
      const url = new URL(route.request().url());
      if(url.pathname.startsWith('/api/')) {
        let payload;
        if(url.pathname.endsWith('/1')){detailReads++;payload={schemaVersion:1,record:changed?{...full,receipt:'new-receipt'}:full};}
        else if(url.searchParams.has('after')){
          updates++;
          payload={schemaVersion:1,items:updates===1?[{id:'2',record:{...record,title:'WorkBuddy 新任务'}},{id:'1',record:{...record,receipt:'new-receipt'}}]:[],updateCursor:'3',nextCursor:null};
          changed=true;
        }else payload={schemaVersion:1,items:[{id:'1',record}],updateCursor:'1',nextCursor:null};
        return route.fulfill({contentType:'application/json',body:JSON.stringify(payload)});
      }
      const name=url.pathname.endsWith('.js')?'audit.js':url.pathname.endsWith('.css')?'audit.css':'index.html';
      return route.fulfill({contentType:name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html',body:fs.readFileSync(path.join(__dirname,'../public',name))});
    });
    await page.goto('http://127.0.0.1:8899/');
    await page.locator('#ara-receipt').filter({hasText:'test-receipt'}).waitFor();
    await page.locator('.tabs [data-tab="memory"]').click();
    await page.locator('#ara-evidence').evaluate(el=>el.dataset.reading='keep');
    await page.clock.fastForward(10000);
    await page.locator('#ara-load-status').filter({hasText:'有新证据'}).waitFor();
    assert.equal(await page.locator('.case').count(),2);
    assert.match(await page.locator('.case').first().innerText(),/WorkBuddy 新任务/);
    assert.equal(detailReads,1);
    assert.equal(await page.locator('#ara-evidence').getAttribute('data-reading'),'keep');
    assert.equal(await page.locator('#ara-receipt').textContent(),'test-receipt');
    await page.locator('.case[aria-pressed="true"]').click();
    await page.locator('#ara-receipt').filter({hasText:'new-receipt'}).waitFor();
    assert.equal(detailReads,2);
    assert.equal(await page.locator('.tabs [data-tab="memory"]').getAttribute('aria-pressed'),'true');
    await page.locator('#ara-mode-toggle').click();
    const before=updates;
    await page.clock.fastForward(30000);
    assert.equal(updates,before);
  } finally {await browser.close();}
});
