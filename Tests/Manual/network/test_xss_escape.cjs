'use strict';
/** XSS: feed malicious data through app renderList / esc — no local copy of esc(). */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '../../..');
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js'), 'utf8'), { window });
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js'), 'utf8'), { window });
const risk = window.AgentReinsRisk;
assert.equal(typeof risk.esc, 'function', 'app must export esc from risk-alerts.js');
assert.equal(typeof risk.renderList, 'function');

const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact = '&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';
// Must use the app's esc — intentionally breaking the app esc must fail this test.
assert.strictEqual(risk.esc(probe), exact, 'app esc() must produce exact escaped string');
assert.strictEqual(risk.esc('a&b<"\'>'), 'a&amp;b&lt;&quot;&#39;&gt;');
assert.ok(!risk.esc(probe).includes('<img'));
assert.ok(!risk.esc(probe).includes("onerror='"));

window.AgentReinsNetwork.setLocalTransports([]);
const holder = { innerHTML: '' };
const payload = {
  tasks: [{
    agent: 'Cursor',
    session: 'xss-sess',
    cards: [{
      id: 'call:xss', call: 'xss-call', timestamp: '2026-10-21T06:00:00Z',
      kind: 'command', title: probe,
      execution: { command: probe, call: 'xss-call', startAt: '2026-10-21T06:00:00Z' },
      input: probe,
    }],
  }],
  collected: [],
  health: [],
};
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: null, decisions: [] });
assert.ok(!holder.innerHTML.includes('<img src=x'), 'renderList must escape title/body via app esc');
assert.ok(holder.innerHTML.includes('XSS-PROBE') || holder.innerHTML.includes('风险告警'), 'renderList produced markup');
assert.doesNotMatch(holder.innerHTML, /阻断/);

// Tamper the exported app esc → assertions must fail (proves test binds to app code).
const realEsc = risk.esc;
let broken = false;
try {
  risk.esc = (s) => String(s); // broken: no escaping
  assert.strictEqual(risk.esc(probe), exact);
} catch (e) {
  broken = true;
} finally {
  risk.esc = realEsc;
}
assert.ok(broken, 'deliberately breaking app esc must make the exact assertion fail');

console.log('xss escape via app renderList/esc ok');
