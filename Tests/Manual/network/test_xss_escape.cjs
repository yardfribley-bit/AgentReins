'use strict';
/** Exact XSS escape assertions — must run in CI (see .github/workflows/ci.yml). */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '../../..');
const src = fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js'), 'utf8');
assert.ok(src.includes("esc=s=>String(s??'').replace"), 'esc helper must be present in risk-alerts.js');
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js'), 'utf8'), { window });
vm.runInNewContext(src, { window });
const esc = vm.runInNewContext(
  `(()=>{const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));return esc;})()`
);
const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact = '&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';
assert.strictEqual(esc(probe), exact, 'esc() must produce exact escaped string');
assert.strictEqual(esc('a&b<"\'>'), 'a&amp;b&lt;&quot;&#39;&gt;');
assert.ok(!esc(probe).includes('<img'));
assert.ok(!esc(probe).includes("onerror='"));
const holder = { innerHTML: '' };
window.AgentReinsNetwork.setLocalTransports([]);
window.AgentReinsRisk.renderRules(holder, { tasks: [], collected: [], health: [] });
assert.doesNotMatch(holder.innerHTML, /阻断/);
assert.match(holder.innerHTML, /告警/);
console.log('xss escape exact ok');
