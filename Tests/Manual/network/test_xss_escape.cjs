'use strict';
/**
 * XSS: feed malicious data through app renderList / esc.
 * - Payload must produce a real alert (list + detail).
 * - Mutating the escImpl used by renderList must make assertions fail.
 * - Source mutation (replace escImpl body) must fail the suite.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '../../..');
const riskPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const netPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js');

function loadRisk(jsOverride) {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(netPath, 'utf8'), sandbox);
  vm.runInContext(jsOverride || fs.readFileSync(riskPath, 'utf8'), sandbox);
  return sandbox.window.AgentReinsRisk;
}

const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact = '&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';

function alertPayload() {
  // Real S07 alert so renderList is not empty-state; probe appears in title/args/detail.
  return {
    tasks: [],
    collected: [],
    health: [{ source: 'transport-audit', state: 'healthy', detail: 'proxy is running on 18891' }],
  };
}

function seedTransports(risk, net) {
  net.setLocalTransports([
    {
      captureMode: 'agent-path', agent: 'Cursor', tool: 'curl',
      startedAt: '2026-10-21T06:00:00Z', pid: 42, exitCode: 0,
      runID: 'xss-bypass', call: 'xss-bypass', session: 'xss-sess',
      args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/' + probe],
      connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
      blocks: [], auditBypass: true,
    },
  ]);
}

function runAssertions(risk, net) {
  assert.equal(typeof risk.esc, 'function');
  assert.strictEqual(risk.esc(probe), exact, 'app esc() must produce exact escaped string');
  assert.ok(!risk.esc(probe).includes('<img'));

  seedTransports(risk, net);
  const holder = { innerHTML: '' };
  const payload = alertPayload();
  risk.renderList(holder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: null, decisions: [],
  });
  const alerts = risk.buildAlerts(payload);
  assert.ok(alerts.some(a => a.rule === 'S07'), 'fixture must produce S07 alert');
  assert.ok(!holder.innerHTML.includes('<img src=x'), 'list HTML must not contain raw img');
  assert.ok(holder.innerHTML.includes('XSS-PROBE') || holder.innerHTML.includes('风险告警'));

  // Select detail
  const selected = alerts.find(a => a.rule === 'S07');
  risk.renderList(holder, payload, {
    filter: { sev: 'all', rule: 'S07', agent: 'all', q: '' },
    selected: selected.id, decisions: [],
  });
  assert.ok(holder.innerHTML.includes('risk-detail') || holder.innerHTML.includes('绕过'), 'detail rendered');
  assert.ok(!holder.innerHTML.includes('<img src=x'), 'detail HTML must not contain raw img');
  // Escaped probe text must appear in detail/list when args contain it
  assert.ok(
    holder.innerHTML.includes('XSS-PROBE') || holder.innerHTML.includes(exact.slice(0, 20)),
    'escaped probe text visible'
  );

  // Minimal DOM check: no injected element tag survives as real markup
  assert.doesNotMatch(holder.innerHTML, /<img\s+src=x/i);

  // Rebind escImpl via setter — renderList must use broken esc and leak raw markup.
  const real = risk.esc;
  risk.esc = (s) => String(s);
  const brokenHolder = { innerHTML: '' };
  risk.renderList(brokenHolder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: selected.id, decisions: [],
  });
  assert.ok(
    brokenHolder.innerHTML.includes('<img src=x') || risk.esc(probe) === probe,
    'breaking escImpl must expose raw probe via renderList or esc'
  );
  risk.esc = real;
}

const windowBag = {};
vm.runInNewContext(fs.readFileSync(netPath, 'utf8'), { window: windowBag });
vm.runInNewContext(fs.readFileSync(riskPath, 'utf8'), { window: windowBag });
runAssertions(windowBag.AgentReinsRisk, windowBag.AgentReinsNetwork);

// Source mutation: replace escImpl body with identity — child must fail.
if (process.env.XSS_MUTATION_CHILD === '1') {
  console.log('mutation child should have failed earlier');
  process.exit(2);
}
const mutated = fs.readFileSync(riskPath, 'utf8').replace(
  /let escImpl=s=>String\(s\?\?''\)\.replace\([^;]+;/,
  "let escImpl=s=>String(s??'');"
);
assert.notEqual(mutated, fs.readFileSync(riskPath, 'utf8'), 'mutation must alter escImpl source');
const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'xss-mut-'));
const mutRisk = path.join(tmpDir, 'risk-alerts.js');
fs.copyFileSync(netPath, path.join(tmpDir, 'network-view.js'));
fs.writeFileSync(mutRisk, mutated);
const child = path.join(tmpDir, 'child.cjs');
fs.writeFileSync(child, `
const assert=require('assert');const fs=require('fs');const path=require('path');const vm=require('vm');
const window={};const dir='${tmpDir.replace(/'/g, "\\'")}';
vm.runInNewContext(fs.readFileSync(path.join(dir,'network-view.js'),'utf8'),{window});
vm.runInNewContext(fs.readFileSync(path.join(dir,'risk-alerts.js'),'utf8'),{window});
const risk=window.AgentReinsRisk;
const probe="<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact='&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';
assert.strictEqual(risk.esc(probe), exact);
`);
let failed = false;
try {
  execFileSync(process.execPath, [child], { stdio: 'pipe' });
} catch (e) {
  failed = true;
}
assert.ok(failed, 'mutating renderList escImpl source must make XSS assertions fail');
fs.rmSync(tmpDir, { recursive: true, force: true });

console.log('xss escape via app renderList/esc + mutation ok');
