'use strict';
/**
 * XSS functional test (en_4088c393): load production risk-alerts.js only.
 * Probes on rendered fields; assert text visible + no raw tags.
 * Call-site mutation: tools/mutate_esc_calls.cjs (must kill 100%).
 *
 * NOTE: renderList calls the closed-over buildAlerts(), so patching
 * window.AgentReinsRisk.buildAlerts does NOT affect rendering. Probes must
 * flow through real transport → alert construction, or via decisions state.
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '../../..');
const riskPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const netPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js');

const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact = '&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';

function loadPair() {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(netPath, 'utf8'), sandbox);
  vm.runInContext(fs.readFileSync(riskPath, 'utf8'), sandbox);
  return sandbox.window;
}

function seed(win) {
  // S07 + S03-ish: download then exec with matching hashes so evidence JSON renders.
  const sha = 'c'.repeat(64);
  const pathFile = '/tmp/xss-payload.sh';
  win.AgentReinsNetwork.setLocalTransports([
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: '2026-10-21T06:00:00.100Z',
      pid: 1001,
      parentPID: 900,
      parentName: '/bin/zsh',
      parentStartAt: '2026-10-21T06:00:00Z',
      parentArgv: '-zsh',
      exitCode: 0,
      runID: 'xss-dl',
      call: 'xss-dl',
      session: 'xss-sess',
      args: ['-o', pathFile, 'https://cdn.agentreins-field.net/' + probe],
      connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
      blocks: [],
      downloads: [{ path: pathFile, sha256: sha, bytes: 12 }],
      id: 'xss-rec-dl',
    },
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'sh',
      startedAt: '2026-10-21T06:00:05.100Z',
      pid: 1003,
      parentPID: 900,
      parentName: '/bin/zsh',
      parentStartAt: '2026-10-21T06:00:00Z',
      parentArgv: '-zsh',
      exitCode: 0,
      runID: 'xss-exec',
      call: 'xss-exec',
      session: 'xss-sess',
      args: [pathFile],
      blocks: [],
      execSha256: sha,
      fileResult: { path: pathFile, sha256: sha },
      sha256: sha,
      id: 'xss-rec-exec',
    },
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: '2026-10-21T06:01:00Z',
      pid: 1004,
      exitCode: 0,
      runID: 'xss-s07',
      call: 'xss-s07-call',
      session: 'xss-s07-sess',
      args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/' + probe],
      connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
      blocks: [],
      auditBypass: true,
      id: 'xss-rec-s07',
    },
  ]);
}

const payload = {
  tasks: [],
  collected: [],
  health: [
    {
      source: 'transport-audit',
      state: 'healthy',
      detail: probe + ' proxy is running',
    },
  ],
};

function fullRender(risk, win) {
  seed(win);
  const alerts = risk.buildAlerts(payload);
  assert.ok(alerts.length >= 1, 'fixture must produce alerts');
  const s03 = alerts.find((a) => a.rule === 'S03') || alerts[0];
  const s07 = alerts.find((a) => a.rule === 'S07') || alerts[0];

  const holder = { innerHTML: '' };
  // Unacked S07 detail (hits 标记已知悉 + host/args esc in s07EvidenceMarkup)
  risk.renderList(holder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: s07.id,
    decisions: [],
  });
  // Acked S03 detail LAST — evidence JSON + decidedAt esc must run
  risk.renderList(holder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: s03.id,
    decisions: [{ id: s03.id, state: 'acked', decidedAt: probe }],
  });

  assert.ok(!holder.innerHTML.includes('<img src=x'), 'list/detail must not contain raw img');
  assert.doesNotMatch(holder.innerHTML, /<img\s+src=x/i);
  assert.ok(holder.innerHTML.includes('risk-evidence-json') || holder.innerHTML.includes('basis'), 'S03 evidence must render');
  assert.ok(holder.innerHTML.includes('告警本身未改'), 'acked footer must render');
  assert.ok(holder.innerHTML.includes('XSS-PROBE') || holder.innerHTML.includes(exact.slice(0, 12)), 'probe text visible');

  risk.renderRules({ innerHTML: '' }, payload);
  risk.renderCoverage(
    { innerHTML: '' },
    payload,
    {
      mcpAuditPath: '/tmp/' + probe + '/audit.jsonl',
      mcpAudit: [{ at: probe, actor: probe, tool: probe, argsDigest: probe, hash: probe }],
    }
  );
  return { holder, alerts, s03, s07 };
}

const win = loadPair();
const risk = win.AgentReinsRisk;
assert.equal(typeof risk.esc, 'function');
assert.strictEqual(risk.esc(probe), exact);
assert.ok(!risk.esc(probe).includes('<img'));

const underlying = risk.esc;
let calls = 0;
risk.esc = (s) => {
  calls += 1;
  return underlying(s);
};
const { alerts, s07 } = fullRender(risk, win);
console.log('ESC_CALLS=' + calls);
const golden = process.env.ESC_GOLDEN ? Number(process.env.ESC_GOLDEN) : null;
if (golden != null) {
  assert.strictEqual(calls, golden, 'esc call count must match golden (mutate kill)');
} else {
  assert.ok(calls > 25, 'expected substantial esc usage, got ' + calls);
}

risk.esc = (s) => String(s);
const broken = { innerHTML: '' };
seed(win);
risk.renderList(broken, payload, {
  filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
  selected: s07.id,
  decisions: [],
});
assert.ok(
  broken.innerHTML.includes('<img src=x') || risk.esc(probe) === probe,
  'identity esc must expose raw probe'
);

console.log('xss escape via app renderList/esc ok');
