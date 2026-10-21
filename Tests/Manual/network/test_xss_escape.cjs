'use strict';
/**
 * XSS functional test (en_d595e9da): real risk-alerts.js + network-view.js.
 * Pass/fail is DOM-based only — never esc() call counts / ESC_GOLDEN.
 * Mutation killer: tools/mutate_esc_calls.cjs (≥57/59 without count criteria).
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

function seedTransports(win) {
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
      args: ['-o', pathFile, 'https://cdn.agentreins-field.net/payload'],
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
      fileResult: { path: pathFile, sha256: sha, hashedAt: 'pre-exec' },
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
      args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/bypass'],
      connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
      blocks: [],
      auditBypass: true,
      id: 'xss-rec-s07',
    },
  ]);
}

function assertSafeDOM(html, label) {
  assert.ok(typeof html === 'string' && html.length > 0, label + ': empty html');
  // Unescaped probe must not appear as a real tag/attribute. Escaped entities may still
  // contain the letters "onerror=" (e.g. onerror=&#39;...) — that is safe text, not DOM.
  assert.doesNotMatch(html, /<img\s+src\s*=\s*x/i, label + ': raw <img> element');
  assert.ok(!html.includes('<img src=x'), label + ': raw img literal');
  assert.ok(!html.includes("onerror='window.hacked"), label + ': raw onerror single-quote');
  assert.ok(!html.includes('onerror="window.hacked'), label + ': raw onerror double-quote');
  assert.ok(
    html.includes(exact) || html.includes('XSS-PROBE') || html.includes(exact.slice(0, 24)),
    label + ': escaped probe text missing'
  );
}

function fullRender(risk, win) {
  seedTransports(win);
  risk.setTestProbe(probe);
  const payload = {
    tasks: [],
    collected: [],
    health: [
      { source: 'Cursor', state: 'healthy', detail: 'cursor ok' },
      { source: 'Codex', state: 'healthy', detail: 'codex ok' },
      { source: 'WorkBuddy', state: 'healthy', detail: 'wb ok' },
      { source: 'transport-audit', state: 'healthy', detail: 'proxy is running on 18891' },
    ],
  };
  const alerts = risk.buildAlerts(payload);
  assert.ok(alerts.length >= 1, 'fixture must produce alerts');
  const s03 = alerts.find((a) => a.rule === 'S03') || alerts[0];
  const s07 = alerts.find((a) => a.rule === 'S07') || alerts[0];

  const s07Holder = { innerHTML: '' };
  risk.renderList(s07Holder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: s07.id,
    decisions: [],
  });
  assert.ok(!s07Holder.innerHTML.includes('risk-empty'), 'S07 detail must render alerts');
  assertSafeDOM(s07Holder.innerHTML, 's07-detail');

  const listHolder = { innerHTML: '' };
  risk.renderList(listHolder, payload, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: s03.id,
    decisions: [{ id: s03.id, state: 'acked', decidedAt: 'ack-time' }],
  });
  assertSafeDOM(listHolder.innerHTML, 's03-detail');
  assert.ok(
    listHolder.innerHTML.includes('risk-evidence-json') || listHolder.innerHTML.includes('basis') || listHolder.innerHTML.includes('XSS-PROBE'),
    'S03 evidence path rendered'
  );
  // Combined DOM used by mutation killer — every esc()'d render path must appear here.
  const combined = s07Holder.innerHTML + listHolder.innerHTML;
  assertSafeDOM(combined, 'combined-list');

  const rulesHolder = { innerHTML: '' };
  risk.renderRules(rulesHolder, payload);
  assertSafeDOM(rulesHolder.innerHTML, 'rules');

  const covHolder = { innerHTML: '' };
  risk.renderCoverage(covHolder, payload, {
    mcpAuditPath: '/tmp/audit.jsonl',
    mcpAudit: [{ at: 't', actor: 'a', tool: 'list_alerts', argsDigest: 'd', hash: 'h' }],
  });
  assertSafeDOM(covHolder.innerHTML, 'coverage');

  risk.setTestProbe(null);
  return { alerts, s03, s07 };
}

const win = loadPair();
const risk = win.AgentReinsRisk;
assert.equal(typeof risk.esc, 'function');
assert.equal(typeof risk.setTestProbe, 'function');
assert.strictEqual(risk.esc(probe), exact);
assert.ok(!risk.esc(probe).includes('<img'));

// No ESC_CALLS / ESC_GOLDEN / call-count assertions anywhere.
fullRender(risk, win);

// Sanity: identity esc + probe must expose raw HTML in DOM.
risk.setTestProbe(probe);
risk.esc = (s) => String(s);
seedTransports(win);
const broken = { innerHTML: '' };
const payload = {
  tasks: [],
  collected: [],
  health: [{ source: 'transport-audit', state: 'healthy', detail: 'proxy is running' }],
};
const alerts = risk.buildAlerts(payload);
const s07 = alerts.find((a) => a.rule === 'S07') || alerts[0];
risk.renderList(broken, payload, {
  filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
  selected: s07.id,
  decisions: [],
});
assert.ok(broken.innerHTML.includes('<img src=x'), 'identity esc must expose raw probe');
risk.setTestProbe(null);

console.log('xss escape via real DOM ok');
