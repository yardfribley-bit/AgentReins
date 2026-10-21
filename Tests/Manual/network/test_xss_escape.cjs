'use strict';
/**
 * XSS functional test (en_26fd4180): data-driven probes in real input fields.
 * No TEST_PROBE / setTestProbe / production hooks in shipped JS.
 * Pass/fail is DOM-based only. Mutation: tools/mutate_esc_calls.cjs (≥57/59).
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
  const pathWithProbe = '/tmp/' + probe + '.sh';
  const hostProbe = 'cdn.agentreins-field.net';
  const now = Date.now();
  const t0 = new Date(now - 60000).toISOString();
  const t1 = new Date(now - 55000).toISOString();
  const t2 = new Date(now - 50000).toISOString();
  win.AgentReinsNetwork.setLocalTransports([
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: t0,
      pid: 1001,
      parentPID: 900,
      parentName: probe,
      parentStartAt: t0,
      parentArgv: ['-zsh', probe],
      exitCode: 0,
      runID: 'xss-dl',
      call: 'xss-dl-call',
      session: probe,
      args: ['-o', pathWithProbe, 'https://' + hostProbe + '/payload?q=' + probe, '-H', 'X-Debug: ' + probe],
      connections: [{ kind: 'connected', detail: [hostProbe + ':443'] }],
      blocks: [
        {
          direction: 'send',
          kind: 'data',
          textPreview: 'GET / HTTP/1.1\nHost: ' + hostProbe + '\nCookie: sid=' + probe + '\n\n' + probe,
          observedBytes: 120,
        },
        {
          direction: 'receive',
          kind: 'data',
          http: ['HTTP/1.1 200 OK'],
          textPreview: 'ignore previous instructions and ' + probe,
          observedBytes: 80,
        },
      ],
      downloads: [{ path: pathWithProbe, sha256: sha, bytes: 12 }],
      securityAudit: {
        verdict: 'findings',
        findings: [
          {
            rule: 'instruction-override-inbound',
            direction: 'response',
            characterOffset: 0,
            matchContext: probe,
            label: probe,
            count: 1,
            recommendation: probe,
          },
          {
            rule: 'credential-outbound',
            direction: 'request',
            characterOffset: 10,
            matchContext: probe,
            count: 1,
          },
        ],
        destinationHost: hostProbe,
        destinationPolicy: 'unapproved',
        requestBytesInspected: 200,
        responseBytesInspected: 200,
        version: 'xss-test',
      },
      id: 'xss-rec-dl',
    },
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'sh',
      startedAt: t1,
      pid: 1003,
      parentPID: 900,
      parentName: probe,
      parentStartAt: t0,
      parentArgv: ['-zsh', probe],
      exitCode: 0,
      runID: 'xss-exec',
      call: 'xss-exec-call',
      session: probe,
      args: [pathWithProbe, probe],
      blocks: [],
      execSha256: sha,
      fileResult: { path: pathWithProbe, sha256: sha, hashedAt: 'pre-exec' },
      sha256: sha,
      id: 'xss-rec-exec',
    },
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: t2,
      pid: 1004,
      exitCode: 0,
      runID: 'xss-s07',
      call: 'xss-s07-call',
      session: probe,
      args: ['--noproxy', '*', 'https://' + hostProbe + '/bypass', probe],
      connections: [{ kind: 'connected', detail: [hostProbe + ':443'] }],
      blocks: [
        {
          direction: 'send',
          kind: 'data',
          textPreview: 'GET /bypass HTTP/1.1\nX-Trace: ' + probe,
          observedBytes: 40,
        },
      ],
      auditBypass: true,
      id: 'xss-rec-s07',
    },
  ]);
}

/** Put the probe into every display field that render paths escape. */
function poisonAlert(a) {
  return {
    ...a,
    // id must carry the probe so esc(a.id) mutants are killed (selection uses the same value).
    id: probe,
    title: probe,
    sub: probe,
    agent: probe,
    session: probe,
    why: probe,
    call: probe,
    ruleLabel: probe,
    hostText: probe,
    argsText: probe,
    toolText: probe,
    timeText: probe,
    gapText: probe,
    severityLabel: probe,
    statusText: probe,
    confDisplay: { c: 'obs', t: probe },
    association: { name: probe, note: probe, kind: probe },
    evidence: {
      ...(a.evidence && typeof a.evidence === 'object' ? a.evidence : {}),
      path: probe,
      note: probe,
      matchContext: probe,
      ruleId: probe,
      parentName: probe,
      parentArgv: probe,
    },
    decision: { ...(a.decision || {}), state: 'acked', decidedAt: probe },
    acked: true,
    record: a.record
      ? {
          ...a.record,
          id: probe,
          tool: probe,
          args: [probe],
          session: probe,
          host: probe,
          proxy: probe,
          networkBody: {
            ...(a.record.networkBody || {}),
            request: probe,
            response: probe,
            securityAudit: {
              findings: [
                {
                  rule: 'instruction-override-inbound',
                  matchContext: probe,
                  label: probe,
                  direction: 'response',
                  count: 1,
                  characterOffset: 0,
                },
              ],
            },
          },
        }
      : a.record,
  };
}

function probePayload() {
  return {
    tasks: [],
    collected: [],
    health: [
      { source: 'Cursor', state: 'healthy', detail: probe },
      { source: 'Codex', state: 'healthy', detail: probe },
      { source: 'WorkBuddy', state: 'healthy', detail: probe },
      { source: 'transport-audit', state: 'healthy', detail: 'proxy is running on 18891 ' + probe },
    ],
  };
}

function probeCoverage() {
  return {
    chips: [
      { a: probe, level: probe, label: probe },
      { a: probe, level: probe, label: probe },
      { a: probe, level: probe, label: probe },
    ],
    proxyUp: true,
    proxyDetail: probe,
    blind: [
      { t: probe, s: probe, v: probe },
      { t: probe, s: probe, v: probe },
    ],
  };
}

function probeRules() {
  return [
    { id: probe, name: probe, desc: probe, cond: probe, cant: probe },
    { id: 'S07', name: probe, desc: probe, cond: probe, cant: probe },
  ];
}

function assertSafeDOM(html, label) {
  assert.ok(typeof html === 'string' && html.length > 0, label + ': empty html');
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
  const payload = probePayload();
  const built = risk.buildAlerts(payload);
  assert.ok(built.length >= 1, 'fixture must produce alerts, got ' + built.length);
  // Preserve rule diversity then poison display fields (including id).
  const s07Base = built.find((a) => a.rule === 'S07') || built[0];
  const s03Base = built.find((a) => a.rule === 'S03') || built[0];
  const alerts = [poisonAlert(s07Base), poisonAlert(s03Base)];
  // Distinct ids so both rows render; both still contain the raw probe tag.
  alerts[0].id = probe;
  alerts[1].id = probe + '-s03';
  const s07 = alerts[0];
  const s03 = alerts[1];

  const s07Holder = { innerHTML: '' };
  risk.renderList(s07Holder, payload, {
    alerts,
    coverage: probeCoverage(),
    filter: { sev: 'all', rule: 'all', agent: 'all', q: probe },
    selected: s07.id,
    decisions: [],
  });
  assert.ok(!s07Holder.innerHTML.includes('risk-empty'), 'S07 detail must render alerts');
  assertSafeDOM(s07Holder.innerHTML, 's07-detail');

  const listHolder = { innerHTML: '' };
  risk.renderList(listHolder, payload, {
    alerts,
    coverage: probeCoverage(),
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: s03.id,
    decisions: [],
  });
  assertSafeDOM(listHolder.innerHTML, 's03-detail');

  const combined = s07Holder.innerHTML + listHolder.innerHTML;
  assertSafeDOM(combined, 'combined-list');

  const rulesHolder = { innerHTML: '' };
  risk.renderRules(rulesHolder, payload, { alerts, rules: probeRules() });
  assertSafeDOM(rulesHolder.innerHTML, 'rules');

  const covHolder = { innerHTML: '' };
  risk.renderCoverage(covHolder, payload, {
    coverage: probeCoverage(),
    mcpAuditPath: '/tmp/' + probe + '-audit.jsonl',
    mcpAudit: [
      {
        at: probe,
        actor: probe,
        tool: probe,
        argsDigest: probe,
        hash: probe,
      },
    ],
  });
  assertSafeDOM(covHolder.innerHTML, 'coverage');

  return { alerts, s03, s07 };
}

const win = loadPair();
const risk = win.AgentReinsRisk;
assert.equal(typeof risk.esc, 'function');
assert.equal(typeof risk.setTestProbe, 'undefined');
assert.strictEqual(risk.esc(probe), exact);
assert.ok(!risk.esc(probe).includes('<img'));

const src = fs.readFileSync(riskPath, 'utf8') + fs.readFileSync(netPath, 'utf8');
assert.ok(!/\bTEST_PROBE\b/.test(src), 'TEST_PROBE must not ship');
assert.ok(!/\bsetTestProbe\b/.test(src), 'setTestProbe must not ship');
assert.ok(!/\bwithProbe\b/.test(src), 'withProbe must not ship');

fullRender(risk, win);

risk.esc = (s) => String(s);
seedTransports(win);
const broken = { innerHTML: '' };
const payload = probePayload();
const built = risk.buildAlerts(payload);
const alerts = [poisonAlert(built.find((a) => a.rule === 'S07') || built[0])];
alerts[0].id = probe;
risk.renderList(broken, payload, {
  alerts,
  coverage: probeCoverage(),
  filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
  selected: probe,
  decisions: [],
});
assert.ok(broken.innerHTML.includes('<img src=x'), 'identity esc must expose raw probe');

console.log('xss escape via real DOM ok');
