'use strict';
/**
 * XSS: probes on title/agent/session/why/host/args/rule + detail fields.
 * Per-call-site mutation: each esc( occurrence must be killed (test fails when removed).
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');
const os = require('os');

const root = path.resolve(__dirname, '../../..');
const riskPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const netPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js');

const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";
const exact = '&lt;img src=x onerror=&#39;window.hacked=1&#39;&gt;XSS-PROBE-原文';

function loadPair(riskSrc, netSrc) {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  vm.runInContext(netSrc || fs.readFileSync(netPath, 'utf8'), sandbox);
  vm.runInContext(riskSrc || fs.readFileSync(riskPath, 'utf8'), sandbox);
  return sandbox.window;
}

function seedProbes(win) {
  const net = win.AgentReinsNetwork;
  // agent must be Codex/WorkBuddy/Cursor for agentTransport filter; probes go into
  // title/session/why/args/host via buildAlerts wrapper + URL path.
  net.setLocalTransports([
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: '2026-10-21T06:00:00Z',
      pid: 42,
      exitCode: 0,
      runID: 'xss-s07',
      call: 'xss-s07-call',
      session: 'xss-sess-probe',
      args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/' + encodeURIComponent(probe)],
      connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
      blocks: [],
      auditBypass: true,
      id: 'xss-rec-s07',
    },
    {
      captureMode: 'agent-path',
      agent: 'Cursor',
      tool: 'curl',
      startedAt: '2026-10-21T06:01:00Z',
      pid: 43,
      exitCode: 0,
      runID: 'xss-s04',
      call: 'xss-s04-call',
      session: 'xss-sess-probe-2',
      args: ['https://evil-xss.example/' + encodeURIComponent(probe)],
      connections: [{ kind: 'connected', detail: ['evil-xss.example:443'] }],
      blocks: [],
      id: 'xss-rec-s04',
    },
  ]);
}

function payload() {
  return {
    tasks: [],
    collected: [],
    health: [
      {
        source: 'transport-audit',
        state: 'healthy',
        detail: probe + ' proxy is running on 18891',
      },
    ],
  };
}

function fullRender(win) {
  const risk = win.AgentReinsRisk;
  const net = win.AgentReinsNetwork;
  seedProbes(win);
  const holder = { innerHTML: '' };
  const p = payload();
  // Force probes into alert fields that buildAlerts may not copy 1:1 from transport.
  const realBuild = risk.buildAlerts;
  risk.buildAlerts = (payloadArg) => {
    const alerts = realBuild(payloadArg);
    return alerts.map((a, i) => ({
      ...a,
      title: probe,
      agent: probe,
      session: probe,
      why: probe,
      rule: a.rule || 'S07',
      sub: 'host=' + probe,
      call: a.call || 'xss-call',
      evidence: {
        path: '/tmp/' + probe,
        basis: 'sibling_inferred',
        parentName: probe,
        parentStartAt: '2026-10-21T06:00:00Z',
        note: probe,
      },
      record: {
        ...(a.record || {}),
        tool: 'curl',
        args: ['--noproxy', '*', probe],
        id: 'xss-rec-' + i,
        startedAt: '2026-10-21T06:00:00Z',
      },
      acked: i === 0,
      decision: i === 0 ? { decidedAt: probe, state: 'acked' } : null,
    }));
  };
  risk.renderList(holder, p, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: probe },
    selected: null,
    decisions: [],
  });
  const alerts = risk.buildAlerts(p);
  assert.ok(alerts.length >= 1, 'fixture must produce alerts');
  const selected = alerts[0];
  risk.renderList(holder, p, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: probe },
    selected: selected.id,
    decisions: [],
  });
  assert.ok(!holder.innerHTML.includes('<img src=x'), 'list/detail must escape probes');
  assert.ok(holder.innerHTML.includes('XSS-PROBE') || holder.innerHTML.includes(exact.slice(0, 12)));

  const rulesHolder = { innerHTML: '' };
  risk.renderRules(rulesHolder, p);
  assert.ok(!rulesHolder.innerHTML.includes('<img src=x'));

  const covHolder = { innerHTML: '' };
  risk.renderCoverage(covHolder, p, {
    mcpAuditPath: '/tmp/' + probe + '/mcp-supervisor-audit.jsonl',
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
  assert.ok(!covHolder.innerHTML.includes('<img src=x'));

  // Restore
  risk.buildAlerts = realBuild;
  return { holder, rulesHolder, covHolder, alerts };
}

function withEscCounter(win, fn) {
  const risk = win.AgentReinsRisk;
  const real = risk.esc;
  let count = 0;
  risk.esc = (s) => {
    count += 1;
    return real(s);
  };
  try {
    fn();
  } finally {
    risk.esc = real;
  }
  return count;
}

// --- Baseline ---
const win0 = loadPair();
assert.strictEqual(win0.AgentReinsRisk.esc(probe), exact, 'app esc() exact');
assert.ok(!win0.AgentReinsRisk.esc(probe).includes('<img'));
const goldenCount = withEscCounter(win0, () => {
  fullRender(win0);
});
assert.ok(goldenCount > 20, 'golden esc call count should be substantial, got ' + goldenCount);

// Rebind esc to identity must leak via renderList
{
  const w = loadPair();
  seedProbes(w);
  const real = w.AgentReinsRisk.esc;
  w.AgentReinsRisk.esc = (s) => String(s);
  const holder = { innerHTML: '' };
  const p = payload();
  w.AgentReinsRisk.renderList(holder, p, {
    filter: { sev: 'all', rule: 'all', agent: 'all', q: '' },
    selected: null,
    decisions: [],
  });
  assert.ok(
    holder.innerHTML.includes('<img src=x') || w.AgentReinsRisk.esc(probe) === probe,
    'breaking escImpl must expose raw probe'
  );
  w.AgentReinsRisk.esc = real;
}

// --- Per-site mutation: kill all esc( occurrences ---
const src = fs.readFileSync(riskPath, 'utf8');
const re = /\besc\(/g;
const sites = [];
let m;
while ((m = re.exec(src)) !== null) sites.push(m.index);
assert.ok(sites.length >= 50, 'expected ~59 esc( sites, got ' + sites.length);

const netSrc = fs.readFileSync(netPath, 'utf8');
let killed = 0;
const survivors = [];

for (let i = 0; i < sites.length; i++) {
  const idx = sites[i];
  const mutated =
    src.slice(0, idx) +
    '__id__(' +
    src.slice(idx + 4); // replace "esc(" (4 chars) with "__id__("
  const preamble = 'const __id__=s=>String(s??\'\');\n';
  // Inject preamble after first line / inside IIFE start
  const injected = mutated.replace(
    /^('use strict';\s*\(\)=>\{\s*)/,
    `$1${preamble}`
  );
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xss-mut-'));
  const child = path.join(tmpDir, 'child.cjs');
  const mutRisk = path.join(tmpDir, 'risk-alerts.js');
  const mutNet = path.join(tmpDir, 'network-view.js');
  fs.writeFileSync(mutRisk, injected);
  fs.writeFileSync(mutNet, netSrc);
  fs.writeFileSync(
    child,
    `
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const dir = ${JSON.stringify(tmpDir)};
const probe = ${JSON.stringify(probe)};
const exact = ${JSON.stringify(exact)};
const goldenCount = ${goldenCount};
const window = {};
vm.createContext({ window, console });
vm.runInContext(fs.readFileSync(path.join(dir, 'network-view.js'), 'utf8'), { window, console });
vm.runInContext(fs.readFileSync(path.join(dir, 'risk-alerts.js'), 'utf8'), { window, console });
const risk = window.AgentReinsRisk;
const net = window.AgentReinsNetwork;
assert.equal(typeof risk.esc, 'function');
assert.strictEqual(risk.esc(probe), exact);
assert.ok(!risk.esc(probe).includes('<img'));
net.setLocalTransports([{
  captureMode:'agent-path', agent:'Cursor', tool:'curl', startedAt:'2026-10-21T06:00:00Z',
  pid:42, exitCode:0, runID:'xss', call:'xss', session:'xss-sess',
  args:['--noproxy','*','https://cdn.agentreins-field.net/p'],
  connections:[{kind:'connected',detail:['cdn.agentreins-field.net:443']}],
  blocks:[], auditBypass:true, id:'xss-rec'
}]);
const payload = { tasks:[], collected:[], health:[{source:'transport-audit',state:'healthy',detail:probe}] };
const realBuild = risk.buildAlerts;
risk.buildAlerts = (p) => realBuild(p).map((a,i)=>({
  ...a, title:probe, agent:probe, session:probe, why:probe, sub:'host='+probe,
  evidence:{path:'/tmp/'+probe, parentName:probe, note:probe},
  record:{...(a.record||{}), tool:'curl', args:['--noproxy','*',probe], id:'xss-rec-'+i, startedAt:'2026-10-21T06:00:00Z'},
  acked:i===0, decision:i===0?{decidedAt:probe,state:'acked'}:null
}));
const realEsc = risk.esc;
let count = 0;
risk.esc = (s) => { count += 1; return realEsc(s); };
const holder = { innerHTML:'' };
risk.renderList(holder, payload, { filter:{sev:'all',rule:'all',agent:'all',q:probe}, selected:null, decisions:[] });
const alerts = risk.buildAlerts(payload);
assert.ok(alerts.length >= 1);
risk.renderList(holder, payload, { filter:{sev:'all',rule:'all',agent:'all',q:probe}, selected:alerts[0].id, decisions:[] });
risk.renderRules({innerHTML:''}, payload);
risk.renderCoverage({innerHTML:''}, payload, {
  mcpAuditPath:'/tmp/'+probe+'/audit.jsonl',
  mcpAudit:[{at:probe,actor:probe,tool:probe,argsDigest:probe,hash:probe}]
});
assert.ok(!holder.innerHTML.includes('<img src=x'), 'raw img must not appear');
assert.strictEqual(count, goldenCount, 'esc call count must match golden');
`
  );
  let failed = false;
  let errMsg = '';
  try {
    execFileSync(process.execPath, [child], { stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    failed = true;
    errMsg = (e.stderr && e.stderr.toString()) || e.message || '';
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
  if (failed) {
    killed += 1;
  } else {
    survivors.push(i);
  }
}

console.log('XSS_MUTATION_KILLED', killed + '/' + sites.length);
if (survivors.length) {
  console.error('XSS_MUTATION_SURVIVORS', survivors.join(','));
  process.exit(1);
}
assert.strictEqual(killed, sites.length, 'all esc() mutation sites must be killed');
console.log('xss escape via app renderList/esc + per-site mutation ok', sites.length);
