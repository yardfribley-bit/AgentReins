'use strict';
/**
 * Phase 2 外网访问 views (destination list, 8-column rows, connection map, destination detail, task view):
 * probes go into real input fields only — local transport records via setLocalTransports(), the socket
 * ledger via setSocketLedger(), tasks/alerts via the render payload — exactly what the app feeds in.
 * No hooks in shipped code. Mutation: node tools/mutate_esc_calls.cjs <network-view.js> <this file>
 * (only the ESC-MUTATION-REGION of network-view.js is mutated).
 */
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '../../..');
const netPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js');
const riskPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const probe = "<img src=x onerror='window.hacked=1'>XSS-PROBE-原文";

function load() {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(netPath, 'utf8'), sandbox);
  vm.runInContext(fs.readFileSync(riskPath, 'utf8'), sandbox);
  return sandbox.window;
}

function assertSafe(html, label) {
  assert.ok(typeof html === 'string' && html.length > 0, label + ': empty html');
  assert.doesNotMatch(html, /<img\s+src\s*=\s*x/i, label + ': raw <img> element');
  assert.ok(!/onerror='window\.hacked/i.test(html), label + ': raw onerror');
  assert.ok(html.includes('XSS-PROBE') || html.includes('xss-probe'), label + ': probe text must still be shown (escaped)');
}

const now = Date.now();
const iso = (s) => new Date(now - s * 1000).toISOString();
const win = load();
const net = win.AgentReinsNetwork;

net.setLocalTransports([
  { captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: iso(50), pid: 11, exitCode: 0,
    runID: probe, call: probe, session: probe,
    args: ['https://' + probe + '/x?q=' + probe, '-H', 'X: ' + probe],
    connections: [{ kind: 'connected', detail: [probe + ':443'] }],
    blocks: [{ direction: 'send', kind: 'data', textPreview: 'GET /' + probe + ' HTTP/1.1\nHost: ' + probe + '\n\n', observedBytes: 40 },
             { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: probe, observedBytes: 20 }],
    securityAudit: { verdict: 'findings', findings: [{ rule: probe, label: probe, direction: 'request', count: 1, characterOffset: 1 }] } },
  { captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: iso(40), pid: 12, exitCode: 7,
    runID: 'bypass-' + probe, session: probe, auditBypass: true,
    args: ['--noproxy', '*', 'https://bypass.example/' + probe] },
]);
net.setSocketLedger({
  coverage: { state: 'sampling', measurementConfidence: 'Observed', observedCycleSecondsP95: probe, missesShorterThanSeconds: probe,
    failures: probe, lastSampleAt: iso(1), integrity: { state: probe } },
  keychain: { state: 'key_unavailable', helper: probe, reason: probe },
  connections: [
    { agent: probe, pid: probe, ppid: probe, processName: probe, protocol: probe, scope: 'public', viaProxy: false,
      remoteAddress: probe, remotePort: probe, realDestination: probe, destinationSource: probe, destinationEvidence: probe,
      state: probe, firstSeen: probe, lastSeen: probe, sampleCount: probe },
    ...Array.from({ length: 7 }, (_, i) => ({ agent: 'Codex', pid: 30 + i, processName: 'node', protocol: 'TCP', scope: 'public',
      viaProxy: false, remoteAddress: probe, remotePort: 443, realDestination: probe, destinationSource: 'socket_sampled',
      destinationEvidence: 'Observed', state: 'ESTABLISHED', firstSeen: iso(20), lastSeen: iso(3), sampleCount: 2 })),
    { agent: 'Codex', pid: 21, ppid: 1, processName: 'node', protocol: 'TCP', scope: 'public', viaProxy: false,
      remoteAddress: '203.0.113.7', remotePort: 443, realDestination: '203.0.113.7', destinationSource: 'socket_sampled',
      destinationEvidence: 'Observed', state: 'ESTABLISHED', firstSeen: iso(30), lastSeen: iso(2), sampleCount: 9 },
  ],
});

// Task titles go through plainTask(), which strips complete tags; an unclosed tag must still be escaped.
const unclosed = 'XSS-PROBE <img src=x onerror=1';
const tasks = [{ id: probe, title: probe, originalRequest: unclosed, agent: probe, session: probe, cards: [], detailsLoaded: true }];
const payload = { tasks, collected: [], health: [] };
const render = (opts) => { const holder = { innerHTML: '' }; net.render(holder, payload, opts); return holder.innerHTML; };

// Every socket field must reach the list as escaped text (one row per probe field, 8 columns).
const list = render({ agent: 'all', selected: 'local-transport:' + probe });
assertSafe(list, 'destination list');
assert.ok(list.includes('<th>结果</th><th>关联</th><th>内容审计</th>'), '结果 / 关联 / 内容审计 are separate columns');
assert.ok(list.includes('没有审计（流量没经过代理）'), 'non-proxied traffic is labelled unaudited');
assert.ok(!/导出证据包/.test(list), 'no evidence-pack export');
for (const opts of [{ agent: probe }, { agent: 'all', query: probe }, { agent: 'all', mode: 'map' }, { agent: 'all', mode: 'map', suspicious: true }]) {
  assertSafe(render(opts), 'view ' + JSON.stringify(Object.keys(opts)));
}
// Destination details: the socket probe destination, and the record destination.
const groups = net.destinationGroups([], net.socketLedgerData().connections);
const probeKey = groups.find((g) => g.key.includes('xss-probe'));
assert.ok(probeKey, 'probe destination group exists');
const alerts = [{ id: probe, rule: probe, title: probe, destination: probeKey.key }];
assertSafe(render({ agent: 'all', destination: probeKey.key, alerts }), 'destination detail (socket)');
const recordDetail = render({ agent: 'all', destination: 'bypass.example', alerts });
assert.ok(recordDetail.includes('destination-detail'), 'record destination detail renders');
// Task-scoped view (same 8 columns).
assertSafe(render({ agent: 'all', taskOnly: probe, focusTask: probe }), 'task view');
assertSafe(render({ agent: 'all', taskOnly: null, focusTask: probe }), 'focus-task pill');
const loading = { innerHTML: '' };
net.render(loading, { tasks: [{ id: probe, title: probe, detailsLoaded: false }] }, { taskOnly: probe });
assert.ok(!loading.innerHTML.includes('<img src=x'), 'loading view escaped');

// Empty / honest states: no ledger loaded, no records → no fake rows.
const empty = load();
const holder = { innerHTML: '' };
empty.AgentReinsNetwork.render(holder, { tasks: [], collected: [] }, { agent: 'all' });
assert.ok(holder.innerHTML.includes('还没有采到外网访问'), 'empty list says so');
holder.innerHTML = '';
empty.AgentReinsNetwork.render(holder, { tasks: [], collected: [] }, { agent: 'all', mode: 'map' });
assert.ok(holder.innerHTML.includes('地图为空') && !holder.innerHTML.includes('<path'), 'empty map draws no edges');

console.log('xss network views ok');
