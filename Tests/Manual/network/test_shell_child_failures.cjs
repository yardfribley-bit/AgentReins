'use strict';
// One agent shell, N failing loopback curls, then one success.
// The parent Bash exit code is 0. Failed attempts must stay visible on the
// destination page and under the shell card.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '../../..');
const netPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js');
const livePath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/live.js');
const transportPath = path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/transport-view.js');

function load() {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(netPath, 'utf8'), sandbox);
  return sandbox.window.AgentReinsNetwork;
}

const script = 'for i in 1 2 3 4 5 6; do curl -sS http://127.0.0.1:59999/attempt$i || true; done; curl -sS https://example.com';
const parentArgv = "bash -lc '" + script + "'";
const parentPID = 4242;

function fail(i, extra) {
  return Object.assign({
    captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl',
    args: ['-sS', 'http://127.0.0.1:59999/attempt' + i],
    startedAt: '2026-10-28T01:00:0' + i + 'Z', pid: 5000 + i, parentPID, parentArgv, parentName: 'bash',
    exitCode: 7, runID: 'fail-' + i, call: 'exec-fail-' + i, session: 'wb-1',
    connections: [{ kind: 'attempt', detail: ['127.0.0.1:59999...'], source: 'curl.trace', line: 3 }],
    blocks: [], transportPeer: '127.0.0.1:59999', realDestination: null, destinationSource: 'transport_peer_only',
  }, extra);
}
const success = {
  captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl',
  args: ['-sS', 'https://example.com'],
  startedAt: '2026-10-28T01:00:07Z', pid: 5007, parentPID, parentArgv, parentName: 'bash',
  exitCode: 0, runID: 'ok-1', call: 'exec-ok-1', session: 'wb-1',
  connections: [
    { kind: 'proxyTunnel', detail: ['example.com:443'] },
    { kind: 'connected', detail: ['127.0.0.1 (127.0.0.1) port 18891'] },
  ],
  blocks: [
    { direction: 'send', kind: 'data', http: ['GET / HTTP/1.1', 'Host: example.com'] },
    { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: 'ok' },
  ],
  transportPeer: '127.0.0.1:18891', realDestination: 'example.com', destinationSource: 'proxy_observed',
};
const localService = {
  captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl',
  args: ['http://127.0.0.1:8769/'],
  startedAt: '2026-10-28T01:00:08Z', pid: 80, parentPID: 9, parentArgv: 'bash -lc curl http://127.0.0.1:8769/',
  exitCode: 0, runID: 'local-ok', call: 'exec-local-ok', session: 'wb-1',
  connections: [{ kind: 'connected', detail: ['127.0.0.1 (127.0.0.1) port 8769'] }],
  blocks: [{ direction: 'send', kind: 'data', http: ['GET / HTTP/1.1', 'Host: 127.0.0.1:8769'] }],
};
const other = {
  captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl',
  args: ['https://other.example/secret'],
  startedAt: '2026-10-28T01:00:09Z', pid: 81, parentPID: 77, parentArgv: 'bash -lc curl https://other.example/secret',
  exitCode: 0, runID: 'other', call: 'exec-other', session: 'wb-1',
  connections: [{ kind: 'connected', detail: ['other.example:443'] }],
  blocks: [],
};

const card = {
  id: 'call:bash-1', kind: 'command', title: 'Bash', phase: 'returned', status: 'returned',
  timestamp: '2026-10-28T01:00:00Z',
  execution: { command: script, exitCode: 0, processID: parentPID, status: 'returned' },
};
const task = { id: 'task-1', agent: 'WorkBuddy', session: 'wb-1', title: 'probe loopback then example', cards: [card] };

const net = load();
net.setLocalTransports([1, 2, 3, 4, 5, 6].map(fail).concat([success, localService, other]));

const children = net.shellChildAttempts(task, card);
const ids = [...children].map((row) => String(row.call)).sort();
assert.deepStrictEqual(ids, ['exec-fail-1', 'exec-fail-2', 'exec-fail-3', 'exec-fail-4', 'exec-fail-5', 'exec-fail-6', 'exec-ok-1']);
assert.strictEqual(children.filter((row) => Number(row.exitCode) === 7).length, 6);
assert.ok(!ids.includes('exec-local-ok'), 'a different shell is not this Bash card');
assert.ok(!ids.includes('exec-other'));

const markup = net.shellChildMarkup(task, card);
assert.match(markup, /同一次 shell 的子命令/);
assert.match(markup, /6 次未成功/);
for (let i = 1; i <= 6; i++) {
  assert.match(markup, new RegExp('exec-fail-' + i));
  assert.match(markup, new RegExp('http://127\\.0\\.0\\.1:59999/attempt' + i));
}
assert.match(markup, /exec-ok-1/);
assert.match(markup, /example\.com/);
assert.doesNotMatch(markup, /exec-other/);

const probeCard = {
  id: 'call:probe', kind: 'command', title: 'Bash',
  execution: { command: script + " <img src=x onerror='window.hacked=1'>", exitCode: 0, processID: 1 },
};
const probeRun = fail(1, { call: "<img src=x onerror='window.hacked=1'>", parentPID: 1, parentArgv: "bash -lc '" + probeCard.execution.command + "'" });
net.setLocalTransports([probeRun]);
const probeHtml = net.shellChildMarkup(task, probeCard);
assert.doesNotMatch(probeHtml, /<img\s+src\s*=\s*x/i);
assert.match(probeHtml, /&lt;img/);

net.setLocalTransports([1, 2, 3, 4, 5, 6].map(fail).concat([success, localService, other]));
const holder = { innerHTML: '' };
net.render(holder, { tasks: [task], collected: [] });
const html = holder.innerHTML;
assert.match(html, /本机回环 · 未成功/);
for (let i = 1; i <= 6; i++) {
  assert.match(html, new RegExp('http://127\\.0\\.0\\.1:59999/attempt' + i));
  assert.match(html, /退出码 7/);
}
assert.match(html, /example\.com/);
assert.doesNotMatch(html, /8769/, 'a successful loopback service stays off the destination page');
const taskHolder = { innerHTML: '' };
net.render(taskHolder, { tasks: [task], collected: [] }, { taskOnly: task.id });
assert.match(taskHolder.innerHTML, /http:\/\/127\.0\.0\.1:59999\/attempt1/);
assert.match(taskHolder.innerHTML, /http:\/\/127\.0\.0\.1:59999\/attempt6/);
assert.match(taskHolder.innerHTML, /退出码 7/);
assert.match(taskHolder.innerHTML, /example\.com/);
const groups = net.destinationGroups(net.localExchanges(), []);
assert.ok(groups.some((g) => g.key === '本机回环 · 未成功' && g.records.length === 6));
assert.ok(groups.some((g) => /example\.com/.test(g.key)));
assert.ok(!groups.some((g) => g.key === '127.0.0.1' || g.key === '::1'));

// No argv and no "Connected" line: the attempt peer is still a row.
const bare = fail(3, { args: [], call: 'exec-bare', runID: 'bare' });
const [projected] = net.projectLocal([bare]);
assert.ok(projected, 'peer-only failure is not dropped');
assert.strictEqual(projected.destinationSource, 'transport_peer_only');
assert.strictEqual(projected.realDestination, null);
assert.match(String(projected.host), /127\.0\.0\.1:59999/);
assert.strictEqual(projected.exitCode, 7);

// $i hides the failing URLs. The success URL plus the shared parent PID still surfaces the failures.
const expanded = [1, 2, 3, 4, 5, 6].map((i) => fail(i, { parentArgv: null })).concat([Object.assign({}, success, { parentArgv: null })]);
net.setLocalTransports(expanded);
const linked = [...net.shellChildAttempts(task, card)].map((row) => String(row.call)).sort();
assert.deepStrictEqual(linked, ['exec-fail-1', 'exec-fail-2', 'exec-fail-3', 'exec-fail-4', 'exec-fail-5', 'exec-fail-6', 'exec-ok-1']);

const live = fs.readFileSync(livePath, 'utf8');
const transport = fs.readFileSync(transportPath, 'utf8');
assert.match(live, /shellChildMarkup/);
assert.match(live, /次子命令未成功/);
assert.match(live, /requestRiskTransports\(\)/);
assert.match(transport, /agentreinsRenderProcess/);

console.log('shell child failures visible');
