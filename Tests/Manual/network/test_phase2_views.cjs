'use strict';
// Phase 2: socket-driven alerts, honest coverage banner, 8-column rows, destination grouping, map, D3 empty graph.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const dir = path.resolve(__dirname, '../../../Sources/AgentReins/Resources/RealtimeWorkspace');
function load(...files) {
  const window = {};
  const sandbox = { window, console };
  vm.createContext(sandbox);
  for (const f of files) vm.runInContext(fs.readFileSync(path.join(dir, f), 'utf8'), sandbox);
  return sandbox.window;
}
const iso = (s) => new Date(Date.now() - s * 1000).toISOString();
const sock = (o) => Object.assign({ agent: 'Codex', pid: 10, ppid: 1, processName: 'node', protocol: 'TCP', scope: 'public',
  viaProxy: false, remotePort: 443, state: 'ESTABLISHED', firstSeen: iso(20), lastSeen: iso(2), sampleCount: 3, evidence: 'Observed' }, o);

// --- D3: no task → no placeholder graph ---
{
  const w = load('runtime-graph.js');
  const g = w.AgentReinsRuntimeGraph;
  for (const build of [g.buildArchitecture, g.buildRelations]) {
    const out = build({ task: null, contexts: [], processes: [{ agent: 'Codex', pid: 1 }], artifacts: [] });
    assert.deepStrictEqual(Array.from(out.nodes), [], 'no task must yield no nodes');
    assert.deepStrictEqual(Array.from(out.edges), [], 'no task must yield no edges');
    assert.strictEqual(out.empty, true);
  }
  const src = fs.readFileSync(path.join(dir, 'runtime-graph.js'), 'utf8');
  assert.ok(!src.includes('等待用户任务'), 'placeholder bubble text is gone');
  const live = fs.readFileSync(path.join(dir, 'live.js'), 'utf8');
  assert.match(live, /graph-empty/, 'live.js renders an honest empty state');
}

// --- socket-driven alerts (S07 / S04) ---
{
  const w = load('network-view.js', 'risk-alerts.js');
  const net = w.AgentReinsNetwork, risk = w.AgentReinsRisk;
  assert.strictEqual(risk.buildAlerts({ tasks: [] }).length, 0, 'no data → no alerts');
  net.setSocketLedger({
    coverage: { state: 'sampling', integrity: { state: 'verified' } },
    connections: [
      sock({ remoteAddress: '140.82.112.4', realDestination: 'github.com', destinationSource: 'argv_parsed', destinationEvidence: 'Correlated' }),
      sock({ remoteAddress: '203.0.113.9', realDestination: 'paste.evil.example', destinationSource: 'dns_inferred', destinationEvidence: 'Inferred' }),
      sock({ remoteAddress: '198.51.100.3', realDestination: '198.51.100.3', destinationSource: 'socket_sampled', destinationEvidence: 'Observed' }),
      sock({ processName: 'curl', viaProxy: true, scope: 'loopback', remoteAddress: '127.0.0.1', remotePort: 18891, realDestination: 'unknown.example', destinationSource: 'proxy_observed' }),
      sock({ agent: 'Cursor', processName: 'Cursor Helper', remoteAddress: '104.16.1.1', realDestination: 'api2.cursor.sh', destinationSource: 'argv_parsed', destinationEvidence: 'Correlated' }),
      sock({ remoteAddress: '192.168.1.5', scope: 'private', realDestination: '192.168.1.5' }),
    ],
  });
  const alerts = risk.buildAlerts({ tasks: [] });
  const s07 = alerts.filter((a) => a.rule === 'S07');
  const s04 = alerts.filter((a) => a.rule === 'S04');
  assert.strictEqual(s07.length, 2, 'one S07 per agent+process with direct public connections');
  const codexNode = s07.find((a) => a.agent === 'Codex');
  assert.strictEqual(codexNode.severity, 'high', 'non-allowlisted direct destination → high');
  assert.strictEqual(codexNode.confidence, 'inf', 'weakest destination evidence wins');
  assert.strictEqual(s07.find((a) => a.agent === 'Cursor').severity, 'medium', 'only allowlisted destinations → medium');
  assert.strictEqual(JSON.stringify(s04.map((a) => a.destination).sort()), JSON.stringify(['198.51.100.3', 'paste.evil.example']));
  assert.strictEqual(s04.find((a) => a.destination === '198.51.100.3').severity, 'medium', 'IP-only → medium');
  assert.strictEqual(s04.find((a) => a.destination === 'paste.evil.example').severity, 'high');
  assert.ok(!alerts.some((a) => a.destination === 'unknown.example'), 'proxied sockets are not bypass alerts');
  assert.ok(!alerts.some((a) => a.destination === '192.168.1.5'), 'private addresses are not 外网 alerts');
  assert.ok(alerts.every((a) => a.call === null || a.call === undefined), 'sampled sockets never claim an execution id');

  // A ledger that failed verification is Unknown, whatever its rows say.
  net.setSocketLedger({ coverage: { state: 'tampered', integrity: { state: 'tampered' } },
    connections: [sock({ remoteAddress: '203.0.113.9', realDestination: 'paste.evil.example', destinationEvidence: 'Observed' })] });
  assert.ok(risk.buildAlerts({ tasks: [] }).every((a) => a.confidence === 'unk'), 'tampered ledger → Unknown confidence');

  // Rule texts describe the socket source.
  assert.match(risk.RULES.find((r) => r.id === 'S07').cond, /viaProxy=false/);
  assert.match(risk.RULES.find((r) => r.id === 'S04').cond, /按进程采样/);
  assert.strictEqual(typeof risk.esc, 'undefined', 'no esc hook');
}

// --- coverage banner states (measured, never assumed) ---
{
  const w = load('network-view.js', 'risk-alerts.js');
  const net = w.AgentReinsNetwork, risk = w.AgentReinsRisk;
  const home = () => { const h = { innerHTML: '' }; risk.renderList(h, { tasks: [], health: [] }, { decisions: [] }); return h.innerHTML; };
  assert.match(home(), /尚未读取采样台账/, 'before the ledger arrives the banner says so');
  net.setSocketLedger({ coverage: { state: 'sampling', measurementConfidence: 'Unknown', observedCycleSecondsP95: 2.1, failures: 0, integrity: { state: 'unsigned' } },
    keychain: { state: 'key_unavailable', helper: 'needs_approval', reason: 'keychain needs user approval' }, connections: [] });
  let html = home();
  assert.match(html, /实测周期：Unknown（样本不足）/, 'p95 is Unknown until enough rounds are measured');
  assert.ok(!html.includes('2.1 秒'), 'an unmeasured p95 is never shown as a number');
  assert.match(html, /台账未签名/);
  assert.match(html, /data-keychain-authorize="needs_approval"/, 'authorize button when approval is needed');
  assert.match(html, /AgentReinsKeychainHelper authorize/, 'terminal instruction too');
  net.setSocketLedger({ coverage: { state: 'stopped', staleSeconds: 95.5, measurementConfidence: 'Observed', observedCycleSecondsP95: 3.2,
    missesShorterThanSeconds: 3.4, failures: 4, lastFailure: 'lsof timed out', integrity: { state: 'verified' } }, keychain: { state: 'ok' }, connections: [] });
  html = home();
  assert.match(html, /按进程采样已停止/);
  assert.match(html, /最近一次采样在 95.5 秒前/);
  assert.match(html, /实测周期 p95 3.2 秒/);
  assert.match(html, /失败 4 次（最近：lsof timed out）/);
  assert.match(html, /台账已签名 · 校验通过/);
  assert.ok(!html.includes('data-keychain-authorize'), 'no authorize button when the key is readable');
  net.setSocketLedger({ coverage: { state: 'tampered', integrity: { state: 'tampered' } }, keychain: { state: 'ok' }, connections: [] });
  assert.match(home(), /台账被改动（按篡改处理）/);
  net.setSocketLedger({ coverage: { state: 'sampling', integrity: { state: 'verified' } }, keychain: { state: 'key_unavailable', helper: 'missing' }, connections: [] });
  assert.ok(!home().includes('data-keychain-authorize'), 'no authorize button when there is no key yet (nothing to approve)');
}

// --- 8 columns, 结果 from structured fields only, destination grouping and map ---
{
  const w = load('network-view.js', 'risk-alerts.js');
  const net = w.AgentReinsNetwork;
  net.setLocalTransports([
    { captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: iso(60), pid: 1, exitCode: 0, runID: 'ok-1', call: 'call-1', session: 's',
      args: ['https://example.org/'], connections: [{ kind: 'connected', detail: ['example.org:443'] }],
      blocks: [{ direction: 'send', kind: 'data', textPreview: 'GET / HTTP/1.1\nHost: example.org\n\n' },
               { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: 'HTTP/1.1 200 OK\n\nSSL certificate problem (page text only)' }] },
    { captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: iso(50), pid: 2, exitCode: 0, runID: 'bp-1', session: 's', auditBypass: true,
      args: ['--noproxy', '*', 'https://direct.example/'] },
  ]);
  net.setSocketLedger({ coverage: { state: 'sampling', integrity: { state: 'verified' } }, connections: [
    sock({ remoteAddress: '203.0.113.9', realDestination: 'direct.example', destinationSource: 'argv_parsed', destinationEvidence: 'Correlated' })] });
  const holder = { innerHTML: '' };
  net.render(holder, { tasks: [], collected: [] }, { agent: 'all' });
  const html = holder.innerHTML;
  assert.ok(html.includes('<th>任务</th><th>时间</th><th>谁</th><th>去了哪里</th><th>协议</th><th>结果</th><th>关联</th><th>内容审计</th>'), 'prototype 8 columns');
  const okRow = html.split('<tr').find((r) => r.includes('example.org') && r.includes('执行编号已对上'));
  assert.ok(okRow, 'association column says the execution id matched');
  assert.match(okRow, /TLS 校验通过/, 'TLS outcome from status + exit code, not from body text');
  assert.ok(!/证书没配好|TLS 校验失败/.test(okRow), 'body text never decides 结果');
  assert.match(html, /直接连接，绕过了审计代理/);
  assert.strictEqual(net.associationCell({ auditBypass: true, args: ['--noproxy', '*', 'https://x.example/'] }), '没有执行编号（命令自带代理参数）');
  assert.strictEqual(net.associationCell({ call: 'c-1' }), '执行编号已对上');
  assert.strictEqual(net.associationCell({ taskConfidence: 'candidate' }), '候选关联（按时间窗，没有执行编号）');
  assert.strictEqual(net.resultCell({ exitCode: 60, args: ['https://x.example/'] }), 'TLS 校验失败（退出码 60）');
  assert.strictEqual(net.resultCell({ exitCode: 0, args: ['-k', 'https://x.example/'], networkBody: { responseStatus: 200 } }), 'HTTP 200 · TLS 未校验（-k / --insecure）');
  assert.strictEqual(net.auditCell({ auditBypass: true }), '没有审计（流量没经过代理）');
  assert.strictEqual(net.resultCell({ exitCode: 0, outboundFiles: ['a.txt', 'b.txt'] }), '退出码 0 · 带走了 a.txt、b.txt');
  assert.strictEqual(net.resultCell({ exitCode: 1, outboundFiles: ['a.txt'] }), '退出码 1', 'failed push carried nothing provable');
  assert.strictEqual(net.resultCell({ exitCode: 0, downloads: [{ path: '/tmp/x/pkg.tgz', state: 'verified' }, { path: '/tmp/y', state: 'failed' }] }), '退出码 0 · 下载了 pkg.tgz');
  assert.match(html, /没有审计（流量没经过代理）/);
  assert.match(html, /data-network-destination="direct.example"/, 'records and sockets grouped under one destination');
  const groups = net.destinationGroups([], net.socketLedgerData().connections);
  assert.strictEqual(groups.length, 1);
  const map = { innerHTML: '' };
  net.render(map, { tasks: [], collected: [] }, { agent: 'all', mode: 'map' });
  assert.match(map.innerHTML, /class="map-edge bypass/, 'bypass edges are drawn as bypass (red dashed)');
  assert.match(map.innerHTML, />AGENT<.*>进程 \/ 命令<.*>目的地</s);
  const detail = { innerHTML: '' };
  net.render(detail, { tasks: [], collected: [] }, { agent: 'all', destination: 'direct.example', alerts: [] });
  for (const h of ['请求时间线', '送出 / 收回', '为什么判为', 'DNS · IP · TLS', '关联告警', '处置']) assert.ok(detail.innerHTML.includes(h), 'detail has ' + h);
  assert.ok(!/加入白名单<\/button>|拦截<\/button>/.test(detail.innerHTML), 'no fake action buttons');
}

// --- shipped UI has no evidence-pack export and no esc hook ---
for (const f of fs.readdirSync(dir)) {
  const src = fs.readFileSync(path.join(dir, f), 'utf8');
  const code = src.split('\n').filter((line) => !/^\s*(\/\/|\/\*|\*)/.test(line)).join('\n');
  assert.ok(!code.includes('导出证据包'), f + ' must not offer 导出证据包');
  assert.ok(!/set\s+esc\s*\(/.test(src), f + ' must not expose an esc setter');
}
// --- home list is rebuilt from data on every render (a stale state.alerts must not freeze it) ---
{
  const w = load('network-view.js', 'risk-alerts.js');
  const state = { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: null, alerts: [], decisions: [] };
  const h = { innerHTML: '' };
  w.AgentReinsRisk.renderList(h, { tasks: [], health: [] }, state);
  assert.strictEqual(state.alerts.length, 0);
  w.AgentReinsNetwork.setSocketLedger({ coverage: { state: 'sampling', integrity: { state: 'verified' } },
    connections: [sock({ remoteAddress: '203.0.113.9', realDestination: 'late.example', destinationSource: 'dns_inferred', destinationEvidence: 'Inferred' })] });
  w.AgentReinsRisk.renderList(h, { tasks: [], health: [] }, state);
  assert.ok(state.alerts.some((a) => a.rule === 'S04' && a.destination === 'late.example'), 'ledger loaded after first render → alerts appear');
  assert.match(h.innerHTML, /late\.example/);
}

// --- a bypass already alerted from the command record is not repeated per process ---
{
  const w = load('network-view.js', 'risk-alerts.js');
  w.AgentReinsNetwork.setLocalTransports([{ captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: iso(30), pid: 77, exitCode: 0,
    runID: 'np-1', call: 'np-1', session: 's', args: ['--noproxy', '*', 'https://drop.example/'],
    connections: [{ kind: 'connected', detail: ['drop.example:443'] }], blocks: [], auditBypass: true }]);
  w.AgentReinsNetwork.setSocketLedger({ coverage: { state: 'sampling', integrity: { state: 'verified' } },
    connections: [sock({ pid: 77, processName: 'curl', remoteAddress: '203.0.113.5', realDestination: 'drop.example', destinationSource: 'argv_parsed', destinationEvidence: 'Correlated' }),
                  sock({ pid: 78, processName: 'node', remoteAddress: '203.0.113.6', realDestination: 'other.example', destinationSource: 'argv_parsed', destinationEvidence: 'Correlated' })] });
  const s07 = w.AgentReinsRisk.buildAlerts({ tasks: [] }).filter((a) => a.rule === 'S07');
  assert.strictEqual(s07.filter((a) => a.record).length, 1, 'record S07 kept');
  assert.strictEqual(s07.filter((a) => Array.isArray(a.sockets) && a.sockets.some((x) => x.processName === 'curl')).length, 0, 'socket S07 for the same bypass is dropped');
  assert.strictEqual(s07.filter((a) => Array.isArray(a.sockets) && a.sockets.some((x) => x.processName === 'node')).length, 1, 'unrelated direct process still alerts');
}

console.log('phase2 views ok');
