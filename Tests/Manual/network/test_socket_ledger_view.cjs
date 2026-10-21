// 外网访问: proxy-independent socket ledger section (escaping, filtering, honest states).
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const window = {};
vm.runInNewContext(fs.readFileSync('Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js', 'utf8'), { window });
const api = window.AgentReinsNetwork;

assert.strictEqual(api.socketLedgerMarkup(), '', 'nothing before the ledger is loaded');
api.setSocketLedger({ connections: [], coverage: { state: 'not_running' } });
assert.match(api.socketLedgerMarkup(), /没有运行/);

const probe = '<img src=x onerror=alert(1)>';
api.setSocketLedger({
  coverage: { state: 'sampling', intervalSeconds: 3, lastSampleAt: '2026-10-21T10:00:06.000Z' },
  connections: [
    { agent: 'Codex', pid: 501, ppid: 500, processName: probe, protocol: 'TCP', scope: 'public', viaProxy: false,
      realDestination: probe, destinationSource: 'dns_inferred', transportPeer: '140.82.112.4:443', state: probe,
      firstSeen: '2026-10-21T10:00:00.000Z', lastSeen: '2026-10-21T10:00:06.000Z', sampleCount: 3, evidence: 'Observed' },
    { agent: 'Codex', pid: 502, ppid: 500, processName: 'curl', protocol: 'TCP', scope: 'loopback', viaProxy: true,
      realDestination: 'api.openai.com', destinationSource: 'proxy_observed', transportPeer: '127.0.0.1:18891',
      state: 'ESTABLISHED', sampleCount: 1, evidence: 'Observed' },
    { agent: 'Codex', pid: 503, ppid: 500, processName: 'node', protocol: 'TCP', scope: 'loopback', viaProxy: false,
      realDestination: '127.0.0.1', destinationSource: 'local', transportPeer: '127.0.0.1:6000', sampleCount: 1 },
    { agent: 'Cursor', pid: 700, ppid: 1, processName: 'Cursor', protocol: 'UDP', scope: 'public', viaProxy: false,
      realDestination: '104.16.132.229', destinationSource: 'socket_sampled', transportPeer: '104.16.132.229:443', sampleCount: 1 }
  ]
});
const html = api.socketLedgerMarkup();
assert.ok(!html.includes(probe), 'probe must be escaped');
assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
assert.match(html, /未走代理的外网连接 2 条/);
assert.match(html, /api\.openai\.com/);
assert.match(html, /127\.0\.0\.1:18891/);
assert.match(html, /反向 DNS 推断 · Inferred/);
assert.ok(!html.includes('127.0.0.1:6000'), 'loopback local services are not listed as 外网');
assert.match(html, /短于采样间隔的连接会漏掉/);
const cursorOnly = api.socketLedgerMarkup('Cursor');
assert.match(cursorOnly, /104\.16\.132\.229/);
assert.ok(!cursorOnly.includes('api.openai.com'));
console.log('SOCKET_LEDGER_VIEW_OK');
