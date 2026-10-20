'use strict';
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const root = path.resolve(__dirname, '../../..');
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js'), 'utf8'), { window });
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js'), 'utf8'), { window });
const risk = window.AgentReinsRisk;
const net = window.AgentReinsNetwork;

const secret = 'sk-or-v1-' + 'x'.repeat(48);
net.setLocalTransports([
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T01:00:00Z',
    pid: 9, exitCode: 0, runID: 'call-s02', call: 'call-s02', session: 's1',
    args: ['https://cdn.agentreins-field.net/upload'],
    connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
    blocks: [
      { direction: 'send', kind: 'data', textPreview: 'Authorization: Bearer ' + secret },
      { direction: 'receive', kind: 'header', http: ['HTTP/2 200 '] },
      { direction: 'receive', kind: 'data', textPreview: 'ok' },
    ],
    securityAudit: { verdict: 'review', findings: [{ rule: 'credential-outbound', direction: 'request', count: 1, characterOffset: 20, label: '发送正文疑似包含访问凭据' }] },
  },
]);
const payload = { tasks: [], collected: [], health: [] };
const alerts = risk.buildAlerts(payload);
assert.ok(alerts.some(a => a.rule === 'S02'), 'S02 alert from credential-outbound');
const id = alerts.find(a => a.rule === 'S02').id;
const decided = risk.applyDecisions(alerts, [{ id, state: 'acked', decidedAt: '2026-10-21T01:05:00Z', evidenceHash: 'abc', note: 'fixture' }]);
const hit = decided.find(a => a.id === id);
assert.equal(hit.acked, true);
assert.equal(hit.decision.state, 'acked');
const holder = { innerHTML: '' };
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: id, decisions: [{ id, state: 'acked', decidedAt: '2026-10-21T01:05:00Z' }] });
assert.match(holder.innerHTML, /已知悉/);
assert.doesNotMatch(holder.innerHTML, /确认无风险|标记已处置|标记待补证据|导出证据包|已处置|已退回/);
assert.match(holder.innerHTML, /仅样式|已知悉（仅样式）|风险告警/);
assert.doesNotMatch(holder.innerHTML, /待我处理/);
const pack = risk.packFields(hit);
assert.equal(pack.id, id);
assert.match(pack.evidenceText, /credential-outbound/);

// Explicit testCapture / seed-session stay out of real-capture view
net.setLocalTransports([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T01:10:00Z',
  pid: 10, exitCode: 0, runID: 'seed-call', call: 'seed-call', session: 'seed-session',
  testCapture: true, provenance: 'test',
  args: ['https://uploads.example.com/'],
  connections: [{ kind: 'connected', detail: ['uploads.example.com:443'] }],
  blocks: [{ direction: 'send', kind: 'data', textPreview: 'Authorization: Bearer ' + secret }],
  securityAudit: { verdict: 'review', findings: [{ rule: 'credential-outbound', direction: 'request', count: 1, characterOffset: 20 }] },
}]);
const seedAlerts = risk.buildAlerts({ tasks: [], collected: [], health: [] });
assert.equal(seedAlerts.length, 0, 'explicit test provenance must not appear as 真实采集');
console.log('risk review store ok');
