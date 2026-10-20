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
    args: ['https://uploads.example.com/'],
    connections: [{ kind: 'connected', detail: ['uploads.example.com:443'] }],
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
const decided = risk.applyDecisions(alerts, [{ id, state: 'accepted', decidedAt: '2026-10-21T01:05:00Z', evidenceHash: 'abc', note: 'fixture' }]);
const hit = decided.find(a => a.id === id);
assert.equal(hit.status, 'done');
assert.equal(hit.decision.state, 'accepted');
const holder = { innerHTML: '' };
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: id, decisions: [{ id, state: 'accepted', decidedAt: '2026-10-21T01:05:00Z' }] });
assert.match(holder.innerHTML, /已确认/);
assert.match(holder.innerHTML, /已处置/);
assert.match(holder.innerHTML, /确认无风险/);
assert.match(holder.innerHTML, /导出证据包/);
assert.match(holder.innerHTML, /本机持久化/);
const pack = risk.packFields(hit);
assert.equal(pack.id, id);
assert.match(pack.evidenceText, /credential-outbound/);
assert.doesNotMatch(holder.innerHTML, /待我处理/);
console.log('risk review store ok');
