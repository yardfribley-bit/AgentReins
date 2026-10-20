'use strict';
/** P5: risk alerts associate by execution id (call), never session-wide. */
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

const callA = 'exec-call-a';
const callB = 'exec-call-b';
const session = 'shared-session-should-not-link';

net.setLocalTransports([
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:00:00Z',
    pid: 11, exitCode: 0, runID: callA, call: callA, session,
    args: ['-o', '/tmp/agentreins-p5-dl.sh', 'https://downloads.example.com/p5.sh'],
    downloads: [{ path: '/tmp/agentreins-p5-dl.sh', sha256: 'abc123def456' }],
    connections: [{ kind: 'connected', detail: ['downloads.example.com:443'] }],
    blocks: [],
    auditBypass: false,
  },
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:01:00Z',
    pid: 12, exitCode: 0, runID: callB, call: callB, session,
    args: ['--noproxy', '*', 'https://example.com/'],
    connections: [{ kind: 'connected', detail: ['example.com:443'] }],
    blocks: [],
    // Frontend must NOT invent S07 from --noproxy alone.
    auditBypass: false,
  },
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T02:02:00Z',
    pid: 13, exitCode: 0, runID: 'bypass-1', call: 'bypass-1', session,
    args: ['--noproxy', '*', 'https://example.com/bypass'],
    connections: [{ kind: 'connected', detail: ['example.com:443'] }],
    blocks: [],
    auditBypass: true,
  },
]);

const payload = {
  tasks: [{
    agent: 'Cursor',
    session,
    cards: [
      // Different call in same session — must NOT create S03 with download callA
      {
        id: 'call:' + callB, call: callB, timestamp: '2026-10-21T02:00:30Z',
        execution: { command: 'chmod +x /tmp/agentreins-p5-dl.sh && sh /tmp/agentreins-p5-dl.sh', call: callB, startAt: '2026-10-21T02:00:30Z' },
        input: 'chmod +x /tmp/agentreins-p5-dl.sh && sh /tmp/agentreins-p5-dl.sh',
      },
      // Same execution id as download — SHOULD create S03
      {
        id: 'call:' + callA, call: callA, timestamp: '2026-10-21T02:00:20Z',
        execution: { command: 'chmod +x /tmp/agentreins-p5-dl.sh && /bin/sh /tmp/agentreins-p5-dl.sh', call: callA, startAt: '2026-10-21T02:00:20Z' },
        input: 'chmod +x /tmp/agentreins-p5-dl.sh && /bin/sh /tmp/agentreins-p5-dl.sh',
      },
    ],
  }],
  collected: [],
  health: [],
};

const alerts = risk.buildAlerts(payload);
const s03 = alerts.filter(a => a.rule === 'S03' && /下载后/.test(a.title));
assert.equal(s03.length, 1, 'exactly one S03 for same call; session-mate must not match');
assert.equal(s03[0].call, callA);
assert.equal(risk.associationOf(s03[0]).name, '已确认');

const s07 = alerts.filter(a => a.rule === 'S07');
assert.equal(s07.length, 1, 'S07 only when auditBypass===true');
assert.equal(s07[0].call, 'bypass-1');
assert.ok(risk.bypassed({ auditBypass: true }));
assert.ok(!risk.bypassed({ auditBypass: false, args: ['--noproxy', '*'] }));
assert.ok(!risk.bypassed({ args: ['--noproxy', '*'] }));

const holder = { innerHTML: '' };
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', q: '' }, selected: s03[0].id, decisions: [] });
assert.match(holder.innerHTML, /关联：已确认/);
assert.match(holder.innerHTML, /Observed|Correlated|已关联|已观测/);
assert.match(holder.innerHTML, /已确认（执行编号）\/ 候选 \/ 缺口|关联强度：已确认/);
assert.doesNotMatch(holder.innerHTML, /待我处理/);

// No-call download must not invent S03 via time window
net.setLocalTransports([
  {
    captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-21T03:00:00Z',
    pid: 21, exitCode: 0, session: 's-nocall',
    // omit call and runID so projectLocal leaves call null
    args: ['-o', '/tmp/agentreins-p5-nocall.sh', 'https://downloads.example.com/x.sh'],
    downloads: [{ path: '/tmp/agentreins-p5-nocall.sh', sha256: 'deadbeef' }],
    connections: [{ kind: 'connected', detail: ['downloads.example.com:443'] }],
    blocks: [],
  },
]);
const noCallLocals = net.localExchanges();
assert.equal(noCallLocals[0]?.call, null, 'fixture has no execution id');
const noCallAlerts = risk.buildAlerts({
  tasks: [{
    agent: 'Cursor', session: 's-nocall',
    cards: [{
      timestamp: '2026-10-21T03:00:10Z',
      execution: { command: 'sh /tmp/agentreins-p5-nocall.sh', startAt: '2026-10-21T03:00:10Z' },
      input: 'sh /tmp/agentreins-p5-nocall.sh',
    }],
  }],
  collected: [], health: [],
});
assert.ok(!noCallAlerts.some(a => a.rule === 'S03' && /下载后/.test(a.title)), 'no S03 without execution id');

console.log('risk p5 association ok');
