'use strict';
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const root = path.resolve(__dirname, '../../..');
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js'), 'utf8'), { window });
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js'), 'utf8'), { window });
vm.runInNewContext(fs.readFileSync(path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/console-pages.js'), 'utf8'), { window });
const risk = window.AgentReinsRisk;
const net = window.AgentReinsNetwork;
const pages = window.AgentReinsConsole;

net.setLocalTransports([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-11-08T01:00:00Z',
  pid: 40, exitCode: 0, runID: 'call-host', call: 'call-host', session: 'sess-1',
  args: ['https://uploads.example/secret'],
  connections: [{ kind: 'connected', detail: ['uploads.example:443'] }],
  blocks: [],
}]);
const payload = { tasks: [], collected: [], health: [{ source: 'workbuddy-network', state: 'healthy', detail: 'proxy is running on 18891' }] };
const alerts = risk.buildAlerts(payload);
const s04 = alerts.find(a => a.rule === 'S04');
assert.ok(s04, 'S04 from non-allow host');
const subject = risk.subjectOf(s04);
assert.ok(subject.startsWith('host:'), subject);

const allow = risk.applyDecisions(alerts, [{ id: 'older', state: 'allowlisted', subject, rule: 'S04', decidedAt: '2026-11-08T01:01:00Z' }]);
const hit = allow.find(a => a.id === s04.id);
assert.equal(hit.allowlisted, true);
assert.equal(risk.dispositionOf(hit).text, '已加白');
assert.equal(risk.isOpen(hit), false);

const confirmed = risk.applyDecisions(alerts, [{ id: s04.id, state: 'confirmed', decidedAt: '2026-11-08T01:02:00Z' }]);
assert.equal(risk.dispositionOf(confirmed.find(a => a.id === s04.id)).text, '已确认');

const holder = { innerHTML: '' };
risk.renderList(holder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', disp: 'all', q: '' }, selected: s04.id, decisions: [] });
assert.match(holder.innerHTML, /放行/);
assert.match(holder.innerHTML, /阻断/);
assert.match(holder.innerHTML, /加白/);
assert.match(holder.innerHTML, /转人工/);
assert.match(holder.innerHTML, /标记已知悉/);
assert.match(holder.innerHTML, /本机处置记录/);
assert.match(holder.innerHTML, /连接仍按原路径进行/);
assert.doesNotMatch(holder.innerHTML, /不会调用模型网关|不会假装|不会因此被拦住/);
assert.match(holder.innerHTML, /关联事件/);
assert.match(holder.innerHTML, /Relation 缺口/);
assert.doesNotMatch(holder.innerHTML, /关联：已确认/);
assert.doesNotMatch(holder.innerHTML, /已阻断连接|网关已拦截|连接已被阻断/);
const blocked = risk.applyDecisions(alerts, [{ id: s04.id, state: 'blocked', decidedAt: '2026-11-08T01:03:00Z' }]);
assert.equal(risk.dispositionOf(blocked.find(a => a.id === s04.id)).text, '已阻断');
assert.equal(risk.isOpen(blocked.find(a => a.id === s04.id)), false);

const events = risk.relatedEvents(s04, payload);
assert.ok(events.some(e => e.layer === 'model' && e.relation === 'gap'), 'no invented model event');
assert.ok(events.some(e => e.layer === 'network' && e.relation === 'explicit'));

const rules = { innerHTML: '' };
risk.renderRules(rules, payload, { decisions: [] });
assert.match(rules.innerHTML, /v1\.1/);
assert.match(rules.innerHTML, /误报/);
assert.match(rules.innerHTML, /S06/);
assert.match(rules.innerHTML, /WebLens/);
assert.doesNotMatch(rules.innerHTML, /0\.91/);

const cov = { innerHTML: '' };
risk.renderCoverage(cov, payload, {});
assert.match(cov.innerHTML, /审计代理/);
assert.match(cov.innerHTML, /不写「已安装 N 个」/);
assert.match(cov.innerHTML, /--noproxy/);

const filePayload = {
  tasks: [{
    id: 't1', agent: 'Cursor', session: 'sess-1', lifecycleStatus: 'awaiting_confirmation',
    originalRequest: '改一下配置', startedAt: '2026-11-08T02:00:00Z',
    cards: [
      { id: 'f1', kind: 'files', title: 'write · .env', timestamp: '2026-11-08T02:01:00Z', confidence: 'explicit', call: 'c1', basis: '同一轮次', resource: { path: '/tmp/proj/.env', before: 'A=1', after: 'A=2' } },
      { id: 'm1', kind: 'model', title: '模型', timestamp: '2026-11-08T02:00:30Z', call: 'c1', output: '我会改 .env' },
      { id: 'cmd1', kind: 'command', title: 'Shell', timestamp: '2026-11-08T02:00:40Z', call: 'c1', execution: { command: 'printf A=2 > .env' } },
      { id: 'm2', kind: 'plan', title: '计划', timestamp: '2026-11-08T02:00:10Z', output: '只读代码，不联网' },
    ],
  }],
  collected: [], artifacts: [], health: [],
};
const files = { innerHTML: '' };
pages.renderFiles(files, filePayload, { fileId: 'f1' });
assert.match(files.innerHTML, /未采到 diff|之前/);
assert.match(files.innerHTML, /S08 敏感文件/);
assert.doesNotMatch(files.innerHTML, /AL-0|今日 Critical 3/);

const reason = pages.reasoningRows(filePayload);
assert.ok(reason.some(r => r.relation === 'explicit' && r.model && r.model.id === 'm1'));
assert.ok(reason.some(r => r.relation === 'gap'));
const paired = reason.find(r => r.relation === 'explicit');
assert.equal(pages.alignmentVerdict(paired, []).label, '可对照');
assert.equal(pages.alignmentVerdict({
  relation: 'explicit', basis: '同一执行编号',
  model: { call: 'c9', output: '只读取，不联网' },
  execs: [{ execution: { command: 'curl https://cdn.example/x' } }],
}, [{ call: 'c9', rule: 'S04', title: '外联非白名单' }]).label, '言行不一');
assert.equal(pages.alignmentVerdict(reason.find(r => r.relation === 'gap'), []).label, '不可对照');
const reasonHolder = { innerHTML: '' };
pages.renderReason(reasonHolder, filePayload, { reasonId: reason.find(r => r.relation === 'gap').id });
assert.match(reasonHolder.innerHTML, /缺口/);
assert.doesNotMatch(reasonHolder.innerHTML, /言行不一|言行一致/);

const inbox = pages.inboxItems(filePayload, []);
assert.equal(inbox.length, 1);
assert.equal(inbox[0].bucket.id, 'confirm');
const packed = pages.evidencePack(filePayload.tasks[0], null);
assert.equal(packed.schema, 'agentreins.acceptance.v1');
assert.equal(packed.task.request, '改一下配置');
assert.ok(packed.evidence.length >= 1);

const returned = pages.inboxItems(filePayload, [{ id: 'task:t1', state: 'return', note: '缺测试', decidedAt: '2026-11-08T03:00:00Z' }]);
assert.equal(returned[0].decision.state, 'return');
const inboxHolder = { innerHTML: '' };
pages.renderInbox(inboxHolder, filePayload, { inboxId: 't1', decisions: returned[0].decision ? [{ id: 'task:t1', state: 'return', note: '缺测试', decidedAt: '2026-11-08T03:00:00Z' }] : [], returnInvalid: true, returnNote: '' });
assert.match(inboxHolder.innerHTML, /已退回/);
assert.match(inboxHolder.innerHTML, /撤销决定/);
assert.match(inboxHolder.innerHTML, /invalid/);
const fileAlertsHolder = { innerHTML: '' };
pages.renderFiles(fileAlertsHolder, filePayload, { fileMode: 'alerts' });
assert.match(fileAlertsHolder.innerHTML, /S08 敏感文件被改/);
assert.doesNotMatch(fileAlertsHolder.innerHTML, /AL-0/);

const sup = { innerHTML: '' };
pages.renderSupervise(sup, filePayload, { mcpAudit: [], mcpAuditPath: '' });
assert.match(sup.innerHTML, /list_alerts/);
assert.match(sup.innerHTML, /不改 Codex/);
assert.doesNotMatch(sup.innerHTML, /已启用监督/);

const about = { innerHTML: '' };
pages.renderAbout(about);
assert.match(about.innerHTML, /关于 AgentReins/);
assert.match(about.innerHTML, /agent 安全观测/);
assert.match(about.innerHTML, /确认、加白、复查/);
assert.match(about.innerHTML, /现在能做的/);
assert.match(about.innerHTML, /本机处置记录/);
assert.match(about.innerHTML, /连接仍按原路径进行/);
assert.match(about.innerHTML, /<h3>下一步<\/h3>/);
assert.match(about.innerHTML, /Endpoint Security/);
assert.match(about.innerHTML, /Network Extension/);
assert.match(about.innerHTML, /WebLens/);
assert.match(about.innerHTML, /本机安装包/);
assert.doesNotMatch(about.innerHTML, /不会假装|不从安装包读取|这版不会|这版会做的/);
assert.doesNotMatch(about.innerHTML, /1\.1\.0|176|FOFA|靶场/);
pages.renderAbout(about, { version: '1.1.0', build: '176' });
assert.match(about.innerHTML, /本机安装包 · 1\.1\.0（176）/);
pages.renderAbout(about, { version: '1.1.0' });
assert.match(about.innerHTML, /本机安装包 · 1\.1\.0</);
assert.doesNotMatch(about.innerHTML, /本机安装包 · 1\.1\.0（/);
pages.renderAbout(about, { build: '20261108.1713' });
assert.match(about.innerHTML, /本机安装包 · 20261108\.1713/);
pages.renderAbout(about, { version: '<img src=x onerror=alert(1)>', build: '176"></script>' });
assert.match(about.innerHTML, /本机安装包</);
assert.doesNotMatch(about.innerHTML, /<img|onerror|script/);
pages.renderAbout(about, null);
assert.match(about.innerHTML, />本机安装包</);

console.log('runtime console ok');
