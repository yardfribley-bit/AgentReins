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
assert.match(holder.innerHTML, /允许此后/);
assert.match(holder.innerHTML, /不会调用模型网关/);
assert.match(holder.innerHTML, /已记下，未拦截/);
assert.doesNotMatch(holder.innerHTML, /连接仍按原路径进行|不会假装|不会因此被拦住/);
assert.match(holder.innerHTML, /关联事件/);
assert.match(holder.innerHTML, /Relation 缺口/);
assert.doesNotMatch(holder.innerHTML, /关联：已确认/);
assert.doesNotMatch(holder.innerHTML, /已阻断连接|网关已拦截|连接已被阻断/);
const blocked = risk.applyDecisions(alerts, [{ id: s04.id, state: 'blocked', decidedAt: '2026-11-08T01:03:00Z' }]);
const reviewOnly = blocked.find(a => a.id === s04.id);
assert.equal(risk.dispositionOf(reviewOnly).text, '已记下，未拦截');
assert.notEqual(risk.dispositionOf(reviewOnly).text, '已阻断');
assert.equal(risk.isOpen(reviewOnly), false);
const reviewHolder = { innerHTML: '' };
risk.renderList(reviewHolder, payload, { filter: { sev: 'all', rule: 'all', agent: 'all', disp: 'all', q: '' }, selected: s04.id, decisions: [{ id: s04.id, state: 'blocked' }] });
assert.match(reviewHolder.innerHTML, /risk-st noted/);
assert.match(reviewHolder.innerHTML, /已记下，未拦截/);
assert.doesNotMatch(reviewHolder.innerHTML, /risk-st block/);
const enforced = risk.applyEnforcement(blocked, [{ subject, action: 'deny', enforced: true, mechanism: 'audit-proxy' }]);
assert.equal(risk.dispositionOf(enforced.find(a => a.id === s04.id)).text, '已阻断');
assert.equal(risk.enforcementFired(enforced.find(a => a.id === s04.id)), true);
const notFired = risk.applyEnforcement(blocked, [{ subject, action: 'deny', enforced: false, mechanism: 'audit-proxy' }]);
assert.equal(risk.dispositionOf(notFired.find(a => a.id === s04.id)).text, '已记下，未拦截');
const reviewMechanism = risk.applyEnforcement(blocked, [{ subject, action: 'deny', enforced: true, mechanism: 'review' }]);
assert.equal(risk.dispositionOf(reviewMechanism.find(a => a.id === s04.id)).text, '已记下，未拦截');
const enforcedHolder = { innerHTML: '' };
risk.renderList(enforcedHolder, payload, {
  filter: { sev: 'all', rule: 'all', agent: 'all', disp: 'all', q: '' }, selected: s04.id,
  decisions: [{ id: s04.id, state: 'blocked' }],
  receipts: [{ subject, action: 'deny', enforced: true, mechanism: 'transport-wrapper' }],
});
assert.match(enforcedHolder.innerHTML, /risk-st block/);
assert.match(enforcedHolder.innerHTML, /已阻断/);

const events = risk.relatedEvents(s04, payload);
assert.ok(events.some(e => e.layer === 'model' && e.relation === 'gap'), 'no invented model event');
assert.ok(events.some(e => e.layer === 'network' && e.relation === 'explicit'));

const rules = { innerHTML: '' };
risk.renderRules(rules, payload, { decisions: [] });
assert.doesNotMatch(rules.innerHTML, /阻断/);
risk.renderRules(rules, payload, { decisions: [], hardGate: { policy: { egress: 'deny-unlisted', credentialReads: 'deny', allowHosts: ['github.com', 'api.openai.com', 'registry.npmjs.org'] } } });
assert.match(rules.innerHTML, /正在执行的策略/);
assert.match(rules.innerHTML, /未列出的外联默认拒绝/);
assert.match(rules.innerHTML, /凭据路径默认拒绝/);
assert.match(rules.innerHTML, /github.com/);
assert.match(rules.innerHTML, /api\.openai\.com/);
assert.doesNotMatch(rules.innerHTML, /阻断/);
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

const reasonHolder = { innerHTML: '' };
pages.renderReason(reasonHolder, filePayload, {});
assert.match(reasonHolder.innerHTML, /~\/\.claude\/projects/);
assert.doesNotMatch(reasonHolder.innerHTML, /言行不一|言行一致/);
const verified = {
  tasks: filePayload.tasks,
  verification: {
    sources: [{ agent: 'Claude Code', state: 'present', note: '读了 1 个 jsonl。' }],
    cards: [{
      id: 'toolu_1', sessionId: 'sess-1', agent: 'Claude Code', timestamp: '2026-11-08T02:00:02Z',
      status: 'mismatched', toolName: 'Edit', arguments: '{"file_path":"/tmp/proj/a.swift"}',
      said: '我改 a.swift。', happened: [],
      mismatches: [{ kind: 'claimed_edit_without_diff', label: '说了没做', detail: '它调用 Edit 要改 /tmp/proj/a.swift，这个时间窗里没有文件 diff。' }],
      note: '它调用 Edit 要改 /tmp/proj/a.swift，这个时间窗里没有文件 diff。',
    }],
    unclaimed: [],
    checklists: [{ sessionId: 'sess-1', taskId: 't1', doneText: '已完成，改了 1 个文件。', claimedFiles: 1, actualFiles: 1, egressCount: 0, credentialsTouched: false }],
  },
};
pages.renderReason(reasonHolder, verified, { decisions: [] });
assert.match(reasonHolder.innerHTML, /模型提出/);
assert.match(reasonHolder.innerHTML, /主机执行/);
assert.match(reasonHolder.innerHTML, /模型收到/);
assert.match(reasonHolder.innerHTML, /说了没做/);
assert.match(reasonHolder.innerHTML, /对不上/);
assert.match(reasonHolder.innerHTML, /data-accept-decide="accept"/);
assert.match(reasonHolder.innerHTML, /data-accept-decide="return"/);
assert.doesNotMatch(reasonHolder.innerHTML, /言行一致/);

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
assert.match(inboxHolder.innerHTML, /噪声/);
assert.match(inboxHolder.innerHTML, /改一下配置/);

const noisyPayload = {
  tasks: [
    filePayload.tasks[0],
    { id: 'hb', agent: 'Codex', lifecycleStatus: 'stopped', title: '<heartbeat>ping', originalRequest: '<heartbeat>ping', startedAt: '2026-11-08T04:00:00Z', cards: [] },
    { id: 'gap', agent: 'Codex', lifecycleStatus: 'completed', title: '当前轮次 · 用户需求未采集', startedAt: '2026-11-08T04:01:00Z', cards: [] },
    { id: 'att', agent: 'Codex', lifecycleStatus: 'stopped', title: '用户附件输入 · 未附带文字', startedAt: '2026-11-08T04:02:00Z', cards: [] },
  ],
  collected: [], artifacts: [], health: [],
};
assert.equal(pages.inboxNoiseReason(noisyPayload.tasks[1]), 'heartbeat');
assert.equal(pages.inboxNoiseReason(noisyPayload.tasks[2]), 'no-user-prompt');
assert.equal(pages.inboxNoiseReason(noisyPayload.tasks[3]), null);
const work = pages.inboxItems(noisyPayload, []).map(i => i.task.id).sort();
assert.deepEqual(work, ['att', 't1']);
const noise = pages.inboxItems(noisyPayload, [], { noise: true }).map(i => i.task.id).sort();
assert.deepEqual(noise, ['gap', 'hb']);
const noiseHolder = { innerHTML: '' };
pages.renderInbox(noiseHolder, noisyPayload, { decisions: [], inboxBucket: 'work' });
assert.match(noiseHolder.innerHTML, /改一下配置/);
assert.match(noiseHolder.innerHTML, /用户附件输入/);
assert.match(noiseHolder.innerHTML, /不进默认队列/);
assert.doesNotMatch(noiseHolder.innerHTML, /data-inbox-id="gap"|data-inbox-id="hb"/);
pages.renderInbox(noiseHolder, noisyPayload, { decisions: [], inboxBucket: 'noise' });
assert.match(noiseHolder.innerHTML, /用户需求未采集/);
assert.match(noiseHolder.innerHTML, /没有删除/);
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
assert.match(about.innerHTML, /证据按值留/);
assert.match(about.innerHTML, /外联、凭据、策略命中/);
assert.match(about.innerHTML, /文件改动/);
assert.match(about.innerHTML, /待我处理的决定/);
assert.match(about.innerHTML, /短摘录/);
assert.match(about.innerHTML, /心跳、没采到用户原话/);
assert.match(about.innerHTML, /不会为了凑容量/);
assert.doesNotMatch(about.innerHTML, /2GB|14 天/);
assert.match(about.innerHTML, /已记下，未拦截/);
assert.match(about.innerHTML, /审计代理拒绝转发/);
assert.doesNotMatch(about.innerHTML, /连接仍按原路径进行/);
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

const heartbeat = { subject: 'host:beat.example', kind: 'egress', action: 'deny', inbox: true, heartbeat: true, tier: 'keep', enforced: true, mechanism: 'audit-proxy' };
const firstHost = { subject: 'host:new.example', kind: 'egress', action: 'deny', inbox: true, heartbeat: false, tier: 'keep', enforced: true, mechanism: 'audit-proxy', detail: '第一次外联到新主机' };
const firstPath = { subject: 'path:/tmp/proj/.env', kind: 'credential-read', action: 'deny', inbox: true, heartbeat: false, tier: 'keep', enforced: false, detail: '第一次读取凭据路径' };
const repeat = { subject: 'host:old.example', kind: 'egress', action: 'deny', inbox: false, heartbeat: false, tier: 'keep', enforced: true, mechanism: 'audit-proxy' };
const mixed = pages.inboxItems(filePayload, [], { inbox: [heartbeat, firstHost, firstPath, repeat] });
assert.equal(mixed.filter(i => i.gate).length, 2);
assert.equal(mixed.filter(i => i.bucket && i.bucket.id === 'confirm').length, 1);
const firedInbox = { innerHTML: '' };
pages.renderInbox(firedInbox, { tasks: [], artifacts: [] }, { inboxId: 'gate:host:new.example', hardGate: { inbox: [firstHost] } });
assert.match(firedInbox.innerHTML, /已阻断/);
assert.match(firedInbox.innerHTML, /允许/);
assert.match(firedInbox.innerHTML, /保持拒绝/);
const quietInbox = { innerHTML: '' };
pages.renderInbox(quietInbox, { tasks: [], artifacts: [] }, { inboxId: 'gate:path:/tmp/proj/.env', hardGate: { inbox: [firstPath] } });
assert.match(quietInbox.innerHTML, /已记下，未拦截/);
assert.doesNotMatch(quietInbox.innerHTML, /已阻断/);
const closed = pages.inboxItems({ tasks: [] }, [], { inbox: [firstHost], allowlist: [{ subject: 'host:new.example', actor: 'user', reason: '发布需要', kind: 'egress' }] });
assert.equal(closed.filter(i => i.gate).length, 0);

const status = pages.homeStatus({
  verification: {
    checklists: [{ doneText: '改好了', actualFiles: 1, claimedFiles: 1 }],
    unclaimed: [{ id: 'u1', path: '/tmp/proj/extra.js' }],
  },
}, [
  { title: '连到 galileotelemetry.tencent.com', agent: 'WorkBuddy', rule: 'S04', timestamp: '2026-11-09T08:00:30Z', sub: 'host:galileotelemetry.tencent.com' },
  { title: '连到 example.net', agent: 'WorkBuddy', rule: 'S04', timestamp: '2026-11-09T08:00:10Z', sub: 'host:example.net', enforcement: { fired: true, mechanism: 'transport-wrapper' } },
  { title: '读取凭据 .env', agent: 'WorkBuddy', rule: 'S01', timestamp: '2026-11-09T08:00:20Z', sub: 'path:/tmp/proj/.env' },
]);
assert.match(status.line1, /WorkBuddy 刚刚读了凭据/);
assert.match(status.line2, /没拦住/);
assert.match(status.line3, /没人认领/);
assert.doesNotMatch(status.line1 + status.detail, /galileotelemetry/);
const newest = pages.inboxItems({
  tasks: [
    { id: 'old', agent: 'Cursor', lifecycleStatus: 'stopped', title: '旧任务', originalRequest: '先做这个', startedAt: '2026-11-09T01:00:00Z', cards: [] },
    { id: 'new', agent: 'Cursor', lifecycleStatus: 'stopped', title: '新任务', originalRequest: '再做这个', startedAt: '2026-11-09T09:00:00Z', cards: [] },
  ],
}, []);
assert.equal(newest[0].task.id, 'new');

console.log('runtime console ok');
