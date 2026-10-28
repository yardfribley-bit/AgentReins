'use strict';
// Vernacular task-process strip. Extracts plainStatus from live.js so the sentence
// stays tied to the page without booting the DOM.
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const livePath = path.resolve(__dirname, '../../../Sources/AgentReins/Resources/RealtimeWorkspace/live.js');
const live = fs.readFileSync(livePath, 'utf8');
const start = live.indexOf('function plainStatus(task){');
const end = live.indexOf('function renderCurrentBar(t){');
assert.ok(start > 0 && end > start, 'plainStatus must sit immediately before renderCurrentBar');
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(live.slice(start, end) + '\nglobalThis.plainStatus = plainStatus;', sandbox);
const plainStatus = sandbox.plainStatus;

const forbidden = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|连接\s*·|\bresponse\b|\bcompleted\b|socket_endpoint_only/i;

function task(extra) {
  return Object.assign({
    agent: 'WorkBuddy',
    lifecycleStatus: 'running',
    completionEvidence: 'unknown',
    currentStep: 'Agent 已停止；最后记录：连接 · mtalk.google.com；目标达成未确认',
    statusBasis: '原生轮次终态：response / completed；记录 6382B84E-1F0A-4C2E-9A11-ABCDEF123456。已停止不等于用户目标已完成。',
    cards: [],
  }, extra);
}

const running = plainStatus(task({
  cards: [{
    id: 'call:git-1', call: 'git-1', kind: 'command', title: 'Bash', phase: 'running',
    execution: { command: 'git -C /repo pull https://github.com/org/repo.git' },
  }],
}));
assert.equal(running.sentence, 'WorkBuddy 正在用 git 拉代码，访问了 github.com');
assert.equal(running.running, true);
assert.equal(running.pill, '进行中');
assert.equal(running.statusChip, '进行中');
assert.equal(running.host, 'github.com');
assert.equal(running.toolChip, 'git');
assert.doesNotMatch(running.sentence, forbidden);

const toolOnly = plainStatus(task({
  agent: 'Cursor',
  cards: [{ id: 'call:1', call: '1', title: 'Bash', phase: 'running', kind: 'command', execution: { command: 'printf hello' } }],
}));
assert.equal(toolOnly.sentence, 'Cursor 正在用 bash 执行命令');
assert.equal(toolOnly.host, '');

const hostOnly = plainStatus(task({
  cards: [{ id: 'net-1', kind: 'web', title: '连接 · github.com', phase: 'recorded', resource: { domain: 'github.com', evidenceType: 'proxy_route' } }],
}));
assert.equal(hostOnly.sentence, 'WorkBuddy 正在访问 github.com');
assert.equal(hostOnly.toolChip, '未采到原生调用');
assert.doesNotMatch(hostOnly.sentence, /连接/);

const idle = plainStatus(task({ cards: [] }));
assert.equal(idle.sentence, 'WorkBuddy 正在运行 · 本轮尚未采到工具或外网');

const stopped = plainStatus(task({
  lifecycleStatus: 'stopped',
  completionEvidence: 'unknown',
  cards: [{ id: 'net-mtalk', kind: 'web', title: '连接 · mtalk.google.com', phase: 'recorded', resource: { domain: 'mtalk.google.com', evidenceType: 'socket' } }],
}));
assert.equal(stopped.sentence, 'WorkBuddy 已停止 · 上次外联 mtalk.google.com · 目标尚未确认');
assert.equal(stopped.running, false);
assert.equal(stopped.pill, '已停止');
assert.equal(stopped.toolChip, '未采到原生调用');
assert.equal(stopped.host, 'mtalk.google.com');
assert.doesNotMatch(stopped.sentence, forbidden);

const stoppedQuiet = plainStatus(task({ lifecycleStatus: 'stopped', cards: [] }));
assert.equal(stoppedQuiet.sentence, 'WorkBuddy 已停止 · 未见外网记录 · 目标尚未确认');

const confirmed = plainStatus(task({
  lifecycleStatus: 'stopped',
  completionEvidence: 'verified_delivery',
  cards: [{ id: 'net-2', kind: 'web', title: '连接 · example.com', resource: { domain: 'example.com' } }],
}));
assert.equal(confirmed.sentence, 'WorkBuddy 已停止 · 上次外联 example.com · 目标已确认');

const unknown = plainStatus(task({ agent: 'Codex', lifecycleStatus: 'observed', cards: [] }));
assert.equal(unknown.sentence, 'Codex 状态未确认 · 请查看证据');
assert.equal(unknown.pill, '未确认');
assert.equal(unknown.statusChip, '未确认');

const intentIgnored = plainStatus(task({
  lifecycleStatus: 'stopped',
  cards: [{ id: 'intent', kind: 'web', title: '连接 · secret.example', resource: { domain: 'secret.example', evidenceType: 'tool_intent' } }],
}));
assert.equal(intentIgnored.host, '');
assert.match(intentIgnored.sentence, /未见外网记录/);

const privateIgnored = plainStatus(task({
  cards: [{ id: 'call:c', call: 'c', title: 'Bash', phase: 'running', kind: 'command', execution: { command: 'curl https://127.0.0.1:9/local' } }],
}));
assert.equal(privateIgnored.host, '');
assert.equal(privateIgnored.toolChip, 'curl');
assert.equal(privateIgnored.sentence, 'WorkBuddy 正在用 curl 请求');

const latestHost = plainStatus(task({
  lifecycleStatus: 'stopped',
  cards: [
    { id: 'call:old', call: 'old', title: 'Bash', phase: 'returned', kind: 'command', execution: { command: 'git fetch https://github.com/org/repo.git' } },
    { id: 'net-new', kind: 'web', title: '连接 · mtalk.google.com', resource: { domain: 'mtalk.google.com' } },
  ],
}));
assert.equal(latestHost.host, 'mtalk.google.com');
assert.equal(latestHost.toolChip, 'git');
assert.equal(latestHost.sentence, 'WorkBuddy 已停止 · 上次外联 mtalk.google.com · 目标尚未确认');

assert.match(live, /function renderCurrentBar\(t\)/);
assert.match(live.slice(end, end + 900), /esc\(status\.sentence\)/);
assert.match(live.slice(end, end + 900), /esc\(status\.host\)/);
assert.match(live.slice(end, end + 900), /esc\(status\.toolChip\)/);
assert.match(live.slice(end, end + 900), /data-timeline="all"/);
assert.doesNotMatch(live.slice(start, end), /statusBasis|currentStep|nativeTerminalEventID/);

const css = fs.readFileSync(path.resolve(__dirname, '../../../Sources/AgentReins/Resources/RealtimeWorkspace/style.css'), 'utf8');
assert.match(css, /#current-bar\.plain-status\.running\{background:#f1f8f4/);
assert.match(css, /#current-bar\.plain-status\{[^}]*background:#f6f4fe/);
assert.match(css, /grid-template-rows:auto auto minmax\(120px,1fr\) auto auto auto 86px/);

console.log('PASS plain status sentences');
