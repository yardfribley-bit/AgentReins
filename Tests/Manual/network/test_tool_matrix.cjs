const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const window = {};
vm.runInNewContext(fs.readFileSync('Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js', 'utf8'), { window });
const api = window.AgentReinsNetwork;

function remote(id, flow, path, body, extra = {}) {
  return {
    id, agent: 'WorkBuddy', source: 'agentsight:workbuddy-network-body', kind: 'network',
    timestamp: extra.timestamp || '2026-10-17T08:00:00Z', session: 'wb-1', turn: extra.turn || 'turn-1',
    details: JSON.stringify({ requestPath: path, method: 'POST', websiteURL: extra.website || 'not captured' }),
    resource: { domain: 'copilot.tencent.com', method: 'POST', url: 'https://copilot.tencent.com' + path, remoteIP: '1.2.3.4', remotePort: 443, evidenceType: 'http' },
    networkBody: Object.assign({ flow: 'workbuddy-http:' + flow, request: JSON.stringify(body), requestComplete: true, responseComplete: extra.status ? true : undefined, responseStatus: extra.status, response: extra.response }, extra.body || {})
  };
}

const task = {
  id: 'visit', agent: 'WorkBuddy', session: 'wb-1', turn: 'turn-1',
  title: '查一下外网', originalRequest: '查一下外网', cards: []
};

api.setLocalTransports([
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl', startedAt: '2026-10-17T08:01:00Z', pid: 1, exitCode: 0, runID: 'curl-direct', session: 'wb-1', args: ['https://example.com/a'], connections: [{ kind: 'connected', detail: ['example.com:443'] }], blocks: [{ direction: 'send', kind: 'data', http: ['GET /a HTTP/1.1', 'Host: example.com', 'Authorization: Bearer sk-live-secret'] }, { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: 'direct ok' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl', startedAt: '2026-10-17T08:02:00Z', pid: 2, exitCode: 0, runID: 'curl-proxy', session: 'wb-1', args: ['https://www.baidu.com/'], connections: [{ kind: 'proxyTunnel', detail: ['www.baidu.com:443'] }, { kind: 'connected', detail: ['127.0.0.1:18891'] }], blocks: [{ direction: 'send', kind: 'data', http: ['GET / HTTP/1.1', 'Host: www.baidu.com'] }, { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: '<html><title>百度一下</title><body>新闻</body></html>' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl', startedAt: '2026-10-17T08:03:00Z', pid: 3, exitCode: 28, runID: 'curl-fail', session: 'wb-1', args: ['-I', 'https://github.com/org/repo'], connections: [{ kind: 'attempt', detail: ['140.82.112.3:443'] }, { kind: 'attempt', detail: ['140.82.112.4:443'] }, { kind: 'closed', detail: ['0'] }], blocks: [{ direction: 'send', kind: 'data', http: ['HEAD /org/repo HTTP/1.1', 'Host: github.com'] }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'git', startedAt: '2026-10-17T08:04:00Z', pid: 4, exitCode: 0, runID: 'git-push', session: 'wb-1', args: ['push', 'origin', 'main'], outboundFiles: ['notes.txt'], gitOperation: { operation: 'push' }, connections: [{ kind: 'proxyTunnel', detail: ['github.com:443'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'git push origin main' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'git', startedAt: '2026-10-17T08:05:00Z', pid: 5, exitCode: 0, runID: 'git-fetch', session: 'wb-1', args: ['fetch', 'origin'], gitOperation: { operation: 'fetch' }, connections: [{ kind: 'connected', detail: ['github.com:443'] }], blocks: [{ direction: 'receive', kind: 'data', textPreview: 'fetched' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'git', startedAt: '2026-10-17T08:06:00Z', pid: 6, exitCode: 0, runID: 'git-diff', session: 'wb-1', args: ['diff'], gitOperation: { operation: 'diff' }, connections: [], blocks: [] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'gh', startedAt: '2026-10-17T08:07:00Z', pid: 7, exitCode: 0, runID: 'gh-api', session: 'wb-1', args: ['api', 'repos/org/name'], connections: [{ kind: 'connected', detail: ['api.github.com:443'] }], blocks: [{ direction: 'receive', kind: 'data', http: ['HTTP/2 200'], textPreview: '{"ok":true}' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'gh', startedAt: '2026-10-17T08:08:00Z', pid: 8, exitCode: 1, runID: 'gh-pr', session: 'wb-1', args: ['pr', 'list', '--hostname', 'github-acme', '--repo', 'acme/app'], connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'pr list --hostname github-acme --repo acme/app' }, { direction: 'receive', kind: 'data', textPreview: 'unknown flag: --hostname' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'gh', startedAt: '2026-10-17T08:09:00Z', pid: 9, exitCode: 0, runID: 'gh-version', session: 'wb-1', args: ['--version'], connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: '--version' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'wget', startedAt: '2026-10-17T08:10:00Z', pid: 10, exitCode: 0, runID: 'wget-1', session: 'wb-1', args: ['https://downloads.example.com/pkg.tgz'], downloads: [{ path: '/tmp/pkg.tgz', bytes: 12, sha256: '0123456789abcdef0123456789abcdef', state: 'verified' }], connections: [{ kind: 'connected', detail: ['downloads.example.com:443'] }], blocks: [{ direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 OK'], textPreview: 'pkg' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'brew', startedAt: '2026-10-17T08:10:30Z', pid: 16, exitCode: 0, runID: 'brew-1', session: 'wb-1', args: ['install', 'wget'], formulas: ['wget'], downloads: [{ path: '/Users/jatsmith/Library/Caches/Homebrew/downloads/wget-1.25.0.bottle.tar.gz', bytes: 4096, sha256: 'fedcba9876543210fedcba9876543210', state: 'verified', source: 'https://ghcr.io/v2/homebrew/core/wget' }], connections: [{ kind: 'connected', detail: ['ghcr.io'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'install wget' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'ssh', startedAt: '2026-10-17T08:11:00Z', pid: 11, exitCode: 0, runID: 'ssh-1', session: 'wb-1', args: ['git@github.com'], gap: '通道是加密的。这里保留本机命令、目标和详细会话日志，不是解密后的通道字节。', connections: [{ kind: 'connected', detail: ['git@github.com'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'git@github.com' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'scp', startedAt: '2026-10-17T08:12:00Z', pid: 12, exitCode: 0, runID: 'scp-1', session: 'wb-1', args: ['report.bin', 'user@backup.example.com:/data/report.bin'], outboundFiles: ['report.bin'], connections: [{ kind: 'connected', detail: ['user@backup.example.com:/data/report.bin'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'report.bin user@backup.example.com:/data/report.bin' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'rsync', startedAt: '2026-10-17T08:13:00Z', pid: 13, exitCode: 0, runID: 'rsync-1', session: 'wb-1', args: ['-a', 'photos.tar', 'user@files.example.net:/incoming'], outboundFiles: ['photos.tar'], connections: [{ kind: 'connected', detail: ['user@files.example.net:/incoming'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'photos.tar' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'sftp', startedAt: '2026-10-17T08:13:30Z', pid: 15, exitCode: 0, runID: 'sftp-1', session: 'wb-1', args: ['user@files.example.net'], gap: '通道是加密的。这里保留本机命令、目标和详细会话日志，不是解密后的通道字节。', connections: [{ kind: 'connected', detail: ['user@files.example.net'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'user@files.example.net' }] },
  { captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'curl', startedAt: '2026-10-17T08:14:00Z', pid: 14, exitCode: 0, runID: 'local-only', session: 'wb-1', args: ['http://127.0.0.1:8766/'], connections: [{ kind: 'connected', detail: ['127.0.0.1:8766'] }], blocks: [{ direction: 'send', kind: 'data', http: ['GET / HTTP/1.1', 'Host: 127.0.0.1:8766'] }] }
]);
api.setCapturedBodies([
  remote('wf', 'wf', '/agenttool/v1/webfetch', { url: 'https://www.baidu.com/', prompt: '提取标题' }, { timestamp: '2026-10-17T08:00:30Z', status: 200, response: '{"title":"百度一下"}', website: 'https://www.baidu.com/' }),
  remote('search', 'search', '/agenttool/v1/search', { query: 'agent security' }, { timestamp: '2026-10-17T08:00:40Z', status: 200, response: '{"results":[{"title":"结果"}]}' }),
  remote('video', 'video', '/v2/videos/generations', { prompt: '一只猫在跑' }, { timestamp: '2026-10-17T08:00:50Z', status: 200, response: '{"id":"vid"}' }),
  remote('wf-fail', 'wf-fail', '/agenttool/v1/webfetch', { url: 'https://down.example/missing' }, { timestamp: '2026-10-17T08:15:00Z', status: 502, response: 'bad gateway', turn: 'turn-2' }),
  remote('model', 'model', '/v2/chat/completions', { messages: [{ role: 'user', content: '你好' }] }, { timestamp: '2026-10-17T08:16:00Z', status: 200, response: '好的', turn: 'turn-2' })
]);

const holder = { innerHTML: '' };
api.render(holder, { tasks: [task], collected: [] }, { taskOnly: 'visit' });
const html = holder.innerHTML;
const text = html.replace(/<[^>]+>/g, '\n');

function has(needle) { assert.match(html, needle); }
function lacks(needle) { assert.doesNotMatch(html, needle); }

has(/<thead><tr><th>时间<\/th><th>谁<\/th><th>去了哪里<\/th><th>协议<\/th><th>结果<\/th>/);
lacks(/<th>任务<\/th>/);
has(/查一下外网/);
has(/WebFetch<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了 百度一下/);
has(/搜索<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了 结果/);
has(/视频生成<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了一段结果/);
has(/curl<\/td><td>example\.com<\/td><td>HTTP\/1\.1<\/td><td>通了/);
has(/www\.baidu\.com<\/td><td>HTTP\/1\.1<\/td><td>通了/);
has(/github\.com<\/td><td>HTTP\/1\.1<\/td><td>没连上/);
has(/github\.com<\/td><td>连接<\/td><td>带走了 notes\.txt/);
has(/Git fetch/);
has(/api\.github\.com<\/td><td>HTTP\/2<\/td><td>通了/);
has(/github-acme\/acme\/app<\/td><td>连接<\/td><td>没连上/);
has(/downloads\.example\.com/);
has(/下载了 pkg\.tgz/);
has(/安装包<\/td><td>下载了 wget-1\.25\.0\.bottle\.tar\.gz/);
has(/git@github\.com<\/td><td>加密通道<\/td><td>看不到通道里的内容/);
has(/report\.bin<\/td>/);
has(/photos\.tar<\/td>/);
has(/files\.example\.net<\/td><td>加密通道<\/td><td>看不到通道里的内容/);
has(/对方返回 502/);
has(/模型接口/);
has(/模型服务/);
lacks(/Git diff/);
lacks(/--version/);
lacks(/127\.0\.0\.1/);
lacks(/sk-live-secret/);
lacks(/Bearer/);
lacks(/经代理连通/);
lacks(/命令退出/);

const curlAt = html.indexOf('example.com</td>');
const fetchAt = html.indexOf('WebFetch');
assert.ok(fetchAt >= 0 && fetchAt < curlAt, 'task page keeps time order');

const all = { innerHTML: '' };
api.render(all, { tasks: [task], collected: [] });
assert.match(all.innerHTML, /<th>任务<\/th>/);
assert.ok(all.innerHTML.indexOf('任务') < all.innerHTML.indexOf('时间'));
assert.match(all.innerHTML, /模型接口/);
assert.match(all.innerHTML, /模型服务/);
assert.match(all.innerHTML, /没成/);
assert.match(all.innerHTML, /对方返回 502/);
const failedTool = { innerHTML: '' };
api.render(failedTool, { tasks: [task], collected: [] }, { selected: 'wf-fail' });
assert.match(failedTool.innerHTML, /https:\/\/down\.example\/missing/);
assert.match(failedTool.innerHTML, /本机和远程工具之间的交互/);
assert.doesNotMatch(all.innerHTML, /127\.0\.0\.1/);
assert.doesNotMatch(all.innerHTML, /sk-live-secret/);

const rows = (all.innerHTML.match(/<tr/g) || []).length - 1;
assert.ok(rows >= 17, 'expected the remote and local visits, got ' + rows);
const detail = { innerHTML: '' };
api.render(detail, { tasks: [task], collected: [] }, { taskOnly: 'visit', selected: 'local-transport:curl-proxy' });
assert.match(detail.innerHTML, /网页《百度一下》/);
assert.doesNotMatch(detail.innerHTML, /sk-live-secret/);
api.render(detail, { tasks: [task], collected: [] }, { taskOnly: 'visit', selected: 'local-transport:curl-direct' });
assert.doesNotMatch(detail.innerHTML, /sk-live-secret/);
assert.doesNotMatch(detail.innerHTML, /Bearer/);
api.render(detail, { tasks: [task], collected: [] }, { taskOnly: 'visit', selected: 'local-transport:gh-pr' });
assert.match(detail.innerHTML, /unknown flag: --hostname/);
api.render(detail, { tasks: [task], collected: [] }, { taskOnly: 'visit', selected: 'local-transport:wget-1' });
assert.match(detail.innerHTML, /下载了 pkg\.tgz/);
assert.match(detail.innerHTML, /12 字节/);
assert.match(detail.innerHTML, /sha256 0123456789abcdef/);
api.render(detail, { tasks: [task], collected: [] }, { taskOnly: 'visit', selected: 'local-transport:brew-1' });
assert.match(detail.innerHTML, /要安装 wget/);
assert.match(detail.innerHTML, /4096 字节/);
api.setCapturedBodies([]);
api.setLocalTransports([]);
const cursor = {
  id: 'cursor-task', agent: 'Cursor', session: '3ab77d48', turn: 'turn-now',
  title: '看看这次任务', originalRequest: '看看这次任务',
  cards: [
    { id: 'fetch-1', kind: 'web', title: 'WebFetch', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:00:00Z', input: JSON.stringify({ url: 'https://example.com/', prompt: '读取标题' }), output: 'Example Domain' },
    { id: 'search-1', kind: 'web', title: 'WebSearch', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:01:00Z', input: JSON.stringify({ search_term: 'agent network audit' }), output: '找到 2 条' },
    { id: 'curl-1', kind: 'command', title: 'Shell', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:02:00Z', execution: { command: 'curl https://www.baidu.com/', exitCode: 0 }, output: '<html><title>百度一下</title></html>' },
    { id: 'node-1', kind: 'command', title: 'Shell', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:03:00Z', execution: { command: 'node Tests/Manual/network/test_tool_matrix.cjs', exitCode: 0 }, output: 'ok' },
    { id: 'git-1', kind: 'command', title: 'run_terminal_command_v2', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:04:00Z', input: JSON.stringify({ command: 'git ls-remote https://github.com/github/gitignore HEAD' }), output: 'abc\tHEAD' }
  ]
};
const cursorPage = { innerHTML: '' };
api.render(cursorPage, { tasks: [cursor], collected: [] }, { taskOnly: 'cursor-task', selected: 'task-tool:curl-1' });
assert.match(cursorPage.innerHTML, /WebFetch<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了 Example Domain/);
assert.match(cursorPage.innerHTML, /搜索<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了 找到 2 条/);
assert.match(cursorPage.innerHTML, /https:\/\/www\.baidu\.com\/<\/td><td>连接<\/td><td>通了/);
assert.match(cursorPage.innerHTML, /网页《百度一下》/);
assert.match(cursorPage.innerHTML, /Git ls-remote/);
assert.match(cursorPage.innerHTML, /github\.com\/github\/gitignore/);
assert.doesNotMatch(cursorPage.innerHTML, /test_tool_matrix/);
assert.equal((cursorPage.innerHTML.match(/data-network-record=/g) || []).length, 4);
assert.match(cursorPage.innerHTML, /aria-pressed="true">收起<\/button><\/td><\/tr><tr class="network-read-row"[\s\S]*网页《百度一下》[\s\S]*Git ls-remote/);

api.setLocalTransports([
  { captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-17T11:27:01Z', pid: 1, exitCode: 0, runID: 'ex', session: '3ab77d48', args: ['-fsS', 'https://example.com/'], connections: [{ kind: 'proxyTunnel', detail: ['example.com:443'] }, { kind: 'connected', detail: ['127.0.0.1 port 18891'] }], blocks: [{ direction: 'send', kind: 'header', http: ['CONNECT example.com:443 HTTP/1.1', 'GET / HTTP/2', 'Host: example.com'] }, { direction: 'receive', kind: 'header', http: ['HTTP/1.1 200 Connection established', 'HTTP/2 200 '] }, { direction: 'receive', kind: 'data', observedBytes: 0 }] },
  { captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-17T11:27:05Z', pid: 2, exitCode: 56, runID: 'missing', session: '3ab77d48', args: ['-fsS', 'https://no-such-agentreins.example/'], connections: [{ kind: 'proxyTunnel', detail: ['no-such-agentreins.example:443'] }], blocks: [{ direction: 'receive', kind: 'header', http: ['HTTP/1.1 200 Connection established', 'HTTP/2 502 '] }] },
  { captureMode: 'agent-path', agent: 'Cursor', tool: 'gh', startedAt: '2026-10-17T11:27:04Z', pid: 3, exitCode: 1, runID: 'rate', session: '3ab77d48', args: ['api', 'rate_limit'], connections: [{ kind: 'attempt', detail: ['api.github.com'] }], blocks: [{ direction: 'receive', kind: 'data', http: ['HTTP/2.0 200 OK'], textPreview: '{"resources":{"core":{"limit":5000}}}' }] },
  { captureMode: 'agent-path', agent: 'Cursor', tool: 'git', startedAt: '2026-10-17T11:27:03Z', pid: 4, exitCode: 128, runID: 'ls', session: '3ab77d48', args: ['ls-remote', 'https://github.com/github/gitignore', 'HEAD'], gitOperation: { operation: 'ls-remote' }, connections: [{ kind: 'proxyTunnel', detail: ['github.com:443'] }, { kind: 'attempt', detail: ['127.0.0.1:1081'] }], blocks: [{ direction: 'receive', kind: 'header', http: ['HTTP/1.1 200 Connection established'] }, { direction: 'receive', kind: 'data', textPreview: 'error setting certificate verify locations:  CAfile:  CApath: none' }] }
]);
const shown = { innerHTML: '' };
api.render(shown, { tasks: [{ id: 'now', agent: 'Cursor', session: '3ab77d48', turn: 't', title: '这次', originalRequest: '这次', cards: [{ id: 'fetch-live', kind: 'web', title: 'WebFetch', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:26:00Z', input: JSON.stringify({ url: 'https://example.com/' }), output: 'Example Domain' }] }] }, { taskOnly: 'now' });
const live = shown.innerHTML;
assert.match(live, /no-such-agentreins\.example<\/td><td>HTTP\/2<\/td><td>对方返回 502/);
assert.match(live, /api\.github\.com<\/td><td>HTTP\/2<\/td><td>网站回了 200，命令失败/);
assert.doesNotMatch(live, /未连通|命令退出|Connection established/);
assert.match(live, /github.com<\/td><td>连接<\/td><td>证书没配好/);
assert.doesNotMatch(live, /certificate verify locations/);
assert.match(live, /WebFetch<\/td><td>远程访问工具<\/td><td>工具调用<\/td><td>收回了 Example Domain/);
assert.match(live, /example\.com<\/td><td>HTTP\/2<\/td><td>通了/);
const fetchDetail = { innerHTML: '' };
api.render(fetchDetail, { tasks: [{ id: 'now', agent: 'Cursor', session: '3ab77d48', turn: 't', title: '这次', originalRequest: '这次', cards: [{ id: 'fetch-live', kind: 'web', title: 'WebFetch', status: 'returned', phase: 'returned', timestamp: '2026-10-17T11:26:00Z', input: JSON.stringify({ url: 'https://example.com/' }), output: 'Example Domain' }] }] }, { taskOnly: 'now', selected: 'task-tool:fetch-live' });
assert.match(fetchDetail.innerHTML, /送出/);
assert.match(fetchDetail.innerHTML, /收回/);
assert.match(fetchDetail.innerHTML, /https:\/\/example.com\//);
assert.match(fetchDetail.innerHTML, /Example Domain/);
assert.match(fetchDetail.innerHTML, /本机和远程工具之间的交互/);
assert.doesNotMatch(fetchDetail.innerHTML, /远程工具访问，本机没有这次连接/);
console.log('tool matrix ok', rows);
