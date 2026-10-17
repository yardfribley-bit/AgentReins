const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const window = {};
vm.runInNewContext(fs.readFileSync('Sources/AgentReins/Resources/RealtimeWorkspace/network-view.js', 'utf8'), { window });
const api = window.AgentReinsNetwork;

const remote = api.accessHop({
  agent: 'WorkBuddy',
  serviceURL: 'https://copilot.tencent.com/agenttool/v1/webfetch',
  requestObject: { url: 'https://www.baidu.com' }
});
assert.strictEqual(remote.kind, 'remote-tool');
assert.strictEqual(remote.delegated, 'https://www.baidu.com');
assert.match(remote.notice, /远程访问工具/);
assert.match(remote.notice, /不是网站原始 HTTP/);

const model = api.accessHop({ serviceURL: 'https://copilot.tencent.com/v2/chat/completions', agent: 'WorkBuddy' });
assert.strictEqual(model.kind, 'model');

const [local] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Codex', tool: 'curl', startedAt: '2026-10-14T00:00:00Z', pid: 7, exitCode: 0, runID: 'abc',
  codexThreadID: 'thread-1',
  connections: [{ kind: 'proxyTunnel', detail: ['www.baidu.com:443'] }, { kind: 'connected', detail: ['127.0.0.1:1087'] }],
  blocks: [
    { direction: 'send', kind: 'header', observedBytes: 40, http: ['GET / HTTP/1.1', 'Host: www.baidu.com'] },
    { direction: 'send', kind: 'data', observedBytes: 0 },
    { direction: 'receive', kind: 'header', observedBytes: 20, http: ['HTTP/1.1 200 OK'] },
    { direction: 'receive', kind: 'data', observedBytes: 227, textPreview: '<html>baidu</html>' }
  ]
}]);
assert.strictEqual(local.accessKind, 'local-tool');
assert.strictEqual(local.host, 'www.baidu.com:443');
assert.strictEqual(local.networkBody.requestBytes, 0);
assert.strictEqual(local.networkBody.responseBytes, 227);
assert.match(local.networkBody.request, /GET \/ HTTP\/1.1/);
assert.match(local.networkBody.response, /baidu/);
const hop = api.accessHop(local);
assert.strictEqual(hop.kind, 'local-tool');
assert.match(hop.localParty, /Codex/);
assert.match(hop.remoteParty, /baidu/);

const html = api.taskExchangeMarkup(local);
assert.match(html, /带出去的资源/);
assert.match(html, /带回来的资源/);
assert.match(html, /本机访问工具与访问目标/);
assert.match(html, /本机工具发给访问目标/);
assert.match(html, /访问目标返回给本机工具/);
assert.match(html, /baidu/);
assert.doesNotMatch(html, /不是网站原始 HTTP/);

const remoteHtml = api.taskExchangeMarkup({
  agent: 'WorkBuddy',
  serviceURL: 'https://copilot.tencent.com/agenttool/v1/webfetch',
  host: 'copilot.tencent.com',
  requestObject: { url: 'https://www.baidu.com', prompt: '提取标题' },
  networkBody: { flow: 'f', request: '{"url":"https://www.baidu.com"}', response: '{"title":"百度"}', requestBytes: 30, responseBytes: 20 }
});
assert.match(remoteHtml, /带出去的资源/);
assert.match(remoteHtml, /带回来的资源/);
assert.match(remoteHtml, /远程访问工具/);
assert.match(remoteHtml, /不是网站原始 HTTP/);
assert.match(remoteHtml, /带走的内容/);
assert.match(remoteHtml, /提取标题/);
assert.match(remoteHtml, /百度/);
assert.doesNotMatch(remoteHtml, /本机访问工具与访问目标/);

const search = api.accessHop({
  agent: 'WorkBuddy',
  serviceURL: 'https://copilot.tencent.com/agenttool/v1/search',
  requestObject: { query: 'agent security' }
});
assert.strictEqual(search.kind, 'remote-tool');
assert.strictEqual(search.delegated, 'agent security');
const video = api.accessHop({ agent: 'WorkBuddy', serviceURL: 'https://copilot.tencent.com/v2/videos/generations' });
assert.strictEqual(video.kind, 'remote-tool');
const direct = api.accessHop({ source: 'agentsight:workbuddy-network-body', host: 'www.baidu.com', agent: 'WorkBuddy' });
assert.strictEqual(direct.kind, 'local-tool');
assert.match(direct.remoteParty, /baidu/);
const [wget] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Codex', tool: 'wget', startedAt: '2026-10-14T00:00:00Z', pid: 9, exitCode: 0, runID: 'wget-1',
  connections: [{ kind: 'proxyTunnel', detail: ['https://example.com/file'] }, { kind: 'connected', detail: ['127.0.0.1:1087'] }],
  blocks: [{ direction: 'send', kind: 'data', observedBytes: 28, textPreview: 'https://example.com/file' }, { direction: 'receive', kind: 'data', observedBytes: 12, textPreview: 'debug log' }]
}]);
assert.strictEqual(wget.tool, 'wget');
assert.strictEqual(wget.accessKind, 'local-tool');
assert.strictEqual(wget.route, 'proxied');
assert.match(api.taskExchangeMarkup(wget), /经过代理/);
const [directTool] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'nc', startedAt: '2026-10-14T00:00:00Z', pid: 3, exitCode: 0, runID: 'nc-1',
  connections: [{ kind: 'connected', detail: ['example.com port 443'] }],
  blocks: [{ direction: 'send', kind: 'data', observedBytes: 4, textPreview: 'GET' }, { direction: 'receive', kind: 'data', observedBytes: 2, textPreview: 'OK' }]
}]);
assert.strictEqual(directTool.route, 'direct');
assert.strictEqual(directTool.taskTitle, 'nc 访问');
const [upload] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'WorkBuddy', tool: 'scp', startedAt: '2026-10-17T00:00:00Z', pid: 4, exitCode: 0, runID: 'scp-1', outboundFiles: ['special-file.txt'],
  connections: [{ kind: 'connected', detail: ['github.com port 22'] }],
  blocks: [{ direction: 'send', kind: 'data', observedBytes: 4, textPreview: 'scp' }]
}]);
assert.match(upload.networkBody.request, /外传文件名/);
assert.match(upload.networkBody.request, /special-file\.txt/);
assert.match(api.taskExchangeMarkup(directTool), /直连访问目标/);
assert.match(api.accessHop({ accessHop: 'local-target', host: 'example.com', agent: 'Codex' }).notice, /直连/);
const ignored = api.projectLocal([{ captureMode: 'manual', agent: 'Codex', tool: 'curl' }, { captureMode: 'agent-path', agent: 'Other', tool: 'curl' }]);
assert.strictEqual(ignored.length, 0);
const [cursorPush] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'git', startedAt: '2026-10-17T00:00:00Z', pid: 11, exitCode: 0, runID: 'cursor-push', outboundFiles: ['cursor-audit-probe.txt'],
  gitOperation: { operation: 'push' },
  connections: [{ kind: 'connected', detail: ['github.com'] }],
  blocks: [{ direction: 'send', kind: 'data', observedBytes: 8, textPreview: 'git push' }]
}]);
assert.strictEqual(cursorPush.agent, 'Cursor');
assert.match(cursorPush.networkBody.request, /cursor-audit-probe\.txt/);
assert.match(api.taskExchangeMarkup(cursorPush), /上传的文件/);
assert.match(api.taskExchangeMarkup(cursorPush), /cursor-audit-probe\.txt/);
const [saved] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-17T00:00:00Z', pid: 12, exitCode: 0, runID: 'curl-save',
  fileResult: { path: '/tmp/cursor-audit-curl-head.txt', bytes: 10, state: 'verified' },
  connections: [{ kind: 'proxyTunnel', detail: ['example.com:443'] }],
  blocks: [{ direction: 'receive', kind: 'data', observedBytes: 10, textPreview: 'ok' }]
}]);
assert.strictEqual(saved.downloadedFiles.join(','), 'cursor-audit-curl-head.txt');
const holder = { innerHTML: '', querySelectorAll: () => [] };
api.setLocalTransports([
  { captureMode: 'agent-path', agent: 'Cursor', tool: 'git', startedAt: '2026-10-17T08:00:00Z', pid: 11, exitCode: 0, runID: 'cursor-push', session: 'chat-1', outboundFiles: ['cursor-audit-probe.txt'], gitOperation: { operation: 'push' }, connections: [{ kind: 'proxyTunnel', detail: ['github.com:443'] }, { kind: 'connected', detail: ['127.0.0.1:1081'] }], blocks: [{ direction: 'send', kind: 'data', observedBytes: 20, textPreview: 'git push origin main' }, { direction: 'receive', kind: 'data', observedBytes: 8, textPreview: 'main -> main' }] },
  { captureMode: 'agent-path', agent: 'Codex', tool: 'git', startedAt: '2026-10-17T07:00:00Z', pid: 9, exitCode: 0, runID: 'old-diff', gitOperation: { operation: 'diff' }, connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }], blocks: [] }
]);
api.render(holder, { tasks: [{ id: 't', agent: 'Cursor', session: 'chat-1', title: '上传探针文件', cards: [] }], collected: [] });
assert.match(holder.innerHTML, /全部外网访问/);
const homeHead=holder.innerHTML.match(/<thead>[\s\S]*?<\/thead>/)[0];
assert.ok(homeHead.indexOf('任务')>=0&&homeHead.indexOf('任务')<homeHead.indexOf('时间'));
assert.match(holder.innerHTML, /上传探针文件/);
assert.match(holder.innerHTML, /谁/);
assert.match(holder.innerHTML, /协议/);
assert.match(holder.innerHTML, /cursor-audit-probe\.txt/);
assert.match(holder.innerHTML, /协议/);
assert.match(holder.innerHTML, /带走了 cursor-audit-probe\.txt/);
assert.match(holder.innerHTML, /带走了 cursor-audit-probe\.txt/);
assert.match(holder.innerHTML, /去了哪里/);
assert.match(holder.innerHTML, /github\.com/);
assert.match(holder.innerHTML, /Git push/);
assert.doesNotMatch(holder.innerHTML, /127\.0\.0\.1/);
const [localOnly] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-17T09:00:00Z', pid: 21, exitCode: 0, runID: 'local-preview',
  fileResult: { path: '/dev/null', state: 'unavailable' },
  connections: [{ kind: 'connected', detail: ['127.0.0.1 (127.0.0.1) port 8769'] }],
  blocks: [{ direction: 'send', kind: 'data', http: ['GET /index.html HTTP/1.1', 'Host: 127.0.0.1:8769'] }]
}]);
assert.strictEqual(localOnly, undefined);
const [localGh] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'gh', startedAt: '2026-10-17T09:03:00Z', pid: 24, exitCode: 1, runID: 'gh-local',
  connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }],
  blocks: [{ direction: 'send', kind: 'data', textPreview: '--version' }]
}]);
assert.strictEqual(localGh, undefined);
const [ghRepo] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'gh', startedAt: '2026-10-17T10:33:20Z', pid: 50, exitCode: 1, runID: 'gh-pr',
  connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }],
  blocks: [{ direction: 'send', kind: 'data', textPreview: 'pr list --hostname github-tajleonbennis --repo tajleonbennis-maker/secretwatcher --json url,state' }, { direction: 'receive', kind: 'data', textPreview: 'unknown flag: --hostname' }]
}]);
assert.strictEqual(ghRepo.host, 'github-tajleonbennis/tajleonbennis-maker/secretwatcher');
assert.match(ghRepo.args.join(' '), /--hostname github-tajleonbennis/);
const ghHolder = { innerHTML: '' };
api.render(ghHolder, { tasks: [], collected: [] });
api.setLocalTransports([{ captureMode: 'agent-path', agent: 'Cursor', tool: 'gh', startedAt: '2026-10-17T10:33:20Z', pid: 50, exitCode: 1, runID: 'gh-pr', connections: [{ kind: 'connected', detail: ['目标未从命令解析'] }], blocks: [{ direction: 'send', kind: 'data', textPreview: 'pr list --hostname github-tajleonbennis --repo tajleonbennis-maker/secretwatcher --json url,state' }, { direction: 'receive', kind: 'data', textPreview: 'unknown flag: --hostname' }] }]);
api.render(ghHolder, { tasks: [], collected: [] });
assert.match(ghHolder.innerHTML, /github-tajleonbennis\/tajleonbennis-maker\/secretwatcher/);
assert.match(ghHolder.innerHTML, /没连上/);
assert.doesNotMatch(ghHolder.innerHTML, /连通/);
const [proxiedSite] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'curl', startedAt: '2026-10-17T09:01:00Z', pid: 22, exitCode: 0, runID: 'via-proxy',
  connections: [{ kind: 'proxyTunnel', detail: ['example.com:443'] }, { kind: 'connected', detail: ['127.0.0.1 (127.0.0.1) port 18891'] }],
  blocks: [{ direction: 'send', kind: 'data', http: ['CONNECT example.com:443 HTTP/1.1', 'HEAD / HTTP/2', 'Host: example.com'] }, { direction: 'receive', kind: 'data', http: ['HTTP/1.1 200 Connection established', 'HTTP/2 200'] }]
}]);
assert.strictEqual(proxiedSite.host, 'example.com:443');
assert.strictEqual(proxiedSite.route, 'proxied');
assert.doesNotMatch(api.taskExchangeMarkup(proxiedSite), /127\.0\.0\.1/);
const [ghHost] = api.projectLocal([{
  captureMode: 'agent-path', agent: 'Cursor', tool: 'gh', startedAt: '2026-10-17T09:02:00Z', pid: 23, exitCode: 0, runID: 'gh-host',
  connections: [{ kind: 'connected', detail: ['127.0.0.1 (127.0.0.1) port 18891'] }],
  blocks: [{ direction: 'send', kind: 'data', textPreview: '> Host: api.github.com\n> Authorization: token secret-value\n> GET /zen' }, { direction: 'receive', kind: 'data', textPreview: '< HTTP/2.0 200 OK' }]
}]);
assert.strictEqual(ghHost.host, 'api.github.com');
assert.doesNotMatch(String(ghHost.networkBody.request), /secret-value/);
assert.match(holder.innerHTML, /带走了 cursor-audit-probe\.txt/);
assert.match(holder.innerHTML, /cursor-audit-probe\.txt/);
assert.doesNotMatch(holder.innerHTML, /git push origin main/);
assert.doesNotMatch(holder.innerHTML, /main -&gt; main/);
assert.doesNotMatch(holder.innerHTML, /old-diff|Git diff/);
assert.match(holder.innerHTML, /打开/);
const taskHolder = { innerHTML: '', querySelectorAll: () => [] };
api.render(taskHolder, { tasks: [{ id: 'hb', agent: 'Cursor', session: 's', title: '<heartbeat><automation_id>agentreins</automation_id>', originalRequest: '<heartbeat><automation_id>agentreins</automation_id>', cards: [] }], collected: [] }, { taskOnly: 'hb' });
assert.match(taskHolder.innerHTML, /机器标记/);
assert.match(taskHolder.innerHTML, /返回任务过程/);
assert.doesNotMatch(taskHolder.innerHTML, /automation_id|<heartbeat>/);

const page='<!doctype html><html><head><title>百度新闻——海量中文资讯平台</title><script>secret()</script></head><body><h1>热点要闻</h1></body></html>';
const baidu={
  id:'baidu-news', agent:'WorkBuddy', source:'agentsight:workbuddy-network-body', kind:'network', timestamp:'2026-10-17T06:53:45Z',
  session:'workbuddy-network:flow-news', turn:'flow-news',
  details:JSON.stringify({requestPath:'/', method:'GET', websiteURL:'not captured', responseStatus:200}),
  resource:{domain:'news.baidu.com', remoteIP:'39.156.68.124', remotePort:443, method:'GET', url:'https://news.baidu.com/', evidenceType:'http'},
  networkBody:{flow:'workbuddy-http:flow-news', request:'', response:page, requestBytes:0, responseBytes:page.length, requestComplete:true, responseComplete:true, responseStatus:200, securityAudit:{findings:[], destinationHost:'news.baidu.com'}}
};
const head={
  id:'baidu-home', agent:'WorkBuddy', source:'agentsight:workbuddy-network-body', kind:'network', timestamp:'2026-10-17T06:51:43Z',
  session:'workbuddy-network:flow-home', turn:'flow-home',
  details:JSON.stringify({requestPath:'/', method:'HEAD', responseStatus:200}),
  resource:{domain:'www.baidu.com', remoteIP:'110.242.68.66', remotePort:443, method:'HEAD', url:'https://www.baidu.com/', evidenceType:'http'},
  networkBody:{flow:'workbuddy-http:flow-home', request:'', response:'', requestBytes:0, responseBytes:0, requestComplete:true, responseComplete:true, responseStatus:200, securityAudit:{findings:[]}}
};
const visitTask={id:'visit', agent:'WorkBuddy', session:'wb-session', title:'访问一下百度', originalRequest:'访问一下百度', cards:[{id:'call:1', kind:'web', title:'WebFetch', input:'{"url":"https://news.baidu.com/"}', output:'', summary:'', resource:{url:'https://www.baidu.com/'}}]};
const pageHolder={innerHTML:'', querySelectorAll:()=>[]};
api.render(pageHolder,{tasks:[visitTask], collected:[baidu, head], processes:[], ipGeolocations:[]},{selected:'baidu-news'});
const allHead=pageHolder.innerHTML.match(/<thead>[\s\S]*?<\/thead>/)[0];
assert.ok(allHead.indexOf('任务')<allHead.indexOf('时间'));
assert.match(pageHolder.innerHTML, /https:\/\/news\.baidu\.com\//);
assert.match(pageHolder.innerHTML, /WebFetch/);
assert.match(pageHolder.innerHTML, /网页《百度新闻——海量中文资讯平台》/);
assert.match(pageHolder.innerHTML, /只要了头信息/);
assert.match(pageHolder.innerHTML, /网页《百度新闻——海量中文资讯平台》/);
assert.match(pageHolder.innerHTML, /热点要闻/);
assert.doesNotMatch(pageHolder.innerHTML, /安全检查：已查看发出和返回的正文/);
assert.match(pageHolder.innerHTML, /访问一下百度/);
assert.doesNotMatch(pageHolder.innerHTML, /<!doctype|<script|secret\(\)/);
const scoped={innerHTML:'', querySelectorAll:()=>[]};
api.setLocalTransports([{captureMode:'agent-path', agent:'WorkBuddy', tool:'curl', startedAt:'2026-10-17T06:55:00Z', pid:30, exitCode:0, runID:'curl-baidu', session:'wb-session', connections:[{kind:'connected', detail:['www.example.com:443']}], blocks:[{direction:'send', kind:'data', http:['GET /probe HTTP/1.1','Host: www.example.com']},{direction:'receive', kind:'data', textPreview:'probe ok'}]}]);
api.render(scoped,{tasks:[visitTask], collected:[baidu, head], processes:[], ipGeolocations:[]},{taskOnly:'visit'});
assert.match(scoped.innerHTML, /<strong>3<\/strong><span>出去了<\/span>/);
const taskHead=scoped.innerHTML.match(/<thead>[\s\S]*?<\/thead>/)[0];
assert.ok(taskHead.startsWith('<thead><tr><th>时间</th>'));
assert.doesNotMatch(taskHead, /任务/);
const headAt=scoped.innerHTML.indexOf('www.baidu.com');
const getAt=scoped.innerHTML.indexOf('news.baidu.com');
const curlAt=scoped.innerHTML.indexOf('>curl<');
assert.ok(headAt>=0&&headAt<getAt&&getAt<curlAt);
const retryHolder={innerHTML:'', querySelectorAll:()=>[]};
api.setLocalTransports([
  {captureMode:'agent-path', agent:'Cursor', tool:'curl', startedAt:'2026-10-17T10:00:00Z', pid:41, exitCode:28, runID:'gh-retry-1', session:'repo-chat', args:['-I','https://github.com/org/repo'], connections:[{kind:'attempt',detail:['140.82.112.3:443']},{kind:'attempt',detail:['140.82.112.4:443']},{kind:'attempt',detail:['140.82.114.3:443']},{kind:'closed',detail:['0']}], blocks:[{direction:'send',kind:'data',http:['HEAD /org/repo HTTP/1.1','Host: github.com']}]},
  {captureMode:'agent-path', agent:'Cursor', tool:'curl', startedAt:'2026-10-17T10:01:00Z', pid:42, exitCode:0, runID:'gh-retry-2', session:'repo-chat', args:['-I','https://github.com/org/repo'], connections:[{kind:'attempt',detail:['140.82.112.3:443']},{kind:'connected',detail:['github.com (140.82.112.3) port 443']}], blocks:[{direction:'send',kind:'data',http:['HEAD /org/repo HTTP/1.1','Host: github.com']},{direction:'receive',kind:'data',http:['HTTP/1.1 200 OK']}]},
  {captureMode:'agent-path', agent:'Cursor', tool:'git', startedAt:'2026-10-17T10:02:00Z', pid:43, exitCode:1, runID:'gh-push-fail', session:'repo-chat', args:['push','origin','main'], gitOperation:{operation:'push'}, connections:[{kind:'proxyTunnel',detail:['github.com:443']},{kind:'connected',detail:['127.0.0.1:18891']}], blocks:[{direction:'send',kind:'data',textPreview:'git push origin main'}]}
]);
api.render(retryHolder,{tasks:[{id:'repo',agent:'Cursor',session:'repo-chat',title:'推送仓库',originalRequest:'推送仓库',cards:[]}],collected:[]},{taskOnly:'repo'});
assert.match(retryHolder.innerHTML, /重复访问/);
assert.match(retryHolder.innerHTML, /curl 去了 github.com 2 次，1 次没成/);
assert.match(retryHolder.innerHTML, /没连上/);
assert.match(retryHolder.innerHTML, /只要了头信息/);
assert.doesNotMatch(retryHolder.innerHTML, /git push origin main/);
assert.doesNotMatch(retryHolder.innerHTML, /140\.82\.112\.3/);
const archiveHolder={innerHTML:'', querySelectorAll:()=>[]};
api.setLocalTransports([]);
api.setCapturedBodies([{
  id:'disk-baidu', agent:'WorkBuddy', source:'agentsight:workbuddy-network-body', kind:'network',
  timestamp:'2026-10-17T06:53:45Z', session:'workbuddy-network:flow', turn:'flow',
  details:JSON.stringify({requestPath:'/', method:'GET'}),
  resource:{domain:'news.baidu.com', method:'GET', url:'https://news.baidu.com/', evidenceType:'http'},
  networkBody:{flow:'workbuddy-http:flow', request:'', response:'网页《百度》', requestComplete:true, responseComplete:true, responseStatus:200}
}]);
api.render(archiveHolder,{tasks:[],collected:[]});
assert.match(archiveHolder.innerHTML, /news\.baidu\.com/);
assert.doesNotMatch(archiveHolder.innerHTML, /这次还没有采到外网交互/);
const copilotHolder={innerHTML:'', querySelectorAll:()=>[]};
api.setCapturedBodies([{
  id:'cap', agent:'WorkBuddy', source:'agentsight:workbuddy-network-body', kind:'network',
  timestamp:'2026-10-17T10:41:50Z', session:'workbuddy-network:e3', turn:'e3',
  details:JSON.stringify({requestPath:'/v2/operation-platform/slots/active-batch', method:'POST', responseStatus:200}),
  resource:{domain:'copilot.tencent.com', method:'POST', url:'https://copilot.tencent.com/v2/operation-platform/slots/active-batch', evidenceType:'http'},
  networkBody:{flow:'workbuddy-http:e3', request:'{}', response:'{}', requestComplete:true, responseComplete:true, responseStatus:200}
}]);
api.render(copilotHolder,{tasks:[],collected:[]});
assert.match(copilotHolder.innerHTML, /copilot\.tencent\.com\/v2\/operation-platform\/slots\/active-batch/);
assert.match(copilotHolder.innerHTML, />POST</);
assert.doesNotMatch(copilotHolder.innerHTML, /这次还没有采到外网交互/);
console.log('access hop ok');
