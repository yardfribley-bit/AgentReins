'use strict';
/** stdin JSON {transports, tasks?} → stdout {alerts} using packaged RealtimeWorkspace JS. */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const candidates = [
  process.env.AGENTREINS_WORKSPACE_JS,
  path.join(__dirname, '../RealtimeWorkspace'),
  path.resolve(__dirname, '../../Sources/AgentReins/Resources/RealtimeWorkspace'),
].filter(Boolean);
let root = null;
for (const c of candidates) {
  if (fs.existsSync(path.join(c, 'risk-alerts.js')) && fs.existsSync(path.join(c, 'network-view.js'))) {
    root = c;
    break;
  }
}
if (!root) {
  process.stderr.write('alerts_bridge: RealtimeWorkspace JS not found\n');
  process.exit(2);
}
const window = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'network-view.js'), 'utf8'), { window });
vm.runInNewContext(fs.readFileSync(path.join(root, 'risk-alerts.js'), 'utf8'), { window });
const chunks = [];
process.stdin.setEncoding('utf8');
process.stdin.on('data', c => chunks.push(c));
process.stdin.on('end', () => {
  const input = JSON.parse(chunks.join('') || '{}');
  const net = window.AgentReinsNetwork;
  const risk = window.AgentReinsRisk;
  net.setLocalTransports(input.transports || []);
  const payload = {
    tasks: input.tasks || [],
    collected: [],
    health: input.health || [],
  };
  const alerts = risk.buildAlerts(payload).map(a => ({
    id: a.id,
    rule: a.rule,
    title: a.title,
    sub: a.sub,
    agent: a.agent,
    session: a.session,
    call: a.call,
    confidence: a.confidence,
    timestamp: a.timestamp,
    why: a.why,
  }));
  process.stdout.write(JSON.stringify({ alerts, engine: 'js-bridge', workspace: root }));
});
