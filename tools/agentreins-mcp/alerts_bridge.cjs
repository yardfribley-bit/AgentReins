'use strict';
/** stdin JSON {transports, tasks?} → stdout {alerts} using packaged RealtimeWorkspace JS. */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const root = path.resolve(__dirname, '../../Sources/AgentReins/Resources/RealtimeWorkspace');
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
  process.stdout.write(JSON.stringify({ alerts }));
});
