#!/usr/bin/env node
// en_4088c393 playbook: delete each esc() call site; the XSS test must fail for every mutant.
'use strict';
const fs = require('fs');
const cp = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');
const SRC = process.argv[2] || path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const TEST = process.argv[3] || path.join(root, 'Tests/Manual/network/test_xss_escape.cjs');
const orig = fs.readFileSync(SRC, 'utf8');
const sites = [...orig.matchAll(/\besc\(/g)]
  .map((m) => m.index)
  .filter((i) => !/function\s+$/.test(orig.slice(Math.max(0, i - 12), i))); // skip definition

// Baseline golden esc call count (via ESC_CALLS=N printed by the test).
const base = cp.spawnSync(process.execPath, [TEST], { encoding: 'utf8' });
if (base.status !== 0) {
  console.error('baseline XSS test failed');
  console.error(base.stdout);
  console.error(base.stderr);
  process.exit(1);
}
const gm = /ESC_CALLS=(\d+)/.exec(base.stdout || '');
if (!gm) {
  console.error('baseline did not print ESC_CALLS=');
  process.exit(1);
}
const golden = gm[1];
const survived = [];
try {
  for (const pos of sites) {
    let d = 0;
    let j = pos + 4;
    for (; j < orig.length; j++) {
      const c = orig[j];
      if (c === '(') d++;
      else if (c === ')') {
        if (!d) break;
        d--;
      }
    }
    fs.writeFileSync(
      SRC,
      orig.slice(0, pos) + '(' + orig.slice(pos + 4, j) + ')' + orig.slice(j + 1)
    );
    const r = cp.spawnSync(process.execPath, [TEST], {
      encoding: 'utf8',
      env: { ...process.env, ESC_GOLDEN: golden },
    });
    if (r.status === 0) {
      survived.push(orig.slice(0, pos).split('\n').length);
    }
  }
} finally {
  fs.writeFileSync(SRC, orig);
}
console.log(`ESC_MUTANTS total=${sites.length} killed=${sites.length - survived.length}`);
if (survived.length) {
  console.error('SURVIVED at lines', survived);
  process.exit(1);
}
