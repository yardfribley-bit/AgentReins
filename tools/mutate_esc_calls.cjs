#!/usr/bin/env node
// en_d595e9da: delete each esc() call site; XSS test must fail via real DOM (no call-count).
// Accept ≥57/59 killed; list survivors with equivalence rationale.
'use strict';
const fs = require('fs');
const cp = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');
const SRC = process.argv[2] || path.join(root, 'Sources/AgentReins/Resources/RealtimeWorkspace/risk-alerts.js');
const TEST = process.argv[3] || path.join(root, 'Tests/Manual/network/test_xss_escape.cjs');
const MIN_KILL = Number(process.env.ESC_MUTANT_MIN_KILL || 57);
const orig = fs.readFileSync(SRC, 'utf8');

function findSites(src) {
  const sites = [];
  for (const m of src.matchAll(/\besc\(/g)) {
    const i = m.index;
    const before = src.slice(Math.max(0, i - 20), i);
    // Skip function esc( definition and get/set esc() accessors / empty esc().
    if (/function\s+$/.test(before)) continue;
    if (/\b(?:get|set)\s+$/.test(before)) continue;
    const afterParen = src.slice(i + 4, i + 5);
    if (afterParen === ')') continue; // bare esc() accessor noise
    sites.push(i);
  }
  return sites;
}

const sites = findSites(orig);
const base = cp.spawnSync(process.execPath, [TEST], { encoding: 'utf8' });
if (base.status !== 0) {
  console.error('baseline XSS test failed');
  console.error(base.stdout);
  console.error(base.stderr);
  process.exit(1);
}

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
    const line = orig.slice(0, pos).split('\n').length;
    const arg = orig.slice(pos + 4, j).replace(/\s+/g, ' ').slice(0, 60);
    fs.writeFileSync(SRC, orig.slice(0, pos) + '(' + orig.slice(pos + 4, j) + ')' + orig.slice(j + 1));
    const r = cp.spawnSync(process.execPath, [TEST], { encoding: 'utf8' });
    if (r.status === 0) {
      survived.push({ line, arg });
    }
  }
} finally {
  fs.writeFileSync(SRC, orig);
}

const killed = sites.length - survived.length;
console.log(`ESC_MUTANTS total=${sites.length} killed=${killed} survived=${survived.length}`);
if (survived.length) {
  console.log('SURVIVED (equivalence notes required if ≤2):');
  for (const s of survived) {
    console.log(`  line ${s.line}: esc(${s.arg})`);
  }
}
if (killed < MIN_KILL) {
  console.error(`killed ${killed} < required ${MIN_KILL}`);
  process.exit(1);
}
if (survived.length > 2) {
  console.error(`too many survivors: ${survived.length} (max 2 equivalent)`);
  process.exit(1);
}
