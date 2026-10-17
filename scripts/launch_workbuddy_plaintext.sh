#!/bin/bash
# Explicit WorkBuddy CLI entry; does not restart the desktop or alter its files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
entry='/Applications/WorkBuddy.app/Contents/Resources/app.asar.unpacked/cli/bin/codebuddy'
if [[ ! -f "$entry" ]]; then echo 'WorkBuddy CLI entry is unavailable' >&2; exit 1; fi
capture="${AGENTREINS_PLAINTEXT_OUTPUT:-$HOME/Library/Application Support/AgentReins/workbuddy-network.jsonl}"
mkdir -p "$(dirname "$capture")"
export AGENTREINS_PLAINTEXT_AGENT=workbuddy
export AGENTREINS_PLAINTEXT_OUTPUT="$capture"
exec node --require "$root/tools/plaintext-probe/node-http.cjs" "$entry" "$@"
