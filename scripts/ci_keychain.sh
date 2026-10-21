#!/usr/bin/env bash
# CI only (GitHub macOS runner). Gives AgentReinsKeychainHelper a dedicated, unlocked, never-auto-locking
# default keychain so the integrity key path is deterministic and never waits for a prompt.
#
#   setup  create + unlock + make default (before any step that touches the Keychain)
#   reset  delete and recreate it empty (before the packaged-app steps), so the packaged helper creates
#          the key itself. Otherwise the item created earlier by the dev-built helper
#          (tools/agentreins-mcp/keychain_helper) only trusts that binary, and the packaged helper would
#          need user approval: it now fails fast with exit 4 (key_unavailable) instead of hanging 15 s.
#
# The keychain password is random per run, kept in $RUNNER_TEMP (0600) and never printed.
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is only set on GitHub runners; this script is CI-only}"
KC="$RUNNER_TEMP/agentreins-ci.keychain-db"
PW_FILE="$RUNNER_TEMP/agentreins-ci.keychain.pw"

create() {
  if [[ ! -s "$PW_FILE" ]]; then
    (umask 077; openssl rand -hex 24 > "$PW_FILE")
  fi
  local pw
  pw="$(cat "$PW_FILE")"
  security create-keychain -p "$pw" "$KC"
  security set-keychain-settings "$KC"            # no -t / -l: never auto-locks during the job
  security unlock-keychain -p "$pw" "$KC"
  # Search list: ours first, then whatever the runner already had (login keychain etc.).
  local existing=()
  while IFS= read -r line; do
    line="${line//\"/}"; line="${line#"${line%%[![:space:]]*}"}"
    [[ -n "$line" && "$line" != "$KC" ]] && existing+=("$line")
  done < <(security list-keychains -d user)
  security list-keychains -d user -s "$KC" "${existing[@]}"
  security default-keychain -d user -s "$KC"
  echo "CI keychain ready: $KC (default, unlocked)"
  security show-keychain-info "$KC" 2>&1 || true
}

case "${1:-}" in
  setup) create ;;
  reset)
    security delete-keychain "$KC" 2>/dev/null || true
    create
    ;;
  *) echo "usage: $0 setup|reset" >&2; exit 2 ;;
esac
