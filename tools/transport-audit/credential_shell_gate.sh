# AgentReins credential shell gate.
# Sourced from an agent shell (zsh always reads .zshenv, including /bin/zsh -c;
# bash reads this file when BASH_ENV points here). A normal terminal returns
# immediately and is unchanged.
#
# Blocked here, before the command runs, exit 126, mechanism shell-gate:
#   cat, head, tail, less, more, cp, grep, awk, sed, base64, xxd, strings,
#   /bin/cat and any other absolute path, python/perl/ruby/node -c or -e,
#   and shell redirects, when the command text names a credential path.
#   Resetting PATH to /usr/bin:/bin does not bypass this. File bytes are not read.
# Detected only, not blocked: an in-process open() (Claude Read, and any reader
# that is not a shell command). libproc / kqueue record that as confirmed or possible.
# Still uncovered: zsh -f, bash --noprofile --norc without BASH_ENV, and a path
# that never appears in the command text.

if [ -z "${AGENTREINS_TRANSPORT_AGENT:-}" ]; then
  if [ -n "${CODEX_THREAD_ID:-}" ] && [ -n "${CODEX_CLI_PATH:-}" ]; then
    AGENTREINS_TRANSPORT_AGENT=Codex
  elif [ -n "${CODEBUDDY_SESSION_ID:-}" ] || [ -n "${CODEBUDDY_CONVERSATION_REQUEST_ID:-}" ]; then
    AGENTREINS_TRANSPORT_AGENT=WorkBuddy
  elif [ "${CURSOR_AGENT:-}" = "1" ] || [ -n "${CURSOR_CONVERSATION_ID:-}" ]; then
    AGENTREINS_TRANSPORT_AGENT=Cursor
  elif [ -n "${CLAUDE_SESSION_ID:-}" ] || [ "${CLAUDECODE:-}" = "1" ]; then
    AGENTREINS_TRANSPORT_AGENT=Claude
  fi
fi
case "${AGENTREINS_TRANSPORT_AGENT:-}" in
  WorkBuddy|Codex|Cursor|Claude) ;;
  *) return 0 2>/dev/null || exit 0 ;;
esac
export AGENTREINS_TRANSPORT_AGENT

_agentreins_gate_check() {
  _agentreins_cmd="$1"
  case "$_agentreins_cmd" in
    *'--shell-gate'*|*_agentreins_gate_*) return 0 ;;
  esac
  case "$_agentreins_cmd" in
    *.env*|*.ssh*|*.aws*|*.azure*|*.netrc*|*.npmrc*|*.pypirc*|*.pem*|\
    *id_rsa*|*id_ed25519*|*id_ecdsa*|\
    *keychain*|*credentials.json*|\
    *docker/config.json*|*.kube/config*|\
    *.config/gh*|*.config/gcloud*|*.config/configstore*|\
    *dump-keychain*|*find-generic-password*|*find-internet-password*|*find-certificate*) ;;
    *) return 0 ;;
  esac
  if [ -z "${AGENTREINS_HARDGATE_POLICY:-}" ] || [ ! -f "$AGENTREINS_HARDGATE_POLICY" ]; then
    printf '%s\n' "AgentReins 已拒绝这条命令，真实程序不会执行。允许需要在待我处理里写原因。" >&2
    return 1
  fi
  _agentreins_py=/usr/bin/python3
  if [ ! -x "$_agentreins_py" ]; then
    _agentreins_py=python3
  fi
  AGENTREINS_GATE_COMMAND="$_agentreins_cmd"
  AGENTREINS_GATE_PID=$$
  AGENTREINS_GATE_PPID=${PPID:-}
  export AGENTREINS_GATE_COMMAND AGENTREINS_GATE_PID AGENTREINS_GATE_PPID
  _agentreins_status=0
  PYTHONDONTWRITEBYTECODE=1 "$_agentreins_py" "$AGENTREINS_HARDGATE_POLICY" --shell-gate || _agentreins_status=$?
  unset AGENTREINS_GATE_COMMAND AGENTREINS_GATE_PID AGENTREINS_GATE_PPID
  if [ "$_agentreins_status" -ne 0 ]; then
    printf '%s\n' "AgentReins 已拒绝这条命令，真实程序不会执行。允许需要在待我处理里写原因。" >&2
    return 1
  fi
  return 0
}

_agentreins_gate_entry() {
  if [ -n "${AGENTREINS_GATE_BUSY:-}" ]; then
    return 0
  fi
  AGENTREINS_GATE_BUSY=1
  _agentreins_gate_check "$1"
  _agentreins_rc=$?
  unset AGENTREINS_GATE_BUSY
  if [ "$_agentreins_rc" -ne 0 ]; then
    exit 126
  fi
}

if [ -n "${ZSH_VERSION:-}" ]; then
  setopt DEBUG_BEFORE_CMD 2>/dev/null || true
  TRAPDEBUG() { _agentreins_gate_entry "$ZSH_DEBUG_CMD"; }
fi
if [ -n "${BASH_VERSION:-}" ]; then
  trap '_agentreins_gate_entry "$BASH_COMMAND"' DEBUG
fi
if [ -z "${BASH_ENV:-}" ] && [ -n "${AGENTREINS_SHELL_GATE:-}" ]; then
  export BASH_ENV="$AGENTREINS_SHELL_GATE"
fi
