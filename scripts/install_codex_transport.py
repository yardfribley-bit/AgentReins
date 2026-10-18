#!/usr/bin/env python3
"""Install the WorkBuddy, Codex, and Cursor audit environment.

Active only when a process already belongs to one of those agents. Normal
shells stay unchanged. HTTP(S) clients then use the local audit proxy even if
they are invoked by absolute path; named commands also pass through the
transport entry.
"""
import datetime, json, os, pathlib, shlex, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
bin_dir = root / 'tools' / 'transport-audit' / 'bin'
tools = sorted(path.name for path in bin_dir.iterdir() if path.name != 'auto.py' and not path.name.startswith('.') and path.name.replace('.', '').replace('_', '').replace('-', '').replace('+', '').isalnum())
if not tools:
    raise SystemExit('No transport entries installed')
home = pathlib.Path.home()
ca = home / '.mitmproxy' / 'mitmproxy-ca-cert.pem'
proxy = 'http://127.0.0.1:18891'
audit_dir = home / '.agentreins'
audit_dir.mkdir(mode=0o700, exist_ok=True)
audit = audit_dir / 'audit.sh'
functions = '\n'.join(
    f'{tool}() {{ AGENTREINS_TRANSPORT_AGENT="$AGENTREINS_TRANSPORT_AGENT" {shlex.quote(str(bin_dir / tool))} "$@"; }}'
    for tool in tools)
audit.write_text(f'''# AgentReins audit environment for WorkBuddy, Codex, and Cursor agent processes.
# Sourced from shell startup. A normal terminal does not enter this branch.
if [ -z "${{AGENTREINS_TRANSPORT_AGENT:-}}" ]; then
  if [ -n "${{CODEX_THREAD_ID:-}}" ] && [ -n "${{CODEX_CLI_PATH:-}}" ]; then
    AGENTREINS_TRANSPORT_AGENT=Codex
  elif [ -n "${{CODEBUDDY_SESSION_ID:-}}" ] || [ -n "${{CODEBUDDY_CONVERSATION_REQUEST_ID:-}}" ]; then
    AGENTREINS_TRANSPORT_AGENT=WorkBuddy
  elif [ "${{CURSOR_AGENT:-}}" = "1" ]; then
    AGENTREINS_TRANSPORT_AGENT=Cursor
  fi
fi
if [ "$AGENTREINS_TRANSPORT_AGENT" != "WorkBuddy" ] && [ "$AGENTREINS_TRANSPORT_AGENT" != "Codex" ] && [ "$AGENTREINS_TRANSPORT_AGENT" != "Cursor" ]; then
  return 0 2>/dev/null || exit 0
fi
export AGENTREINS_TRANSPORT_AGENT
# The audit proxy belongs to AgentReins. When that process is not listening,
# leave the agent's own network alone instead of black-holing it.
if /usr/bin/nc -z -G 1 127.0.0.1 18891 >/dev/null 2>&1; then
  export HTTP_PROXY={shlex.quote(proxy)} HTTPS_PROXY={shlex.quote(proxy)} ALL_PROXY={shlex.quote(proxy)}
  export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" all_proxy="$ALL_PROXY"
  export NO_PROXY=localhost,127.0.0.1,::1 no_proxy="$NO_PROXY"
  if [ -f {shlex.quote(str(ca))} ]; then
    export CURL_CA_BUNDLE={shlex.quote(str(ca))} SSL_CERT_FILE="$CURL_CA_BUNDLE" GIT_SSL_CAINFO="$CURL_CA_BUNDLE"
    export NODE_EXTRA_CA_CERTS="$CURL_CA_BUNDLE" REQUESTS_CA_BUNDLE="$CURL_CA_BUNDLE"
  fi
  if [ -z "${{GIT_CONFIG_COUNT:-}}" ]; then
    export GIT_CONFIG_COUNT=2
    export GIT_CONFIG_KEY_0=http.proxy GIT_CONFIG_VALUE_0="$HTTP_PROXY"
    export GIT_CONFIG_KEY_1=http.sslCAInfo GIT_CONFIG_VALUE_1="${{CURL_CA_BUNDLE:-}}"
  fi
else
  case "${{HTTP_PROXY:-}}${{HTTPS_PROXY:-}}${{ALL_PROXY:-}}${{http_proxy:-}}${{https_proxy:-}}${{all_proxy:-}}${{GIT_CONFIG_VALUE_0:-}}" in
    *127.0.0.1:18891*|*127.0.0.1:18893*)
      unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
      unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1
      ;;
  esac
fi
case ":$PATH:" in
  *:{shlex.quote(str(bin_dir))}:*) ;;
  *) export PATH={shlex.quote(str(bin_dir))}:$PATH ;;
esac
{functions}
''')
audit.chmod(0o700)
start = '# BEGIN AgentReins transport\n'
end = '# END AgentReins transport\n'
old_start = '# BEGIN AgentReins Codex transport\n'
old_end = '# END AgentReins Codex transport\n'
hook = start + f'[ -f {shlex.quote(str(audit))} ] && . {shlex.quote(str(audit))}\n' + end

def splice(path):
    original = path.read_text() if path.exists() else ''
    for marker_start, marker_end in ((old_start, old_end), (start, end)):
        if marker_start in original and marker_end in original:
            a = original.index(marker_start)
            b = original.index(marker_end, a) + len(marker_end)
            original = original[:a] + original[b:]
    if path.exists():
        backup = path.with_name(path.name + '.agentreins-backup-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        backup.write_text(path.read_text())
        backup.chmod(0o600)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.agentreins-tmp')
    temporary.write_text(original.rstrip() + '\n\n' + hook)
    os.replace(temporary, path)

for name in ('.zshenv', '.bashrc', '.bash_profile'):
    splice(home / name)

settings_path = home / '.workbuddy' / 'settings.json'
if settings_path.exists():
    original = settings_path.read_bytes()
    settings = json.loads(original)
    env = settings.setdefault('terminal.integrated.env.osx', {})
    if isinstance(env, dict):
        # Do not store the audit proxy in WorkBuddy settings. That value
        # survives AgentReins and makes WorkBuddy fail open-network when the
        # proxy process is gone. audit.sh applies the proxy only while it listens.
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy',
                    'NO_PROXY', 'no_proxy', 'NODE_EXTRA_CA_CERTS', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE',
                    'GIT_SSL_CAINFO', 'REQUESTS_CA_BUNDLE'):
            value = env.get(key)
            if isinstance(value, str) and ('127.0.0.1:18891' in value or '127.0.0.1:18893' in value or value.endswith('mitmproxy-ca-cert.pem')):
                env.pop(key, None)
        env.update({
            'AGENTREINS_TRANSPORT_AGENT': 'WorkBuddy',
            'BASH_ENV': str(audit),
            'ENV': str(audit),
        })
        if settings.get('http.proxy') in ('http://127.0.0.1:18891', 'http://127.0.0.1:18893'):
            settings.pop('http.proxy', None)
        backup = settings_path.with_name(settings_path.name + '.agentreins-env-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S'))
        backup.write_bytes(original)
        backup.chmod(0o600)
        fd, temporary = tempfile.mkstemp(prefix='.agentreins-settings-', dir=settings_path.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                json.dump(settings, handle, ensure_ascii=False, indent=2)
                handle.write('\n')
                handle.flush()
                os.fsync(handle.fileno())
            if settings_path.read_bytes() != original:
                raise SystemExit('WorkBuddy settings changed concurrently; shell audit was installed, settings were not replaced')
            os.replace(temporary, settings_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
print('Installed audit environment for ' + str(len(tools)) + ' commands. Restart WorkBuddy, Codex, and Cursor so already-running processes inherit it.')
