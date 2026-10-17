#!/usr/bin/env python3
"""Reversible zsh integration, active only in native Codex command environment."""
import pathlib,datetime,shlex,os
root=pathlib.Path(__file__).resolve().parents[1]
path=pathlib.Path.home()/'.zshenv'
original=path.read_text() if path.exists() else ''
start='# BEGIN AgentReins Codex transport\n';end='# END AgentReins Codex transport\n'
if start in original:
 a=original.index(start);b=original.index(end,a)+len(end);original=original[:a]+original[b:]
block=start+'if [[ -n "${CODEX_THREAD_ID:-}" && -n "${CODEX_CLI_PATH:-}" ]]; then\n'
for tool in ['curl','git']:
 entry=shlex.quote(str(root/'tools/transport-audit/bin'/tool))
 block+=f'  function {tool}() {{ AGENTREINS_TRANSPORT_AGENT=Codex {entry} "$@"; }}\n'
block+='fi\n'+end
if path.exists():
 backup=path.with_name('.zshenv.agentreins-backup-'+datetime.datetime.now().strftime('%Y%m%d%H%M%S'));backup.write_text(path.read_text());backup.chmod(0o600)
tmp=path.with_name('.zshenv.agentreins-tmp');tmp.write_text(original+'\n'+block);os.replace(tmp,path)
print('Installed Codex-only curl/git shell functions; no WorkBuddy configuration changed')
