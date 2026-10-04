#!/usr/bin/env python3
"""Install independent AgentReins observation hooks without removing other hooks."""
import argparse, datetime, hashlib, json, os, pathlib, shlex, shutil, tempfile
p = argparse.ArgumentParser()
p.add_argument('--settings', type=pathlib.Path, default=pathlib.Path.home()/'.workbuddy/settings.json')
p.add_argument('--hook', type=pathlib.Path, required=True)
p.add_argument('--dry-run', action='store_true')
a = p.parse_args()
if not a.hook.is_file() or not os.access(a.hook, os.X_OK): raise SystemExit('Hook executable unavailable')
original = a.settings.read_bytes() if a.settings.exists() else b'{}'
settings = json.loads(original)
hooks = settings.setdefault('hooks', {})
if not isinstance(hooks, dict): raise SystemExit('Unsupported hooks configuration; no change made')
added = 0
for event in ['SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop']:
    entries = hooks.setdefault(event, [])
    if not isinstance(entries, list): raise SystemExit('Unsupported hook event configuration; no change made')
    command = shlex.quote(str(a.hook.resolve())) + ' ' + event
    if any(isinstance(group, dict) and any(isinstance(h, dict) and h.get('command') == command
           for h in group.get('hooks', [])) for group in entries): continue
    entries.append({'matcher': '.*' if event in ['PreToolUse','PostToolUse'] else '*',
                    'hooks': [{'type':'command','command':command}]})
    added += 1
if a.dry_run or not added:
    print(json.dumps({'new_hooks':added,'dry_run':a.dry_run})); raise SystemExit(0)
a.settings.parent.mkdir(parents=True, exist_ok=True)
backup = a.settings.with_name(a.settings.name + '.agentreins-backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
if a.settings.exists():
    shutil.copy2(a.settings, backup); backup.chmod(0o600)
fd, temporary = tempfile.mkstemp(prefix='.agentreins-settings-', dir=a.settings.parent)
try:
    with os.fdopen(fd,'w') as f:
        json.dump(settings,f,ensure_ascii=False,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    current = a.settings.read_bytes() if a.settings.exists() else b'{}'
    if hashlib.sha256(current).digest() != hashlib.sha256(original).digest():
        raise SystemExit('Settings changed concurrently; no overwrite made')
    os.replace(temporary,a.settings)
finally:
    if os.path.exists(temporary): os.unlink(temporary)
print(json.dumps({'new_hooks':added,'backup':str(backup)}))
