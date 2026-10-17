#!/usr/bin/env python3
"""Launch only WorkBuddy through AgentReins' independent local audit proxy.
Does not change system proxy settings or install certificates. Refuses to
interrupt an already-running WorkBuddy instance; close it normally first.
"""
import argparse, pathlib, socket, subprocess, json, datetime, os, tempfile
p=argparse.ArgumentParser()
p.add_argument('--dry-run',action='store_true')
a=p.parse_args()
app=pathlib.Path('/Applications/WorkBuddy.app')
ca=pathlib.Path.home()/'.mitmproxy/mitmproxy-ca-cert.pem'
if not app.is_dir() or not ca.is_file():raise SystemExit('WorkBuddy or local audit CA file unavailable')
command=['/usr/bin/open','-a',str(app)]
for item in ['HTTP_PROXY=http://127.0.0.1:18891','HTTPS_PROXY=http://127.0.0.1:18891',
             'ALL_PROXY=http://127.0.0.1:18891','NO_PROXY=localhost,127.0.0.1,::1',
             'NODE_EXTRA_CA_CERTS='+str(ca)]:command+=['--env',item]
audit_bin=pathlib.Path(__file__).resolve().parents[1]/'tools/transport-audit/bin'
for item in ['PATH='+str(audit_bin)+os.pathsep+os.environ.get('PATH','/usr/bin:/bin'), 'WORKBUDDY_EXTRA_PATHS='+str(audit_bin)+(':'+os.environ['WORKBUDDY_EXTRA_PATHS'] if os.environ.get('WORKBUDDY_EXTRA_PATHS') else ''), 'AGENTREINS_TRANSPORT_AGENT=WorkBuddy', 'AGENTREINS_REAL_CURL=/usr/bin/curl', 'AGENTREINS_REAL_GIT=/usr/bin/git']:
 command+=['--env',item]
if a.dry_run:
 print('Target: WorkBuddy; proxy: 127.0.0.1:18891; CA: '+str(ca));raise SystemExit(0)
processes=subprocess.check_output(['ps','-axo','comm='],text=True).splitlines()
if any(s.strip()==str(app/'Contents/MacOS/Electron') for s in processes):
 raise SystemExit('WorkBuddy is running. Close it normally, then run this launcher; no task was interrupted.')
with socket.create_connection(('127.0.0.1',18891),timeout=2):pass
# WorkBuddy's own proxy preference overrides the inherited HTTP(S)_PROXY
# variables in its backend. Keep both routes consistent, with a reversible
# backup and a compare-before-replace check.
settings=pathlib.Path.home()/'.workbuddy/settings.json'
original=settings.read_bytes() if settings.exists() else b'{}'
data=json.loads(original)
if data.get('http.proxy')!='http://127.0.0.1:18891':
 data['http.proxy']='http://127.0.0.1:18891'
 backup=settings.with_name(settings.name+'.agentreins-proxy-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
 if settings.exists():backup.write_bytes(original);backup.chmod(0o600)
 fd,temporary=tempfile.mkstemp(prefix='.agentreins-proxy-',dir=settings.parent)
 try:
  with os.fdopen(fd,'w') as f:json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
  if (settings.read_bytes() if settings.exists() else b'{}')!=original:raise SystemExit('WorkBuddy settings changed concurrently; no overwrite made')
  os.replace(temporary,settings)
 finally:
  if os.path.exists(temporary):os.unlink(temporary)
 print('WorkBuddy proxy setting updated; backup: '+str(backup))
subprocess.run(command,check=True)
print('WorkBuddy launched with AgentReins audit proxy. Submit a new task to verify actual request-body capture.')
