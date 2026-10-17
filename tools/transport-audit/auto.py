#!/usr/bin/env python3
"""Agent-only PATH entry. No permission decisions, shell parsing or proxy changes."""
import datetime,json,os,pathlib,signal,subprocess,sys,uuid
BASE=pathlib.Path(__file__).resolve().parent

def main():
    tool=pathlib.Path(sys.argv[0]).name
    if tool not in ('curl','git'):raise SystemExit('Invalid transport entry')
    args=sys.argv[1:];env=os.environ.copy()
    real=env.get('AGENTREINS_REAL_'+tool.upper(),'/usr/bin/'+tool)
    if pathlib.Path(real).resolve().parent==BASE/'bin':raise SystemExit('Recursive transport entry')
    agent=env.get('AGENTREINS_TRANSPORT_AGENT')
    if agent not in ('WorkBuddy','Codex'):os.execv(real,[real,*args])
    root=pathlib.Path(env.get('AGENTREINS_TRANSPORT_ROOT','/private/tmp/agentreins-transport-audit'))
    try:
        run=root/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
        manifest={'schema':1,'agent':agent,'tool':tool,'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'launcherPID':os.getpid(),'parentPID':os.getppid(),'captureMode':'agent-path',
                  'task':None,'call':None,'codexThreadID':env.get('CODEX_THREAD_ID') if agent=='Codex' else None,'session':env.get('CODEX_THREAD_ID') if agent=='Codex' else env.get('CODEBUDDY_SESSION_ID'),'nativeRequestID':env.get('CODEBUDDY_CONVERSATION_REQUEST_ID'),'nativeMessageID':env.get('CODEBUDDY_CONVERSATION_MESSAGE_ID'),'coverage':'PATH-resolved command; absolute paths and overwritten PATH bypass this entry'}
        def save(name,data):
            tmp=run/(name+'.tmp')
            fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            with os.fdopen(fd,'w') as f:json.dump(data,f,ensure_ascii=False)
            os.replace(tmp,run/name)
        save('manifest.json',manifest)
        for name in ('curl.trace','git-curl.trace','git-processes.jsonl'):
            fd=os.open(run/name,os.O_CREAT|os.O_WRONLY,0o600);os.close(fd)
        command=[real,*args]
        if tool=='git':
            if any(k in env for k in ('GIT_TRACE_CURL','GIT_TRACE2_EVENT')):
                manifest['gap']='Existing Git trace configuration retained'
            else:
                env.update(GIT_TRACE2_EVENT=str(run/'git-processes.jsonl'),GIT_TRACE_CURL=str(run/'git-curl.trace'),GIT_TRACE_CURL_NO_DATA='0',GIT_TRACE_REDACT='1')
                # Git's native binary pack trace is separate from its lossy curl text dump.
                # Respect user configuration; never redirect a user-selected trace.
                if 'GIT_TRACE_PACKFILE' not in env:
                    pack=run/'git-packfile.pack'
                    fd=os.open(pack,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600);os.close(fd)
                    env['GIT_TRACE_PACKFILE']=str(pack)
                    manifest['packTracing']=True
                else:manifest['packTracing']=False
                if agent=='Codex':
                    try:
                        from git_helpers import prepare
                        manifest['helperTracing']=prepare(real,args,env,run)
                    except (OSError,ValueError,subprocess.SubprocessError):
                        manifest['helperTracing']=False

        else:
            conflicts=any(x.startswith(('--trace','--verbose','--no-trace','--config','-K')) or (x.startswith('-') and not x.startswith('--') and 'v' in x[1:]) for x in args)
            # Do not override user curl tracing/config semantics.
            if conflicts:manifest['gap']='Explicit curl trace/config options retained; body capture unavailable'
            else:command=[real,'--trace',str(run/'curl.trace'),'--trace-time','--trace-ids',*args]
    except OSError:
        os.execv(real,[real,*args])
    from results import git_invocation,git_state
    operation=git_invocation(args,os.getcwd()) if tool=='git' else None
    metadataArgs=operation.pop('metadataArgs',None) if operation else None
    metadataCwd=operation.pop('metadataCwd',os.getcwd()) if operation else os.getcwd()
    # clone creates a different repository. Its launch directory is not its
    # before-state; comparing that directory's HEAD to the new clone is false.
    repositoryPath=(operation.get('destination') if operation['operation']=='clone' else operation['cwd']) if operation else None
    def repository_state():
        if not repositoryPath:return None
        if operation['operation']=='clone':return git_state(repositoryPath,isolate=True)
        return git_state(metadataCwd,metadataArgs) if metadataArgs is not None else None
    beforeState=repository_state()
    if operation and operation['operation']!='clone' and beforeState and beforeState.get('state')=='observed':
        repositoryPath=beforeState['path']
    manifest['operation']=operation
    proc=subprocess.Popen(command,env=env)
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        signal.signal(sig,lambda s,f:proc.send_signal(s) if proc.poll() is None else None)
    manifest['pid']=proc.pid;save('manifest.json',manifest)
    code=proc.wait();manifest.update(exitCode=code,finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat());save('manifest.json',manifest)
    try:
        from parse import parse
        from results import file_result,repo_result
        evidence=parse(run)
        # Only one unambiguous explicit -o output; never guess shell redirection.
        outputs=[args[i+1] for i,x in enumerate(args[:-1]) if x in ('-o','--output')]
        if tool=='curl' and len(outputs)==1 and outputs[0]!='-' and not any(x in args for x in ('--output-dir','--remote-name','-O')):
            evidence['fileResult']=file_result(outputs[0])
        if operation:
            destination=operation.get('destination')
            evidence['gitOperation']={'operation':operation['operation'],'repositoryPath':repositoryPath,'before':beforeState,'after':repository_state(),'exitCode':code}
            if destination and code==0:evidence['repoResult']=repo_result(destination)
        evidence['attribution']='Agent launch environment; native task and call identity unconfirmed'
        save('transport.json',evidence)
    except Exception as error:
        manifest['projectionError']=type(error).__name__;save('manifest.json',manifest)
    if code<0:
        signal.signal(-code,signal.SIG_DFL);os.kill(os.getpid(),-code)
    return code
if __name__=='__main__':sys.exit(main())
