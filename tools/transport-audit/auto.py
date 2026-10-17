#!/usr/bin/env python3
"""Agent-only PATH entry. No permission decisions, shell parsing or proxy changes."""
import datetime,json,os,pathlib,re,signal,subprocess,sys,threading,time,uuid
BASE=pathlib.Path(__file__).resolve().parent
ENCRYPTED_TOOLS={'ssh','scp','sftp','rsync'}

def entry_allowed(tool):
    return tool not in ('auto.py','') and re.fullmatch(r'[A-Za-z0-9._+-]{1,32}', tool) is not None

def redact_text(text):
    text=re.sub(r'(?i)(authorization:\s*(?:bearer|token|basic)\s+)\S+', r'\1[隐藏]', text)
    text=re.sub(r'(?i)((?:password|secret|token|api[_-]?key)\s*[\"\']?\s*[:=]\s*[\"\']?)[^\s\"\',}]+', r'\1[隐藏]', text)
    return text

def flag_value(args, name):
    for index, arg in enumerate(args):
        if arg==name and index+1<len(args) and not str(args[index+1]).startswith('-'):
            return args[index+1]
        if str(arg).startswith(name+'='):
            return str(arg).split('=',1)[1]
    return None

def command_destination(tool, args, env):
    found=destination_from_args(args)
    if found: return found
    if tool=='gh':
        host=flag_value(args,'--hostname')
        repo=flag_value(args,'--repo') or flag_value(args,'-R')
        if host and repo: return host+'/'+repo
        if host: return host
        if repo: return (env.get('GH_HOST') or 'github.com')+'/'+str(repo).lstrip('/')
        if 'api' in args:
            host=env.get('GH_HOST') or 'github.com'
            return host if host.startswith('api.') else 'api.'+host
    return None

def destination_from_args(args):
    """The peer the local tool was asked to reach. An output filename is not a destination."""
    host=r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+(?::\d{1,5})?'
    ipv4=r'(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?'
    output_flags={'-O','--output-document','-o','--output','-P','--directory-prefix'}
    urls=[]; peers=[]
    for index, item in enumerate(args):
        if str(item).startswith('-') or (index and args[index-1] in output_flags): continue
        if '://' in item: urls.append(item)
        elif '@' in item or re.fullmatch(host, item) or re.fullmatch(ipv4, item): peers.append(item)
    return (urls or peers or [None])[0]

def main():
    tool=pathlib.Path(sys.argv[0]).name
    if not entry_allowed(tool):raise SystemExit('Invalid transport entry')
    args=sys.argv[1:];env=os.environ.copy()
    real=env.get('AGENTREINS_REAL_'+tool.upper()) or next((os.path.join(directory,tool) for directory in env.get('PATH','/usr/bin:/bin:/opt/homebrew/bin').split(os.pathsep) if os.path.realpath(directory)!=os.path.realpath(BASE/'bin') and os.access(os.path.join(directory,tool),os.X_OK)),'/usr/bin/'+tool)
    if pathlib.Path(real).resolve().parent==BASE/'bin':raise SystemExit('Recursive transport entry')
    agent=env.get('AGENTREINS_TRANSPORT_AGENT')
    if agent not in ('WorkBuddy','Codex','Cursor'):os.execv(real,[real,*args])
    root=pathlib.Path(env.get('AGENTREINS_TRANSPORT_ROOT','/private/tmp/agentreins-transport-audit'))
    try:
        run=root/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
        manifest={'schema':1,'agent':agent,'tool':tool,'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'launcherPID':os.getpid(),'parentPID':os.getppid(),'captureMode':'agent-path',
                  'args':[redact_text(str(arg))[:500] for arg in args][:40],
                  'task':None,'call':None,'codexThreadID':env.get('CODEX_THREAD_ID') if agent=='Codex' else None,'session':env.get('CODEX_THREAD_ID') if agent=='Codex' else env.get('CODEBUDDY_SESSION_ID') if agent=='WorkBuddy' else env.get('CURSOR_CONVERSATION_ID'),'nativeRequestID':env.get('CODEBUDDY_CONVERSATION_REQUEST_ID'),'nativeMessageID':env.get('CODEBUDDY_CONVERSATION_MESSAGE_ID'),'coverage':'PATH-resolved command; absolute paths and overwritten PATH bypass this entry'}
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

        elif tool=='curl':
            conflicts=any(x.startswith(('--trace','--verbose','--no-trace','--config','-K')) or (x.startswith('-') and not x.startswith('--') and 'v' in x[1:]) for x in args)
            # Do not override user curl tracing/config semantics.
            if conflicts:manifest['gap']='Explicit curl trace/config options retained; body capture unavailable'
            else:command=[real,'--trace',str(run/'curl.trace'),'--trace-time','--trace-ids',*args]
        elif tool=='wget' and '-d' not in args and '--debug' not in args:
            command=[real,'-d',*args]
        elif tool=='gh' and 'GH_DEBUG' not in env:
            env['GH_DEBUG']='api'
        elif tool in ENCRYPTED_TOOLS and not any(a in ('-v','-vv','-vvv') for a in args):
            command=[real,'-v',*args]
            manifest['gap']='通道是加密的。这里保留本机命令、目标和详细会话日志，不是解密后的通道字节。'
        elif tool not in ('curl','git','wget','gh'):
            manifest['gap']='该工具没有专用协议跟踪。已保留命令、退出码和会话日志，不能把它当成完整协议正文。'
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
    session=None
    stderr_copy=None
    cache_before=None
    try:
        if tool=='brew':
            from results import brew_cache_dir, cache_snapshot
            cache_before=cache_snapshot(brew_cache_dir())
        if tool not in ('curl','git'):
            proc=subprocess.Popen(command,env=env,stderr=subprocess.PIPE)
        else:
            proc=subprocess.Popen(command,env=env)
    except FileNotFoundError:
        manifest['gap']='本机没有找到 '+tool+'，这次访问没有执行。'
        manifest['exitCode']=127
        save('manifest.json',manifest)
        return 127
    if tool not in ('curl','git'):
        session=run/'session.log'
        log=os.open(session,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
        def copy_stderr():
            try:
                while True:
                    chunk=proc.stderr.read(65536)
                    if not chunk:break
                    os.write(log,chunk)
                    try:os.write(2,chunk)
                    except OSError:pass
            finally:
                os.close(log);proc.stderr.close()
        stderr_copy=threading.Thread(target=copy_stderr,daemon=True);stderr_copy.start()
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):
        signal.signal(sig,lambda s,f:proc.send_signal(s) if proc.poll() is None else None)
    manifest['pid']=proc.pid;save('manifest.json',manifest)
    code=proc.wait();
    if stderr_copy:stderr_copy.join()
    manifest.update(exitCode=code,finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat());save('manifest.json',manifest)
    try:
        from parse import parse
        from results import file_result,repo_result
        if tool in ('curl','git'):
            evidence=parse(run)
        else:
            raw=session.read_bytes() if session and session.exists() else b''
            text=redact_text(raw.decode('utf-8','replace'))
            sent=redact_text(' '.join(args))
            target=command_destination(tool,args,env)
            from results import session_http_lines, brew_download_host
            request_http, response_http=session_http_lines(text)
            if tool=='brew' and not target:target=brew_download_host(text)
            evidence={'schema':1,'invocation':manifest,'helpers':[],'packFiles':[],'children':[],
                      'connections':[{'kind':'connected' if code==0 else 'attempt','detail':[target],'time':manifest['startedAt'],'source':'argv','line':1}] if target else [],
                      'blocks':[{'direction':'send','kind':'data','observedBytes':len(sent.encode()),'http':request_http,'textPreview':sent[:4000],'previewTruncated':len(sent)>4000},
                                {'direction':'receive','kind':'data','observedBytes':len(raw),'http':response_http,'textPreview':text[:4000],'previewTruncated':len(text)>4000}],
                      'limitations':[manifest.get('gap') or '会话日志不是逐字节的原始协议正文。']}
        # Only one unambiguous explicit -o output; never guess shell redirection.
        outputs=[args[i+1] for i,x in enumerate(args[:-1]) if x in ('-o','--output')]
        if tool=='curl' and len(outputs)==1 and outputs[0]!='-' and not any(x in args for x in ('--output-dir','--remote-name','-O')):
            evidence['fileResult']=file_result(outputs[0])
        if operation:
            destination=operation.get('destination')
            evidence['gitOperation']={'operation':operation['operation'],'repositoryPath':repositoryPath,'before':beforeState,'after':repository_state(),'exitCode':code}
            if destination and code==0:evidence['repoResult']=repo_result(destination)
            if operation['operation']=='push':
                from results import pushed_paths
                evidence['outboundFiles']=pushed_paths(repositoryPath,beforeState,args)
        else:
            from results import upload_names
            names=upload_names(tool,args)
            if names:evidence['outboundFiles']=names
        from results import brew_formulas, download_evidence
        downloaded=download_evidence(tool,args,os.getcwd(),cache_before,text if tool not in ('curl','git') else '')
        if downloaded:evidence['downloads']=downloaded
        formulas=brew_formulas(args) if tool=='brew' else []
        if formulas:evidence['formulas']=formulas
        evidence['attribution']='Agent launch environment; native task and call identity unconfirmed'
        save('transport.json',evidence)
    except Exception as error:
        manifest['projectionError']=type(error).__name__;save('manifest.json',manifest)
    if code<0:
        signal.signal(-code,signal.SIG_DFL);os.kill(os.getpid(),-code)
    return code
if __name__=='__main__':sys.exit(main())
