"""Result evidence from explicitly named outputs; never scans Agent history."""
import hashlib, os, pathlib, re, subprocess
from urllib.parse import urlsplit, urlunsplit

def metadata_environment(isolate=False):
    env=os.environ.copy();env['GIT_OPTIONAL_LOCKS']='0'
    if isolate:
        # A clone result is a distinct physical repository. Caller repository
        # variables must not redirect its verification to another Git directory.
        for key in ('GIT_DIR','GIT_WORK_TREE','GIT_COMMON_DIR','GIT_INDEX_FILE','GIT_OBJECT_DIRECTORY','GIT_ALTERNATE_OBJECT_DIRECTORIES','GIT_NAMESPACE'):
            env.pop(key,None)
    return env

def safe_url(value):
    try:
        u=urlsplit(value)
        host=u.hostname or ''
        if ':' in host:host='['+host+']'
        if u.port:host+=':'+str(u.port)
        return urlunsplit((u.scheme,host,u.path,'[query hidden]' if u.query else '', ''))
    except ValueError:return '[invalid URL]'

def file_result(path):
    p=pathlib.Path(path)
    if not p.is_file() or p.is_symlink():return {'path':str(p),'state':'unavailable'}
    before=p.stat();h=hashlib.sha256()
    with p.open('rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):h.update(chunk)
    after=p.stat()
    return {'path':str(p.resolve()),'bytes':after.st_size,'sha256':h.hexdigest(),
            'state':'verified' if (before.st_mtime_ns,before.st_size)==(after.st_mtime_ns,after.st_size) else 'changedDuringRead'}

def repo_result(path):
    p=pathlib.Path(path).resolve()
    def git(*args):
        return subprocess.check_output(['/usr/bin/git','-C',str(p),*args],env=metadata_environment(isolate=True),stderr=subprocess.DEVNULL,timeout=30)
    try:
        head=git('rev-parse','HEAD').decode().strip()
        entries=[]
        for row in git('ls-tree','-r','-z','--long',head).split(b'\0'):
            if not row:continue
            meta,name=row.split(b'\t',1);mode,kind,oid,size=meta.split()
            entries.append({'path':name.decode('utf-8','replace'),'type':kind.decode(),'object':oid.decode(),'bytes':int(size) if size!=b'-' else None})
        try:remote=safe_url(git('remote','get-url','origin').decode().strip())
        except subprocess.SubprocessError:remote=None
        return {'path':str(p),'state':'verified','commit':head,'repository':remote,'files':entries,
                'meaning':'Git commit tree after operation; not a list of bytes downloaded by this operation'}
    except (OSError,ValueError,subprocess.SubprocessError):return {'path':str(p),'state':'unavailable'}

def git_state(path, global_args=(), isolate=False):
    """Metadata of this invocation's repository, never file contents/history crawl."""
    p=pathlib.Path(path).resolve()
    environment=metadata_environment(isolate=isolate)
    def query(*args):
        return subprocess.check_output(['/usr/bin/git','-C',str(p),*global_args,*args],env=environment,stderr=subprocess.DEVNULL,timeout=15).decode('utf-8','replace').strip()
    try:
        directory=query('rev-parse','--absolute-git-dir')
        bare=query('rev-parse','--is-bare-repository')=='true'
        top=directory if bare else query('rev-parse','--show-toplevel')
    except subprocess.SubprocessError:return {'state':'notRepository','path':str(p)}
    def optional(*args):
        try:return query(*args)
        except subprocess.SubprocessError:return None
    return {'state':'observed','path':top,'gitDirectory':directory,'bare':bare,'commit':optional('rev-parse','HEAD'),
            'branch':optional('symbolic-ref','--short','HEAD'),
            'refs':optional('for-each-ref','--format=%(refname) %(objectname)'),
            'worktree':None if bare else optional('-c','core.fsmonitor=false','status','--porcelain=v1','-uno')}

def _flag_value(args, name):
    for index, arg in enumerate(args):
        if arg==name and index+1<len(args) and (args[index+1]=='-' or not str(args[index+1]).startswith('-')):
            return args[index+1]
        if str(arg).startswith(name+'='):
            return str(arg).split('=',1)[1]
    return None

def _url_name(value):
    try:
        name=pathlib.PurePosixPath(urlsplit(value).path).name
    except ValueError:
        return None
    if not name or name in ('.','..'):return None
    return name

def download_paths(tool, args, cwd):
    """Files a download command was asked to write. Missing files stay unverified."""
    root=pathlib.Path(cwd or os.getcwd())
    paths=[]
    def add(path):
        if not path or path=='-':return
        candidate=pathlib.Path(path)
        if not candidate.is_absolute():candidate=root/candidate
        text=str(candidate)
        if text not in paths:paths.append(text)
    if tool=='wget' and '--spider' not in args:
        output=_flag_value(args,'-O') or _flag_value(args,'--output-document')
        if output=='-':return []
        if output:add(output)
        else:
            for arg in args:
                if not str(arg).startswith('-') and '://' in str(arg):
                    name=_url_name(arg)
                    if name:add(name)
    elif tool=='curl':
        for index, arg in enumerate(args[:-1]):
            if arg in ('-o','--output'):add(args[index+1])
            elif str(arg).startswith('--output='):add(str(arg).split('=',1)[1])
        if '-O' in args or '--remote-name' in args:
            for arg in args:
                if not str(arg).startswith('-') and '://' in str(arg):
                    name=_url_name(arg)
                    if name:add(name)
    return paths[:20]

def brew_formulas(args):
    verbs={'install','fetch','upgrade','reinstall'}
    if not any(arg in verbs for arg in args):return []
    names=[]
    started=False
    for arg in args:
        if arg in verbs:
            started=True
            continue
        if not started or str(arg).startswith('-') or '://' in str(arg):continue
        if arg not in names:names.append(arg)
    return names[:20]

def brew_cache_dir():
    home=os.environ.get('HOME') or str(pathlib.Path.home())
    return pathlib.Path(home)/'Library'/'Caches'/'Homebrew'/'downloads'

def cache_snapshot(directory):
    snap={}
    if not directory.is_dir():return snap
    for path in directory.iterdir():
        if path.is_file() and not path.is_symlink():
            stat=path.stat()
            snap[path.name]=(stat.st_mtime_ns, stat.st_size)
    return snap

def cache_changes(directory, before):
    changed=[]
    if not directory.is_dir():return changed
    for path in directory.iterdir():
        if not path.is_file() or path.is_symlink():continue
        stat=path.stat()
        if before.get(path.name)!=(stat.st_mtime_ns, stat.st_size):changed.append(path)
    changed.sort(key=lambda item: item.stat().st_mtime_ns, reverse=True)
    return changed[:8]

def download_record(path, source=None, max_bytes=32*1024*1024):
    p=pathlib.Path(path)
    record={'path':str(p),'source':source}
    if not p.is_file() or p.is_symlink():
        record['state']='unavailable'
        return record
    size=p.stat().st_size
    record['bytes']=size
    if size>max_bytes:
        record['state']='tooLarge'
        return record
    hashed=file_result(path)
    hashed['source']=source
    return hashed

def session_http_lines(text):
    """Request and status lines from curl -v or wget --debug. CONNECT is not the site status."""
    request=[]; response=[]
    for line in (text or '').splitlines():
        raw=line[2:].strip() if line.startswith(('> ','< ')) else line.strip()
        if re.match(r'(?i)(?:GET|HEAD|POST|PUT|PATCH|DELETE)\s+\S+.*HTTP/', raw):
            if raw not in request:request.append(raw)
        elif re.match(r'(?i)Host:\s*\S+', raw):
            if raw not in request:request.append(raw)
        elif re.match(r'HTTP/\d', raw) and 'connection established' not in raw.lower():
            if raw not in response:response.append(raw)
    return request[:8], response[:8]

def brew_download_host(text):
    for url in re.findall(r'https://[^\s\'\"]+', text or ''):
        if not any(part in url for part in ('ghcr.io','github.com','brew.sh')):continue
        host=urlsplit(url).hostname
        if host:return host
    return None

def download_evidence(tool, args, cwd, cache_before=None, log_text=''):
    records=[]
    for path in download_paths(tool, args, cwd):
        records.append(download_record(path))
    if tool=='brew':
        urls=re.findall(r'https://\S+', log_text or '')
        source=next((item for item in urls if 'ghcr.io' in item or 'github' in item or 'brew' in item), urls[0] if urls else None)
        for path in cache_changes(brew_cache_dir(), cache_before or {}):
            records.append(download_record(path, source=source))
    seen=[]; unique=[]
    for record in records:
        key=record.get('path')
        if key in seen:continue
        seen.append(key); unique.append(record)
    return unique[:8]

def upload_names(tool,args):
    """Local file names an outbound command was asked to send. Directory trees are not expanded."""
    names=[]
    if tool=='curl':
        values={'--upload-file','-T','--data','--data-raw','--data-binary','--data-ascii','-d','--form','-F','--form-string'}
        for i,arg in enumerate(args):
            source=None
            if arg in values and i+1<len(args):source=args[i+1]
            elif any(arg.startswith(flag+'=') for flag in values):source=arg.split('=',1)[1]
            if not source:continue
            for part in source.split(';'):
                if '@' in part:part=part.split('@',1)[1]
                part=part.split(',',1)[0]
                if part and part not in ('-','') and not part.startswith('http'):names.append(pathlib.Path(part).name)
    elif tool in ('scp','rsync'):
        operands=[arg for arg in args if not arg.startswith('-')]
        sources=operands[:-1] if len(operands)>1 else []
        names+=[pathlib.Path(item).name for item in sources if item and ':' not in item]
    seen=[];
    for name in names:
        if name and name not in seen:seen.append(name)
    return seen[:500]

def pushed_paths(repository,before,args):
    """File names in the commits a push would send. This is not the pack byte stream."""
    if not before or before.get('state')!='observed' or not repository:return []
    refs={}
    for line in (before.get('refs') or '').splitlines():
        parts=line.split()
        if len(parts)==2:refs[parts[0]]=parts[1]
    branch=before.get('branch')
    local=before.get('commit')
    remote=None
    if branch:
        remote=next((sha for name,sha in refs.items() if name.startswith('refs/remotes/') and name.endswith('/'+branch)),None)
    operands=[arg for arg in args if not arg.startswith('-')]
    tail=operands[operands.index('push')+1:] if 'push' in operands else []
    if len(tail)>=2 and ':' not in tail[-1]:
        branch=tail[-1]
        local=refs.get('refs/heads/'+branch) or local
        remote=next((sha for name,sha in refs.items() if name.startswith('refs/remotes/') and name.endswith('/'+branch)),None)
    if not local:return []
    env=metadata_environment(isolate=True)
    spec=f'{remote}..{local}' if remote else local
    command=['/usr/bin/git','-C',repository,'log' if remote else 'ls-tree','--name-only']
    if remote:command+=['--pretty=format:',spec]
    else:command+=['-r',local]
    try:
        text=subprocess.check_output(command,env=env,stderr=subprocess.DEVNULL,timeout=20).decode('utf-8','replace')
    except (OSError,subprocess.SubprocessError):
        return []
    seen=[]
    for line in text.splitlines():
        name=line.strip()
        if name and name not in seen:seen.append(name)
        if len(seen)>=500:break
    return seen

def git_invocation(args,cwd):
    """Parse Git global options to locate operation; preserve unknown cases as unknown."""
    path=pathlib.Path(cwd);i=0;context_known=True
    flags={'--bare','--no-replace-objects','--no-optional-locks','--literal-pathspecs','--glob-pathspecs','--noglob-pathspecs','--icase-pathspecs','--no-lazy-fetch','--no-advice','-p','--paginate','-P','--no-pager'}
    while i<len(args):
        a=args[i]
        if a in ('-C','-c','--git-dir','--work-tree','--namespace','--config-env'):
            if i+1>=len(args):return {'operation':'unknown','cwd':str(path),'metadataArgs':None,'metadataCwd':str(cwd)}
            if a=='-C':path=(path/args[i+1]).resolve()
            i+=2;continue
        if a.startswith(('--git-dir=','--work-tree=','--namespace=','--config-env=')) or a in flags:i+=1;continue
        if a.startswith('-'):context_known=False;i+=1;continue
        break
    op=args[i] if i<len(args) else 'unknown';tail=args[i+1:]
    # These private query arguments are consumed and removed by the launcher;
    # -c/config-env values must never be copied into the display manifest.
    result={'operation':op,'cwd':str(path),'repository':None,'destination':None,
            'metadataArgs':args[:i] if context_known and op!='unknown' else None,'metadataCwd':str(cwd)}
    if not context_known:
        result['operation']='unknown';return result
    if op=='clone':
        # Known clone options with arguments; unknown options disable result guessing.
        values={'--depth','--branch','-b','--origin','-o','--reference','--reference-if-able','--separate-git-dir','--filter','--template','--jobs','-j','--config','-c','--upload-pack','-u','--revision'}
        flags={'--quiet','-q','--verbose','-v','--bare','--mirror','--no-checkout','-n','--single-branch','--no-single-branch','--recurse-submodules','--recursive','--shallow-submodules','--no-tags','--local','-l','--shared','-s','--no-hardlinks','--no-local','--progress','--sparse','--reject-shallow'}
        operands=[];j=0
        while j<len(tail):
            a=tail[j]
            if a=='--':operands+=tail[j+1:];break
            if a in values:j+=2;continue
            if a in flags or any(a.startswith(v+'=') for v in values):j+=1;continue
            if a.startswith('-'):return result
            operands.append(a);j+=1
        if operands:result['repository']=safe_url(operands[0]) if '://' in operands[0] else operands[0]
        if len(operands)==2:result['destination']=str((path/operands[1]).resolve())
    return result
