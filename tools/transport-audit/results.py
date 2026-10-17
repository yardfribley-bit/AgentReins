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
