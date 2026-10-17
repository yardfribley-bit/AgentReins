"""Per-command Git helper tracing. Original helper binaries and arguments are retained."""
import json,os,pathlib,subprocess,sys

HELPERS=('git-remote-http','git-remote-https','git-remote-ftp','git-remote-ftps')

def prepare(real,args,env,run):
    # Explicit user helper paths/configuration take precedence over audit configuration.
    if 'GIT_EXEC_PATH' in env or any(a.startswith('--exec-path') for a in args):
        return False
    native=pathlib.Path(subprocess.check_output([real,'--exec-path'],env=env,timeout=5,text=True).strip())
    if not native.is_dir():return False
    overlay=run/'git-helpers';overlay.mkdir(mode=0o700)
    original=run/'git-helper-targets.json'
    targets={name:str(native/name) for name in HELPERS if (native/name).is_file()}
    if not targets:return False
    fd=os.open(original,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as out:json.dump(targets,out)
    script=pathlib.Path(__file__).resolve()
    for source in native.iterdir():
        dest=overlay/source.name
        if source.name in targets:
            # Python invocation avoids shell interpretation of paths or arguments.
            text='#!'+sys.executable+'\nimport runpy\nrunpy.run_path('+repr(str(script))+',init_globals={"_entry":__file__},run_name="__main__")\n'
            fd=os.open(dest,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o700)
            with os.fdopen(fd,'w') as out:out.write(text)
        else:dest.symlink_to(source)
    env['GIT_EXEC_PATH']=str(overlay)
    return True

def main():
    entry=pathlib.Path(globals().get('_entry',sys.argv[0]))
    name=entry.name
    run=entry.resolve().parent.parent
    targets=json.loads((run/'git-helper-targets.json').read_text())
    target=targets[name]
    try:
        trace=run/('git-curl-'+str(os.getpid())+'.trace')
        fd=os.open(trace,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600);os.close(fd)
        record={'pid':os.getpid(),'parentPID':os.getppid(),'helper':name,'traceFile':trace.name}
        if os.environ.get('GIT_TRACE_PACKFILE')==str(run/'git-packfile.pack'):
            pack=run/('git-packfile-'+str(os.getpid())+'.pack')
            fd=os.open(pack,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600);os.close(fd)
            os.environ['GIT_TRACE_PACKFILE']=str(pack)
            record['packFile']=pack.name
        fd=os.open(run/('git-helper-'+str(os.getpid())+'.json'),os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as out:json.dump(record,out)
        os.environ['GIT_TRACE_CURL']=str(trace)
    except OSError:
        pass  # Keep executing the user's original helper if audit storage fails.
    # exec retains this PID. Trace2 child_exit independently reports the same child PID.
    os.execv(target,[target,*sys.argv[1:]])

if __name__=='__main__':main()
