#!/usr/bin/env python3
"""Explicit Agent-scoped curl/Git native tracing. Does not alter system proxies.
Raw traces may contain secrets: directories 0700, files 0600. No stdout copying.
"""
import argparse, datetime, json, os, pathlib, subprocess, sys, uuid

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--agent',required=True,choices=['Codex','WorkBuddy'])
    p.add_argument('--task',required=True)
    p.add_argument('--call',required=True)
    p.add_argument('--root',type=pathlib.Path,required=True)
    p.add_argument('--result-file',type=pathlib.Path)
    p.add_argument('--repo-result',type=pathlib.Path)
    p.add_argument('tool',choices=['curl','git'])
    p.add_argument('args',nargs=argparse.REMAINDER)
    a=p.parse_args();os.umask(0o077)
    run=a.root/str(uuid.uuid4());run.mkdir(parents=True,mode=0o700)
    args=a.args[1:] if a.args[:1]==['--'] else a.args
    env=os.environ.copy();command=['/usr/bin/'+a.tool]
    if a.tool=='curl':
        if any(x.split('=')[0] in ['--trace','--trace-ascii','--trace-config','--no-trace','-v','--verbose'] for x in args):
            p.error('trace options are owned by the audit launcher')
        command+=['--trace',str(run/'curl.trace'),'--trace-time','--trace-ids']
    else:
        env.update(GIT_TRACE2_EVENT=str(run/'git-processes.jsonl'),GIT_TRACE_CURL=str(run/'git-curl.trace'),GIT_TRACE_CURL_NO_DATA='0',GIT_TRACE_REDACT='1')
    command+=args
    manifest={'schema':1,'agent':a.agent,'task':a.task,'call':a.call,'tool':a.tool,'startedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'launcherPID':os.getpid(),'coverage':'native tracing for this explicitly launched invocation; SSH payload unavailable; not blanket Agent coverage'}
    path=run/'manifest.json'
    path.write_text(json.dumps(manifest,indent=2));print('Audit evidence: '+str(run),file=sys.stderr)
    from results import file_result, repo_result
    beforeFile=file_result(a.result_file) if a.result_file else None
    beforeRepo=repo_result(a.repo_result) if a.repo_result else None
    proc=subprocess.Popen(command,env=env)
    manifest['pid']=proc.pid;path.write_text(json.dumps(manifest,indent=2))
    code=proc.wait();manifest.update(exitCode=code,finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat());path.write_text(json.dumps(manifest,indent=2))
    from parse import parse
    evidence=parse(run)
    if a.result_file:
        evidence['fileResult']=file_result(a.result_file)
        evidence['fileResult']['before']=beforeFile
    if a.repo_result:
        evidence['repoResult']=repo_result(a.repo_result)
        evidence['repoResult']['beforeCommit']=(beforeRepo or {}).get('commit')
    (run/'transport.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2))
    return code
if __name__=='__main__':sys.exit(main())
