#!/usr/bin/env python3
"""Native transport evidence. No inference of a network request from command text."""
import hashlib, json, pathlib, re, os
import sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))

CURL = re.compile(r'^(\S+) \[([^\]]+)\] (.*)$')
GIT = re.compile(r'^(\S+) http\.c:\d+\s+(.*)$')


def parse(run, trace_path=None):
    run = pathlib.Path(run)
    manifest = json.loads((run/'manifest.json').read_text())
    is_curl = manifest['tool'] == 'curl'
    path = pathlib.Path(trace_path) if trace_path else run/('curl.trace' if is_curl else 'git-curl.trace')
    events, blocks, processes = [], [], {}
    block = None
    sink=None
    bodies=run/'bodies';bodies.mkdir(exist_ok=True,mode=0o700)
    # Streaming input: do not hold downloaded bodies in memory.
    if not path.exists(): path.touch(mode=0o600)
    with path.open(errors='replace') as source:
        for line_number, line in enumerate(source, 1):
            match = (CURL if is_curl else GIT).match(line.rstrip('\n'))
            if not match:
                if is_curl and block and re.match(r'^[0-9a-fA-F]+: ', line):
                    # curl --trace is a 16-byte hex dump followed by display text.
                    encoded = line.split(': ', 1)[1][:48]
                    values = re.findall(r'(?<!\S)[0-9a-fA-F]{2}(?!\S)', encoded)
                    data = bytes.fromhex(''.join(values))
                    block['_hash'].update(data)
                    if sink:sink.write(data)
                    block['capturedBytes'] += len(data)
                    if block['kind']=='header':block['_header'].extend(data)
                    elif len(block['_preview'])<2048:block['_preview'].extend(data[:2048-len(block['_preview'])])
                continue
            if is_curl:
                timestamp, identity, message = match.groups()
                transfer, _, connection = identity.partition('-')
            else:
                timestamp, message = match.groups()
                transfer = connection = None
            info = {'line': line_number, 'time': timestamp, 'transferID': transfer,
                    'connectionID': connection, 'source': path.name}
            if sink:sink.close();sink=None
            if not is_curl and block:
                headerLine=re.match(r'(?:=> Send|<= Recv) header: ?(.*)',message)
                if headerLine:
                    block['_header'].extend((headerLine[1]+'\r\n').encode())
                    continue
            block = None
            m = re.match(r'(=> Send|<= Recv) (header|data), (\d+) bytes', message)
            if m:
                block = dict(info, direction='send' if m[1].startswith('=>') else 'receive',
                             kind=m[2], observedBytes=int(m[3]), capturedBytes=0,
                             byteExact=is_curl, _hash=hashlib.sha256(), _header=bytearray(), _preview=bytearray())
                blocks.append(block)
                if is_curl:
                    bodyFile=bodies/(str(line_number)+'.bin')
                    fd=os.open(bodyFile,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
                    sink=os.fdopen(fd,'wb');block['bodyFile']='bodies/'+bodyFile.name
            elif message.startswith('== Info:'):
                message = message[len('== Info:'):].strip()
                # Only route/connection lifecycle metadata, never arbitrary trace text.
                for kind, pattern in (
                    ('attempt', r'^Trying (.+)$'),
                    ('connected', r'^Connected to (.+)$'),
                    ('proxyTunnel', r'^Establish HTTP proxy tunnel to (.+)$'),
                    ('reuse', r'^Re-using existing connection (.+)$'),
                    ('connectionState', r'^Connection #(\d+) to host (.+) (left intact|closed)$'),
                    ('closed', r'^Closing connection (.+)$')):
                    m = re.match(pattern, message)
                    if m:
                        events.append(dict(info, kind=kind, detail=m.groups()))
                        break
    if sink:sink.close()
    for item in blocks:
        digest = item.pop('_hash').hexdigest()
        preview=item.pop('_preview')
        try:
            text=preview.decode('utf-8')
            if all(ord(c)>=32 or c in '\r\n\t' for c in text):
                text=re.sub(r'(?i)(Bearer\s+)[^\s]+',r'\1[隐藏]',text)
                text=re.sub(r'(?i)((?:password|secret|token|api[_-]?key)\s*[\"\']?\s*[:=]\s*[\"\']?)[^\s\"\',}]+',r'\1[隐藏]',text)
                item['textPreview']=text
                item['previewTruncated']=item['observedBytes']>len(preview)
        except UnicodeDecodeError:pass
        header=item.pop('_header').decode('utf-8','replace')
        # Expose only request/status lines, Host and Location; no cookies/auth headers.
        from results import safe_url
        item['http'] = []
        for line in header.splitlines():
            if re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT) ',line):
                parts=line.split(' ',2)
                target=parts[1].split('?',1)[0]
                if '://' in target:target=safe_url(target)
                item['http'].append(parts[0]+' '+target+' '+parts[-1])
            elif line.startswith('HTTP/'):item['http'].append(line)
            elif line.lower().startswith('host:'):item['http'].append(line)
            elif line.lower().startswith('location:'):item['http'].append('Location: '+safe_url(line.split(':',1)[1].strip()))
        if item['byteExact']:
            item['sha256'] = digest
            item['completeBlock'] = item['capturedBytes'] == item['observedBytes']
        else:
            # Git's textual libcurl dump is lossy for binary bodies.
            item['capturedBytes'] = None
            item['completeBlock'] = False
    trace2 = run/'git-processes.jsonl'
    if trace2.exists():
        with trace2.open() as trace_source:
            trace_lines = trace_source.readlines()
        for line in trace_lines:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get('event') not in ('child_start', 'child_exit'):
                continue
            key = e['sid'] + ':' + str(e['child_id'])
            child = processes.setdefault(key, {'id': key, 'parentSession': e['sid']})
            if e['event'] == 'child_start':
                child.update(startedAt=e.get('time'), childClass=e.get('child_class'))
            else:
                child.update(pid=e.get('pid'), exitCode=e.get('code'), finishedAt=e.get('time'))
    helpers=[]
    if not is_curl and trace_path is None:
        for metadata in sorted(run.glob('git-helper-*.json')):
            try:
                helper=json.loads(metadata.read_text())
                pid=helper['pid'];helperTrace=run/helper['traceFile']
                if helperTrace.resolve().parent!=run.resolve():continue
                matched=next((p for p in processes.values() if p.get('pid')==pid),None)
                helper['trace2Confirmed']=matched is not None
                detail=parse(run,trace_path=helperTrace)
                for row in detail['connections']+detail['blocks']:
                    row.update(helperPID=pid,helperName=helper['helper'],helperConfirmed=matched is not None)
                events.extend(detail['connections']);blocks.extend(detail['blocks']);helpers.append(helper)
            except (OSError,ValueError,KeyError):continue
    from git_packs import received_packs
    packs=received_packs(run,helpers) if not is_curl and trace_path is None else []
    return {'schema': 1, 'invocation': manifest, 'helpers': helpers, 'packFiles':packs, 'connections': events, 'blocks': blocks,
            'children': list(processes.values()),
            'attribution': 'explicit launcher labels; native task identity not independently verified',
            'limitations': ([] if is_curl else ['Git curl trace has no reliable per-line connection ID; helper PID attribution is confirmed only for independently logged helpers matched to Trace2', 'Git text trace is not byte-exact response payload; separately traced incoming PACK files cover clone/fetch object data only'])}

if __name__ == '__main__':
    import sys
    print(json.dumps(parse(sys.argv[1]), ensure_ascii=False, indent=2))
