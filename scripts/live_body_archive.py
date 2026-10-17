"""Archive only newly appended Agent capture records; never discover historical logs."""
import base64,hashlib,json,os,pathlib,threading

class LiveBodyArchive:
    def __init__(self,source,root,start_offset=None):
        self.source=pathlib.Path(source);self.root=pathlib.Path(root);self.lock=threading.Lock()
        self.root.mkdir(parents=True,exist_ok=True,mode=0o700);self.cursor=self.root/'cursor.json'
        stat=self.source.stat() if self.source.exists() else None
        self.offset=start_offset if start_offset is not None else stat.st_size if stat else 0
        self.identity=(stat.st_dev,stat.st_ino) if stat else None
        if start_offset is None and self.cursor.exists():
            state=json.loads(self.cursor.read_text())
            if state.get('identity')==list(self.identity or []):self.offset=state['offset']
        self.errors=0
        # Persist the live boundary even while idle. A page-service restart can
        # then read bytes appended after this boundary instead of skipping them.
        if stat:self.write(self.cursor,json.dumps({'identity':list(self.identity),'offset':self.offset,'errors':self.errors}).encode())
    def write(self,path,data):
        temp=path.with_suffix(path.suffix+'.tmp');fd=os.open(temp,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as out:out.write(data)
        os.replace(temp,path)
    def ingest(self,item):
        flow=item.get('flowID')
        if not isinstance(flow,str) or not flow:return
        key=hashlib.sha256(flow.encode()).hexdigest();folder=self.root/key;folder.mkdir(exist_ok=True,mode=0o700)
        if self.root.resolve() not in folder.resolve().parents:raise ValueError('Invalid archive directory')
        metadata=folder/'metadata.json'
        if self.root.resolve() not in metadata.resolve().parents:raise ValueError('Invalid archive metadata')
        record=json.loads(metadata.read_text()) if metadata.exists() else {'flowID':flow}
        for side in ('request','response'):
            encoded=item.get(side+'BodyBase64');expected=item.get(side+'SHA256')
            if not isinstance(encoded,str) or not isinstance(expected,str):continue
            data=base64.b64decode(encoded,validate=True);digest=hashlib.sha256(data).hexdigest()
            if digest!=expected.lower():raise ValueError('Body hash mismatch')
            previous=record.get(side)
            if previous and previous.get('sha256')!=digest and previous.get('complete'):
                raise ValueError('Conflicting complete body for one flow')
            if not previous or previous.get('sha256')!=digest:self.write(folder/(side+'.bin'),data)
            record[side]={'bytes':len(data),'sha256':digest,'complete':item.get(side+'Complete') is True or bool(previous and previous.get('sha256')==digest and previous.get('complete')),'downloadURL':'/agent-body?key='+key+'&side='+side}
        if 'request' in record or 'response' in record:self.write(metadata,json.dumps(record).encode())
    def poll(self):
        with self.lock:
            if not self.source.exists():return
            stat=self.source.stat();identity=(stat.st_dev,stat.st_ino)
            if self.identity!=identity or stat.st_size<self.offset:
                # A replaced file starts a new live boundary; do not replay its old contents.
                self.identity=identity;self.offset=stat.st_size
            if stat.st_size==self.offset:return
            with self.source.open('rb') as src:
                src.seek(self.offset)
                for _ in range(32):
                    start=src.tell();line=src.readline(64*1024*1024+1)
                    if not line:break
                    if not line.endswith(b'\n'):break  # Retain the offset until the record is complete.
                    try:self.ingest(json.loads(line))
                    except (ValueError,TypeError,KeyError):self.errors+=1
                    self.offset=src.tell()
            self.write(self.cursor,json.dumps({'identity':list(self.identity),'offset':self.offset,'errors':self.errors}).encode())
    def details(self,flow):
        if not isinstance(flow,str):return None
        flow=flow.removeprefix('workbuddy-http:')
        metadata=self.root/hashlib.sha256(flow.encode()).hexdigest()/'metadata.json'
        if not metadata.exists() or self.root.resolve() not in metadata.resolve().parents:return None
        record=json.loads(metadata.read_text())
        return record if record.get('flowID')==flow else None
    def decorate(self,payload):
        task=payload.get('task',{})
        for card in task.get('cards',[]):
            body=card.get('networkBody')
            if not body:continue
            archive=self.details(body.get('flow'))
            if archive:
                if archive.get('request'):body['wireRequest']=archive['request']
                if archive.get('response'):body['wireResponse']=archive['response']
        return payload
