"""Validate native incoming Git PACK bytes without decoding or retaining them in memory."""
import hashlib,pathlib,struct

def inspect_pack(path):
    path=pathlib.Path(path)
    size=path.stat().st_size
    if not size:return None  # ls-remote and no-change fetch do not receive an object pack.
    record={'packFile':path.name,'bytes':size,'representation':'native-received-git-pack',
            'direction':'receive','complete':False}
    hashes={'sha256':hashlib.sha256(),'sha1Trailer':hashlib.sha1(),'sha256Trailer':hashlib.sha256()}
    offset=0
    with path.open('rb') as source:
        header=source.read(12);source.seek(0)
        while chunk:=source.read(65536):
            hashes['sha256'].update(chunk)
            for name,trailer in (('sha1Trailer',20),('sha256Trailer',32)):
                count=max(0,min(len(chunk),size-trailer-offset))
                hashes[name].update(chunk[:count])
            offset+=len(chunk)
        source.seek(max(0,size-32));tail=source.read()
    record['sha256']=hashes['sha256'].hexdigest()
    if len(header)!=12 or header[:4]!=b'PACK':
        record['problem']='Missing Git PACK header';return record
    record['version'],record['objects']=struct.unpack('>II',header[4:])
    if record['version'] not in (2,3):
        record['problem']='Unsupported Git PACK version';return record
    if size>=32 and hashes['sha1Trailer'].digest()==tail[-20:]:
        record.update(complete=True,objectHash='sha1')
    elif size>=44 and hashes['sha256Trailer'].digest()==tail:
        record.update(complete=True,objectHash='sha256')
    else:record['problem']='PACK trailer mismatch; partial or multiple packs cannot be exported as one complete pack'
    return record

def received_packs(run,helpers):
    run=pathlib.Path(run).resolve()
    candidates=[('git-packfile.pack',None)]+[(h['packFile'],h) for h in helpers if h.get('packFile')]
    records=[]
    for name,helper in candidates:
        try:
            path=run/name
            if path.resolve().parent!=run or path.is_symlink():continue
            item=inspect_pack(path)
            if item:
                if helper:item.update(helperPID=helper['pid'],helperName=helper['helper'],helperConfirmed=helper['trace2Confirmed'])
                records.append(item)
        except (OSError,ValueError):continue
    return records
