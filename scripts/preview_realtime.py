#!/usr/bin/env python3
"""Read-only localhost preview of the native app's live projection."""
import argparse
import json
import gzip
import hashlib
from urllib.parse import urlparse, parse_qs
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLIENT = r"""(()=>{let last=null,etag=null,busy=false;async function update(){if(busy)return;busy=true;try{const r=await fetch('/live-payload.json',{cache:'no-store',headers:etag?{'If-None-Match':etag}:{},signal:AbortSignal.timeout(10000)});if(r.status===304)return;etag=r.headers.get('ETag');if(!r.ok)throw Error('尚未收到原生实时数据');const p=await r.json();last=p;p.continuityNotice=['本页与 AgentReins 原生应用共用实时采集数据；文件打开等操作请在原生应用使用。',p.continuityNotice].filter(Boolean).join(' · ');window.agentreinsReceive(p);if(p.previewFreshness==='unconfirmed'&&p.observing){const label=document.getElementById('live-label');if(label)label.textContent='实时状态待核验';}}catch(e){if(last)window.agentreinsReceive({...last,observing:false,continuityNotice:'实时数据连接中断，当前保留最后一次采集画面。'+String(e.message)});else{const w=document.getElementById('workspace-warning');w.hidden=false;w.textContent='实时数据尚未连接：'+String(e.message);}}finally{busy=false;}}update();setInterval(update,1000);})();"""

def snapshot_bytes(raw, stale):
    if not stale:return gzip.compress(raw,compresslevel=3)
    payload=json.loads(raw)
    payload['previewFreshness']='unconfirmed'
    payload['continuityNotice']='数据快照超过 30 秒未变化。静默时系统不会重复发布相同数据；仅凭此时间无法判断采集是否中断，当前实时状态待核验。 · '+(payload.get('continuityNotice') or '')
    return gzip.compress(json.dumps(payload).encode(),compresslevel=3)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--payload',required=True,type=Path)
    parser.add_argument('--port',type=int,default=18955)
    parser.add_argument('--body-start-offset',type=int)
    parser.add_argument('--body-archive',type=Path,help='Private persistent directory for already captured HTTP bodies and their live cursor')
    args=parser.parse_args()
    from live_body_archive import LiveBodyArchive
    archive=LiveBodyArchive(Path.home()/'Library/Application Support/AgentReins/workbuddy-network.jsonl',args.body_archive or args.payload.parent/'body-archive',args.body_start_offset)
    def archive_loop():
        import time
        while True:
            try:archive.poll()
            except (OSError,ValueError):pass
            time.sleep(2)
    threading.Thread(target=archive_loop,daemon=True).start()
    resources=Path(__file__).resolve().parents[1]/'Sources/AgentReins/Resources/RealtimeWorkspace'
    cache={'stamp':None,'data':None};lock=threading.Lock()
    allowed={'index.html','style.css','flow.js','live.js','runtime-graph.js','spider-graph.js','network-view.js','transport-view.js'}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route=self.path.split('?',1)[0]
            name=route.lstrip('/') or 'index.html'
            if route=='/agent-body':
                query=parse_qs(urlparse(self.path).query);key=query.get('key',[''])[0];side=query.get('side',[''])[0]
                import re
                if not re.fullmatch('[a-f0-9]{64}',key) or side not in ('request','response'):self.send_error(400);return
                folder=archive.root/key
                try:
                    metadata_file=folder/'metadata.json'
                    if archive.root.resolve() not in metadata_file.resolve().parents:raise ValueError('Invalid archive metadata')
                    metadata=json.loads(metadata_file.read_text());record=metadata[side];file=folder/(side+'.bin')
                    if archive.root.resolve() not in file.resolve().parents or file.stat().st_size!=record['bytes']:raise ValueError('Invalid archive')
                    self.send_response(200);self.send_header('Content-Type','application/octet-stream')
                    self.send_header('Content-Disposition','attachment; filename="agent-'+side+'.bin"');self.send_header('X-Content-Type-Options','nosniff')
                    self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(record['bytes']));self.end_headers()
                    with file.open('rb') as source:
                        while chunk:=source.read(65536):self.wfile.write(chunk)
                except (OSError,ValueError,KeyError):self.send_error(404)
                return
            if route=='/transport-body':
                query=parse_qs(urlparse(self.path).query)
                run=query.get('run',[''])[0];line=query.get('line',[''])[0]
                import re
                if not re.fullmatch(r'[0-9a-f-]{36}',run) or not line.isdigit():self.send_error(400);return
                root=Path('/private/tmp/agentreins-transport-audit').resolve()
                folder=root/run
                try:
                    metadata=folder/'transport.json'
                    if root not in metadata.resolve().parents:raise ValueError('Invalid path')
                    item=json.loads(metadata.read_text())
                    block=next(b for b in item['blocks'] if str(b.get('line'))==line and b.get('kind')=='data' and b.get('byteExact') and b.get('completeBlock'))
                    file=folder/block['bodyFile']
                    if folder.resolve() not in file.resolve().parents:raise ValueError('Invalid path')
                    # Stream archived bytes without rendering untrusted HTML or loading full bodies.
                    if file.stat().st_size!=block['capturedBytes']:raise ValueError('Changed body')
                    self.send_response(200)
                    self.send_header('Content-Type','application/octet-stream')
                    self.send_header('Content-Disposition','attachment; filename="response-'+line+'.bin"')
                    self.send_header('X-Content-Type-Options','nosniff')
                    self.send_header('Cache-Control','no-store')
                    self.send_header('Content-Length',str(file.stat().st_size));self.end_headers()
                    with file.open('rb') as source:
                        while chunk:=source.read(65536):self.wfile.write(chunk)
                except (OSError,ValueError,KeyError,StopIteration):self.send_error(404)
                return
            if route=='/transport-pack':
                query=parse_qs(urlparse(self.path).query);run=query.get('run',[''])[0];name=query.get('file',[''])[0]
                import re
                if not re.fullmatch(r'[0-9a-f-]{36}',run) or not re.fullmatch(r'git-packfile(?:-\d+)?\.pack',name):self.send_error(400);return
                root=Path('/private/tmp/agentreins-transport-audit').resolve();folder=root/run
                try:
                    metadata=folder/'transport.json'
                    if root not in metadata.resolve().parents or metadata.stat().st_size>4_000_000:raise ValueError('Invalid metadata')
                    item=json.loads(metadata.read_text())
                    pack=next(p for p in item.get('packFiles',[]) if p['packFile']==name and p.get('complete'))
                    file=folder/name
                    if folder.resolve() not in file.resolve().parents or file.is_symlink() or file.stat().st_size!=pack['bytes']:raise ValueError('Invalid pack')
                    # Verify the stored proof at explicit download time; no background rehashing.
                    digest=hashlib.sha256()
                    with file.open('rb') as source:
                        while chunk:=source.read(65536):digest.update(chunk)
                    if digest.hexdigest()!=pack['sha256']:raise ValueError('Changed pack')
                    self.send_response(200);self.send_header('Content-Type','application/octet-stream')
                    self.send_header('Content-Disposition','attachment; filename="'+name+'"');self.send_header('X-Content-Type-Options','nosniff')
                    self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(pack['bytes']));self.end_headers()
                    with file.open('rb') as source:
                        while chunk:=source.read(65536):self.wfile.write(chunk)
                except (OSError,ValueError,KeyError,StopIteration):self.send_error(404)
                return
            if route=='/transport-audit.json':
                records=[]
                root=Path('/private/tmp/agentreins-transport-audit')
                for file in sorted(root.glob('*/transport.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:50]:
                    if file.is_symlink() or root.resolve() not in file.resolve().parents:continue
                    try:
                        if file.stat().st_size>4_000_000:continue
                        item=json.loads(file.read_text())
                        manifest=item.get('invocation',{})
                        record={k:manifest.get(k) for k in ['agent','tool','task','startedAt','pid','exitCode','captureMode','gap','codexThreadID','session']}
                        record['runID']=file.parent.name
                        record.update({k:item.get(k,[]) for k in ['connections','children','blocks','helpers','packFiles']})
                        record['fileResult']=item.get('fileResult')
                        record['repoResult']=item.get('repoResult')
                        record['gitOperation']=item.get('gitOperation')
                        record['limitations']=['只有独立 helper 日志并经 Trace2 核对的记录可确认子进程；同一 helper 的并发连接编号仍未提供。','Git 文本追踪不能还原完整二进制正文；单独保存的对象包仅覆盖 clone/fetch 接收的 PACK 数据，不代表整个协议或 push 正文。'] if manifest.get('tool')=='git' else []
                        records.append(record)
                    except (OSError,ValueError):continue
                records.sort(key=lambda r:r.get('startedAt') or '',reverse=True)
                self.respond(json.dumps(records).encode(),'application/json; charset=utf-8');return
            if route=='/task.json':
                query=parse_qs(urlparse(self.path).query);task_id=query.get('id',[''])[0];expected=query.get('revision',[None])[0]
                if not task_id or len(task_id)>4096:self.send_error(400);return
                if expected is not None and len(expected)>256:self.send_error(400);return
                name=hashlib.sha256(task_id.encode()).hexdigest()+'.json'
                file=args.payload.parent/'tasks'/name
                if file.is_symlink() or file.resolve().parent!=(args.payload.parent/'tasks').resolve():self.send_error(404);return
                from preview_task_details import task_detail,TaskExportChanging
                try:data=gzip.compress(json.dumps(archive.decorate(task_detail(file,args.payload,task_id,expected))).encode(),compresslevel=3)
                except TaskExportChanging:self.send_error(409,'Task export is updating');return
                except (OSError,ValueError):self.send_error(404,'Task detail unavailable');return
                self.respond(data,'application/json; charset=utf-8',compressed=True);return
            if route=='/live-payload.json':
                file=args.payload
                mime='application/json; charset=utf-8'
            elif route=='/preview-feed.js':
                self.respond(CLIENT.encode(),'text/javascript; charset=utf-8');return
            elif name in allowed:
                file=resources/name
                mime='text/html; charset=utf-8' if name.endswith('.html') else 'text/css; charset=utf-8' if name.endswith('.css') else 'text/javascript; charset=utf-8'
            else:self.send_error(404);return
            try:
                if route=='/live-payload.json':
                    stamp=file.stat().st_mtime_ns
                    import time
                    stale=time.time()-file.stat().st_mtime>30
                    etag='"'+str(stamp)+('-unchanged' if stale else '')+'"'
                    if self.headers.get('If-None-Match')==etag:self.send_response(304);self.end_headers();return
                    with lock:
                        cache_key=(stamp,stale)
                        if cache['stamp']!=cache_key:cache.update(stamp=cache_key,data=snapshot_bytes(file.read_bytes(),stale))
                        data=cache['data']
                else:data=file.read_bytes()
            except OSError:self.send_error(503,'Live data unavailable');return
            if name=='index.html':
                # Only this localhost preview can request its same-origin live feed.
                # The bundled native document keeps connect-src 'none'.
                data=data.replace(b"connect-src 'none'",b"connect-src 'self'")
                data=data.replace(b'</body>',b'<script src="/preview-feed.js"></script></body>')
            self.respond(data,mime,compressed=route=='/live-payload.json',etag=etag if route=='/live-payload.json' else None)
        def respond(self,data,mime,compressed=False,etag=None):
            self.send_response(200)
            self.send_header('Content-Type',mime)
            self.send_header('Cache-Control','no-store')
            if etag:self.send_header('ETag',etag)
            if compressed:self.send_header('Content-Encoding','gzip')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
    print(f'Native realtime preview: http://127.0.0.1:{args.port}/',flush=True)
    server.serve_forever()

if __name__=='__main__':main()
