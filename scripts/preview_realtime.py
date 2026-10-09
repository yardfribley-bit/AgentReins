#!/usr/bin/env python3
"""Read-only localhost preview of the native app's live projection."""
import argparse
import gzip
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLIENT = r"""(()=>{let last=null,etag=null,busy=false;async function update(){if(busy)return;busy=true;try{const r=await fetch('/live-payload.json',{cache:'no-store',headers:etag?{'If-None-Match':etag}:{},signal:AbortSignal.timeout(10000)});if(r.status===304)return;etag=r.headers.get('ETag');if(!r.ok)throw Error('尚未收到原生实时数据');const p=await r.json();last=p;p.continuityNotice=['本页与 AgentReins 原生应用共用实时采集数据；文件打开等操作请在原生应用使用。',p.continuityNotice].filter(Boolean).join(' · ');window.agentreinsReceive(p);}catch(e){if(last)window.agentreinsReceive({...last,observing:false,continuityNotice:'实时数据连接中断，当前保留最后一次采集画面。'+String(e.message)});else{const w=document.getElementById('workspace-warning');w.hidden=false;w.textContent='实时数据尚未连接：'+String(e.message);}}finally{busy=false;}}update();setInterval(update,1000);})();"""

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--payload',required=True,type=Path)
    parser.add_argument('--port',type=int,default=18955)
    args=parser.parse_args()
    resources=Path(__file__).resolve().parents[1]/'Sources/AgentReins/Resources/RealtimeWorkspace'
    cache={'stamp':None,'data':None};lock=threading.Lock()
    allowed={'index.html','style.css','flow.js','live.js','runtime-graph.js','spider-graph.js'}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            route=self.path.split('?',1)[0]
            name=route.lstrip('/') or 'index.html'
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
                    etag='"'+str(stamp)+'"'
                    if self.headers.get('If-None-Match')==etag:self.send_response(304);self.end_headers();return
                    with lock:
                        if cache['stamp']!=stamp:cache.update(stamp=stamp,data=gzip.compress(file.read_bytes(),compresslevel=3))
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
