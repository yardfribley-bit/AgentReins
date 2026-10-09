#!/usr/bin/env python3
"""Local deterministic acceptance fixture; never launches or controls an Agent."""
import argparse, hashlib, json, os, pathlib, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

DATA = {'city': '上海', 'days': [{'date': '2026-10-10', 'low': 19, 'high': 24, 'rain': 70}, {'date': '2026-10-11', 'low': 18, 'high': 23, 'rain': 20}, {'date': '2026-10-12', 'low': 19, 'high': 25, 'rain': 10}]}

def append(root, filename, row):
    with (root / filename).open('a', encoding='utf-8') as f:
        f.write(json.dumps(row, ensure_ascii=False) + '\n')
        f.flush()

def create(root):
    root.mkdir(parents=True, exist_ok=False)
    (root / 'output').mkdir()
    (root / 'input').mkdir()
    (root / 'evidence').mkdir()
    for name, value in [('sales.csv', '渠道,本周,上周\n直营,128400,114337\n线上,96200,88504\n'), ('notes.txt', '中文材料\n不含凭证\n'), ('long.txt', '甲' * 70000 + '\nEND-MARKER\n')]:
        (root / 'input' / name).write_text(value, encoding='utf-8')
    (root / 'manifest.json').write_text(json.dumps({'version': 1, 'root': str(root), 'created_at_ns': time.time_ns(), 'data': DATA}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(root)

def serve(root):
    class Handler(BaseHTTPRequestHandler):
        counts = {}
        lock = threading.Lock()
        def log_message(self, *args): pass
        def do_GET(self):
            u = urlsplit(self.path)
            key = (u.path, parse_qs(u.query).get('run', ['default'])[0])
            with self.lock:
                n = self.counts.get(key, 0) + 1
                self.counts[key] = n
            status = 200
            headers = {'Content-Type': 'application/json; charset=utf-8'}
            body = json.dumps(DATA, ensure_ascii=False).encode()
            if u.path == '/retry' and n == 1:
                status, body = 429, b'{"error":"rate_limit"}'
                headers['Retry-After'] = '2'
            elif u.path == '/redirect':
                status, body = 302, b''
                headers['Location'] = '/data?' + u.query
            elif u.path == '/invalid': body = b'{invalid json'
            elif u.path == '/slow': time.sleep(4)
            elif u.path == '/download':
                body = b'fixture-download\n' * 1024
                headers = {'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="sample.txt"'}
            elif u.path not in ['/data', '/retry', '/slow']:
                status, body = 404, b'{"error":"not_found"}'
            append(root, 'server.jsonl', {'time_ns': time.time_ns(), 'method': 'GET', 'target': self.path, 'status': status, 'attempt': n, 'bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest()})
            self.send_response(status)
            for k, v in headers.items(): self.send_header(k, v)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    addr = f'http://127.0.0.1:{server.server_port}'
    (root / 'server.json').write_text(json.dumps({'url': addr, 'pid': os.getpid()}))
    print(addr, flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()

def run(root, case, run_id):
    append(root, 'runner.jsonl', {'phase': 'start', 'case': case, 'run': run_id, 'pid': os.getpid(), 'time_ns': time.time_ns()})
    code = 0
    try:
        if case == 'stream':
            for i in range(1, 6):
                value = f'{run_id} LINE-{i} 中文'
                append(root, 'runner.jsonl', {'phase': 'output', 'seq': i, 'text': value, 'stream': 'stdout' if i % 2 else 'stderr', 'time_ns': time.time_ns()})
                print(value, file=sys.stdout if i % 2 else sys.stderr, flush=True)
                time.sleep(1)
        elif case == 'business-error': print('{"status":"failed","error":"fixture-invalid-data"}', flush=True)
        elif case == 'fail':
            print(f'{run_id} fixture-exit-one', file=sys.stderr, flush=True)
            code = 1
        elif case == 'large':
            for i in range(2000): print(f'{run_id} ROW-{i:04d} ' + '输出' * 40, flush=True)
            print(f'{run_id} OUTPUT-END', flush=True)
        elif case == 'report':
            import urllib.request, urllib.error
            base = json.loads((root / 'server.json').read_text())['url']
            for attempt in (1, 2):
                try:
                    with urllib.request.urlopen(f'{base}/retry?run={run_id}', timeout=10) as response:
                        body = response.read()
                    print(f'{run_id} HTTP 200 attempt={attempt}', flush=True)
                    break
                except urllib.error.HTTPError as error:
                    print(f'{run_id} HTTP {error.code} attempt={attempt}', file=sys.stderr, flush=True)
                    if error.code != 429 or attempt == 2: raise
                    time.sleep(2)
            data = json.loads(body)
            target = root / 'output' / run_id
            target.mkdir(exist_ok=False)
            (target / 'weather.json').write_bytes(body)
            lines = ['# 上海出行建议', '', f'验收标记：{run_id}', '', '| 日期 | 温度 | 降雨 | 建议 |', '| --- | --- | --- | --- |']
            for d in data['days']:
                lines.append(f"| {d['date']} | {d['low']}–{d['high']}℃ | {d['rain']}% | " + ('携带雨具' if d['rain'] >= 50 else '适合户外') + ' |')
            lines += ['', f'数据来源：{base}/retry?run={run_id}', '']
            report = '\n'.join(lines)
            (target / 'report.md').write_text(report, encoding='utf-8')
            print(f'{run_id} ARTIFACT {target / "report.md"}', flush=True)
        else: raise ValueError(case)
    except Exception as error:
        code = 1
        append(root, 'runner.jsonl', {'phase': 'exception', 'case': case, 'run': run_id, 'type': type(error).__name__, 'time_ns': time.time_ns()})
        raise
    finally:
        append(root, 'runner.jsonl', {'phase': 'exit', 'case': case, 'run': run_id, 'code': code, 'time_ns': time.time_ns()})
    return code

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'serve', 'run'])
    parser.add_argument('--root', required=True, type=pathlib.Path)
    parser.add_argument('--case', choices=['stream', 'fail', 'business-error', 'large', 'report'])
    parser.add_argument('--run', default='RUN-A')
    args = parser.parse_args()
    root = args.root.resolve()
    if args.action == 'init': create(root)
    else:
        if not (root / 'manifest.json').is_file(): parser.error('fixture root has not been initialized')
        if args.action == 'serve': serve(root)
        else:
            if not args.case: parser.error('--case is required for run')
            if not args.run.replace('-', '').replace('_', '').isalnum(): parser.error('invalid run ID')
            sys.exit(run(root, args.case, args.run))
