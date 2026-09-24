"""Single-enterprise audit service. TLS terminates at the dedicated Nginx vhost.
Full evidence is stored outside the web root; all read paths require admin auth.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import sqlite3
import threading
from contextlib import contextmanager
from audit_blocks import Blocks, MissingBlock
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

MAX_BODY = 64 * 1024 * 1024


def utc():
    return datetime.now(timezone.utc).isoformat()


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200_000).hex()


def validate_identity(value):
    if value is None:
        return None  # Older clients remain readable; never invent an employee.
    if not isinstance(value, dict):
        raise ValueError('invalid_identity')
    for field in ['localUser', 'deviceName']:
        if not isinstance(value.get(field), str) or not 1 <= len(value[field]) <= 255:
            raise ValueError('invalid_identity')
    ips = value.get('localIPs')
    if not isinstance(ips, list) or len(ips) > 64:
        raise ValueError('invalid_identity_ips')
    networks = [ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
    for ip in ips:
        if not isinstance(ip, str) or not any(ipaddress.ip_address(ip) in n for n in networks):
            raise ValueError('invalid_identity_ip')
    if not isinstance(value.get('observedAt'), str):
        raise ValueError('invalid_identity_time')
    timestamp(value['observedAt'])
    return {k: value[k] for k in ['localUser', 'deviceName', 'localIPs', 'observedAt']}


def summarize(snapshot, device, receipt, received, identity=None):
    task = snapshot['task']
    activities = snapshot.get('activities', {})
    requests = snapshot.get('outboundRequests', [])
    memory = snapshot.get('analysis', {}).get('memoryEvidence', {})
    flows = activities.get('networkFlows', [])
    title = next(iter(snapshot.get('conversation', {}).get('userInputs', [])), '任务原话未采集')
    subject = identity or {}
    who = ' · '.join(['使用者：' + (subject.get('localUser') or '未采集'),
                      '设备：' + (subject.get('deviceName') or '未采集'),
                      '内网 IP：' + ('、'.join(subject.get('localIPs', [])) or '未采集')])
    return dict(title=title[:240], who=who, identity=identity,
                summary=f"{len(requests)} 条请求证据 · {len(flows)} 条外联证据",
                process=task['agentID'], data=f"{len(activities.get('files', []))} 条文件活动",
                send='已采集请求，发送状态需核对' if requests else '请求正文未采集',
                target='、'.join(str(f.get('domain') or f.get('ip') or '未知') for f in flows[:3]) or '外联目标未采集',
                conclusion='真实终端证据已接收；请逐项核对请求内容、记忆与实际连接。',
                limit='请求正文或加密前捕获不单独证明发送完成；未采集的记录不等于未发生。',
                receipt=f"已接收 · {receipt} · {received}", memoryAssessment=memory.get('assessment', 'unknown'))


def display_summary(raw):
    summary = json.loads(raw)
    # Historical summaries predate identity capture. Do not reinterpret a
    # hostname/IP enrollment label as a verified user or device name.
    if not summary.get('identity'):
        summary['who'] = '使用者：未采集 · 设备：未采集 · 内网 IP：未采集'
    return summary


def details(snapshot, summary, include_snapshot=False):
    a = snapshot.get('activities', {})
    analysis = snapshot.get('analysis', {})
    result = dict(summary)
    result['views'] = {
        'request': {'facts': [['内容来源', '右侧是终端采集的请求与响应正文，保留原始值；captureMode 与 completeness 指明覆盖范围。'],
                             ['敏感判断', '终端已有分析保留在 contextExposure 与 egressAudit。尚未配置服务端组织策略，不伪造命中或泄露结论。'],
                             ['发送状态', '不能仅凭出现请求正文判断发送完成；请对照来源、连接与响应关联证据。']],
                    'raw': {k: snapshot.get(k) for k in ['outboundRequests', 'modelResponses', 'externalRequests', 'capture', 'metrics']}},
        'memory': {'facts': [['记忆状态', 'usageInstructions 是使用规则，不等于记忆内容；memoryFileContent 与 contentMatches 提供内容及关联依据。'],
                            ['上传含义', '这份记忆证据已被企业审计端接收；是否进入模型请求，以各段 requestEventID 与采集完整性为准。']],
                   'raw': {'memoryEvidence': analysis.get('memoryEvidence'), 'memoryActivities': a.get('memory'), 'memoryCommits': analysis.get('memoryCommits')}},
        'relay': {'facts': [['外联归属', '保留 networkFlows 的 category、grade、reason 和原始 sourceEvent。连接归属与正文关联不是同一结论。'],
                           ['位置与运营者', '仅展示原始证据已有字段；服务端尚未接入地理与运营主体情报，不猜测节点位置。'],
                           ['中转获取内容', '服务端是否保留、查看或继续转发正文通常无法由终端连接单独证明。']],
                  'raw': {'networkFlows': a.get('networkFlows'), 'relaySecurity': analysis.get('relaySecurity')}},
        'process': {'facts': [['执行与读取', '工具参数、返回、文件记录和原始事件完整保留；读取、修改、进入请求分别核对。'],
                             ['使用者与设备', '使用者是终端上报的本机账号，尚未绑定企业员工身份。内网 IP 是采样时的地址，可含 VPN 地址，不作为唯一标识。'],
                             ['关联边界', '没有进程身份或父子关系的记录不补写进程链。']],
                    'raw': {'identity': summary.get('identity'), 'tools': a.get('tools'), 'toolResults': a.get('toolResults'), 'files': a.get('files'), 'mcpCalls': a.get('mcpCalls'),
                            'sourceEvents': snapshot.get('sourceEvents'), 'contextExposure': analysis.get('contextExposure'), 'egressAudit': analysis.get('egressAudit')}}
    }
    if include_snapshot:
        result['snapshot'] = snapshot
    return result


class Store:
    def __init__(self, path):
        self.path = str(path)
        self.blocks = Blocks(str(path) + '.blocks')
        self.assembly_slot = threading.BoundedSemaphore(1)
        with self.connect() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY, device TEXT NOT NULL, task TEXT NOT NULL,
              sequence INTEGER NOT NULL, latest TEXT NOT NULL, summary TEXT NOT NULL, UNIQUE(device,task));
            CREATE TABLE IF NOT EXISTS evidence(receipt TEXT PRIMARY KEY, device TEXT NOT NULL, task TEXT NOT NULL,
              sequence INTEGER NOT NULL, digest TEXT NOT NULL, received TEXT NOT NULL, body BLOB NOT NULL,
              UNIQUE(device,task,sequence));
            CREATE TABLE IF NOT EXISTS access_log(id INTEGER PRIMARY KEY, at TEXT, actor TEXT, action TEXT, target TEXT);
            CREATE TABLE IF NOT EXISTS evidence_identity(receipt TEXT PRIMARY KEY, identity TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS snapshot_bodies(digest TEXT PRIMARY KEY,body BLOB NOT NULL);
            ''')
            if 'revision' not in [r['name'] for r in db.execute('PRAGMA table_info(cases)')]:
                db.execute('ALTER TABLE cases ADD COLUMN revision INTEGER NOT NULL DEFAULT 0')
            db.execute('CREATE INDEX IF NOT EXISTS cases_revision ON cases(revision)')
            columns = {r['name'] for r in db.execute('PRAGMA table_info(evidence)')}
            for column in ['root_hash', 'body_digest']:
                if column not in columns: db.execute(f'ALTER TABLE evidence ADD COLUMN {column} TEXT')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db: yield db
        finally: db.close()

    def audit(self, actor, action, target):
        with self.connect() as db:
            db.execute('INSERT INTO access_log(at,actor,action,target) VALUES(?,?,?,?)', (utc(), actor, action, target))

    def snapshot(self, row, keys=None):
        if row['root_hash']:
            if not self.assembly_slot.acquire(blocking=False): raise OSError('assembly_busy')
            try: return self.blocks.assemble(row['device'], row['root_hash'], keys)
            finally: self.assembly_slot.release()
        body = row['body']
        if row['body_digest']:
            with self.connect() as db:
                body = db.execute('SELECT body FROM snapshot_bodies WHERE digest=?', (row['body_digest'],)).fetchone()[0]
        value = json.loads(body)
        return value if keys is None else {k:v for k,v in value.items() if k in keys}

    def ingest_v2(self, packet, device_id, device):
        if packet.get('deviceID') != device_id: raise ValueError('invalid_device')
        operation = packet.get('op')
        if operation == 'probe': return {'missing': self.blocks.missing(device_id, packet.get('hashes'))}
        if operation == 'block':
            self.blocks.put(device_id, packet.get('hash'), packet.get('data'))
            return {'stored': packet['hash']}
        if operation != 'commit': raise ValueError('invalid_operation')
        root = packet['root']
        if not self.assembly_slot.acquire(blocking=False): raise OSError('assembly_busy')
        try:
            snapshot = self.blocks.assemble(device_id, root)
            return self.ingest(dict(packet, snapshot=snapshot), device_id, device, root=root)
        finally: self.assembly_slot.release()

    def ingest(self, packet, device_id, device, root=None):
        identity = validate_identity(packet.get('identity'))
        snapshot = packet.get('snapshot', {})
        task = snapshot.get('task', {})
        sequence = packet.get('sequence')
        if packet.get('deviceID') != device_id or not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise ValueError('invalid_device_or_sequence')
        if not all(isinstance(task.get(k), str) and 0 < len(task[k]) <= 2048 for k in ['taskID', 'sessionID', 'turnID', 'agentID']):
            raise ValueError('invalid_task_identity')
        boundary = timestamp(device['enabledAt'])
        if timestamp(task['startedAt']) < boundary:
            raise ValueError('historical_task_rejected')
        prompts = [e for e in snapshot.get('sourceEvents', []) if e.get('kind') == 'model' and e.get('op') == 'prompt']
        if not prompts or min(timestamp(e.get('startedAt') or e['ts']) for e in prompts) < boundary:
            raise ValueError('missing_new_task_request')
        if not snapshot.get('conversation', {}).get('userInputs'):
            raise ValueError('missing_user_request')
        if timestamp(task['startedAt']) > datetime.now(timezone.utc).timestamp() + 300:
            raise ValueError('future_task_rejected')
        body = json.dumps(snapshot, ensure_ascii=False, separators=(',', ':')).encode()
        body_digest = hashlib.sha256(body).hexdigest()
        identity_body = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(',', ':')) if identity else None
        digest = hashlib.sha256(body + (identity_body.encode() if identity_body else b'')).hexdigest()
        receipt = hashlib.sha256(f'{device_id}:{task["taskID"]}:{sequence}'.encode()).hexdigest()
        now = utc()
        with self.connect() as db:
            prior = db.execute('SELECT digest,received FROM evidence WHERE receipt=?', (receipt,)).fetchone()
            if prior:
                if prior['digest'] != digest:
                    raise ValueError('sequence_content_conflict')
                return dict(receiptID=receipt, receivedAt=prior['received'], sequence=sequence, persisted=True)
            summary = summarize(snapshot, device, receipt, now, identity)
            if not root:
                db.execute('INSERT OR IGNORE INTO snapshot_bodies VALUES(?,?)', (body_digest, body))
            db.execute('INSERT INTO evidence(receipt,device,task,sequence,digest,received,body,root_hash,body_digest) VALUES(?,?,?,?,?,?,?,?,?)',
                (receipt, device_id, task['taskID'], sequence, digest, now, b'', root, None if root else body_digest))
            if identity_body:
                db.execute('INSERT INTO evidence_identity VALUES(?,?)', (receipt, identity_body))
            revision = db.execute('INSERT INTO access_log(at,actor,action,target) VALUES(?,?,?,?)', (now, device_id, 'ingest', receipt)).lastrowid
            db.execute('''INSERT INTO cases(device,task,sequence,latest,summary,revision) VALUES(?,?,?,?,?,?)
              ON CONFLICT(device,task) DO UPDATE SET sequence=excluded.sequence,latest=excluded.latest,summary=excluded.summary,revision=excluded.revision
              WHERE excluded.sequence>cases.sequence''', (device_id, task['taskID'], sequence, receipt, json.dumps(summary, ensure_ascii=False), revision))
        return dict(receiptID=receipt, receivedAt=now, sequence=sequence, persisted=True)


def handler(config, store, public):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # No credentials, query strings or evidence in web logs.

        def send_json(self, code, value):
            data = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def admin(self):
            header = self.headers.get('Authorization', '')
            try:
                username, password = base64.b64decode(header.removeprefix('Basic '), validate=True).decode().split(':', 1)
                valid = header.startswith('Basic ') and hmac.compare_digest(username, config['admin']['username']) and hmac.compare_digest(password_hash(password, config['admin']['salt']), config['admin']['passwordHash'])
            except (ValueError, UnicodeError):
                valid = False
            if not valid:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="AgentReins enterprise audit", charset="UTF-8"')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', '0')
                self.end_headers()
            return valid

        def do_GET(self):
            if not self.admin():
                return
            url = urlsplit(self.path)
            try:
                if url.path == '/api/audit/cases':
                    query = parse_qs(url.query)
                    limit = max(1, min(20, int(query.get('limit', ['20'])[0])))
                    cursor = int(query.get('cursor', [str(2**63 - 1)])[0])
                    after = int(query['after'][0]) if 'after' in query else None
                    if after is not None and after < 0:
                        raise ValueError('invalid_update_cursor')
                    with store.connect() as db:
                        db.execute('BEGIN')
                        watermark = db.execute('SELECT COALESCE(MAX(revision),0) FROM cases').fetchone()[0]
                        if after is None:
                            rows = db.execute('SELECT id,summary,revision FROM cases WHERE id<? ORDER BY id DESC LIMIT ?', (cursor, limit + 1)).fetchall()
                        else:
                            rows = db.execute('SELECT id,summary,revision FROM cases WHERE revision>? ORDER BY revision LIMIT ?', (after, limit + 1)).fetchall()
                            watermark = rows[limit-1]['revision'] if len(rows) > limit else max(after, watermark)
                    store.audit(config['admin']['username'], 'list', str(cursor))
                    return self.send_json(200, dict(schemaVersion=1, items=[dict(id=str(r['id']), record=display_summary(r['summary'])) for r in rows[:limit]],
                        updateCursor=str(watermark), nextCursor=str(rows[limit-1]['id']) if after is None and len(rows)>limit else None))
                if url.path.startswith('/api/audit/cases/'):
                    parts = url.path.strip('/').split('/')
                    case_id = int(parts[3])
                    section = parts[4] if len(parts) == 5 else None
                    if len(parts) > 5 or section not in [None, 'snapshot', 'request', 'memory', 'relay', 'process']:
                        return self.send_json(404, {'error': 'not_found'})
                    with store.connect() as db:
                        row = db.execute('SELECT c.summary,e.* FROM cases c JOIN evidence e ON e.receipt=c.latest WHERE c.id=?', (case_id,)).fetchone()
                        if not row:
                            return self.send_json(404, {'error': 'not_found'})
                    store.audit(config['admin']['username'], 'read_' + (section or 'detail'), str(case_id))
                    if section == 'snapshot':
                        return self.send_json(200, dict(schemaVersion=1, identity=display_summary(row['summary']).get('identity'), snapshot=store.snapshot(row)))
                    keys = {'request': ['outboundRequests','modelResponses','externalRequests','capture','metrics'],
                            'memory': ['analysis','activities'], 'relay': ['analysis','activities'],
                            'process': ['analysis','activities','sourceEvents']}.get(section)
                    record = details(store.snapshot(row, keys), display_summary(row['summary']))
                    if section: record['views'] = {section: record['views'][section]}
                    return self.send_json(200, dict(schemaVersion=1, record=record))
                files = {'/': ('index.html', 'text/html'), '/audit.js': ('audit.js', 'text/javascript'), '/audit.css': ('audit.css', 'text/css')}
                if url.path not in files:
                    return self.send_json(404, {'error': 'not_found'})
                name, mime = files[url.path]
                data = (public / name).read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', mime + '; charset=utf-8')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except (ValueError, TypeError):
                self.send_json(400, {'error': 'invalid_request'})
            except (OSError, sqlite3.Error):
                self.send_json(503, {'error': 'temporarily_unavailable'})

        def do_POST(self):
            if urlsplit(self.path).path != '/api/audit/ingest':
                return self.send_json(404, {'error': 'not_found'})
            supplied = self.headers.get('Authorization', '')
            device_id = self.headers.get('X-AgentReins-Device', '')
            device = config['devices'].get(device_id)
            if not device or not supplied.startswith('Bearer ') or not hmac.compare_digest(hashlib.sha256(supplied[7:].encode()).hexdigest(), device['tokenHash']):
                return self.send_json(401, {'error': 'device_auth_required'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if length < 1 or length > MAX_BODY:
                    return self.send_json(413, {'error': 'body_size_limit'})
                self.connection.settimeout(30)
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete_body')
                packet = json.loads(body)
                if not isinstance(packet, dict):
                    raise ValueError('invalid_packet')
                if packet.get('protocol') == 2 and length > 1024 * 1024:
                    return self.send_json(413, {'error': 'block_packet_size_limit'})
                receipt = store.ingest_v2(packet, device_id, device) if packet.get('protocol') == 2 else store.ingest(packet, device_id, device)
                self.send_json(200, receipt)
            except MissingBlock as error:
                self.send_json(409, {'error': 'missing_block', 'hash': str(error)})
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                self.send_json(400, {'error': 'invalid_or_out_of_scope_task'})
            except (OSError, sqlite3.Error):
                self.send_json(503, {'error': 'persistence_unavailable'})
    return Handler


if __name__ == '__main__':
    os.umask(0o077)
    config = json.loads(Path(os.environ.get('AUDIT_CONFIG', '/etc/agentreins-audit/config.json')).read_text())
    store = Store(os.environ.get('AUDIT_DB', '/var/lib/agentreins-audit/evidence.sqlite3'))
    server = ThreadingHTTPServer(('127.0.0.1', 8900), handler(config, store, Path(__file__).parent / 'public'))
    server.serve_forever()
