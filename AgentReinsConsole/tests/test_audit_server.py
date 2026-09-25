import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_server import Store, handler, password_hash


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / 'audit.sqlite3')
        self.device = {'enabledAt': '2026-01-01T00:00:00Z', 'label': 'test-device', 'tokenHash': hashlib.sha256(b'device-secret').hexdigest()}
        self.config = {'admin': {'username': 'admin', 'salt': '12'*16, 'passwordHash': password_hash('test-password', '12'*16)}, 'devices': {'device': self.device}}
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), handler(self.config, self.store, Path(self.temp.name)))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.temp.cleanup()

    def packet(self):
        return {'deviceID': 'device', 'sequence': 1, 'snapshot': {
            'task': dict(taskID='task-1',sessionID='s',turnID='t',agentID='workbuddy',startedAt='2026-01-02T00:00:00Z'),
            'sourceEvents': [dict(kind='model',op='prompt',ts='2026-01-02T00:00:00Z')],
            'conversation': {'userInputs':['real task']}, 'outboundRequests': [{'body':'FULL-SECRET-NOT-REDACTED'}]}}

    def request(self, path, packet=None, admin=False, device=False):
        headers = {}
        if admin: headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:test-password').decode()
        if device: headers.update(Authorization='Bearer device-secret', **{'X-AgentReins-Device':'device'})
        with urlopen(Request(self.url+path, data=json.dumps(packet).encode() if packet is not None else None, headers=headers)) as r:
            return json.load(r)

    def test_authentication_full_evidence_idempotency_and_pagination(self):
        for path in ['/api/audit/cases', '/api/audit/cases/1', '/']:
            with self.assertRaises(HTTPError) as error: self.request(path)
            self.assertEqual(error.exception.code, 401)
        packet = self.packet()
        with self.assertRaises(HTTPError): self.request('/api/audit/ingest',packet)
        receipt = self.request('/api/audit/ingest', packet, device=True)
        self.assertEqual(receipt, self.request('/api/audit/ingest', packet, device=True))
        with self.assertRaises(HTTPError): self.request('/api/audit/cases',device=True)
        listing = self.request('/api/audit/cases?limit=1',admin=True)
        self.assertNotIn('FULL-SECRET',json.dumps(listing))
        full = self.request('/api/audit/cases/'+listing['items'][0]['id'],admin=True)
        self.assertIn('FULL-SECRET-NOT-REDACTED',json.dumps(full))
        packet['snapshot']['task']['taskID']='task-2'
        self.request('/api/audit/ingest',packet,device=True)
        listing = self.request('/api/audit/cases?limit=1',admin=True)
        self.assertIsNotNone(listing['nextCursor'])
        older = self.request('/api/audit/cases?limit=1&cursor='+listing['nextCursor'],admin=True)
        self.assertNotEqual(listing['items'][0]['id'],older['items'][0]['id'])

    def test_history_and_reused_sequence_rejected(self):
        packet = self.packet()
        packet['snapshot']['task']['startedAt']='2025-01-01T00:00:00Z'
        with self.assertRaises(ValueError): self.store.ingest(packet,'device',self.device)
        packet = self.packet()
        self.store.ingest(packet,'device',self.device)
        packet['snapshot']['conversation']['userInputs']=['changed']
        with self.assertRaises(ValueError): self.store.ingest(packet,'device',self.device)

    def test_blocks_missing_retry_dedup_and_selective_read(self):
        def upload(value):
            data = json.dumps(value, separators=(',', ':')).encode()
            digest = hashlib.sha256(data).hexdigest()
            packet = dict(protocol=2, deviceID='device', op='block', hash=digest, data=base64.b64encode(data).decode())
            first = self.request('/api/audit/ingest', packet, device=True)
            self.assertEqual(first, self.request('/api/audit/ingest', packet, device=True))
            return digest
        snapshot = self.packet()['snapshot']
        children = {key: upload({'t': 'j', 'v': value}) for key, value in snapshot.items()}
        root = upload({'t': 'o', 'v': children})
        probe = self.request('/api/audit/ingest', dict(protocol=2, deviceID='device', op='probe', hashes=[root, '0'*64]), device=True)
        self.assertEqual(probe['missing'], ['0'*64])
        self.assertEqual(probe['serverStatus'], 'accepting')
        self.assertEqual(probe['missingCount'], 1)
        commit = dict(protocol=2, deviceID='device', op='commit', root='0'*64, sequence=1)
        with self.assertRaises(HTTPError) as error: self.request('/api/audit/ingest', commit, device=True)
        self.assertEqual(error.exception.code, 409)
        commit['root'] = root
        ack = self.request('/api/audit/ingest', commit, device=True)
        self.assertEqual(ack['serverStatus'], 'committed')
        self.assertEqual(ack, self.request('/api/audit/ingest', commit, device=True))
        commit['sequence'] = 2
        self.request('/api/audit/ingest', commit, device=True)
        full = self.request('/api/audit/cases/1/snapshot', admin=True)
        self.assertEqual(full['snapshot'], snapshot)
        selected = self.request('/api/audit/cases/1/request', admin=True)['record']
        self.assertEqual(list(selected['views']), ['request'])
        self.assertNotIn('snapshot', selected)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT SUM(length(body)) FROM evidence').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM snapshot_bodies').fetchone()[0], 0)
        self.assertEqual(self.store.blocks.missing('another-device', [root]), [root])
        with self.assertRaises(ValueError): self.store.blocks.put('device', root, base64.b64encode(b'tampered').decode())

    def test_receiver_backpressure_returns_retry_after(self):
        self.store.assembly_slot.acquire()
        try:
            packet = dict(protocol=2, deviceID='device', op='commit', root='0'*64, sequence=1)
            request = Request(self.url + '/api/audit/ingest', data=json.dumps(packet).encode(),
                headers={'Authorization': 'Bearer device-secret', 'X-AgentReins-Device': 'device'})
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 503)
            self.assertEqual(error.exception.headers.get('Retry-After'), '5')
            payload = json.loads(error.exception.read())
            self.assertEqual(payload['serverStatus'], 'backpressure')
            self.assertEqual(payload['retryAfterMs'], 5000)
        finally:
            self.store.assembly_slot.release()

    def test_legacy_revisions_share_body_storage(self):
        packet = self.packet()
        for sequence in range(1, 4):
            packet['sequence'] = sequence
            self.store.ingest(packet, 'device', self.device)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 3)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM snapshot_bodies').fetchone()[0], 1)
        packet = self.packet(); packet['snapshot']['sourceEvents']=[]
        with self.assertRaises(ValueError): self.store.ingest(packet,'device',self.device)

    def test_out_of_order_revision_cannot_replace_newer(self):
        packet=self.packet(); packet['sequence']=2
        self.store.ingest(packet,'device',self.device)
        packet['sequence']=1
        self.store.ingest(packet,'device',self.device)
        with self.store.connect() as db:
            self.assertEqual(db.execute('SELECT sequence FROM cases').fetchone()[0],2)
            self.assertEqual(db.execute('SELECT count(*) FROM evidence').fetchone()[0],2)

    def test_identity_is_preserved_and_legacy_is_explicit(self):
        packet = self.packet()
        packet['identity'] = dict(localUser='employee', deviceName='Office Mac', localIPs=['192.168.1.11'], observedAt='2026-01-02T00:00:01Z')
        self.store.ingest(packet, 'device', self.device)
        full = self.request('/api/audit/cases/1', admin=True)['record']
        self.assertEqual(full['who'], '使用者：employee · 设备：Office Mac · 内网 IP：192.168.1.11')
        self.assertEqual(full['identity'], packet['identity'])
        self.assertNotIn('snapshot', full)
        self.assertEqual(self.request('/api/audit/cases/1/snapshot', admin=True)['snapshot'], packet['snapshot'])
        packet['identity']['localUser'] = 'different'
        with self.assertRaises(ValueError): self.store.ingest(packet, 'device', self.device)
        packet['sequence'] = 2
        packet.pop('identity')
        self.store.ingest(packet, 'device', self.device)
        listing = self.request('/api/audit/cases', admin=True)
        self.assertIn('使用者：未采集', listing['items'][0]['record']['who'])
        self.assertIn('设备：未采集', listing['items'][0]['record']['who'])
        self.assertIn('内网 IP：未采集', listing['items'][0]['record']['who'])
        full = self.request('/api/audit/cases/1', admin=True)['record']
        self.assertIn('使用者：未采集', full['who'])
        self.assertIn('内网 IP：未采集', full['who'])
        with self.store.connect() as db:
            self.assertEqual(json.loads(db.execute('SELECT identity FROM evidence_identity').fetchone()[0])['localUser'], 'employee')

    def test_incremental_updates_are_bounded_and_include_revisions(self):
        packet = self.packet()
        self.store.ingest(packet, 'device', self.device)
        cursor = self.request('/api/audit/cases', admin=True)['updateCursor']
        self.assertEqual(self.request('/api/audit/cases?after='+cursor, admin=True)['items'], [])
        packet['sequence'] = 2
        self.store.ingest(packet, 'device', self.device)
        for i in range(25):
            packet['snapshot']['task']['taskID'] = f'new-{i}'
            self.store.ingest(packet, 'device', self.device)
        updated = self.request('/api/audit/cases?after='+cursor, admin=True)
        self.assertEqual(len(updated['items']), 20)
        self.assertEqual(updated['items'][0]['id'], '1')
        self.assertNotIn('FULL-SECRET', json.dumps(updated))
        rest = self.request('/api/audit/cases?after='+updated['updateCursor'], admin=True)
        self.assertEqual(len(rest['items']), 6)
        self.assertEqual(self.request('/api/audit/cases?after='+rest['updateCursor'], admin=True)['items'], [])

    def test_invalid_identity_rejected(self):
        packet = self.packet()
        for ips in [['8.8.8.8'], ['bad'], '192.168.1.11', [None]]:
            packet['identity'] = dict(localUser='u', deviceName='d', localIPs=ips, observedAt='2026-01-02T00:00:00Z')
            with self.assertRaises(ValueError): self.store.ingest(packet, 'device', self.device)

if __name__=='__main__': unittest.main()
