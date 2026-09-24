import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_blocks import Blocks, BLOCK_BYTES, MissingBlock


class BlockTests(unittest.TestCase):
    def test_more_than_64_mib_reassembles_without_large_http_packet(self):
        with tempfile.TemporaryDirectory() as directory:
            blocks = Blocks(directory)
            data = b'x' * BLOCK_BYTES
            digest = hashlib.sha256(data).hexdigest()
            blocks.put('device', digest, base64.b64encode(data).decode())
            node = json.dumps({'t': 's', 'parts': [digest] * 260}).encode()
            root = hashlib.sha256(node).hexdigest()
            blocks.put('device', root, base64.b64encode(node).decode())
            result = blocks.assemble('device', root)
            self.assertEqual(len(result), 65 * 1024 * 1024)
            self.assertTrue(result.startswith('xxx') and result.endswith('xxx'))
            self.assertEqual(sum(p.stat().st_size for p in Path(directory).rglob('*') if p.is_file()), len(data) + len(node))

    def test_unicode_split_and_stored_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            blocks = Blocks(directory)
            text = '用户原始内容🙂'
            data = text.encode()
            parts = []
            for chunk in (data[:1], data[1:]):
                digest = hashlib.sha256(chunk).hexdigest()
                blocks.put('device', digest, base64.b64encode(chunk).decode())
                parts.append(digest)
            node = json.dumps({'t': 's', 'parts': parts}).encode()
            root = hashlib.sha256(node).hexdigest()
            blocks.put('device', root, base64.b64encode(node).decode())
            self.assertEqual(blocks.assemble('device', root), text)
            with self.assertRaises(MissingBlock): blocks.assemble('other', root)
            blocks.path('device', parts[0]).write_bytes(b'corrupt')
            with self.assertRaises(ValueError): blocks.assemble('device', root)
