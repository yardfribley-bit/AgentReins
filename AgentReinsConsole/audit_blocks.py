"""Device-scoped, content-addressed evidence blocks. No task-sized HTTP bodies.

Nodes are JSON objects: v=value, o=object of child hashes, a=array of hashes,
l=concatenated array pages, s=UTF-8 string split into raw byte blocks.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile

BLOCK_BYTES = 256 * 1024
MAX_ASSEMBLED_BYTES = 512 * 1024 * 1024


def valid_hash(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


class MissingBlock(ValueError):
    pass


class Blocks:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, device, digest):
        if not valid_hash(digest):
            raise ValueError('invalid_block_hash')
        return self.root / hashlib.sha256(device.encode()).hexdigest() / digest[:2] / digest

    def missing(self, device, hashes):
        if not isinstance(hashes, list) or len(hashes) > 512:
            raise ValueError('invalid_probe')
        return [h for h in hashes if not self.path(device, h).is_file()]

    def put(self, device, digest, encoded):
        payload = base64.b64decode(encoded, validate=True)
        if len(payload) > BLOCK_BYTES or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('block_integrity_or_size')
        path = self.path(device, digest)
        if path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as file:
                file.write(payload)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def read(self, device, digest):
        try: payload = self.path(device, digest).read_bytes()
        except FileNotFoundError: raise MissingBlock(digest)
        if len(payload) > BLOCK_BYTES or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('stored_block_corrupt')
        return payload

    def assemble(self, device, root, keys=None):
        budget = [0, 0]
        def read(digest):
            payload = self.read(device, digest)
            budget[0] += len(payload)
            budget[1] += 1
            if budget[0] > MAX_ASSEMBLED_BYTES or budget[1] > 200000:
                raise ValueError('assembly_budget_exceeded')
            return payload
        def expand(digest, depth=0):
            if depth > 64: raise ValueError('node_depth_exceeded')
            node = json.loads(read(digest))
            kind = node['t']
            if kind == 'j':
                value = node['v']
                if depth == 0 and keys is not None and isinstance(value, dict):
                    return {k: v for k, v in value.items() if k in keys}
                return value
            if kind == 'v':
                if isinstance(node['v'], (dict, list)): raise ValueError('invalid_scalar')
                return node['v']
            if kind == 's': return b''.join(read(h) for h in node['parts']).decode('utf-8')
            if kind == 'o': return {k: expand(v, depth+1) for k,v in node['v'].items() if depth or keys is None or k in keys}
            if kind == 'a': return [expand(h, depth+1) for h in node['v']]
            if kind == 'l':
                result = []
                for h in node['v']:
                    page = expand(h, depth+1)
                    if not isinstance(page, list): raise ValueError('invalid_array_page')
                    result.extend(page)
                return result
            raise ValueError('invalid_node')
        return expand(root)
