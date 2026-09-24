"""Create initial single-enterprise enrollment locally; never print secrets.
Run only after explicit authorization. Existing enrollment is never overwritten.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import uuid
from datetime import datetime, timezone
from audit_server import password_hash

os.umask(0o077)
directory = Path.home() / 'Library/Application Support/AgentGuard/CloudAudit'
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
if (directory / 'device.json').exists():
    raise SystemExit('Enrollment exists; refusing to overwrite credentials or activation boundary.')
device_id = str(uuid.uuid4())
token = secrets.token_urlsafe(48)
password = secrets.token_urlsafe(24)
salt = secrets.token_hex(16)
enabled = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
device = dict(endpoint='https://165.154.254.180/api/audit/ingest', deviceID=device_id,
              token=token, enabledAt=enabled, uploadEnabled=True)
server = dict(admin=dict(username='admin', salt=salt, passwordHash=password_hash(password,salt)),
              devices={device_id:dict(label=socket.gethostname(), tokenHash=hashlib.sha256(token.encode()).hexdigest(), enabledAt=enabled)})
for name, obj in [('device.json',device),('server-config.json',server)]:
    with (directory/name).open('x') as file: json.dump(obj,file,indent=2)
with (directory/'管理员登录.txt').open('x') as file:
    file.write('AgentReins 企业审计管理端\nhttps://165.154.254.180/\n用户名：admin\n密码：'+password+'\n启用时间（UTC）：'+enabled+'\n仅启用后开始的新任务；历史不回传。\n')
print('Enrollment generated; activation UTC:',enabled)
print('Credential directory:',directory)
