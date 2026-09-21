"""Opt-in mitmproxy addon for audited WorkBuddy model requests.

Run only for a WorkBuddy process explicitly launched with this local proxy.
The addon never changes system proxy settings or the trust store.
"""

import base64
import datetime
import hashlib
import json
import os
from pathlib import Path


ALLOWED_HOST = "copilot.tencent.com"
ALLOWED_PATHS = {"/v2/chat/completions", "/agenttool/v1/intent/recall"}
OUTPUT = Path(os.environ.get(
    "AGENTREINS_WORKBUDDY_NETWORK_JSONL",
    "~/Library/Application Support/AgentReins/workbuddy-network.jsonl",
)).expanduser()


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def response(flow):
    if flow.request.pretty_host.lower() != ALLOWED_HOST:
        return
    if flow.request.path.split("?", 1)[0] not in ALLOWED_PATHS:
        return

    encoded_request = flow.request.raw_content or b""
    decoded_request = flow.request.get_content(strict=False) or b""
    decoded_response = flow.response.get_content(strict=False) if flow.response else b""
    declared = flow.request.headers.get("content-length")
    record = {
        "observedAt": _iso_now(),
        "host": flow.request.pretty_host,
        "path": flow.request.path.split("?", 1)[0],
        "method": flow.request.method,
        "httpVersion": flow.request.http_version,
        "contentEncoding": flow.request.headers.get("content-encoding"),
        "declaredContentLength": int(declared) if declared and declared.isdigit() else None,
        "capturedWireBodyBytes": len(encoded_request),
        "requestBodyBase64": base64.b64encode(decoded_request).decode("ascii"),
        "requestSHA256": hashlib.sha256(decoded_request).hexdigest(),
        "responseStatus": flow.response.status_code if flow.response else None,
        "responseComplete": flow.response is not None and flow.response.timestamp_end is not None,
        "responseBodyBase64": base64.b64encode(decoded_response).decode("ascii") if flow.response else None,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    finally:
        os.close(fd)
