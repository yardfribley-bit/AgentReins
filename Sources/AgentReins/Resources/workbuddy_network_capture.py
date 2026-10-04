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
ALLOWED_PATHS = {
    "/v1/chat/completions",
    "/v2/chat/completions",
    "/v3/chat/completions",
    "/agenttool/v1/intent/recall",
    "/v2/videos/generations",
    "/v2/videos/tasks",
}
OUTPUT = Path(os.environ.get(
    "AGENTREINS_WORKBUDDY_NETWORK_JSONL",
    "~/Library/Application Support/AgentReins/workbuddy-network.jsonl",
)).expanduser()
ROUTE_OUTPUT = Path(os.environ.get(
    "AGENTREINS_WORKBUDDY_ROUTE_JSONL",
    "~/Library/Application Support/AgentReins/workbuddy-network-routes.jsonl",
)).expanduser()


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _endpoint(value):
    if not value:
        return None
    host, port = value[0], value[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        data = memoryview((json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
        while data:
            written = os.write(fd, data)
            if written <= 0:
                raise OSError("capture journal write made no progress")
            data = data[written:]
    finally:
        os.close(fd)


def request(flow):
    _capture(flow, "request")


def response(flow):
    _capture(flow, "response")


def error(flow):
    _capture(flow, "error")


def _capture(flow, stage):
    server_address = flow.server_conn.ip_address
    _append_jsonl(ROUTE_OUTPUT, {
        "flowID": flow.id,
        "captureStage": stage,
        "observedAt": _iso_now(),
        "host": flow.request.pretty_host,
        # Strip the query string because it can contain user or session data.
        "path": flow.request.path.split("?", 1)[0],
        "method": flow.request.method,
        "httpVersion": flow.request.http_version,
        "responseStatus": flow.response.status_code if flow.response else None,
        "clientAddress": _endpoint(flow.client_conn.peername),
        "remoteHost": server_address[0] if server_address else None,
        "remotePort": server_address[1] if server_address else None,
    })

    if flow.request.pretty_host.lower() != ALLOWED_HOST:
        return
    if flow.request.path.split("?", 1)[0] not in ALLOWED_PATHS:
        return

    encoded_request = flow.request.raw_content or b""
    decoded_request = flow.request.get_content(strict=False) or b""
    decoded_response = flow.response.get_content(strict=False) if flow.response else b""
    declared = flow.request.headers.get("content-length")
    record = {
        "flowID": flow.id,
        "captureStage": stage,
        "transportError": str(flow.error) if flow.error else None,
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
        # These values come from the exact mitmproxy flow carrying the body.
        # They prove route correlation without guessing from a nearby socket.
        "clientAddress": _endpoint(flow.client_conn.peername),
        "remoteHost": server_address[0] if server_address else None,
        "remotePort": server_address[1] if server_address else None,
    }
    _append_jsonl(OUTPUT, record)
