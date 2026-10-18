import asyncio
"""Opt-in mitmproxy addon for audited WorkBuddy model requests.

Run only for a WorkBuddy process explicitly launched with this local proxy.
The addon never changes system proxy settings or the trust store.
"""

import base64
import datetime
import hashlib
import importlib.util
import json
import os
import re
import threading
import time
from urllib.parse import urlsplit, quote
from pathlib import Path


ALLOWED_HOST = "copilot.tencent.com"
ALLOWED_PATHS = {
    "/v1/chat/completions",
    "/v2/chat/completions",
    "/v3/chat/completions",
    "/agenttool/v1/intent/recall",
    "/agenttool/v1/webfetch",
    "/agenttool/v1/search",
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
# One machine-wide journal used to grow without a bound. Keep the recent tail.
_JSONL_MAX = 128 * 1024 * 1024
_JSONL_KEEP = 64 * 1024 * 1024
_jsonl_lock = threading.Lock()


def _trim_jsonl(path):
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return
    if size <= _JSONL_MAX:
        return
    with open(path, "rb") as handle:
        handle.seek(size - _JSONL_KEEP)
        tail = handle.read()
    newline = tail.find(b"\n")
    if newline != -1:
        tail = tail[newline + 1 :]
    temporary = path.with_name(path.name + ".trim")
    temporary.write_bytes(tail)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


# Website scope is learned only from the audited Agent WebFetch request.
# Exact URLs expire after two minutes; redirects and unrelated hosts are not enrolled.
_targets = {}

def _website_scope(flow, stage):
    now = time.monotonic()
    for key in list(_targets):
        if _targets[key][0] < now:
            del _targets[key]
    if stage == "request" and flow.request.pretty_host.lower() == ALLOWED_HOST and flow.request.path.split("?", 1)[0] == "/agenttool/v1/webfetch":
        try:
            payload = json.loads(flow.request.get_content(strict=False) or b"{}")
            target = payload.get("url") if isinstance(payload, dict) else None
            parts = urlsplit(target) if isinstance(target, str) else None
            if parts and parts.scheme in ("http", "https") and parts.hostname and not parts.username and not parts.password:
                if len(_targets) >= 256:
                    del _targets[next(iter(_targets))]
                _targets[quote(target, safe=":/?&=%#+@;,~!$'()*[]")] = (now + 120, flow.id)
        except (ValueError, TypeError):
            pass
    if stage == "request":
        target = _targets.get(quote(flow.request.pretty_url, safe=":/?&=%#+@;,~!$'()*[]"))
        if target:
            flow.metadata["agentreins_webfetch_parent"] = target[1]
    return flow.metadata.get("agentreins_webfetch_parent")

def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _endpoint(value):
    if not value:
        return None
    host, port = value[0], value[1]
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = memoryview((json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
    with _jsonl_lock:
        _trim_jsonl(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            data = payload
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError("capture journal write made no progress")
                data = data[written:]
        finally:
            os.close(fd)


def _take_transport_call(flow):
    name = "X-AgentReins-Call"
    value = flow.request.headers.get(name)
    if value and re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", str(value)):
        flow.metadata["agentreins_call"] = str(value)
    try:
        del flow.request.headers[name]
    except KeyError:
        pass


def request(flow):
    _take_transport_call(flow)
    _capture(flow, "request")


def response(flow):
    _capture(flow, "response")
    _release(flow)


def error(flow):
    _capture(flow, "error")
    _release(flow)


def _release(flow):
    """Drop the flow from mitmdump's view after the body is recorded.

    This hook runs before the response is sent. Clearing response.content here
    replaces the download the client receives with an empty body.
    """
    try:
        from mitmproxy import ctx
        ctx.master.commands.call("view.flows.remove", [flow])
    except Exception:
        pass


_audit_module = None

def _content_audit():
    global _audit_module
    if _audit_module is not None:
        return _audit_module
    path = Path(__file__).with_name("content_audit.py")
    spec = importlib.util.spec_from_file_location("agentreins_content_audit", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _audit_module = module
    return module


def _security_audit(request_body, response_body, response_present, host=None):
    """Deterministic content indicators, never an assertion of compromise."""
    module = _content_audit()
    request_text = request_body.decode("utf-8", errors="replace") if isinstance(request_body, (bytes, bytearray)) else str(request_body or "")
    response_text = response_body.decode("utf-8", errors="replace") if isinstance(response_body, (bytes, bytearray)) else str(response_body or "")
    return module.audit(request_text, response_text, response_present, host)


def _safe_headers(headers):
    # Preserve repeated headers without persisting authentication credentials.
    hidden = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key"}
    return [[str(k), "[redacted]" if str(k).lower() in hidden else str(v)]
            for k, v in headers.items(multi=True)]


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

    website_parent = _website_scope(flow, stage)
    host = flow.request.pretty_host.lower()
    path = flow.request.path.split("?", 1)[0]
    remote_hosts = {item.strip().lower() for item in os.environ.get("AGENTREINS_REMOTE_TOOL_HOSTS", ALLOWED_HOST).split(",") if item.strip()}
    if path.rstrip("/").endswith("/chat/completions"):
        access_hop = "model"
    elif "/agenttool/" in path or (host in remote_hosts and path.startswith("/v2/videos/")):
        access_hop = "remote-tool"
    else:
        access_hop = "local-target"

    encoded_request = flow.request.raw_content or b""
    decoded_request = flow.request.get_content(strict=False) or b""
    decoded_response = flow.response.get_content(strict=False) if flow.response else b""
    declared = flow.request.headers.get("content-length")
    record = {
        "flowID": flow.id,
        "accessHop": access_hop,
        "websiteParentFlow": website_parent,
        "websiteURL": flow.request.pretty_url if website_parent else None,
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
        "securityAudit": _security_audit(decoded_request, decoded_response or b"", flow.response is not None, flow.request.pretty_host),
        "requestComplete": getattr(flow.request, "timestamp_end", None) is not None,
        "requestHeaders": _safe_headers(flow.request.headers),
        "responseHeaders": _safe_headers(flow.response.headers) if flow.response else None,
        "responseSHA256": hashlib.sha256(decoded_response).hexdigest() if flow.response else None,
        "responseStatus": flow.response.status_code if flow.response else None,
        "responseComplete": flow.response is not None and flow.response.timestamp_end is not None,
        "responseBodyBase64": base64.b64encode(decoded_response).decode("ascii") if flow.response else None,
        "transportCall": flow.metadata.get("agentreins_call"),
        # These values come from the exact mitmproxy flow carrying the body.
        # They prove route correlation without guessing from a nearby socket.
        "clientAddress": _endpoint(flow.client_conn.peername),
        "remoteHost": server_address[0] if server_address else None,
        "remotePort": server_address[1] if server_address else None,
    }
    _append_jsonl(OUTPUT, record)


# A proxy belongs to the live collector that launched it. Normal application
# exit stops it directly; parent loss also covers crashes and SIGTERM.
_parent_watch = None

async def _watch_capture_parent(parent_pid):
    from mitmproxy import ctx
    while os.getppid() == parent_pid:
        await asyncio.sleep(1)
    ctx.master.shutdown()

def running():
    global _parent_watch
    parent = os.environ.get("AGENTREINS_CAPTURE_PARENT_PID", "")
    if parent.isdigit() and int(parent) > 1:
        _parent_watch = asyncio.create_task(_watch_capture_parent(int(parent)))

def done():
    if _parent_watch is not None:
        _parent_watch.cancel()
