"""Read-only evidence helpers for the AgentReins supervisor MCP.

Data sources: existing transport-audit folders and (optionally) the same
RealtimeWorkspace JS used by the packaged app. No new collectors.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1]
_TOOLS = REPO / "tools"
for _p in (_TOOLS, ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
from redact_secrets import redact_obj, redact_text  # noqa: E402

AUDIT_DIR = pathlib.Path.home() / "Library/Application Support/AgentGuard"
DEFAULT_TRANSPORT = pathlib.Path(
    os.environ.get(
        "AGENTREINS_TRANSPORT_ROOT",
        str(AUDIT_DIR / "transport-audit"),
    )
)
# Legacy world-writable path — never trusted as primary evidence (Unknown / skipped).
LEGACY_TRANSPORT = pathlib.Path("/private/tmp/agentreins-transport-audit")
AUDIT_LOG = AUDIT_DIR / "mcp-supervisor-audit.jsonl"
AUDIT_SEAL = AUDIT_DIR / "mcp-supervisor-audit.seal"
HMAC_KEY_FILE = AUDIT_DIR / "mcp-supervisor-hmac.key"
RUN_INVENTORY = AUDIT_DIR / "transport-run-inventory.jsonl"
# Integrity anchors live OUTSIDE the main audit wipe path (B9/B10). Still same uid (B6).
INTEGRITY_DIR = pathlib.Path.home() / "Library/Application Support/AgentReinsIntegrity"
PROTECTED_SEAL_DIR = INTEGRITY_DIR / "seals"
SIGNED_ERA_FLAG = INTEGRITY_DIR / "signed-era"
RUN_INVENTORY_MAC = INTEGRITY_DIR / "transport-run-inventory.mac"
KEYCHAIN_SERVICE = "com.agentreins.mcp-integrity"
KEYCHAIN_ACCOUNT_HMAC = "hmac-key"
KEYCHAIN_ACCOUNT_ERA = "signed-era"
KEYCHAIN_ACCOUNT_BOUNDARY = "integrity-boundary"
BOUNDARY_TOOL = "integrity-boundary"
BOUNDARY_ACTOR = "agentreins-integrity"
LEGACY_REASON = "signed with deleted pre-migration key"
KEYCHAIN_HELPER = ROOT / "keychain_helper"
KEYCHAIN_LIMITATION = (
    "HMAC 密钥与安装锚点经 Security.framework（AgentReinsKeychainHelper）写入 Keychain，"
    "不经 `security -A`、不把密钥放进 argv。旧明文 hmac 文件在迁入后删除。"
    "无无签名豁免清单：mac_mismatch 一律 ok=false。"
)
# Prefer packaged RealtimeWorkspace next to this MCP copy; fall back to repo Sources.
_PACKAGED_JS = ROOT.parent / "RealtimeWorkspace"
_REPO_JS = REPO / "Sources/AgentReins/Resources/RealtimeWorkspace"
WORKSPACE_JS = _PACKAGED_JS if (_PACKAGED_JS / "risk-alerts.js").is_file() else _REPO_JS
BRIDGE = ROOT / "alerts_bridge.cjs"
# Packaged Swift/JSC bridge (no system node). Falls back to node only in repo dev.
def _resolve_swift_bridge() -> pathlib.Path:
    env = os.environ.get("AGENTREINS_ALERTS_BRIDGE")
    if env:
        return pathlib.Path(env)
    packaged = ROOT.parent.parent / "MacOS" / "AgentReinsAlertsBridge"
    if packaged.is_file():
        return packaged
    return ROOT / "AgentReinsAlertsBridge"


SWIFT_BRIDGE = _resolve_swift_bridge()

DEFAULT_ALLOW = {
    "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
    "cdn.jsdelivr.net", "unpkg.com", "formulae.brew.sh", "ghcr.io", "docker.io",
    "registry-1.docker.io", "api.openai.com", "api.anthropic.com", "api2.cursor.sh",
    "cursor.com", "www.cursor.com", "chatgpt.com", "claude.ai", "openrouter.ai",
}


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_test_capture(record: dict[str, Any]) -> bool:
    """Same explicit provenance filter as risk-alerts.js (no hostname guessing)."""
    if record.get("testCapture") is True:
        return True
    if record.get("provenance") in ("test", "seed"):
        return True
    inv = record.get("invocation")
    if isinstance(inv, dict):
        if inv.get("testCapture") is True:
            return True
        if inv.get("provenance") in ("test", "seed"):
            return True
    sess = str(record.get("session") or record.get("codexThreadID") or "")
    if re.match(r"^(seed-session|test-capture)([:._-]|$)", sess, re.I):
        return True
    if str(record.get("agent") or "") == "__test__":
        return True
    return False


INB_RULE_IDS = ("INB", "instruction-override-inbound")
INB_PATTERN = re.compile(
    r"(?i)(?:ignore (?:all |the )?(?:previous|prior|system) instructions|忽略(?:之前|上述|系统)(?:的)?(?:指令|规则))"
)


def normalize_rule(rule: Any) -> Any:
    """Alerts say 'INB'; content_audit findings say 'instruction-override-inbound'. Same rule."""
    return "INB" if rule in INB_RULE_IDS else rule


def _window(text: str, start: int, end: int, window: int = 80) -> str:
    return text[max(0, start - window): min(len(text), end + window)]


def _redacted_match_context(finding: dict[str, Any], window: int = 80) -> str | None:
    """INB: redacted ±window chars around the stored hit. Never invents a stub when nothing was stored."""
    context = finding.get("matchContext") or finding.get("context")
    if not isinstance(context, str) or not context:
        return None
    text = context
    hit = INB_PATTERN.search(text)
    if hit and len(text) > 2 * window + len(hit.group(0)):
        text = _window(text, hit.start(), hit.end(), window)
    return redact_text(text)


def rescan_stored_response(record: dict[str, Any], window: int = 80, max_bytes: int = 2_000_000) -> str | None:
    """Older captures stored only rule + offset. Re-run the same INB pattern on the stored
    response bodies of that run (read-only) and return a redacted window, or None."""
    path = record.get("evidencePath")
    if not path:
        return None
    run = pathlib.Path(str(path)).parent
    budget = max_bytes
    for block in record.get("blocks") or []:
        if not isinstance(block, dict) or block.get("direction") != "receive" or not block.get("bodyFile"):
            continue
        body = (run / str(block["bodyFile"])).resolve()
        if run.resolve() not in body.parents or not body.is_file():
            continue
        try:
            text = body.read_bytes()[:budget].decode("utf-8", "replace")
        except OSError:
            continue
        budget -= len(text)
        hit = INB_PATTERN.search(text)
        if hit:
            return redact_text(_window(text, hit.start(), hit.end(), window))
        if budget <= 0:
            break
    return None


def credential_finding_summary(finding: dict[str, Any], record: dict[str, Any] | None = None) -> dict[str, Any]:
    """S02: metadata only. INB: redacted context snippet + rule id."""
    rule = finding.get("rule")
    out: dict[str, Any] = {
        "rule": rule,
        "direction": finding.get("direction"),
        "severity": finding.get("severity"),
        "count": finding.get("count"),
        "characterOffset": finding.get("characterOffset"),
        "label": finding.get("label") or rule,
        "matchedText": None,
        "ruleId": rule,
        "note": "原始匹配文本不通过 MCP 返回",
        "confidence": "Observed",
    }
    if normalize_rule(rule) == "INB":
        snippet = _redacted_match_context(finding)
        source = "stored_match_context" if snippet else None
        if snippet is None and record is not None:
            snippet = rescan_stored_response(record)
            source = "rescan_stored_response_body" if snippet else None
        out["matchContextRedacted"] = snippet
        out["matchContextSource"] = source
        out["note"] = (
            "MCP 仅返回脱敏上下文片段（命中处前后约 80 字符）；完整内容见本机详情页。"
            if snippet
            else "这次采集没有保存命中上下文，存下来的返回正文里也没有再次命中（可能是压缩或分块传输）；只有规则和字符位置。"
        )
    return out


def inb_finding_for(record: dict[str, Any] | None) -> dict[str, Any] | None:
    audit = (record or {}).get("securityAudit") or {}
    for finding in audit.get("findings") or []:
        if isinstance(finding, dict) and normalize_rule(finding.get("rule")) == "INB":
            return finding
    return None


# In-process index of transport runs. Warm list_agents does not re-read every transport.json.
# Invalidated when the set of run directory names or the transport root mtime changes.
_TRANSPORT_INDEX: dict[str, Any] = {
    "root": None,
    "rootMtime": None,
    "names": None,
    "rows": {},  # run name -> (dir_mtime_ns, row or None)
    "parsedFiles": 0,
    "lastTruncated": False,
}


def _parse_transport_file(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8")
        item = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return None
    _TRANSPORT_INDEX["parsedFiles"] = int(_TRANSPORT_INDEX.get("parsedFiles") or 0) + 1
    inv = item.get("invocation") if isinstance(item.get("invocation"), dict) else {}
    if inv.get("captureMode") != "agent-path":
        return None
    run_id = path.parent.name
    row = {
        "runID": run_id,
        "captureMode": "agent-path",
        "agent": inv.get("agent"),
        "tool": inv.get("tool"),
        "args": inv.get("args") or [],
        "task": inv.get("task"),
        "call": inv.get("call") or run_id,
        "startedAt": inv.get("startedAt"),
        "pid": inv.get("pid"),
        "parentPID": inv.get("parentPID"),
        "launcherPID": inv.get("launcherPID"),
        "exitCode": inv.get("exitCode"),
        "gap": inv.get("gap"),
        "auditBypass": inv.get("auditBypass"),
        "session": inv.get("session") or inv.get("codexThreadID"),
        "codexThreadID": inv.get("codexThreadID"),
        "provenance": inv.get("provenance") or "live",
        "testCapture": inv.get("testCapture") is True,
        "connections": item.get("connections") or [],
        "blocks": item.get("blocks") or [],
        "downloads": item.get("downloads") or [],
        "outboundFiles": item.get("outboundFiles") or [],
        "securityAudit": item.get("securityAudit"),
        "fileResult": item.get("fileResult"),
        "gitOperation": item.get("gitOperation"),
        "evidencePath": str(path),
        "evidenceSha256": sha256_hex(text[:200_000]),
        "confidence": "Observed",
    }
    if is_test_capture(row):
        return None
    return row


def _load_transport_dir(root: pathlib.Path, limit: int) -> list[dict[str, Any]]:
    if not root.is_dir():
        _TRANSPORT_INDEX["lastTruncated"] = False
        return []
    try:
        if (root.stat().st_mode & 0o777) != 0o700:
            root.chmod(0o700)
    except OSError:
        pass
    try:
        names = {entry.name for entry in os.scandir(root) if entry.is_dir(follow_symlinks=False) and not entry.name.startswith(".")}
        root_mtime = root.stat().st_mtime_ns
    except OSError:
        _TRANSPORT_INDEX["lastTruncated"] = False
        return []
    index = _TRANSPORT_INDEX
    same = index.get("root") == str(root) and index.get("names") == names and index.get("rootMtime") == root_mtime
    cached: dict[str, Any] = index.get("rows") if same else {}
    if not same:
        # Only directories that appeared or disappeared need a stat. Unchanged names keep their row.
        previous = index.get("rows") if index.get("root") == str(root) else {}
        cached = {name: previous[name] for name in names if name in previous}
        for name in names - set(cached):
            path = root / name / "transport.json"
            try:
                mtime = path.stat().st_mtime_ns if path.is_file() else None
            except OSError:
                mtime = None
            row = _parse_transport_file(path) if mtime is not None else None
            cached[name] = (mtime, row)
        index["root"] = str(root)
        index["rootMtime"] = root_mtime
        index["names"] = set(names)
        index["rows"] = cached
    ranked = [item for item in cached.values() if item and item[1] is not None]
    ranked.sort(key=lambda item: item[0] or 0, reverse=True)
    rows = [item[1] for item in ranked]
    index["lastTruncated"] = len(rows) > limit
    return rows[:limit]


def load_transport_records(root: pathlib.Path | None = None, limit: int = 80) -> list[dict[str, Any]]:
    """Load only the user-owned transport root. /private/tmp is not trusted and is skipped."""
    if root is not None:
        resolved = root.resolve()
        if str(resolved).startswith(str(LEGACY_TRANSPORT.resolve())) or str(resolved) == "/private/tmp" or str(resolved).startswith("/private/tmp/"):
            # Explicit legacy path → return empty with Unknown (caller may surface warning).
            return []
        return _load_transport_dir(root, limit)
    return _load_transport_dir(DEFAULT_TRANSPORT, limit)


def host_of(record: dict[str, Any]) -> str | None:
    for conn in record.get("connections") or []:
        if not isinstance(conn, dict):
            continue
        detail = conn.get("detail") or []
        if detail:
            token = str(detail[0]).split("/")[0]
            if ":" in token and not token.startswith("["):
                token = token.rsplit(":", 1)[0]
            return token.lower()
    for arg in record.get("args") or []:
        s = str(arg)
        if "://" in s:
            try:
                from urllib.parse import urlparse

                host = urlparse(s).hostname
                if host:
                    return host.lower()
            except Exception:
                pass
    return None


def is_allowed_host(host: str | None) -> bool:
    if not host:
        return False
    if host in DEFAULT_ALLOW:
        return True
    return any(host.endswith("." + a) for a in DEFAULT_ALLOW)


_EXECUTION_ID_CAP = 40
_SESSION_CAP = 40
_PAGE_MAX = 500


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(str(offset).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str) -> int | None:
    try:
        pad = "=" * (-len(cursor) % 4)
        n = int(base64.urlsafe_b64decode((cursor + pad).encode()).decode())
    except (ValueError, TypeError):
        return None
    return n if n >= 0 else None


def _parse_page(limit: int | None, offset: int | None, cursor: str | None,
                default_limit: int | None, max_limit: int = _PAGE_MAX) -> tuple[int, int | None]:
    if cursor:
        decoded = _decode_cursor(str(cursor))
        if decoded is None:
            raise ValueError("invalid cursor")
        offset = decoded
    else:
        offset = int(offset or 0)
    if offset < 0:
        raise ValueError("invalid offset")
    if limit is None:
        return offset, default_limit
    limit = int(limit)
    if limit < 1:
        limit = 1
    if limit > max_limit:
        limit = max_limit
    return offset, limit


def _page_window(items: list, offset: int, limit: int | None, known_total: int | None = None) -> dict[str, Any]:
    source_total = max(known_total if known_total is not None else len(items), len(items))
    start = min(max(0, offset), len(items))
    if limit is None:
        page = items[start:]
        effective = len(page)
    else:
        page = items[start:start + limit]
        effective = limit
    consumed = offset + len(page)
    truncated = consumed < source_total
    return {
        "items": page,
        "total": source_total,
        "offset": offset,
        "limit": effective,
        "truncated": truncated,
        "nextCursor": _encode_cursor(consumed) if truncated else None,
    }


def _page_meta(window: dict[str, Any]) -> dict[str, Any]:
    return {k: window[k] for k in ("total", "offset", "limit", "truncated", "nextCursor")}


def _in_time_range(value: Any, since_ts: float | None, until_ts: float | None) -> bool:
    """A bound drops a row only when its timestamp parses and falls outside, same as list_alerts."""
    if since_ts is None and until_ts is None:
        return True
    ts = _iso_ts(value)
    if ts is None:
        return True
    if since_ts is not None and ts < since_ts:
        return False
    if until_ts is not None and ts > until_ts:
        return False
    return True


def list_agents(
    records: list[dict[str, Any]] | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    cursor: str | None = None,
    transport_truncated: bool = False,
) -> dict[str, Any]:
    if records is None:
        records = load_transport_records()
        transport_truncated = bool(_TRANSPORT_INDEX.get("lastTruncated"))
    since_ts, until_ts = _iso_ts(since), _iso_ts(until)
    by_agent: dict[str, dict[str, Any]] = {}
    for row in records:
        if not _in_time_range(row.get("startedAt"), since_ts, until_ts):
            continue
        agent = str(row.get("agent") or "Unknown")
        bucket = by_agent.setdefault(
            agent,
            {
                "agent": agent,
                "sessions": set(),
                "executionIds": [],
                "tools": set(),
                "confidence": "Observed",
            },
        )
        if row.get("session"):
            bucket["sessions"].add(str(row["session"]))
        if row.get("call"):
            bucket["executionIds"].append(str(row["call"]))
        if row.get("tool"):
            bucket["tools"].add(str(row["tool"]))
    page_offset, page_limit = _parse_page(limit, offset, cursor, None)
    session_limit = min(_SESSION_CAP, page_limit if page_limit is not None else _SESSION_CAP)
    agents = []
    for agent, bucket in sorted(by_agent.items()):
        sessions = sorted(bucket["sessions"])
        ids = bucket["executionIds"]
        agents.append(
            {
                "agent": agent,
                "isCursor": agent == "Cursor",
                "sessions": sessions[:session_limit],
                "sessionCount": len(sessions),
                "sessionsTruncated": len(sessions) > session_limit,
                "executionIds": ids[:_EXECUTION_ID_CAP],
                "executionCount": len(ids),
                "executionIdsTruncated": len(ids) > _EXECUTION_ID_CAP,
                "tools": sorted(bucket["tools"]),
                "confidence": "Observed" if ids else "Unknown",
            }
        )
    window = _page_window(agents, page_offset, page_limit)
    result = {
        "agents": window["items"],
        "confidence": "Observed" if agents else "Unknown",
        "note": "仅来自 agent-path 传输审计；未走包装入口的进程不会出现。",
        "transportTruncated": transport_truncated,
    }
    result.update(_page_meta(window))
    return result


def _bridge_payload(records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "tasks": [],
        "collected": [],
        "health": [],
        "transports": [
            {
                "captureMode": "agent-path",
                "agent": r.get("agent"),
                "tool": r.get("tool"),
                "startedAt": r.get("startedAt"),
                "pid": r.get("pid") or 0,
                "parentPID": r.get("parentPID"),
                "launcherPID": r.get("launcherPID"),
                "exitCode": r.get("exitCode"),
                "runID": r.get("runID"),
                "call": r.get("call"),
                "session": r.get("session"),
                "args": r.get("args") or [],
                "connections": r.get("connections") or [],
                "blocks": r.get("blocks") or [],
                "downloads": r.get("downloads") or [],
                "auditBypass": r.get("auditBypass"),
                "securityAudit": r.get("securityAudit"),
                "gap": r.get("gap"),
                "provenance": r.get("provenance"),
                "testCapture": r.get("testCapture"),
            }
            for r in records
            if not is_test_capture(r)
        ],
    }


def build_alerts_via_bridge(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (alerts, meta). Prefer packaged Swift/JSC bridge (no system node); else node; else Python fallback."""
    meta: dict[str, Any] = {"engine": "js-bridge", "warning": None}
    js_ok = (WORKSPACE_JS / "risk-alerts.js").is_file()
    payload = _bridge_payload(records)
    payload_text = json.dumps(payload)

    def _run(cmd: list[str], engine: str) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
        try:
            proc = subprocess.run(
                cmd,
                input=payload_text,
                text=True,
                capture_output=True,
                timeout=20,
                cwd=str(ROOT),
                env={**os.environ, "AGENTREINS_WORKSPACE_JS": str(WORKSPACE_JS)},
            )
            if proc.returncode != 0:
                return None
            data = json.loads(proc.stdout)
            return data.get("alerts") or [], {"engine": engine, "warning": None}
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            return None

    if js_ok and SWIFT_BRIDGE.is_file() and os.access(SWIFT_BRIDGE, os.X_OK):
        hit = _run([str(SWIFT_BRIDGE)], "swift-jsc-bridge")
        if hit:
            return hit
    if js_ok and BRIDGE.is_file():
        # Dev / CI may still have node; packaged app prefers Swift bridge above.
        hit = _run(["node", str(BRIDGE)], "js-bridge")
        if hit:
            return hit
        meta = {
            "engine": "python-fallback",
            "warning": "JS 规则桥接失败；已显式回退，结果可能不完整。",
        }
        return build_alerts_fallback(records), meta
    meta = {
        "engine": "python-fallback",
        "warning": "未加载与 App 相同的 JS 规则引擎（risk-alerts.js）；Python 回退可能缺少完整 S03 关联。",
    }
    return build_alerts_fallback(records), meta


def conf_label(kind: str | None) -> str:
    return {
        "obs": "Observed",
        "cor": "Correlated",
        "inf": "Inferred",
        "unk": "Unknown",
        "Observed": "Observed",
        "Correlated": "Correlated",
        "Inferred": "Inferred",
        "Unknown": "Unknown",
    }.get(str(kind or "unk"), "Unknown")


def build_alerts_fallback(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Incomplete Python fallback — includes path-based S03; always paired with an explicit warning."""
    alerts = []
    downloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    execs: list[dict[str, Any]] = []
    for r in records:
        if is_test_capture(r):
            continue
        call = r.get("call")
        host = host_of(r) or "未知主机"
        audit = r.get("securityAudit") or {}
        for finding in audit.get("findings") or []:
            rule = finding.get("rule")
            if rule in ("credential-outbound", "private-key-outbound"):
                alerts.append(
                    {
                        "id": f"S02:{call}:{rule}",
                        "rule": "S02",
                        "title": "出站请求体含疑似密钥（已打码）",
                        "agent": r.get("agent"),
                        "session": r.get("session"),
                        "call": call,
                        "host": host,
                        "confidence": "Observed",
                        "finding": credential_finding_summary(finding),
                        "timestamp": r.get("startedAt"),
                    }
                )
            if normalize_rule(rule) == "INB":
                alerts.append(
                    {
                        "id": f"INB:{call}",
                        "rule": "INB",
                        "title": "收回内容含提示覆盖指令",
                        "agent": r.get("agent"),
                        "session": r.get("session"),
                        "call": call,
                        "host": host,
                        "confidence": "Observed",
                        "finding": credential_finding_summary(finding, r),
                        "timestamp": r.get("startedAt"),
                    }
                )
        if r.get("auditBypass") is True:
            alerts.append(
                {
                    "id": f"S07:{call}",
                    "rule": "S07",
                    "title": "命令绕过了审计代理",
                    "agent": r.get("agent"),
                    "session": r.get("session"),
                    "call": call,
                    "host": host,
                    "confidence": "Observed",
                    "timestamp": r.get("startedAt"),
                }
            )
        if host and not is_allowed_host(host) and not str(host).startswith("127."):
            alerts.append(
                {
                    "id": f"S04:{call}:{host}",
                    "rule": "S04",
                    "title": f"外联非白名单主机 {host}",
                    "agent": r.get("agent"),
                    "session": r.get("session"),
                    "call": call,
                    "host": host,
                    "confidence": "Observed" if call else "Unknown",
                    "timestamp": r.get("startedAt"),
                }
            )
        for d in r.get("downloads") or []:
            if isinstance(d, dict) and d.get("path"):
                downloads.append((r, d))
        tool = str(r.get("tool") or "")
        cmd = " ".join([tool] + [str(a) for a in (r.get("args") or [])])
        if tool in ("sh", "bash", "open") or re.search(
            r"/bin/(ba)?sh\b|(?:^|[\s;|&])sh\s+|\bbash\b|\bopen\s+", cmd
        ):
            if tool == "chmod" or re.match(r"^\s*chmod\b", cmd):
                pass
            elif not (r.get("downloads") or []):
                execs.append(r)
    for dl_rec, d in downloads:
        full = str(d.get("path"))
        name = full.rsplit("/", 1)[-1]
        try:
            start = time.mktime(time.strptime(str(dl_rec.get("startedAt") or "")[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        for ex in execs:
            cmd = " ".join([str(ex.get("tool") or "")] + [str(a) for a in (ex.get("args") or [])])
            if full not in cmd and name not in cmd:
                continue
            try:
                end = time.mktime(time.strptime(str(ex.get("startedAt") or "")[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                continue
            dt = end - start
            if dt < 0 or dt > 300:
                continue
            tool = str(ex.get("tool") or "")
            if tool == "chmod" or re.match(r"^\s*chmod\b", cmd):
                continue  # chmod is not execution
            lineage = dl_rec.get("pid") and ex.get("parentPID") and str(dl_rec.get("pid")) == str(ex.get("parentPID"))
            hash_hit = False
            dl_sha = str(d.get("sha256") or "").lower()
            ex_sha = str(ex.get("sha256") or (ex.get("fileResult") or {}).get("sha256") or "").lower()
            if dl_sha and ex_sha and dl_sha == ex_sha:
                hash_hit = True
            conf = "Correlated" if lineage or hash_hit else "Inferred"
            alerts.append(
                {
                    "id": f"S03:{dl_rec.get('call')}:{name}",
                    "rule": "S03",
                    "title": "下载后在 5 分钟内执行",
                    "agent": dl_rec.get("agent"),
                    "session": dl_rec.get("session"),
                    "call": ex.get("call") or dl_rec.get("call"),
                    "confidence": conf,
                    "timestamp": ex.get("startedAt"),
                    "sub": name,
                    "why": (
                        f"分级依据 {conf}：lineage={bool(lineage)} hashMatch={hash_hit} Δt={int(dt)}s"
                    ),
                }
            )
    # Dedupe by id keep last
    by_id: dict[str, dict[str, Any]] = {}
    for a in alerts:
        by_id[str(a.get("id"))] = a
    return list(by_id.values())


def list_alerts(
    agent: str | None = None,
    since: str | None = None,
    rule: str | None = None,
    records: list[dict[str, Any]] | None = None,
    until: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    cursor: str | None = None,
    transport_truncated: bool = False,
) -> dict[str, Any]:
    if records is None:
        records = load_transport_records()
        transport_truncated = bool(_TRANSPORT_INDEX.get("lastTruncated"))
    alerts, engine_meta = build_alerts_via_bridge(records)
    since_ts = _iso_ts(since)
    until_ts = _iso_ts(until)
    by_call: dict[str, dict[str, Any]] = {}
    for r in records:
        for k in (r.get("call"), r.get("runID")):
            if k:
                by_call.setdefault(str(k), r)
    out = []
    for alert in alerts:
        conf = conf_label(alert.get("confidence"))
        finding = alert.get("finding")
        if normalize_rule(alert.get("rule")) == "INB" and not finding:
            record = by_call.get(str(alert.get("call") or alert.get("executionId") or ""))
            raw = inb_finding_for(record)
            if raw is not None:
                finding = credential_finding_summary(raw, record)
        item = {
            "id": alert.get("id"),
            "rule": normalize_rule(alert.get("rule")),
            "title": alert.get("title"),
            "agent": alert.get("agent"),
            "session": alert.get("session"),
            "executionId": alert.get("call"),
            "confidence": conf,
            "timestamp": alert.get("timestamp") or alert.get("startedAt"),
            "sub": alert.get("sub"),
            "finding": finding,
        }
        if isinstance(finding, dict) and "matchContextRedacted" in finding:
            item["matchContextRedacted"] = finding.get("matchContextRedacted")
        if agent and agent != "all" and str(item.get("agent")) != agent:
            continue
        if rule and rule != "all" and str(item.get("rule")) != rule:
            continue
        if not _in_time_range(item.get("timestamp"), since_ts, until_ts):
            continue
        out.append(redact_obj(item))
    page_offset, page_limit = _parse_page(limit, offset, cursor, None)
    window = _page_window(out, page_offset, page_limit)
    result = {
        "alerts": window["items"],
        "confidence": "Observed" if out else "Unknown",
        "note": "告警由本机传输审计 + 与 App 相同的 risk-alerts.js 推导；无数据即为空，不放样本。",
        "engine": engine_meta.get("engine"),
        "transportTruncated": transport_truncated,
    }
    result.update(_page_meta(window))
    if engine_meta.get("warning"):
        result["warning"] = engine_meta["warning"]
    return result


def get_execution(execution_id: str, records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    records = records if records is not None else load_transport_records()
    hit = next(
        (
            r
            for r in records
            if str(r.get("call")) == execution_id or str(r.get("runID")) == execution_id
        ),
        None,
    )
    if not hit:
        return {
            "executionId": execution_id,
            "confidence": "Unknown",
            "note": "未找到该执行编号的传输审计记录。",
        }
    downloads = []
    for d in hit.get("downloads") or []:
        if not isinstance(d, dict):
            continue
        downloads.append(
            {
                "path": d.get("path"),
                "sha256": d.get("sha256"),
                "bytes": d.get("bytes"),
                "state": d.get("state"),
                "confidence": "Observed" if d.get("sha256") else "Unknown",
            }
        )
    audit = hit.get("securityAudit") or {}
    findings = [credential_finding_summary(f, hit) for f in (audit.get("findings") or [])]
    return redact_obj(
        dict(
            {
            "executionId": hit.get("call") or hit.get("runID"),
            "agent": hit.get("agent"),
            "session": hit.get("session"),
            "tool": hit.get("tool"),
            "commandArgs": hit.get("args") or [],
            "startedAt": hit.get("startedAt"),
            "exitCode": hit.get("exitCode"),
            "auditBypass": hit.get("auditBypass") is True,
            "downloads": downloads,
            "securityFindings": findings,
            "requestBytes": sum(
                int(b.get("observedBytes") or 0)
                for b in (hit.get("blocks") or [])
                if isinstance(b, dict) and b.get("direction") == "send"
            ),
            "responseBytes": sum(
                int(b.get("observedBytes") or 0)
                for b in (hit.get("blocks") or [])
                if isinstance(b, dict) and b.get("direction") == "receive"
            ),
            "evidenceSha256": hit.get("evidenceSha256"),
            "confidence": "Observed",
            "note": "正文预览已脱敏；S02 仅返回 finding 元数据。目的地字段与 list_network 同源（destination_fields）。",
            },
            **destination_fields(hit),
        )
    )


LOOPBACK_NAMES = ("localhost", "::1", "[::1]")
PROXY_VALUE_OPTIONS = {"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
                       "--proxy1.0", "--connect-to", "--resolve", "-e", "--referer", "-H", "--header"}
DESTINATION_EVIDENCE = {
    "proxy_observed": "Observed",       # curl/git trace of this execution: proxy CONNECT / Connected to <host>
    "connection_observed": "Observed",  # direct connection recorded in the trace of this execution
    "argv_parsed": "Inferred",          # host the command asked for; not seen on the wire
    "transport_peer_only": "Unknown",   # only the loopback proxy hop is known
}


def _is_loopback(host: str | None) -> bool:
    h = str(host or "").strip().lower()
    return h in LOOPBACK_NAMES or h.startswith("127.")


def argv_destination(args: list[Any]) -> str | None:
    """First destination host in argv; values of proxy / header options are skipped (shared rule with the sampler)."""
    from urllib.parse import urlparse

    skip = False
    for arg in args or []:
        s = str(arg)
        if skip:
            skip = False
            continue
        if s in PROXY_VALUE_OPTIONS:
            skip = True
            continue
        if s.startswith("-"):
            continue
        if "://" in s:
            try:
                host = urlparse(s).hostname
            except ValueError:
                host = None
            if host and not _is_loopback(host):
                return host.lower()
            continue
        m = re.match(r"^(?:[^@\s/]+@)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::|$)", s)
        if m:
            return m.group(1).lower()
    return None


def _real_destination(record: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Return (realHost, transportPeer, source) for proxied vs direct traffic.

    transportPeer stays the loopback proxy hop (e.g. 127.0.0.1:1087) when the TCP peer is a local proxy.
    """
    peer = None
    real = None
    source = None
    proxied = False
    for conn in record.get("connections") or []:
        if not isinstance(conn, dict):
            continue
        kind = conn.get("kind")
        if conn.get("source") == "argv":
            continue  # auto.py writes the argv target as a pseudo-connection for untraced tools; not observed
        if kind not in (None, "attempt", "connected", "proxyTunnel", "reuse"):
            continue  # e.g. connectionState detail[0] is a connection number, not a host
        for detail in conn.get("detail") or []:
            d = str(detail)
            hostport = (d.split()[0] if d else "").rstrip(".")
            if not re.search(r"[.:]", hostport) and hostport.lower() != "localhost":
                break
            host = hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport
            host = host.strip("[]").lower()
            if _is_loopback(host):
                port = re.search(r"port (\d+)", d)
                peer = peer or (f"{host}:{port.group(1)}" if port and ":" not in hostport else hostport or host)
                proxied = True
            elif host and not real:
                real = host
                source = "proxy_observed" if (kind == "proxyTunnel" or proxied) else "connection_observed"
            break  # only the first detail item names the endpoint
    if real and peer:
        source = "proxy_observed"
    if not real:
        audit = record.get("securityAudit") if isinstance(record.get("securityAudit"), dict) else {}
        argv_conn = next((str((c.get("detail") or [""])[0]).split()[0] for c in record.get("connections") or []
                          if isinstance(c, dict) and c.get("source") == "argv" and c.get("detail")), None)
        cand = (audit.get("destinationHost") or record.get("destinationHost") or argv_destination(record.get("args") or [])
                or argv_conn)
        if cand and not _is_loopback(cand):
            real = str(cand).split(":")[0].lower()
            source = "argv_parsed"
    if peer and not real:
        source = "transport_peer_only"
    return real, peer, source


# Loopback HTTP MCP listens here by default. A transport peer on this port is the supervisor
# itself, not the audit proxy (mitmdump, 18891/18893 or an explicit --proxy hop).
MCP_HTTP_PORT = 18977


def _peer_port(peer: str | None) -> int | None:
    if not peer or ":" not in peer:
        return None
    try:
        return int(peer.rsplit(":", 1)[-1])
    except ValueError:
        return None


def _argv_opts_out_of_proxy(args: Any) -> bool:
    for arg in args or []:
        text = str(arg).strip().lower()
        if text in ("--noproxy", "--no-proxy") or text.startswith("--noproxy=") or text.startswith("--no-proxy="):
            return True
    return False


def _via_proxy(record: dict[str, Any], peer: str | None, source: str | None) -> bool | None:
    """False when the command bypassed the audit proxy or the only peer is the MCP server."""
    if not source:
        return None
    if record.get("auditBypass") is True or _argv_opts_out_of_proxy(record.get("args")):
        return False
    if _peer_port(peer) == MCP_HTTP_PORT:
        return False
    return bool(peer)


def destination_fields(record: dict[str, Any]) -> dict[str, Any]:
    """One definition for get_execution and list_network (Python and Swift MCP mirror this)."""
    real, peer, source = _real_destination(record)
    # Never fall back to the loopback proxy hop as "the destination" (that is transportPeer).
    host = real or (None if source == "transport_peer_only" else host_of(record))
    if host and _is_loopback(host) and peer:
        host = None
    return {
        "destination": host,
        "realDestination": real,
        "transportPeer": peer,
        "destinationSource": source,
        "destinationEvidence": DESTINATION_EVIDENCE.get(source or "", "Unknown"),
        "viaProxy": _via_proxy(record, peer, source),
    }


SOCKET_LEDGER = pathlib.Path(
    os.environ.get("AGENTREINS_SOCKET_LEDGER", str(AUDIT_DIR / "socket-ledger.json"))
)
SOCKET_FIELDS = (
    "id", "agent", "pid", "ppid", "processName", "processPath", "processStartAt", "protocol",
    "localAddress", "remoteAddress", "remoteIP", "remotePort", "state", "firstSeen", "lastSeen",
    "sampleCount", "scope", "viaProxy", "transportPeer", "realDestination", "realDestinationPort",
    "destinationSource", "destinationEvidence", "destinationBasis", "forwardConfirmed", "transportCall",
    "proxy", "evidence", "proxyAttribution",
)


def _iso_ts(value: Any) -> float | None:
    if not value:
        return None
    try:
        import datetime as _dt

        return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def socket_ledger_seal_path(path: pathlib.Path) -> pathlib.Path:
    """Must match tools/socket-sampler/socket_sampler.py default_seal_path()."""
    home = AUDIT_DIR / "socket-ledger.json"
    try:
        if path.resolve() == home.resolve():
            return PROTECTED_SEAL_DIR / "socket-ledger.seal"
    except OSError:
        pass
    return path.with_name(path.name + ".seal")


def _read_locked(path: pathlib.Path) -> tuple[bytes | None, Any, Any]:
    """Read ledger + sidecar + seal under a shared lock so a concurrent sampler write is never seen half-done.
    The lock file is only opened if it already exists (read-only MCP never creates files here)."""
    import fcntl

    lock_path = path.with_name(path.name + ".lock")
    fh = None
    try:
        if lock_path.is_file():
            fh = open(lock_path, "rb")
            fcntl.flock(fh, fcntl.LOCK_SH)
        try:
            data = path.read_bytes()
        except OSError:
            data = None

        def rj(p: pathlib.Path) -> Any:
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None

        return data, rj(path.with_name(path.name + ".mac")), rj(socket_ledger_seal_path(path))
    finally:
        if fh is not None:
            fh.close()


def verify_socket_ledger(data: bytes | None, side: Any, seal: Any, key: bytes | None) -> dict[str, Any]:
    """Mirror of socket_sampler.verify_snapshot (kept in sync; Swift MCP ports the same rules)."""
    def bad(reason: str, **extra: Any) -> dict[str, Any]:
        return dict({"state": "tampered", "ok": False, "reason": reason, "confidence": "Unknown"}, **extra)

    sealed = isinstance(seal, dict) and not seal.get("unsigned")
    if data is None:
        if sealed:
            return bad("ledger_deleted_after_signed", sealSeq=seal.get("seq"))
        return {"state": "missing", "ok": None, "confidence": "Unknown", "reason": "no ledger"}
    if not isinstance(side, dict):
        if sealed:
            return bad("ledger_mac_missing_after_signed", sealSeq=seal.get("seq"))
        return {"state": "unsigned", "ok": None, "confidence": "Unknown",
                "reason": "no .mac sidecar (sampler older than tamper evidence, or never signed)"}
    if side.get("unsigned"):
        if sealed:
            return bad("unsigned_snapshot_after_signed", sealSeq=seal.get("seq"))
        return {"state": "unsigned", "ok": None, "confidence": "Unknown",
                "reason": str(side.get("reason") or "integrity key unavailable to the sampler")}
    if key is None:
        return {"state": "unverifiable", "ok": None, "confidence": "Unknown",
                "reason": "integrity key not available to this reader", "seq": side.get("seq")}
    fields = ("schema", "seq", "prevHash", "fileSha256", "at")
    body = {k: side[k] for k in fields if k in side}
    if not hmac.compare_digest(str(side.get("mac") or ""), entry_hmac(body, key)):
        return bad("ledger_mac_mismatch", seq=side.get("seq"))
    if side.get("fileSha256") != sha256_bytes(data):
        return bad("ledger_content_modified", seq=side.get("seq"))
    if side.get("hash") != sha256_hex(canonical_json(dict(body, mac=side.get("mac")))):
        return bad("ledger_sidecar_hash_mismatch", seq=side.get("seq"))
    seq = int(side.get("seq") or 0)
    if sealed:
        seal_body = {k: seal[k] for k in fields if k in seal}
        if not hmac.compare_digest(str(seal.get("mac") or ""), entry_hmac(seal_body, key)):
            return bad("ledger_seal_mac_mismatch", seq=seq)
        sseq = int(seal.get("seq") or 0)
        if sseq > seq:
            return bad("ledger_rolled_back", seq=seq, sealSeq=sseq)
        if sseq == seq and seal.get("hash") != side.get("hash"):
            return bad("ledger_seal_mismatch", seq=seq, sealSeq=sseq)
        if sseq < seq and not (sseq == seq - 1 and side.get("prevHash") == seal.get("hash")):
            return bad("ledger_seal_behind", seq=seq, sealSeq=sseq)
    elif seq > 1:
        return bad("ledger_seal_missing", seq=seq)
    return {"state": "verified", "ok": True, "confidence": "Observed", "seq": seq, "signedAt": side.get("at"),
            "reason": "HMAC over the exact ledger bytes verified; sequence matches the external seal"}


def _ledger_key() -> bytes | None:
    # A tool call that already decided the helper is still pending must not start a second 15s wait.
    if KEY_WARM.state == "pending":
        return None
    try:
        return load_or_create_hmac_key(create=False)
    except OSError:
        return None


def socket_freshness(samples: dict[str, Any], coverage: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """'sampling' only while samples keep arriving; otherwise 'stopped' with how long ago."""
    now = time.time() if now is None else now
    last = _iso_ts(samples.get("lastAt"))
    cadence = [coverage.get(k) for k in ("successGapSecondsP95", "configuredIntervalSeconds", "intervalSeconds")]
    base = max([float(c) for c in cadence if isinstance(c, (int, float))] or [3.0])
    limit = max(10.0, 3 * base)
    if last is None:
        return {"state": "stopped", "staleSeconds": None, "staleAfterSeconds": limit}
    age = now - last
    return {"state": "sampling" if age <= limit else "stopped", "staleSeconds": round(age, 1),
            "staleAfterSeconds": round(limit, 1)}


def load_socket_ledger(
    agent: str | None = None,
    since: str | None = None,
    path: pathlib.Path | None = None,
    limit: int = 200,
    until: str | None = None,
) -> dict[str, Any]:
    """Read-only view of tools/socket-sampler output (proxy-independent sockets)."""
    path = path or SOCKET_LEDGER
    raw, side, seal = _read_locked(path)
    # Freshness is judged at the moment the ledger was read, not after a (possibly slow) Keychain lookup.
    read_at = time.time()
    integrity = verify_socket_ledger(raw, side, seal, _ledger_key())
    try:
        data = json.loads(raw.decode("utf-8")) if raw is not None else None
        if not isinstance(data, dict):
            raise ValueError
    except (ValueError, UnicodeDecodeError):
        data = None
    if data is None:
        state = "tampered" if integrity["state"] == "tampered" else "not_running"
        return {
            "connections": [],
            "total": 0,
            "coverage": {
                "state": state,
                "confidence": "Unknown",
                "integrity": integrity,
                "note": "未找到按进程采样的连接记录（socket-sampler 未运行）；未走代理的流量不可见。"
                if state == "not_running" else "台账已签过名但现在不见了：按篡改处理，未走代理的流量不可见。",
            },
        }
    since_ts = _iso_ts(since)
    until_ts = _iso_ts(until)
    tampered = integrity["state"] == "tampered"
    rows = []
    for row in data.get("connections") or []:
        if not isinstance(row, dict):
            continue
        if agent and agent != "all" and str(row.get("agent")) != agent:
            continue
        if since_ts is not None and (_iso_ts(row.get("lastSeen")) or 0) < since_ts:
            continue
        if until_ts is not None and (_iso_ts(row.get("lastSeen")) or 0) > until_ts:
            continue
        out = {k: row.get(k) for k in SOCKET_FIELDS if k in row}
        if tampered:
            # Content no longer matches its signature: nothing in it can be called observed.
            out["evidence"] = "Unknown"
            out["destinationEvidence"] = "Unknown"
            out["ledgerIntegrity"] = "tampered"
        rows.append(out)
    rows.sort(key=lambda r: str(r.get("lastSeen") or ""), reverse=True)
    coverage = dict(data.get("coverage") or {})
    samples = data.get("samples") or {}
    fresh = socket_freshness(samples, coverage, now=read_at)
    coverage.update(
        samples=samples.get("count"),
        lastSampleAt=samples.get("lastAt"),
        failures=samples.get("failures", 0),
        lastFailure=samples.get("lastFailure"),
        lastFailureAt=samples.get("lastFailureAt"),
        failureLog=(samples.get("failureLog") or [])[-20:],
        samplerStartedAt=samples.get("samplerStartedAt"),
        integrity=dict(integrity, integritySince=data.get("integritySince"),
                       events=data.get("integrityEvents") or []),
        **fresh,
    )
    if tampered:
        coverage["state"] = "tampered"
    if tampered or fresh["state"] != "sampling" or integrity["state"] != "verified":
        coverage["confidence"] = "Unknown"
    if "missesShorterThanSeconds" in coverage and coverage.get("measurementConfidence") is None:
        # Ledger written by socket-sampler/1: its value was the configured interval, not a measurement.
        coverage["measurementConfidence"] = "Unknown"
        coverage["measurementNote"] = "采样器版本过旧：该值是配置间隔，不是实测周期"
    return {"connections": redact_obj(rows[:limit]), "total": len(rows), "coverage": coverage}


ROUTE_JOURNAL = pathlib.Path(os.environ.get(
    "AGENTREINS_WORKBUDDY_ROUTE_JSONL",
    str(pathlib.Path.home() / "Library/Application Support/AgentReins/workbuddy-network-routes.jsonl"),
))
_ROUTE_TAIL = {"sig": None, "flows": [], "bytesRead": 0}
_LOST_ATTRIBUTION = "via proxy · attribution lost"


def load_proxy_flows(path: pathlib.Path | None = None, limit: int = 200, tail_bytes: int = 2 * 1024 * 1024) -> list[dict[str, Any]]:
    """Recent proxy route records, read from the tail of the route journal (not the whole file).

    A flow the proxy could not attribute is returned with attributionState
    ``via proxy · attribution lost`` and a null pid. The host is the proxy's own observation.
    """
    path = path or ROUTE_JOURNAL
    try:
        st = path.stat()
    except OSError:
        return []
    sig = (str(path), st.st_size, st.st_mtime_ns)
    if _ROUTE_TAIL.get("sig") == sig:
        _ROUTE_TAIL["bytesRead"] = 0
        return list(_ROUTE_TAIL["flows"])
    try:
        with path.open("rb") as fh:
            fh.seek(max(0, st.st_size - tail_bytes))
            blob = fh.read()
    except OSError:
        return []
    _ROUTE_TAIL["bytesRead"] = len(blob)
    if st.st_size > tail_bytes:
        newline = blob.find(b"\n")
        if newline != -1:
            blob = blob[newline + 1:]
    by_flow: dict[str, dict[str, Any]] = {}
    for line in blob.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        flow_id = str(rec.get("flowID") or "")
        if not flow_id:
            continue
        state = rec.get("attributionState")
        pid = rec.get("clientPid") if isinstance(rec.get("clientPid"), int) else None
        if state is None and pid is None:
            # Journals written before request-time attribution have no owner. Say so; do not guess.
            state = _LOST_ATTRIBUTION
        lost = state == _LOST_ATTRIBUTION or pid is None
        by_flow[flow_id] = {
            "flowID": flow_id,
            "observedAt": rec.get("observedAt"),
            "agent": None if lost else rec.get("clientAgent"),
            "pid": None if lost else pid,
            "ppid": None if lost else rec.get("clientPpid"),
            "processName": None if lost else rec.get("clientProcess"),
            "processPath": None if lost else rec.get("clientPath"),
            "processStartAt": None if lost else rec.get("clientStartAt"),
            "parentChain": [] if lost else (rec.get("parentChain") or []),
            "attributionState": state,
            "attributionBasis": None if lost else rec.get("attributionBasis"),
            "host": rec.get("host"),
            "path": rec.get("path"),
            "method": rec.get("method"),
            "clientAddress": rec.get("clientAddress"),
            "remoteHost": rec.get("remoteHost"),
            "remotePort": rec.get("remotePort"),
            "viaProxy": True,
            "realDestination": rec.get("host"),
            "destinationSource": "proxy_attributed" if not lost else "proxy_unattributed",
            "destinationEvidence": "Observed" if not lost else "Unknown",
            "captureStage": rec.get("captureStage"),
            "confidence": "Observed" if not lost else "Unknown",
        }
    flows = sorted(by_flow.values(), key=lambda row: str(row.get("observedAt") or ""), reverse=True)[:limit]
    _ROUTE_TAIL["sig"] = sig
    _ROUTE_TAIL["flows"] = flows
    return list(flows)


def list_network(
    agent: str | None = None,
    since: str | None = None,
    records: list[dict[str, Any]] | None = None,
    until: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    cursor: str | None = None,
    transport_truncated: bool = False,
) -> dict[str, Any]:
    if records is None:
        records = load_transport_records()
        transport_truncated = bool(_TRANSPORT_INDEX.get("lastTruncated"))
    until_ts = _iso_ts(until)
    since_ts = _iso_ts(since) if until_ts is not None else None
    rows = []
    for r in records:
        if agent and agent != "all" and str(r.get("agent")) != agent:
            continue
        # `since` alone stays socket-only (historical). Command rows gain a bound when `until` is set.
        if until_ts is not None and not _in_time_range(r.get("startedAt"), since_ts, until_ts):
            continue
        dest = destination_fields(r)
        host = dest["destination"]
        rows.append(
            {
                "executionId": r.get("call") or r.get("runID"),
                "agent": r.get("agent"),
                "tool": r.get("tool"),
                **dest,
                "allowed": is_allowed_host(host) if host else None,
                "nonWhitelist": bool(
                    host and not is_allowed_host(host) and not str(host).startswith("127.")
                ),
                "auditBypass": r.get("auditBypass") is True,
                "startedAt": r.get("startedAt"),
                "exitCode": r.get("exitCode"),
                "confidence": "Observed" if host else "Unknown",
            }
        )
    page_offset, page_limit = _parse_page(limit, offset, cursor, None)
    fetch = min(5000, max(200, page_offset + (page_limit if page_limit is not None else 200)))
    sockets = load_socket_ledger(agent=agent, since=since, limit=fetch, until=until)
    connections = sockets["connections"]
    direct = [r for r in connections if r.get("viaProxy") is False and r.get("scope") == "public"]
    network_window = _page_window(rows, page_offset, page_limit)
    socket_window = _page_window(connections, page_offset, page_limit, known_total=sockets.get("total"))
    result = {
        "network": redact_obj(network_window["items"]),
        "sockets": socket_window["items"],
        "socketSummary": {
            "total": sockets.get("total", 0),
            "notViaProxyPublic": len(direct),
            "viaProxy": sum(1 for r in connections if r.get("viaProxy")),
            "ledgerIntegrity": (sockets["coverage"].get("integrity") or {}).get("state"),
        },
        "socketCoverage": sockets["coverage"],
        "socketsPage": _page_meta(socket_window),
        "proxyFlows": redact_obj(load_proxy_flows()),
        "confidence": "Observed" if rows or connections else "Unknown",
        "transportTruncated": transport_truncated,
        "note": (
            "network = 经审计入口的命令（transport-audit）。每条的 realDestination / destinationSource / transportPeer"
            "与 get_execution 同源：proxy_observed=本次 trace 里看到经代理连到该主机（Observed）；"
            "connection_observed=trace 里直连该主机（Observed）；argv_parsed=只从命令参数推出，线上没看到（Inferred）；"
            "transport_peer_only=只知道连到本机代理口（Unknown）。"
            "sockets = 按进程采样的全部 TCP/UDP 连接，与是否走代理无关（viaProxy=false 即未走代理）；其 realDestination："
            "proxy_observed=代理路由日志按本机端口+时间对上（Correlated）；argv_parsed=命令参数主机正向解析到同一 IP"
            "（Correlated）；dns_inferred=反向 DNS（Inferred）；socket_sampled=只有 IP（Observed）；proxy_unjoined="
            "走了代理但目的地未对上（Unknown）。transportPeer 保留实际对端（代理时为 127.0.0.1:端口）。"
            "采样会漏掉短于实测间隔（socketCoverage.missesShorterThanSeconds）的连接。"
        ),
    }
    result.update(_page_meta(network_window))
    return result


def _socket_sampling(cov: dict[str, Any]) -> dict[str, Any]:
    return {
        "effectiveIntervalSeconds": cov.get("effectiveIntervalSeconds"),
        "effectiveIntervalSecondsP95": cov.get("effectiveIntervalSecondsP95"),
        "missesShorterThanSeconds": cov.get("missesShorterThanSeconds"),
        "estimatedMissRate": cov.get("estimatedMissRate"),
        "estimatedMissRateBasis": cov.get("estimatedMissRateBasis"),
        "referenceShortConnectionSeconds": cov.get("referenceShortConnectionSeconds"),
        "measurementConfidence": cov.get("measurementConfidence"),
        "configuredIntervalSeconds": cov.get("configuredIntervalSeconds"),
        "state": cov.get("state"),
    }


def _socket_blind_spot_from(cov: dict[str, Any]) -> dict[str, Any]:
    if cov.get("state") != "sampling":
        return {"topic": "未走代理流量", "confidence": "Unknown", "status": cov.get("state"),
                "note": "socket-sampler 当前没有在采样（%s）；不估算比例" % cov.get("state")}
    return {
        "topic": "未走代理流量",
        "confidence": "Observed" if cov.get("measurementConfidence") == "Observed" else "Unknown",
        "status": "sampled",
        "note": "按进程采样 TCP/UDP 连接：有效间隔 p50 %ss / p95 %ss（成功采样间隔，不是配置的 %ss），"
        "短于 %ss 的连接可能漏掉，按 %.1f 秒连接估算漏采率 %s"
        "（最近一次 %s；失败 %s 次）；系统解析器发出的 DNS 不可见"
        % (cov.get("effectiveIntervalSeconds"), cov.get("effectiveIntervalSecondsP95"),
           cov.get("configuredIntervalSeconds"), cov.get("missesShorterThanSeconds"),
           cov.get("referenceShortConnectionSeconds") or 1.5, cov.get("estimatedMissRate"),
           cov.get("lastSampleAt"), cov.get("failures")),
    }


IN_PROCESS_BLIND_SPOT = {
    "topic": "进程内工具（Read/Edit/Write/Glob）",
    "confidence": "Observed",
    "status": "outside_system_visibility",
    "note": "Read/Edit/Write/Glob 等不派生子进程、也不打开套接字的进程内工具，不在系统级采样和审计代理的可见范围内。"
            "这里没看到，不能当成没发生。Network Extension 不在本接口范围内。",
}


def get_coverage() -> dict[str, Any]:
    if KEY_WARM.state == "pending":
        integrity = pending_integrity()
    else:
        integrity = validate_audit()
    proxy_up = False
    detail = "未探测"
    # Lightweight local listen check — does not open Network Extension.
    try:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        proxy_up = sock.connect_ex(("127.0.0.1", 18891)) == 0
        sock.close()
        detail = "127.0.0.1:18891 可连接" if proxy_up else "127.0.0.1:18891 未监听"
    except OSError:
        detail = "端口探测失败"
    ledger_cov = load_socket_ledger(limit=0)["coverage"]
    result = {
        "proxy": {"listening": proxy_up, "detail": detail, "confidence": "Observed" if proxy_up else "Unknown"},
        "rules": [
            {"id": "S01", "status": "blind", "confidence": "Unknown", "note": "无 Endpoint Security 级文件读证据"},
            {"id": "S02", "status": "supported", "confidence": "Observed", "note": "content_audit credential-outbound"},
            {"id": "S03", "status": "supported", "confidence": "Correlated", "note": "同执行编号下载后执行"},
            {"id": "S04", "status": "supported", "confidence": "Observed", "note": "非白名单目的地"},
            {"id": "S06", "status": "blind", "confidence": "Unknown", "note": "未监看 agent 配置变更"},
            {"id": "S07", "status": "supported", "confidence": "Observed", "note": "仅认后端 auditBypass=true"},
        ],
        "blindSpots": [
            _socket_blind_spot_from(ledger_cov),
            IN_PROCESS_BLIND_SPOT,
            {"topic": "SSH 通道内正文", "confidence": "Unknown", "note": "只看到连到哪台主机"},
        ],
        "socketSampling": _socket_sampling(ledger_cov),
        "evidenceIntegrity": integrity,
        "integritySummary": integrity_summary(integrity),
        "socketLedgerIntegrity": ledger_cov.get("integrity"),
        "transportRoot": str(DEFAULT_TRANSPORT),
        "confidence": "Observed" if proxy_up else "Unknown",
    }
    if KEY_WARM.state == "pending":
        result["keychainStatus"] = "pending"
    return result


def ensure_audit_dir() -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(AUDIT_DIR, 0o700)
    except OSError:
        pass
    try:
        DEFAULT_TRANSPORT.mkdir(parents=True, exist_ok=True)
        os.chmod(DEFAULT_TRANSPORT, 0o700)
    except OSError:
        pass


def _keychain_backend() -> str:
    """'security' (macOS Keychain via AgentReinsKeychainHelper) or 'unsupported'. There is no file or
    in-memory key store in shipped code: unit tests inject a fake from test-only code (keychain_fake.py)."""
    return "security" if sys.platform == "darwin" else "unsupported"


class KeychainUnavailable(OSError):
    """The Keychain could not be read (as opposed to: the item does not exist). Never mint a new key then."""


def _find_keychain_helper(compile_if_missing: bool = True) -> pathlib.Path | None:
    """Packaged helper (Contents/MacOS/AgentReinsKeychainHelper) first; dev tree builds tools/.../keychain_helper.
    Never compiles into a signed .app bundle."""
    packaged = ROOT.parent.parent / "MacOS" / "AgentReinsKeychainHelper"
    if packaged.is_file():
        return packaged
    dev = ROOT / "keychain_helper"
    if dev.is_file():
        return dev
    if not compile_if_missing or ".app/Contents/" in str(ROOT):
        return None
    src = ROOT.parents[1] / "Sources" / "AgentReinsKeychainHelper" / "main.swift"
    if src.is_file():
        try:
            subprocess.run(["swiftc", "-O", "-o", str(dev), str(src)], capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
    return dev if dev.is_file() else None


KEYCHAIN_HELPER_TIMEOUT = 15.0
# After a helper timeout, answer "error" without calling it again for this long (per process), so a
# Keychain that blocks costs one timeout, not one per account per MCP call.
KEYCHAIN_UNRESPONSIVE_BACKOFF = 60.0
# Process-wide result cache. A blocked or unreadable key stays key_unavailable for five minutes
# instead of launching the helper on every tools/call. `missing` is not cached.
KEYCHAIN_STATUS_CACHE_TTL = 300.0
_KEYCHAIN_STATE: dict[str, Any] = {"unresponsiveUntil": 0.0, "lastError": None}
HELPER_EXIT_NOT_FOUND = 3
HELPER_EXIT_NEEDS_APPROVAL = 4


class KeychainHelperUnresponsive(OSError):
    """The helper timed out recently; not retried until the backoff passes."""


def _run_keychain_helper(args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    helper = _find_keychain_helper()
    if helper is None:
        raise FileNotFoundError("AgentReins keychain helper not installed")
    if time.monotonic() < _KEYCHAIN_STATE["unresponsiveUntil"]:
        raise KeychainHelperUnresponsive("keychain helper timed out recently; not retried yet")
    try:
        return subprocess.run([str(helper), *args], input=stdin, capture_output=True,
                              timeout=KEYCHAIN_HELPER_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        _KEYCHAIN_STATE["unresponsiveUntil"] = time.monotonic() + KEYCHAIN_UNRESPONSIVE_BACKOFF
        raise


def keychain_last_error() -> str | None:
    """Why the last Keychain lookup failed (no secret material), for status texts."""
    return _KEYCHAIN_STATE["lastError"]


# Tool calls wait at most this long for the background Keychain warmup. A helper that would
# block for KEYCHAIN_HELPER_TIMEOUT (15s) is reported as pending instead of stalling the read.
KEYCHAIN_TOOL_WAIT = 0.25


class KeychainWarmup:
    """Load the integrity key off the tool-call thread.

    ``ready`` means the helper returned (key present or honestly unavailable). ``pending`` means
    it has not returned yet; callers must not block and must not mint a replacement key.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self.state = "cold"  # cold | pending | ready | unavailable
        self.error: str | None = None
        self.queue: list[tuple[str, str, dict[str, Any]]] = []
        self._generation = 0

    def reset(self) -> None:
        """Tests start from cold. An in-flight helper from an older generation cannot publish its result."""
        with self._cv:
            self._generation += 1
            self.state = "cold"
            self.error = None
            self.queue.clear()
            self._cv.notify_all()

    def start(self) -> None:
        with self._cv:
            if self.state != "cold":
                return
            self.state = "pending"
            generation = self._generation
            thread = threading.Thread(target=self._run, args=(generation,), name="agentreins-keychain-warm", daemon=True)
            thread.start()

    def _run(self, generation: int) -> None:
        state = "unavailable"
        error = None
        try:
            load_or_create_hmac_key()
            state = "ready"
        except OSError as exc:
            error = str(exc)
            state = "unavailable"
        with self._cv:
            if generation != self._generation:
                return
            self.state = state
            self.error = error
            queued = list(self.queue)
            self.queue.clear()
            self._cv.notify_all()
        if state == "ready":
            for actor, tool, arguments in queued:
                try:
                    append_audit(actor, tool, arguments)
                except OSError:
                    pass

    def wait(self, timeout: float | None = None) -> str:
        self.start()
        limit = KEYCHAIN_TOOL_WAIT if timeout is None else timeout
        with self._cv:
            if self.state == "pending":
                self._cv.wait(timeout=max(0.0, limit))
            return self.state

    def enqueue(self, actor: str, tool: str, arguments: dict[str, Any]) -> None:
        with self._cv:
            if self.state == "pending" or self.state == "cold":
                self.queue.append((actor, tool, arguments))
                if self.state == "cold":
                    self.state = "pending"
                    generation = self._generation
                    threading.Thread(target=self._run, args=(generation,), name="agentreins-keychain-warm", daemon=True).start()
                return
        if self.state == "ready":
            try:
                append_audit(actor, tool, arguments)
            except OSError:
                pass


KEY_WARM = KeychainWarmup()


def pending_integrity() -> dict[str, Any]:
    """get_coverage payload when the helper has not answered yet. Not a tamper verdict."""
    return {
        "ok": False,
        "status": "pending",
        "statusText": "完整性密钥正在后台读取，这一次不阻塞等待钥匙串。",
        "confidence": "Unknown",
        "keychainStatus": "pending",
        "entriesChecked": 0,
        "tampered": [],
        "deletedOrGap": [],
        "currentTampered": {"count": 0, "reasons": {}},
        "legacyUnverifiable": {"count": 0, "from": None, "to": None},
        "b6": {"sameUidCanForge": True, "reasons": ["钥匙串结果尚未返回，不把这次等待算成校验失败。"]},
        "note": "pending 不是 key_unavailable，也不是篡改。助手返回后下一次读取会给出真实状态。",
    }


def _helper_failure(proc: subprocess.CompletedProcess[bytes]) -> str:
    if proc.returncode == HELPER_EXIT_NEEDS_APPROVAL:
        return ("keychain needs user approval (locked, or this helper is not yet on the item's access list; "
                "run AgentReinsKeychainHelper authorize in a logged-in session)")
    detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] if proc.stderr else []
    return "keychain helper exit %s%s" % (proc.returncode, (": " + detail[0][:120]) if detail else "")


def _keychain_status_cache() -> dict[str, Any]:
    cache = _KEYCHAIN_STATE.get("statusCache")
    if not isinstance(cache, dict):
        cache = {}
        _KEYCHAIN_STATE["statusCache"] = cache
    return cache


def _invalidate_keychain_cache(account: str) -> None:
    cache = _KEYCHAIN_STATE.get("statusCache")
    if isinstance(cache, dict):
        cache.pop(account, None)


def _keychain_lookup(account: str) -> tuple[str, bytes | None]:
    """('found', data) | ('missing', None) | ('error', None) | ('no_helper', None) | ('no_backend', None).

    `found` and `error` are cached for KEYCHAIN_STATUS_CACHE_TTL so a tools/call does not launch
    AgentReinsKeychainHelper again while the answer is still the one we just got.
    """
    if _keychain_backend() != "security":
        return "no_backend", None
    cache = _keychain_status_cache()
    hit = cache.get(account)
    now = time.monotonic()
    if isinstance(hit, dict) and hit.get("status") in ("found", "error") and now < float(hit.get("until") or 0):
        _KEYCHAIN_STATE["lastError"] = hit.get("error")
        return hit["status"], hit.get("data")
    status, data = _keychain_lookup_uncached(account)
    if status in ("found", "error"):
        cache[account] = {
            "status": status,
            "data": data,
            "error": _KEYCHAIN_STATE.get("lastError"),
            "until": now + KEYCHAIN_STATUS_CACHE_TTL,
        }
    else:
        cache.pop(account, None)
    return status, data


def _keychain_lookup_uncached(account: str) -> tuple[str, bytes | None]:
    """('found', data) | ('missing', None) | ('error', None) | ('no_helper', None) | ('no_backend', None)."""
    if _keychain_backend() != "security":
        return "no_backend", None
    try:
        proc = _run_keychain_helper(["get", account])
    except FileNotFoundError:
        return "no_helper", None
    except subprocess.TimeoutExpired:
        _KEYCHAIN_STATE["lastError"] = "keychain helper timed out after %.0fs" % KEYCHAIN_HELPER_TIMEOUT
        return "error", None
    except (OSError, subprocess.SubprocessError) as exc:
        _KEYCHAIN_STATE["lastError"] = str(exc)[:160] or exc.__class__.__name__
        return "error", None
    if proc.returncode == HELPER_EXIT_NOT_FOUND:
        return "missing", None
    if proc.returncode != 0 or not proc.stdout.strip():
        _KEYCHAIN_STATE["lastError"] = _helper_failure(proc)
        return "error", None
    raw = proc.stdout.decode("utf-8", "replace").strip()
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        data = raw.encode("utf-8")
    # Legacy `security -A -w <hex>` stored ASCII hex digits as the secret.
    if len(data) == 64 and all(chr(b) in "0123456789abcdef" for b in data):
        try:
            return "found", bytes.fromhex(data.decode("ascii"))
        except ValueError:
            return "found", data
    return "found", data


def keychain_get(account: str) -> bytes | None:
    status, data = _keychain_lookup(account)
    return data if status == "found" else None


def keychain_set(account: str, value: bytes) -> bool:
    _invalidate_keychain_cache(account)
    if _keychain_backend() == "security":
        # Never put the secret on argv; never use `security -A`.
        try:
            proc = _run_keychain_helper(["set", account], stdin=value.hex().encode("ascii"))
        except subprocess.TimeoutExpired:
            _KEYCHAIN_STATE["lastError"] = "keychain helper timed out after %.0fs" % KEYCHAIN_HELPER_TIMEOUT
            return False
        except (OSError, subprocess.SubprocessError) as exc:
            _KEYCHAIN_STATE["lastError"] = str(exc)[:160] or exc.__class__.__name__
            return False
        if proc.returncode != 0:
            _KEYCHAIN_STATE["lastError"] = _helper_failure(proc)
        return proc.returncode == 0
    return False


def keychain_delete(account: str) -> bool:
    _invalidate_keychain_cache(account)
    if _keychain_backend() == "security":
        try:
            proc = _run_keychain_helper(["delete", account])
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False
    return False


def keychain_has_install_anchor() -> bool:
    for account in (KEYCHAIN_ACCOUNT_ERA, KEYCHAIN_ACCOUNT_HMAC, KEYCHAIN_ACCOUNT_BOUNDARY):
        if keychain_get(account) is not None:
            return True
    return False


def _delete_hmac_key_file() -> None:
    """Remove plaintext key material once Keychain holds the secret."""
    try:
        if HMAC_KEY_FILE.is_file():
            HMAC_KEY_FILE.unlink()
    except OSError:
        pass


def load_or_create_hmac_key(create: bool = True) -> bytes:
    """HMAC key: Keychain first, then one-time file migrate (file deleted after).

    A Keychain *read error* (locked, helper failed, timeout) raises KeychainUnavailable: minting a fresh
    key in that case would silently replace the real one and turn every later entry into a mismatch.
    """
    ensure_audit_dir()
    status, existing = _keychain_lookup(KEYCHAIN_ACCOUNT_HMAC)
    if status == "found" and existing and len(existing) >= 16:
        _delete_hmac_key_file()
        return existing
    if status == "error":
        raise KeychainUnavailable("keychain read failed (%s); not creating a replacement integrity key"
                                  % (keychain_last_error() or "unknown"))
    if HMAC_KEY_FILE.is_file():
        raw = HMAC_KEY_FILE.read_bytes()
        # Ignore non-secret marker left by older builds.
        if len(raw) >= 16 and raw.strip() not in (b"keychain", b"keychain\n"):
            if status == "missing" and keychain_set(KEYCHAIN_ACCOUNT_HMAC, raw):
                _delete_hmac_key_file()
            return raw
    if not create:
        raise KeychainUnavailable("no integrity key yet")
    if status == "no_helper":
        raise KeychainUnavailable("AgentReinsKeychainHelper not found; nothing is signed (no file-key fallback)")
    if status != "missing":
        raise KeychainUnavailable("no Keychain on this platform (%s); nothing is signed" % sys.platform)
    key = os.urandom(32)
    if keychain_set(KEYCHAIN_ACCOUNT_HMAC, key):
        _delete_hmac_key_file()
        return key
    # The Keychain is there but refused the write (locked / needs approval / timeout): a plaintext
    # replacement key would be readable by anything and would fork the key from the Swift MCP's.
    raise KeychainUnavailable("could not store a new integrity key in the Keychain (%s)"
                              % (keychain_last_error() or "helper set failed"))


def canonical_json(obj: Any) -> str:
    """Match Swift JSONSerialization sortedKeys compact form (no spaces)."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def entry_hmac(entry_body: dict[str, Any], key: bytes) -> str:
    payload = canonical_json(entry_body)
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def evidence_file_mac(path: pathlib.Path, key: bytes) -> str:
    data = path.read_bytes()
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _ensure_integrity_dir() -> None:
    try:
        INTEGRITY_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(INTEGRITY_DIR, 0o700)
    except OSError:
        pass


def _key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:32]


def mark_signed_era() -> None:
    """Persist that a signed era has started (Keychain + file; Keychain survives full wipe).

    Once an era fingerprint exists it is never overwritten — a replaced HMAC key
    must surface as tamper (B12), not a silent re-anchor.
    """
    key = load_or_create_hmac_key()
    existing = keychain_get(KEYCHAIN_ACCOUNT_ERA)
    if existing:
        try:
            prev = json.loads(existing.decode("utf-8"))
            if prev.get("keyFingerprint"):
                # Keep original fingerprint even if current key differs (B12 signal).
                _ensure_integrity_dir()
                if not SIGNED_ERA_FLAG.is_file():
                    SIGNED_ERA_FLAG.write_bytes(existing + b"\n")
                    try:
                        os.chmod(SIGNED_ERA_FLAG, 0o600)
                    except OSError:
                        pass
                if prev.get("keyFingerprint") == _key_fingerprint(key):
                    establish_boundary(key, fresh=False)  # upgrade path: era predates the marker
                return
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            pass
    payload_obj = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "schema": 2,
        "keyFingerprint": _key_fingerprint(key),
    }
    payload = json.dumps(payload_obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    keychain_set(KEYCHAIN_ACCOUNT_ERA, payload)
    _ensure_integrity_dir()
    SIGNED_ERA_FLAG.write_bytes(payload + b"\n")
    try:
        os.chmod(SIGNED_ERA_FLAG, 0o600)
    except OSError:
        pass
    establish_boundary(key, fresh=True)


# ------------------------------------------------------------------------------------------------
# Migration boundary (legacy vs current). Recorded once, HMAC-sealed with the current key, stored in the
# Keychain (survives wiping both data directories) and mirrored to INTEGRITY_DIR for reading; the audit
# chain itself gets an `integrity-boundary` entry, so deleting the marker later is detectable and can
# never move more entries into "legacy".
#   * fresh install: established when the signed era starts -> boundary index 0, no legacy at all.
#   * upgrade (era already existed, no marker): legacy = audit entries before BOTH the first entry that
#     verifies with the Keychain key AND the era start time (and in time order); evidence files whose MAC
#     fails and whose mtime predates that time. Those exact bytes are pinned (prefix sha256 + a manifest of
#     file hashes), so editing a legacy item afterwards is current tampering. The upgrade split is inferred
#     and labelled as such.

def _boundary_mirror() -> pathlib.Path:
    return INTEGRITY_DIR / "integrity-boundary.json"


def _legacy_manifest_path() -> pathlib.Path:
    return INTEGRITY_DIR / "legacy-evidence-manifest.json"


def _audit_lines(log: pathlib.Path | None = None) -> list[str]:
    log = log or AUDIT_LOG
    try:
        return [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        return []


def _prefix_sha(lines: list[str], count: int) -> str:
    return sha256_hex("\n".join(lines[:count]))


def _entry_verifies(line: str, key: bytes) -> bool:
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return False
    if "mac" not in entry:
        return False
    body = {k: entry[k] for k in ("at", "actor", "tool", "argsDigest", "prevHash") if k in entry}
    return hmac.compare_digest(str(entry.get("mac")), entry_hmac(body, key))


def _entry_at(line: str) -> str:
    try:
        return str(json.loads(line).get("at") or "")
    except json.JSONDecodeError:
        return ""


def _era_at() -> str | None:
    blob = keychain_get(KEYCHAIN_ACCOUNT_ERA)
    if blob is None and SIGNED_ERA_FLAG.is_file():
        try:
            blob = SIGNED_ERA_FLAG.read_bytes()
        except OSError:
            blob = None
    try:
        return json.loads(blob.decode("utf-8")).get("at") if blob else None
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        return None


def _iso_from_epoch(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def load_boundary(key: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """(marker, problem). problem = 'boundary_marker_unreadable' | 'boundary_marker_mac_mismatch'."""
    blob = keychain_get(KEYCHAIN_ACCOUNT_BOUNDARY)
    if blob is None:
        return None, None
    try:
        marker = json.loads(blob.decode("utf-8"))
        assert isinstance(marker, dict)
    except (UnicodeDecodeError, json.JSONDecodeError, AssertionError):
        return None, "boundary_marker_unreadable"
    body = {k: v for k, v in marker.items() if k != "mac"}
    if not hmac.compare_digest(str(marker.get("mac") or ""), entry_hmac(body, key)):
        return None, "boundary_marker_mac_mismatch"
    return marker, None


def _log_has_boundary_entry(lines: list[str]) -> bool:
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("tool") == BOUNDARY_TOOL and entry.get("actor") == BOUNDARY_ACTOR:
            return True
    return False


def establish_boundary(key: bytes, fresh: bool) -> dict[str, Any] | None:
    """Record the legacy/current boundary exactly once. Returns the marker (or None if it already exists)."""
    if keychain_get(KEYCHAIN_ACCOUNT_BOUNDARY) is not None:
        return None
    lines = _audit_lines()
    if _log_has_boundary_entry(lines):
        return None  # marker was deleted after being recorded: never re-establish (would launder entries)
    now = time.time()
    era_at = _era_at()
    if fresh or not lines:
        index = len(lines) if not fresh else 0
        source = "recorded-at-signed-era-start" if fresh else "recorded-going-forward"
        cutoff_iso = _iso_from_epoch(now)
    else:
        first_ok = next((i for i, ln in enumerate(lines) if _entry_verifies(ln, key)), len(lines))
        by_time = next((i for i, ln in enumerate(lines) if era_at and _entry_at(ln) >= era_at), len(lines))
        index = min(first_ok, by_time)
        for i in range(index):  # legacy must be in time order; stop at the first out-of-order entry
            if i + 1 < len(lines) and _entry_at(lines[i]) > _entry_at(lines[i + 1]):
                index = i + 1
                break
        source = "upgrade-inferred"
        cutoff_iso = era_at or (_entry_at(lines[first_ok]) if first_ok < len(lines) else _iso_from_epoch(now))
    if fresh and lines:
        # Era starts now but a log already exists (older unsigned build): everything so far is legacy.
        index, source = len(lines), "recorded-at-signed-era-start"
    legacy_audit = [ln for ln in lines[:index] if not _entry_verifies(ln, key)]
    # Evidence files that no longer verify and were written before the cutoff.
    legacy_files = []
    cutoff_ts = _iso_ts(cutoff_iso) or now
    base = DEFAULT_TRANSPORT
    if base.is_dir():
        for path in sorted(list(base.glob("*/transport.json")) + list(base.glob("*/manifest.json"))):
            mac_path = path.with_suffix(path.suffix + ".mac")
            if not mac_path.is_file():
                continue
            try:
                ok = hmac.compare_digest(mac_path.read_text(encoding="utf-8").strip(), evidence_file_mac(path, key))
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if not ok and mtime < cutoff_ts:
                legacy_files.append({"path": f"{path.parent.name}/{path.name}",
                                     "sha256": sha256_bytes(path.read_bytes()),
                                     "macSha256": sha256_bytes(mac_path.read_bytes()),
                                     "mtime": _iso_from_epoch(mtime)})
    manifest_text = canonical_json({"schema": 1, "files": legacy_files}) + "\n"
    times = sorted([t for t in (_entry_at(ln) for ln in legacy_audit) if t] + [f["mtime"] for f in legacy_files])
    marker: dict[str, Any] = {
        "schema": 1,
        "establishedAt": _iso_from_epoch(now),
        "source": source,
        "eraAt": era_at,
        "cutoff": cutoff_iso,
        "keyFingerprint": _key_fingerprint(key),
        "auditBoundaryIndex": index,
        "auditPrefixSha256": _prefix_sha(lines, index),
        "legacyAuditCount": len(legacy_audit),
        "legacyEvidenceCount": len(legacy_files),
        "legacyManifestSha256": sha256_hex(manifest_text),
        "legacyFrom": times[0] if times else None,
        "legacyTo": times[-1] if times else None,
    }
    marker["mac"] = entry_hmac(marker, key)
    blob = canonical_json(marker).encode("utf-8")
    if not keychain_set(KEYCHAIN_ACCOUNT_BOUNDARY, blob):
        return None  # without the Keychain anchor the boundary would be deletable; do not record a weak one
    _ensure_integrity_dir()
    for target, text in ((_legacy_manifest_path(), manifest_text), (_boundary_mirror(), blob.decode() + "\n")):
        target.write_text(text, encoding="utf-8")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    append_audit(BOUNDARY_ACTOR, BOUNDARY_TOOL, {"auditBoundaryIndex": index, "markerSha256": sha256_bytes(blob)})
    return marker


def _load_legacy_manifest(marker: dict[str, Any] | None) -> tuple[dict[str, str], str | None]:
    """{relative path: sha256} of legacy evidence pinned at the boundary, or a problem reason."""
    if not marker or not marker.get("legacyEvidenceCount"):
        return {}, None
    try:
        text = _legacy_manifest_path().read_text(encoding="utf-8")
    except OSError:
        return {}, "legacy_manifest_missing"
    if sha256_hex(text) != marker.get("legacyManifestSha256"):
        return {}, "legacy_manifest_modified"
    try:
        return {f["path"]: f["sha256"] for f in json.loads(text).get("files") or []}, None
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        return {}, "legacy_manifest_unreadable"


def signed_era_active() -> bool:
    return (
        keychain_has_install_anchor()
        or _boundary_mirror().is_file()
        or SIGNED_ERA_FLAG.is_file()
        or (PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal").is_file()
    )


def era_key_mismatch(key: bytes | None = None) -> bool:
    """True when Keychain/file era was sealed under a different HMAC key (B12)."""
    key = key or load_or_create_hmac_key()
    fp = _key_fingerprint(key)
    for blob in (keychain_get(KEYCHAIN_ACCOUNT_ERA),):
        if not blob:
            continue
        try:
            data = json.loads(blob.decode("utf-8"))
            stored = data.get("keyFingerprint")
            if stored and stored != fp:
                return True
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
            continue
    if SIGNED_ERA_FLAG.is_file():
        try:
            data = json.loads(SIGNED_ERA_FLAG.read_text(encoding="utf-8"))
            stored = data.get("keyFingerprint")
            if stored and stored != fp:
                return True
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return False


def sign_run_inventory(key: bytes | None = None) -> None:
    """HMAC the run inventory; MAC stored outside AUDIT_DIR (B8)."""
    if not RUN_INVENTORY.is_file():
        return
    _ensure_integrity_dir()
    key = key or load_or_create_hmac_key()
    mac = evidence_file_mac(RUN_INVENTORY, key)
    RUN_INVENTORY_MAC.write_text(mac + "\n", encoding="utf-8")
    try:
        os.chmod(RUN_INVENTORY_MAC, 0o600)
    except OSError:
        pass
    # Keep seal inventorySha256 in sync when inventory grows (not re-signing audit rows).
    if AUDIT_SEAL.is_file():
        try:
            seal = json.loads(AUDIT_SEAL.read_text(encoding="utf-8"))
            seal_body = {
                k: seal[k]
                for k in ("headHash", "count", "schema")
                if k in seal
            }
            seal_body["inventorySha256"] = sha256_bytes(RUN_INVENTORY.read_bytes())
            seal_body["mac"] = entry_hmac(seal_body, key)
            text = canonical_json(seal_body) + "\n"
            AUDIT_SEAL.write_text(text, encoding="utf-8")
            mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
            PROTECTED_SEAL_DIR.mkdir(parents=True, exist_ok=True)
            mirror.write_text(text, encoding="utf-8")
            try:
                os.chmod(AUDIT_SEAL, 0o600)
                os.chmod(mirror, 0o600)
            except OSError:
                pass
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    mark_signed_era()


def validate_run_inventory(key: bytes | None = None) -> dict[str, Any]:
    """Detect B8: deleting inventory rows without the external MAC."""
    result: dict[str, Any] = {"ok": True, "tampered": []}
    key = key or load_or_create_hmac_key()
    sig = _file_sig(RUN_INVENTORY)
    mac_sig = _file_sig(RUN_INVENTORY_MAC)
    fp = sha256_bytes(key)[:16]
    cached = _INV_CACHE.get("valid")
    if cached is not None and _INV_CACHE.get("fp") == fp and _INV_CACHE.get("validSig") == (sig, mac_sig):
        return {"ok": cached["ok"], "tampered": list(cached["tampered"])}

    def _store(done: dict[str, Any]) -> dict[str, Any]:
        _INV_CACHE["valid"] = {"ok": done["ok"], "tampered": list(done["tampered"])}
        _INV_CACHE["fp"] = fp
        _INV_CACHE["validSig"] = (sig, mac_sig)
        return done

    if RUN_INVENTORY_MAC.is_file():
        if not RUN_INVENTORY.is_file():
            result["ok"] = False
            result["tampered"].append({"reason": "inventory_missing_after_signed"})
            return _store(result)
        expected = RUN_INVENTORY_MAC.read_text(encoding="utf-8").strip()
        actual = evidence_file_mac(RUN_INVENTORY, key)
        if not hmac.compare_digest(expected, actual):
            result["ok"] = False
            result["tampered"].append({"reason": "inventory_mac_mismatch"})
    elif RUN_INVENTORY.is_file() and signed_era_active():
        # Signed era but inventory MAC wiped with the inventory edits.
        result["ok"] = False
        result["tampered"].append({"reason": "inventory_mac_missing_after_signed_era"})
    return _store(result)


def register_run_id(run_id: str, run_path: pathlib.Path | None = None) -> None:
    """Append run ID to durable inventory so deleted runs are detectable.

    The inventory is re-signed only if it still verifies before this append; otherwise an edit made
    by someone else would be laundered into a fresh MAC. A mismatch stays visible as tampering."""
    ensure_audit_dir()
    try:
        was_intact = validate_run_inventory().get("ok", False)
    except OSError:
        was_intact = False
    entry = {
        "runID": run_id,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "path": str(run_path) if run_path else None,
    }
    with RUN_INVENTORY.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
    try:
        os.chmod(RUN_INVENTORY, 0o600)
    except OSError:
        pass
    if not was_intact:
        return
    try:
        sign_run_inventory()
    except OSError:
        pass


def known_run_ids() -> set[str]:
    if not RUN_INVENTORY.is_file():
        return set()
    out: set[str] = set()
    for line in RUN_INVENTORY.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.add(str(json.loads(line).get("runID") or ""))
        except json.JSONDecodeError:
            continue
    out.discard("")
    return out


def sign_evidence_tree(root: pathlib.Path | None = None) -> dict[str, Any]:
    """HMAC-sign transport.json + manifest.json. Collection-time only.

    en_4088c393: allow_resign removed entirely. Existing MAC that does not match
    current bytes → refuse wash (TAMPER), never overwrite.
    """
    ensure_audit_dir()
    key = load_or_create_hmac_key()
    base = root or DEFAULT_TRANSPORT
    signed = 0
    refused: list[dict[str, Any]] = []
    # Single run directory (contains transport.json directly) or transport root.
    if (base / "transport.json").is_file() or (base / "manifest.json").is_file():
        candidates = [p for p in (base / "transport.json", base / "manifest.json") if p.is_file()]
    else:
        candidates = list(base.glob("*/transport.json")) + list(base.glob("*/manifest.json"))
    for path in candidates:
        mac_path = path.with_suffix(path.suffix + ".mac")
        actual = evidence_file_mac(path, key)
        if mac_path.is_file():
            expected = mac_path.read_text(encoding="utf-8").strip()
            if hmac.compare_digest(expected, actual):
                continue
            # B7: never re-sign over a mismatched MAC.
            refused.append({"path": str(path), "reason": "refuse_resign_mac_mismatch"})
            continue
        mac_path.write_text(actual + "\n", encoding="utf-8")
        try:
            os.chmod(mac_path, 0o600)
        except OSError:
            pass
        signed += 1
        try:
            register_run_id(path.parent.name, path.parent)
        except OSError:
            pass
    mark_signed_era()
    return {"signedFiles": signed, "root": str(base), "refused": refused, "ok": not refused}


def validate_evidence_files(root: pathlib.Path | None = None, key: bytes | None = None,
                            marker: dict[str, Any] | None = None) -> dict[str, Any]:
    """Detect tampering of transport/manifest evidence.

    MAC is required only for inventory-registered runs (not every historical folder).
    External signed-era flag makes wipe-everything look like tamper (B9/B10), not 'unsigned'.
    """
    ensure_audit_dir()
    key = key or load_or_create_hmac_key()
    base = root or DEFAULT_TRANSPORT
    result: dict[str, Any] = {
        "ok": True,
        "checked": 0,
        "tampered": [],
        "legacyUnverifiable": [],
        "missingMac": [],
        "missingRuns": [],
        "confidence": "Observed",
        "keyLimitation": KEYCHAIN_LIMITATION,
    }
    legacy, legacy_problem = _load_legacy_manifest(marker)
    if legacy_problem:
        result["ok"] = False
        result["tampered"].append({"reason": legacy_problem})
    inv = validate_run_inventory(key)
    if not inv.get("ok", True):
        result["ok"] = False
        result["tampered"].extend(inv.get("tampered") or [])
        result["confidence"] = "Unknown"

    # B9/B10: signed era existed, then audit/evidence wiped → tamper, not 'never signed'.
    if signed_era_active():
        seal_primary = AUDIT_SEAL.is_file()
        seal_mirror = (PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal").is_file()
        if not seal_primary and not seal_mirror and not RUN_INVENTORY.is_file() and not (base.is_dir() and any(base.glob("*/*"))):
            result["ok"] = False
            result["tampered"].append({"reason": "signed_era_evidence_wiped"})
            result["confidence"] = "Unknown"
            return result
        if not seal_primary and not seal_mirror and AUDIT_LOG.is_file() is False and known_run_ids():
            # Inventory remains but seals gone.
            result["ok"] = False
            result["tampered"].append({"reason": "seal_missing_after_signed_era"})
            result["confidence"] = "Unknown"

    if not base.is_dir():
        result["note"] = "无传输审计目录"
        known = known_run_ids()
        if known or signed_era_active():
            result["ok"] = False
            result["missingRuns"] = sorted(known)
            result["confidence"] = "Unknown"
            result["tampered"].append({"reason": "run_directory_missing", "runs": sorted(known)})
        return result

    known = known_run_ids()
    files = list(base.glob("*/transport.json")) + list(base.glob("*/manifest.json"))
    for path in files:
        run_id = path.parent.name
        mac_path = path.with_suffix(path.suffix + ".mac")
        # Enforce MAC for inventory-registered runs OR any file that already has a .mac.
        enforce = run_id in known or mac_path.is_file()
        if not enforce:
            continue
        result["checked"] += 1
        if not mac_path.is_file():
            result["ok"] = False
            result["missingMac"].append(str(path))
            result["tampered"].append({"path": str(path), "reason": "missing_mac"})
            continue
        expected = mac_path.read_text(encoding="utf-8").strip()
        actual = evidence_file_mac(path, key)
        if not hmac.compare_digest(expected, actual):
            rel = f"{path.parent.name}/{path.name}"
            pinned = legacy.get(rel)
            if pinned is not None and pinned == sha256_bytes(path.read_bytes()):
                # Unchanged since the boundary was recorded; signed with a key that no longer exists.
                result["legacyUnverifiable"].append({"path": str(path), "reason": LEGACY_REASON})
                continue
            result["ok"] = False
            result["tampered"].append({
                "path": str(path),
                "reason": "legacy_evidence_modified_after_boundary" if pinned is not None else "evidence_mac_mismatch",
            })
    # Deleted runs listed in inventory
    on_disk = {p.parent.name for p in base.glob("*/transport.json")}
    missing = sorted(known - on_disk)
    if missing:
        result["ok"] = False
        result["missingRuns"] = missing
        result["tampered"].append({"reason": "run_deleted_from_inventory", "runs": missing})
        result["confidence"] = "Unknown"
    return result


def _write_seal(head_hash: str, count: int, key: bytes) -> None:
    body: dict[str, Any] = {"headHash": head_hash, "count": count, "schema": 1}
    # Anchor the inventory hash inside the seal (B8) only while the inventory still verifies;
    # otherwise keep the previously sealed anchor so an edit is not re-sealed by the next read.
    anchor = _inventory_anchor(key)
    if anchor:
        body["inventorySha256"] = anchor
    body["mac"] = entry_hmac(body, key)
    text = canonical_json(body) + "\n"
    AUDIT_SEAL.write_text(text, encoding="utf-8")
    try:
        os.chmod(AUDIT_SEAL, 0o600)
    except OSError:
        pass
    # Mirror seal OUTSIDE AUDIT_DIR (B9/B10); still same uid (B6).
    try:
        _ensure_integrity_dir()
        PROTECTED_SEAL_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(PROTECTED_SEAL_DIR, 0o700)
        mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
        mirror.write_text(text, encoding="utf-8")
        os.chmod(mirror, 0o600)
        mark_signed_era()
    except OSError:
        pass


def _inventory_sha(path: pathlib.Path) -> str:
    sig = _file_sig(path)
    if sig is not None and _INV_CACHE.get("sig") == sig and _INV_CACHE.get("sha"):
        return str(_INV_CACHE["sha"])
    digest = sha256_bytes(path.read_bytes())
    _INV_CACHE["sig"] = sig
    _INV_CACHE["sha"] = digest
    _INV_CACHE["valid"] = None
    return digest


def _inventory_anchor(key: bytes) -> str | None:
    if not RUN_INVENTORY.is_file():
        return None
    if not RUN_INVENTORY_MAC.is_file() or validate_run_inventory(key).get("ok"):
        return _inventory_sha(RUN_INVENTORY)
    for seal in (AUDIT_SEAL, PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"):
        try:
            prev = json.loads(seal.read_text(encoding="utf-8")).get("inventorySha256")
        except (OSError, ValueError, AttributeError):
            continue
        if prev:
            return str(prev)
    return None


class AuditTip:
    """Last hash and line count of the audit jsonl without re-parsing the whole file on every call.

    The first sight of a file streams it once (only the last line is JSON-parsed). Later calls
    read the bytes appended since that offset. The HMAC prev-hash and the seal count stay the
    same values a full read would have produced.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.identity: tuple | None = None
        self.count = 0
        self.last_hash = "0" * 64
        self.bytes_read = 0

    def _stat_id(self, path: pathlib.Path):
        st = path.stat()
        return (str(path), st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)

    def tip(self, path: pathlib.Path) -> tuple[int, str]:
        with self._lock:
            if not path.is_file():
                self.identity = None
                self.count = 0
                self.last_hash = "0" * 64
                return 0, self.last_hash
            ident = self._stat_id(path)
            if ident == self.identity:
                return self.count, self.last_hash
            # Stat miss: count the file. Do not add to a previous file's count (that inflated the seal).
            count = 0
            last = b""
            try:
                with path.open("rb") as fh:
                    for line in fh:
                        self.bytes_read += len(line)
                        if line.strip():
                            count += 1
                            last = line
            except OSError:
                return self.count, self.last_hash
            self.count = count
            if last:
                try:
                    parsed = json.loads(last.decode("utf-8")).get("hash")
                    if parsed:
                        self.last_hash = parsed
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            else:
                self.last_hash = "0" * 64
            self.identity = ident
            return self.count, self.last_hash

    def remember(self, path: pathlib.Path, count: int, new_hash: str) -> None:
        """The line just appended is `count` lines long and ends with `new_hash`. Absolute, not additive."""
        with self._lock:
            try:
                self.identity = self._stat_id(path)
            except OSError:
                self.identity = None
                return
            self.count = count
            self.last_hash = new_hash


AUDIT_TIP = AuditTip()

_INV_CACHE: dict[str, Any] = {"sig": None, "sha": None, "valid": None, "fp": None}


def _file_sig(path: pathlib.Path):
    try:
        st = path.stat()
    except OSError:
        return None
    return (str(path), st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)


def append_audit(actor: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Append one audit line. Readers must NEVER re-sign evidence trees (B3 wash prevention)."""
    ensure_audit_dir()
    key = load_or_create_hmac_key()
    prev = "0" * 64
    count = 0
    if AUDIT_LOG.exists():
        try:
            count, prev = AUDIT_TIP.tip(AUDIT_LOG)
            prev = prev or ("0" * 64)
        except (OSError, json.JSONDecodeError, IndexError):
            prev = "0" * 64
    args_digest = sha256_hex(canonical_json(arguments))[:24]
    entry: dict[str, Any] = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "tool": tool,
        "argsDigest": args_digest,
        "prevHash": prev,
    }
    entry["mac"] = entry_hmac(entry, key)
    entry["hash"] = sha256_hex(canonical_json(entry) + prev)
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(canonical_json(entry) + "\n")
    try:
        os.chmod(AUDIT_LOG, 0o600)
    except OSError:
        pass
    AUDIT_TIP.remember(AUDIT_LOG, count + 1, entry["hash"])
    _write_seal(entry["hash"], count + 1, key)
    # Intentionally do NOT call sign_evidence_tree() here — collection signs; read only verifies.
    return entry


def key_storage_facts() -> dict[str, Any]:
    """What actually protects the integrity key on this machine (drives b6.sameUidCanForge)."""
    backend = _keychain_backend()
    status, _ = _keychain_lookup(KEYCHAIN_ACCOUNT_HMAC)
    helper = _find_keychain_helper(compile_if_missing=False)
    facts: dict[str, Any] = {
        "backend": backend,
        "keyInKeychain": status == "found",
        "keychainLookup": status,
        "plaintextKeyFile": HMAC_KEY_FILE.is_file(),
        "helperPath": str(helper) if helper else None,
    }
    reasons = []
    if facts["plaintextKeyFile"]:
        reasons.append("密钥在同一用户可读的文件里")
    if backend == "security":
        facts["keychainAclTrustsHelperByPath"] = True
        facts["helperVerifiesCaller"] = False
        reasons.append(
            "钥匙串条目的访问控制只信任 keychain helper 这个程序本身；同一用户的任何进程都能直接运行它"
            "（get hmac-key）拿到密钥，helper 不检查是谁在调用它"
        )
    reasons.append("签名、日志、封条都由同一用户写入，没有 root 守护进程或远端锚点")
    # Every backend available today is readable by same-uid code, so this is True by fact, not by default.
    return {"sameUidCanForge": True, "keyStorage": facts, "reasons": reasons}


def _boundary_public(marker: dict[str, Any] | None, problem: str | None) -> dict[str, Any]:
    if marker is None:
        return {"state": problem or "not_recorded"}
    return {
        "state": "recorded",
        "anchoredIn": "Keychain (HMAC-sealed) + integrity mirror + audit chain entry",
        **{k: marker.get(k) for k in ("establishedAt", "source", "eraAt", "cutoff", "auditBoundaryIndex",
                                      "legacyAuditCount", "legacyEvidenceCount", "legacyFrom", "legacyTo")},
        "confidence": "Inferred" if marker.get("source") == "upgrade-inferred" else "Observed",
    }


def _finish_split(result: dict[str, Any], legacy_audit: list[dict[str, Any]], marker: dict[str, Any] | None) -> None:
    """Fill ok/currentTampered/legacyUnverifiable/status. `tampered` and `deletedOrGap` hold CURRENT problems only."""
    ev = result.get("evidenceFiles") or {}
    legacy_files = ev.get("legacyUnverifiable") or []
    current = list(result["tampered"]) + list(result["deletedOrGap"])
    result["ok"] = not current
    reasons: dict[str, int] = {}
    for item in current:
        reasons[str(item.get("reason"))] = reasons.get(str(item.get("reason")), 0) + 1
    result["currentTampered"] = {"count": len(current), "reasons": reasons}
    times = sorted(t for t in [str(e.get("at") or "") for e in legacy_audit] if t)
    result["legacyUnverifiable"] = {
        "count": len(legacy_audit) + len(legacy_files),
        "auditEntries": len(legacy_audit),
        "evidenceFiles": len(legacy_files),
        "from": (marker or {}).get("legacyFrom") or (times[0] if times else None),
        "to": (marker or {}).get("legacyTo") or (times[-1] if times else None),
        "reason": LEGACY_REASON,
        "confidence": "Unknown",
        "note": "迁移前用旧密钥签的历史记录：旧密钥已删除，既不能证明完好，也不能证明被改；"
                "它们自分界点记录后未再变动（字节已固定），不计入 ok。",
        "items": (legacy_audit + legacy_files)[:50],
    }
    if current:
        status = "current_tampered"
        text = "当前记录有 %d 处校验失败（迁移后的记录被改、删或伪造），ok=false。" % len(current)
    elif legacy_audit or legacy_files:
        status = "current_ok_legacy_unverifiable"
        text = "迁移后的记录全部校验通过；另有 %d 条迁移前的历史记录无法验证（旧密钥已删除），按 Unknown 处理。" % (
            len(legacy_audit) + len(legacy_files))
    else:
        status = "ok"
        text = "全部记录校验通过。"
    result["status"] = status
    result["statusText"] = text + " 注意：同一用户的进程能拿到密钥并重写记录（b6），所以这只证明没有被不懂密钥的程序改过。"


def validate_audit(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Validate keyed HMAC chain, split into current (ok) vs legacy (Unknown). No resign-on-read."""
    log = path or AUDIT_LOG
    result: dict[str, Any] = {
        "mode": "keyed-HMAC-SHA256 append-only + required seal + evidence MAC + run inventory",
        "keyPath": str(HMAC_KEY_FILE),
        "logPath": str(log),
        "ok": True,
        "entriesChecked": 0,
        "tampered": [],
        "deletedOrGap": [],
        "confidence": "Observed",
        "limitation": KEYCHAIN_LIMITATION,
        "legacyPathPolicy": "never_read_/private/tmp",
    }
    legacy_audit: list[dict[str, Any]] = []
    marker: dict[str, Any] | None = None
    try:
        key = load_or_create_hmac_key()
    except OSError as exc:
        result["ok"] = False
        result["warning"] = f"无法读取 HMAC 密钥：{exc}"
        result["confidence"] = "Unknown"
        result["status"] = "key_unavailable"
        result["statusText"] = "读不到完整性密钥，无法校验（不是篡改结论）。"
        result["b6"] = dict(key_storage_facts(), confidence="Unknown")
        return result
    marker, problem = load_boundary(key)
    if marker is None and problem is None and log.is_file():
        if _log_has_boundary_entry(_audit_lines(log)):
            problem = "boundary_marker_deleted"
        elif path is None:
            marker = establish_boundary(key, fresh=not signed_era_active())
            marker, problem = load_boundary(key) if marker else (None, None)
    if problem:
        result["tampered"].append({"reason": problem})
        result["confidence"] = "Unknown"
    result["boundary"] = _boundary_public(marker, problem)
    if not log.is_file():
        result["note"] = "尚无审计日志"
        if signed_era_active():
            # B9/B10/B11: signed era (incl. Keychain) then wipe dirs/log is tamper, not a fresh install.
            result["tampered"].append({"reason": "audit_log_missing_after_signed_era"})
            result["confidence"] = "Unknown"
            mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
            if not AUDIT_SEAL.is_file() and not mirror.is_file():
                result["tampered"].append({"reason": "seal_missing_after_signed_era"})
            if not INTEGRITY_DIR.is_dir() and not AUDIT_DIR.is_dir():
                result["tampered"].append({"reason": "integrity_dirs_wiped_after_keychain_anchor"})
        elif not keychain_has_install_anchor() and not SIGNED_ERA_FLAG.is_file() and not (
            PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
        ).is_file():
            # Playbook: never anchored → Unknown(never_anchored), not Observed / not ok success claim.
            result["confidence"] = "Unknown"
            result["note"] = "never_anchored"
            result["neverAnchored"] = True
        ev = validate_evidence_files(key=key, marker=marker)
        result["evidenceFiles"] = ev
        if not ev.get("ok", True):
            result["tampered"].extend(ev.get("tampered") or [])
            result["confidence"] = "Unknown"
        _finish_split(result, legacy_audit, marker)
        result["b6"] = dict(key_storage_facts(), confidence="Unknown", note=KEYCHAIN_LIMITATION)
        return result
    if era_key_mismatch(key):
        # B12: wipe + forge under a replaced HMAC key while install era remains.
        result["tampered"].append({"reason": "hmac_key_replaced_after_signed_era"})
        result["confidence"] = "Unknown"
    lines = _audit_lines(log)
    boundary = int((marker or {}).get("auditBoundaryIndex") or 0)
    if marker is not None:
        if len(lines) < boundary:
            result["tampered"].append({"reason": "audit_truncated_below_boundary", "boundary": boundary})
            boundary = len(lines)
        elif _prefix_sha(lines, boundary) != marker.get("auditPrefixSha256"):
            result["tampered"].append({"reason": "legacy_audit_prefix_modified", "boundary": boundary})
            boundary = 0  # pinned legacy bytes changed: nothing before the boundary can be excused any more
    prev = "0" * 64
    seen_signed = False
    head = prev
    for idx, line in enumerate(lines):
        legacy_zone = idx < boundary
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            if legacy_zone:
                legacy_audit.append({"index": idx, "reason": "invalid_json"})
            else:
                result["tampered"].append({"index": idx, "reason": "invalid_json"})
            continue
        result["entriesChecked"] += 1
        if entry.get("prevHash") != prev:
            gap = {"index": idx, "reason": "prevHash_mismatch", "expectedPrev": prev, "gotPrev": entry.get("prevHash")}
            if legacy_zone:
                legacy_audit.append(dict(gap, at=entry.get("at")))
            else:
                result["deletedOrGap"].append(gap)
        body = {k: entry[k] for k in ("at", "actor", "tool", "argsDigest", "prevHash") if k in entry}
        if "mac" not in entry:
            item = {"index": idx, "reason": "missing_mac", "tool": entry.get("tool"), "at": entry.get("at")}
            if legacy_zone:
                legacy_audit.append(item)
            else:
                # Any missing MAC is tamper once signing is in use (B2: strip MACs + rewrite).
                result["tampered"].append(item)
        else:
            seen_signed = True
            if entry.get("mac") != entry_hmac(body, key):
                item = {"index": idx, "reason": "mac_mismatch", "tool": entry.get("tool"), "at": entry.get("at"),
                        "actor": entry.get("actor")}
                if legacy_zone:
                    legacy_audit.append(dict(item, reason=LEGACY_REASON))
                else:
                    # en_26fd4180: no unsigned quarantine / allowlist can wash this to ok=true.
                    result["tampered"].append(item)
                    result["confidence"] = "Unknown"
        prev = entry.get("hash") or prev
        head = prev
    seal_path = AUDIT_SEAL if path is None else path.with_suffix(".seal")
    mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
    # Seal once present is mandatory (B1: truncate + delete seal). Prefer primary, fall back to mirror.
    seal_required = seen_signed or result["entriesChecked"] > 0 or mirror.is_file() or signed_era_active()
    active_seal = seal_path if seal_path.is_file() else (mirror if mirror.is_file() else None)
    if seal_required and active_seal is None:
        result["tampered"].append(
            {"reason": "seal_missing_after_signed_era" if signed_era_active() else "seal_missing_required"}
        )
        result["confidence"] = "Unknown"
    elif active_seal is not None:
        try:
            seal = json.loads(active_seal.read_text(encoding="utf-8"))
            seal_body = {k: seal[k] for k in ("headHash", "count", "schema", "inventorySha256") if k in seal}
            if seal.get("mac") != entry_hmac(seal_body, key):
                result["tampered"].append({"reason": "seal_mac_mismatch"})
            elif int(seal.get("count") or 0) != result["entriesChecked"] or seal.get("headHash") != head:
                result["deletedOrGap"].append(
                    {
                        "reason": "truncated_or_count_mismatch",
                        "sealCount": seal.get("count"),
                        "actualCount": result["entriesChecked"],
                        "sealHead": seal.get("headHash"),
                        "actualHead": head,
                    }
                )
            elif "inventorySha256" in seal and RUN_INVENTORY.is_file():
                if seal.get("inventorySha256") != sha256_bytes(RUN_INVENTORY.read_bytes()):
                    result["tampered"].append({"reason": "inventory_seal_anchor_mismatch"})
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            result["tampered"].append({"reason": "seal_unreadable", "error": type(exc).__name__})
    ev = validate_evidence_files(key=key, marker=marker)
    result["evidenceFiles"] = ev
    if not ev.get("ok", True):
        result["tampered"].extend(ev.get("tampered") or [])
        result["confidence"] = "Unknown"
    _finish_split(result, legacy_audit, marker)
    if not result["ok"]:
        result["confidence"] = "Unknown"
    # Same-uid key forgeability (B6/B15): see key_storage_facts(). Without an external (root/remote)
    # anchor, local MACs alone must never claim Observed — even when ok=true.
    result["b6"] = dict(key_storage_facts(), confidence="Unknown", note=KEYCHAIN_LIMITATION)
    if result.get("confidence") == "Observed":
        result["confidence"] = "Unknown"
        result["observedBlockedBy"] = "same_uid_no_external_anchor"
    return result


def integrity_summary(v: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": v.get("ok"),
        "status": v.get("status"),
        "statusText": v.get("statusText"),
        "currentTampered": (v.get("currentTampered") or {}).get("count"),
        "legacyUnverifiable": (v.get("legacyUnverifiable") or {}).get("count"),
        "legacyRange": [(v.get("legacyUnverifiable") or {}).get("from"), (v.get("legacyUnverifiable") or {}).get("to")],
        "sameUidCanForge": (v.get("b6") or {}).get("sameUidCanForge"),
        "confidence": "Unknown",
    }


def recent_audit(limit: int = 30) -> list[dict[str, Any]]:
    if not AUDIT_LOG.exists():
        return []
    lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def list_mcp_audit(
    limit: int | None = 30,
    offset: int | None = None,
    cursor: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> dict[str, Any]:
    page_offset, page_limit = _parse_page(limit, offset, cursor, 30)
    since_ts, until_ts = _iso_ts(since), _iso_ts(until)
    entries = []
    if AUDIT_LOG.exists():
        for line in AUDIT_LOG.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _in_time_range(entry.get("at"), since_ts, until_ts):
                entries.append(entry)
    # Newest page first; each page stays chronological, matching the old suffix(limit).
    window_limit = page_limit if page_limit is not None else 30
    total = len(entries)
    end = max(0, total - page_offset)
    start = max(0, end - window_limit)
    page = entries[start:end]
    truncated = start > 0
    return {
        "entries": page,
        "validation": validate_audit(),
        "confidence": "Observed",
        "total": total,
        "offset": page_offset,
        "limit": window_limit,
        "truncated": truncated,
        "nextCursor": _encode_cursor(page_offset + window_limit) if truncated else None,
    }
