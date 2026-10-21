"""Read-only evidence helpers for the AgentReins supervisor MCP.

Data sources: existing transport-audit folders and (optionally) the same
RealtimeWorkspace JS used by the packaged app. No new collectors.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import sys
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
KEYCHAIN_LIMITATION = (
    "HMAC 密钥位于用户目录 0600 文件（非 Keychain）。同一 uid 的被监督进程可读密钥并伪造 MAC；"
    "相关完整性结论标为 Unknown，除非改用 Keychain/独立特权守护。"
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


def credential_finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    """S02-style findings: type/count/offset only — never matched plaintext."""
    return {
        "rule": finding.get("rule"),
        "direction": finding.get("direction"),
        "severity": finding.get("severity"),
        "count": finding.get("count"),
        "characterOffset": finding.get("characterOffset"),
        "label": finding.get("label") or finding.get("rule"),
        "matchedText": None,
        "note": "原始匹配文本不通过 MCP 返回",
        "confidence": "Observed",
    }


def _load_transport_dir(root: pathlib.Path, limit: int) -> list[dict[str, Any]]:
    if not root.is_dir():
        return []
    try:
        root.chmod(0o700)
    except OSError:
        pass
    files = sorted(
        root.glob("*/transport.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )[:limit]
    rows: list[dict[str, Any]] = []
    for path in files:
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        inv = item.get("invocation") if isinstance(item.get("invocation"), dict) else {}
        if inv.get("captureMode") != "agent-path":
            continue
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
            "evidenceSha256": sha256_hex(path.read_bytes().decode("utf-8", "replace")[:200_000]),
            "confidence": "Observed",
        }
        if is_test_capture(row):
            continue
        rows.append(row)
    return rows


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


def list_agents(records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    records = records if records is not None else load_transport_records()
    by_agent: dict[str, dict[str, Any]] = {}
    for row in records:
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
    agents = []
    for agent, bucket in sorted(by_agent.items()):
        agents.append(
            {
                "agent": agent,
                "isCursor": agent == "Cursor",
                "sessions": sorted(bucket["sessions"]),
                "executionIds": bucket["executionIds"][:40],
                "tools": sorted(bucket["tools"]),
                "confidence": "Observed" if bucket["executionIds"] else "Unknown",
            }
        )
    return {
        "agents": agents,
        "confidence": "Observed" if agents else "Unknown",
        "note": "仅来自 agent-path 运输审计；未走包装入口的进程不会出现。",
    }


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
            if rule == "instruction-override-inbound":
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
                        "finding": credential_finding_summary(finding),
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
) -> dict[str, Any]:
    records = records if records is not None else load_transport_records()
    alerts, engine_meta = build_alerts_via_bridge(records)
    since_ts = None
    if since:
        try:
            since_ts = time.mktime(time.strptime(since[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            since_ts = None
    out = []
    for alert in alerts:
        conf = conf_label(alert.get("confidence"))
        item = {
            "id": alert.get("id"),
            "rule": alert.get("rule"),
            "title": alert.get("title"),
            "agent": alert.get("agent"),
            "session": alert.get("session"),
            "executionId": alert.get("call"),
            "confidence": conf,
            "timestamp": alert.get("timestamp") or alert.get("startedAt"),
            "sub": alert.get("sub"),
            "finding": alert.get("finding"),
        }
        if agent and agent != "all" and str(item.get("agent")) != agent:
            continue
        if rule and rule != "all" and str(item.get("rule")) != rule:
            continue
        if since_ts and item.get("timestamp"):
            try:
                ts = time.mktime(time.strptime(str(item["timestamp"])[:19], "%Y-%m-%dT%H:%M:%S"))
                if ts < since_ts:
                    continue
            except ValueError:
                pass
        out.append(redact_obj(item))
    result = {
        "alerts": out,
        "confidence": "Observed" if out else "Unknown",
        "note": "告警由本机运输审计 + 与 App 相同的 risk-alerts.js 推导；无数据即为空，不放样本。",
        "engine": engine_meta.get("engine"),
    }
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
            "note": "未找到该执行编号的运输审计记录。",
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
    findings = [credential_finding_summary(f) for f in (audit.get("findings") or [])]
    return redact_obj(
        {
            "executionId": hit.get("call") or hit.get("runID"),
            "agent": hit.get("agent"),
            "session": hit.get("session"),
            "tool": hit.get("tool"),
            "commandArgs": hit.get("args") or [],
            "startedAt": hit.get("startedAt"),
            "exitCode": hit.get("exitCode"),
            "destination": host_of(hit),
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
            "note": "正文预览已脱敏；S02 仅返回 finding 元数据。",
        }
    )


def list_network(
    agent: str | None = None,
    since: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    records = records if records is not None else load_transport_records()
    rows = []
    for r in records:
        if agent and agent != "all" and str(r.get("agent")) != agent:
            continue
        host = host_of(r)
        rows.append(
            {
                "executionId": r.get("call") or r.get("runID"),
                "agent": r.get("agent"),
                "tool": r.get("tool"),
                "destination": host,
                "allowed": is_allowed_host(host) if host else None,
                "nonWhitelist": bool(host and not is_allowed_host(host) and not str(host).startswith("127.")),
                "auditBypass": r.get("auditBypass") is True,
                "startedAt": r.get("startedAt"),
                "exitCode": r.get("exitCode"),
                "confidence": "Observed" if host else "Unknown",
            }
        )
    return {
        "network": redact_obj(rows),
        "confidence": "Observed" if rows else "Unknown",
        "note": "目的地主机来自运输审计连接/参数；看不到正文的仍标 Unknown。",
    }


def get_coverage() -> dict[str, Any]:
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
    return {
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
            {"topic": "未走代理流量", "confidence": "Unknown", "note": "不估算比例"},
            {"topic": "SSH 通道内正文", "confidence": "Unknown", "note": "只看到连到哪台主机"},
        ],
        "evidenceIntegrity": validate_audit(),
        "transportRoot": str(DEFAULT_TRANSPORT),
        "confidence": "Observed" if proxy_up else "Unknown",
    }


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


def load_or_create_hmac_key() -> bytes:
    """Keyed HMAC material in user-only 0600 file (Keychain-equivalent for local MCP)."""
    ensure_audit_dir()
    if HMAC_KEY_FILE.is_file():
        key = HMAC_KEY_FILE.read_bytes()
        if len(key) >= 16:
            return key
    key = os.urandom(32)
    fd = os.open(HMAC_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    try:
        os.chmod(HMAC_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


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


def mark_signed_era() -> None:
    """Persist that a signed era has started (survives wiping AUDIT_DIR)."""
    _ensure_integrity_dir()
    if not SIGNED_ERA_FLAG.is_file():
        SIGNED_ERA_FLAG.write_text(
            json.dumps(
                {
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "schema": 1,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(SIGNED_ERA_FLAG, 0o600)
        except OSError:
            pass


def signed_era_active() -> bool:
    return SIGNED_ERA_FLAG.is_file() or (PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal").is_file()


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
    mark_signed_era()


def validate_run_inventory(key: bytes | None = None) -> dict[str, Any]:
    """Detect B8: deleting inventory rows without the external MAC."""
    result: dict[str, Any] = {"ok": True, "tampered": []}
    key = key or load_or_create_hmac_key()
    if RUN_INVENTORY_MAC.is_file():
        if not RUN_INVENTORY.is_file():
            result["ok"] = False
            result["tampered"].append({"reason": "inventory_missing_after_signed"})
            return result
        expected = RUN_INVENTORY_MAC.read_text(encoding="utf-8").strip()
        actual = evidence_file_mac(RUN_INVENTORY, key)
        if not hmac.compare_digest(expected, actual):
            result["ok"] = False
            result["tampered"].append({"reason": "inventory_mac_mismatch"})
    elif RUN_INVENTORY.is_file() and signed_era_active():
        # Signed era but inventory MAC wiped with the inventory edits.
        result["ok"] = False
        result["tampered"].append({"reason": "inventory_mac_missing_after_signed_era"})
    return result


def register_run_id(run_id: str, run_path: pathlib.Path | None = None) -> None:
    """Append run ID to durable inventory so deleted runs are detectable."""
    ensure_audit_dir()
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


def validate_evidence_files(root: pathlib.Path | None = None) -> dict[str, Any]:
    """Detect tampering of transport/manifest evidence.

    MAC is required only for inventory-registered runs (not every historical folder).
    External signed-era flag makes wipe-everything look like tamper (B9/B10), not 'unsigned'.
    """
    ensure_audit_dir()
    key = load_or_create_hmac_key()
    base = root or DEFAULT_TRANSPORT
    result: dict[str, Any] = {
        "ok": True,
        "checked": 0,
        "tampered": [],
        "missingMac": [],
        "missingRuns": [],
        "confidence": "Observed",
        "keyLimitation": KEYCHAIN_LIMITATION,
    }
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
        result["note"] = "无运输审计目录"
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
            result["ok"] = False
            result["tampered"].append({"path": str(path), "reason": "evidence_mac_mismatch"})
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
    # Anchor inventory hash inside seal when inventory exists (B8).
    if RUN_INVENTORY.is_file():
        body["inventorySha256"] = sha256_bytes(RUN_INVENTORY.read_bytes())
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
        sign_run_inventory(key)
    except OSError:
        pass


def append_audit(actor: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Append one audit line. Readers must NEVER re-sign evidence trees (B3 wash prevention)."""
    ensure_audit_dir()
    key = load_or_create_hmac_key()
    prev = "0" * 64
    count = 0
    if AUDIT_LOG.exists():
        try:
            lines = [ln for ln in AUDIT_LOG.read_text(encoding="utf-8").splitlines() if ln.strip()]
            count = len(lines)
            if lines:
                prev = json.loads(lines[-1]).get("hash") or prev
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
    _write_seal(entry["hash"], count + 1, key)
    # Intentionally do NOT call sign_evidence_tree() here — collection signs; read only verifies.
    return entry


def validate_audit(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Validate keyed HMAC chain. Seal is mandatory once a signed era exists; no resign-on-read."""
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
    if not log.is_file():
        result["ok"] = True
        result["note"] = "尚无审计日志"
        if signed_era_active():
            # B9/B10: signed era then wipe log (+ often seals) is tamper, not a fresh install.
            result["ok"] = False
            result["tampered"].append({"reason": "audit_log_missing_after_signed_era"})
            result["confidence"] = "Unknown"
            mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
            if not AUDIT_SEAL.is_file() and not mirror.is_file():
                result["tampered"].append({"reason": "seal_missing_after_signed_era"})
        elif not SIGNED_ERA_FLAG.is_file() and not (PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal").is_file():
            # Playbook: never anchored → Unknown(never_anchored), not ok=true success claim.
            result["confidence"] = "Unknown"
            result["note"] = "never_anchored"
            result["neverAnchored"] = True
        # Still check evidence / inventory.
        ev = validate_evidence_files()
        result["evidenceFiles"] = ev
        if not ev.get("ok", True):
            result["ok"] = False
            result["tampered"].extend(ev.get("tampered") or [])
            result["confidence"] = "Unknown"
        return result
    try:
        key = load_or_create_hmac_key()
    except OSError as exc:
        result["ok"] = False
        result["warning"] = f"无法读取 HMAC 密钥：{exc}"
        result["confidence"] = "Unknown"
        return result
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    prev = "0" * 64
    seen_signed = False
    head = prev
    for idx, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            result["ok"] = False
            result["tampered"].append({"index": idx, "reason": "invalid_json"})
            continue
        result["entriesChecked"] += 1
        if entry.get("prevHash") != prev:
            result["ok"] = False
            result["deletedOrGap"].append(
                {
                    "index": idx,
                    "reason": "prevHash_mismatch",
                    "expectedPrev": prev,
                    "gotPrev": entry.get("prevHash"),
                }
            )
        body = {k: entry[k] for k in ("at", "actor", "tool", "argsDigest", "prevHash") if k in entry}
        if "mac" not in entry:
            # Any missing MAC is tamper once signing is in use (B2: strip MACs + rewrite).
            result["ok"] = False
            result["tampered"].append(
                {"index": idx, "reason": "missing_mac", "tool": entry.get("tool")}
            )
        else:
            seen_signed = True
            expected_mac = entry_hmac(body, key)
            if entry.get("mac") != expected_mac:
                result["ok"] = False
                result["tampered"].append({"index": idx, "reason": "mac_mismatch", "tool": entry.get("tool")})
        prev = entry.get("hash") or prev
        head = prev
    seal_path = AUDIT_SEAL if path is None else path.with_suffix(".seal")
    mirror = PROTECTED_SEAL_DIR / "mcp-supervisor-audit.seal"
    # Seal once present is mandatory (B1: truncate + delete seal). Prefer primary, fall back to mirror.
    # B9/B10: external signed-era flag also requires a seal to still exist somewhere.
    seal_required = (
        seen_signed
        or result["entriesChecked"] > 0
        or mirror.is_file()
        or signed_era_active()
    )
    active_seal = seal_path if seal_path.is_file() else (mirror if mirror.is_file() else None)
    if seal_required and active_seal is None:
        result["ok"] = False
        result["tampered"].append(
            {"reason": "seal_missing_after_signed_era" if signed_era_active() else "seal_missing_required"}
        )
        result["confidence"] = "Unknown"
    elif active_seal is not None:
        try:
            seal = json.loads(active_seal.read_text(encoding="utf-8"))
            seal_body = {
                k: seal[k]
                for k in ("headHash", "count", "schema", "inventorySha256")
                if k in seal
            }
            if seal.get("mac") != entry_hmac(seal_body, key):
                result["ok"] = False
                result["tampered"].append({"reason": "seal_mac_mismatch"})
            elif int(seal.get("count") or 0) != result["entriesChecked"] or seal.get("headHash") != head:
                result["ok"] = False
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
                actual_inv = sha256_bytes(RUN_INVENTORY.read_bytes())
                if seal.get("inventorySha256") != actual_inv:
                    result["ok"] = False
                    result["tampered"].append({"reason": "inventory_seal_anchor_mismatch"})
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            result["ok"] = False
            result["tampered"].append({"reason": "seal_unreadable", "error": type(exc).__name__})
    # B9/B10: log wiped but signed-era flag remains.
    if signed_era_active() and not log.is_file() and result["entriesChecked"] == 0:
        result["ok"] = False
        result["tampered"].append({"reason": "audit_log_missing_after_signed_era"})
        result["confidence"] = "Unknown"
    ev = validate_evidence_files()
    result["evidenceFiles"] = ev
    if not ev.get("ok", True):
        result["ok"] = False
        result["tampered"].extend(ev.get("tampered") or [])
        result["confidence"] = "Unknown"
    # Same-uid key forgeability (B6): never claim Observed for integrity against same-uid attacker.
    result["b6"] = {
        "sameUidCanForge": True,
        "confidence": "Unknown",
        "note": KEYCHAIN_LIMITATION,
    }
    return result


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


def list_mcp_audit(limit: int = 30) -> dict[str, Any]:
    return {
        "entries": recent_audit(limit=limit),
        "validation": validate_audit(),
        "confidence": "Observed",
    }
