"""Read-only evidence helpers for the AgentReins supervisor MCP.

Data sources: existing transport-audit folders and (optionally) the same
RealtimeWorkspace JS used by the packaged app. No new collectors.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1]
DEFAULT_TRANSPORT = pathlib.Path(
    os.environ.get("AGENTREINS_TRANSPORT_ROOT", "/private/tmp/agentreins-transport-audit")
)
AUDIT_DIR = pathlib.Path.home() / "Library/Application Support/AgentGuard"
AUDIT_LOG = AUDIT_DIR / "mcp-supervisor-audit.jsonl"
WORKSPACE_JS = REPO / "Sources/AgentReins/Resources/RealtimeWorkspace"
BRIDGE = ROOT / "alerts_bridge.cjs"

SECRET_RE = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"Bearer\s+\S+|api[_-]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+)"
)
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


def redact_text(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        kind = "credential"
        if raw.lower().startswith("bearer"):
            kind = "bearer"
        elif raw.startswith("sk-"):
            kind = "api_key"
        elif raw.startswith("ghp_") or raw.startswith("github_pat_"):
            kind = "github_token"
        digest = sha256_hex(raw)[:12]
        return f"[{kind}:len={len(raw)}:sha256={digest}]"

    return SECRET_RE.sub(repl, text)


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if key in ("textPreview", "request", "response", "blocks") or "secret" in key.lower():
                out[key] = redact_obj(item)
            else:
                out[key] = redact_obj(item)
        return out
    return value


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


def load_transport_records(root: pathlib.Path | None = None, limit: int = 80) -> list[dict[str, Any]]:
    root = root if root is not None else DEFAULT_TRANSPORT
    if not root.is_dir():
        return []
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
            "exitCode": inv.get("exitCode"),
            "gap": inv.get("gap"),
            "auditBypass": inv.get("auditBypass"),
            "session": inv.get("session") or inv.get("codexThreadID"),
            "codexThreadID": inv.get("codexThreadID"),
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
        rows.append(row)
    return rows


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


def build_alerts_via_bridge(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not BRIDGE.is_file() or not (WORKSPACE_JS / "risk-alerts.js").is_file():
        return build_alerts_fallback(records)
    payload = {
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
            }
            for r in records
        ],
    }
    try:
        proc = subprocess.run(
            ["node", str(BRIDGE)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=20,
            cwd=str(REPO),
        )
        if proc.returncode != 0:
            return build_alerts_fallback(records)
        data = json.loads(proc.stdout)
        return data.get("alerts") or []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return build_alerts_fallback(records)


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
    alerts = []
    for r in records:
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
        if host and not is_allowed_host(host) and not host.startswith("127."):
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
    return alerts


def list_alerts(
    agent: str | None = None,
    since: str | None = None,
    rule: str | None = None,
    records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    records = records if records is not None else load_transport_records()
    alerts = build_alerts_via_bridge(records)
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
        # Never leak raw secrets from nested record bodies
        out.append(redact_obj(item))
    return {
        "alerts": out,
        "confidence": "Observed" if out else "Unknown",
        "note": "告警由本机运输审计 + content_audit 推导；无数据即为空，不放样本。",
    }


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
        "evidenceIntegrity": {
            "mode": "append-only transport folders + sha256 of transport.json",
            "limitation": "被监督 agent 若对本机文件系统有写权限，仍可能删改文件；MCP 本身不提供删除/改写接口。",
            "confidence": "Inferred",
        },
        "confidence": "Observed" if proxy_up else "Unknown",
    }


def append_audit(actor: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    prev = "0" * 64
    if AUDIT_LOG.exists():
        try:
            last = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-1]
            prev = json.loads(last).get("hash") or prev
        except (OSError, json.JSONDecodeError, IndexError):
            prev = "0" * 64
    args_digest = sha256_hex(json.dumps(arguments, ensure_ascii=False, sort_keys=True))[:24]
    entry = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "tool": tool,
        "argsDigest": args_digest,
        "prevHash": prev,
    }
    entry["hash"] = sha256_hex(json.dumps(entry, ensure_ascii=False, sort_keys=True) + prev)
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    try:
        os.chmod(AUDIT_LOG, 0o600)
    except OSError:
        pass
    return entry


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
