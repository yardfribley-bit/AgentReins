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
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent
REPO = ROOT.parents[1]
AUDIT_DIR = pathlib.Path.home() / "Library/Application Support/AgentGuard"
DEFAULT_TRANSPORT = pathlib.Path(
    os.environ.get(
        "AGENTREINS_TRANSPORT_ROOT",
        str(AUDIT_DIR / "transport-audit"),
    )
)
LEGACY_TRANSPORT = pathlib.Path("/private/tmp/agentreins-transport-audit")
AUDIT_LOG = AUDIT_DIR / "mcp-supervisor-audit.jsonl"
HMAC_KEY_FILE = AUDIT_DIR / "mcp-supervisor-hmac.key"
# Prefer packaged RealtimeWorkspace next to this MCP copy; fall back to repo Sources.
_PACKAGED_JS = ROOT.parent / "RealtimeWorkspace"
_REPO_JS = REPO / "Sources/AgentReins/Resources/RealtimeWorkspace"
WORKSPACE_JS = _PACKAGED_JS if (_PACKAGED_JS / "risk-alerts.js").is_file() else _REPO_JS
BRIDGE = ROOT / "alerts_bridge.cjs"

# Per-class secret patterns — unit tests assert each original is absent after redact.
RE_PASSWORD = re.compile(
    r"(?i)((?:password|passwd|pwd)\s*[=:]\s*)([^\s'\"&,;]+)"
)
RE_USERPASS_FLAG = re.compile(
    r"(?i)(-u|--user|--username)(\s+| =)(\S+:\S+)"
)
RE_AWS_AKIA = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_AWS_SECRET = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"
)
RE_BEARER = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._\-+/=]{8,})")
RE_URL_USERINFO = re.compile(r"(https?://)([^/\s:@]+):([^/\s@]+)@")
RE_GENERIC_TOKEN = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"api[_-]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+)"
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


def _mask(kind: str, raw: str) -> str:
    return f"[{kind}:len={len(raw)}:sha256={sha256_hex(raw)[:12]}]"


def redact_text(text: str) -> str:
    """Redact password, -u user:pass, AWS AKIA/secret, Bearer, URL userinfo, and common tokens."""
    if not text:
        return text
    out = text

    def sub_password(m: re.Match[str]) -> str:
        return m.group(1) + _mask("password", m.group(2))

    def sub_userpass(m: re.Match[str]) -> str:
        return m.group(1) + m.group(2) + _mask("userpass", m.group(3))

    def sub_akia(m: re.Match[str]) -> str:
        return _mask("aws_access_key", m.group(1))

    def sub_aws_secret(m: re.Match[str]) -> str:
        return m.group(1) + _mask("aws_secret", m.group(2))

    def sub_bearer(m: re.Match[str]) -> str:
        return m.group(1) + _mask("bearer", m.group(2))

    def sub_userinfo(m: re.Match[str]) -> str:
        return m.group(1) + _mask("url_userinfo", m.group(2) + ":" + m.group(3)) + "@"

    def sub_generic(m: re.Match[str]) -> str:
        raw = m.group(0)
        kind = "credential"
        if raw.startswith("sk-"):
            kind = "api_key"
        elif raw.startswith("ghp_") or raw.startswith("github_pat_"):
            kind = "github_token"
        return _mask(kind, raw)

    out = RE_URL_USERINFO.sub(sub_userinfo, out)
    out = RE_USERPASS_FLAG.sub(sub_userpass, out)
    out = RE_PASSWORD.sub(sub_password, out)
    out = RE_BEARER.sub(sub_bearer, out)
    out = RE_AWS_AKIA.sub(sub_akia, out)
    out = RE_AWS_SECRET.sub(sub_aws_secret, out)
    out = RE_GENERIC_TOKEN.sub(sub_generic, out)
    return out


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
    if root is not None:
        return _load_transport_dir(root, limit)
    primary = _load_transport_dir(DEFAULT_TRANSPORT, limit)
    if str(DEFAULT_TRANSPORT.resolve()) == str(LEGACY_TRANSPORT.resolve()):
        return primary
    legacy = _load_transport_dir(LEGACY_TRANSPORT, limit)
    by_id: dict[str, dict[str, Any]] = {}
    for row in primary + legacy:
        by_id.setdefault(str(row.get("runID")), row)
    return sorted(by_id.values(), key=lambda r: str(r.get("startedAt") or ""), reverse=True)[:limit]


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


def build_alerts_via_bridge(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (alerts, meta). meta.engine is 'js-bridge' or 'python-fallback' with warning."""
    meta: dict[str, Any] = {"engine": "js-bridge", "warning": None}
    js_ok = BRIDGE.is_file() and (WORKSPACE_JS / "risk-alerts.js").is_file()
    if not js_ok:
        meta = {
            "engine": "python-fallback",
            "warning": "未加载与 App 相同的 JS 规则引擎（risk-alerts.js）；Python 回退可能缺少完整 S03 关联。",
        }
        return build_alerts_fallback(records), meta
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
    try:
        proc = subprocess.run(
            ["node", str(BRIDGE)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=20,
            cwd=str(ROOT),
            env={**os.environ, "AGENTREINS_WORKSPACE_JS": str(WORKSPACE_JS)},
        )
        if proc.returncode != 0:
            meta = {
                "engine": "python-fallback",
                "warning": f"JS 规则桥接失败（exit {proc.returncode}）；已显式回退，结果可能不完整。stderr={proc.stderr[:200]}",
            }
            return build_alerts_fallback(records), meta
        data = json.loads(proc.stdout)
        return data.get("alerts") or [], meta
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        meta = {
            "engine": "python-fallback",
            "warning": f"JS 规则桥接异常，已显式回退：{type(exc).__name__}",
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
        if tool in ("chmod", "sh", "bash", "open") or re.search(
            r"chmod\s+\+x|/bin/(ba)?sh\b|\bsh\b|\bbash\b", cmd
        ):
            if not (r.get("downloads") or []):
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
            lineage = dl_rec.get("pid") and ex.get("parentPID") and str(dl_rec.get("pid")) == str(ex.get("parentPID"))
            alerts.append(
                {
                    "id": f"S03:{dl_rec.get('call')}:{name}:{ex.get('call')}",
                    "rule": "S03",
                    "title": "下载后在 5 分钟内执行",
                    "agent": dl_rec.get("agent"),
                    "session": dl_rec.get("session"),
                    "call": ex.get("call") or dl_rec.get("call"),
                    "confidence": "Correlated" if lineage or ex.get("tool") in ("chmod", "sh", "bash") else "Inferred",
                    "timestamp": ex.get("startedAt"),
                    "sub": name,
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


def entry_hmac(entry_body: dict[str, Any], key: bytes) -> str:
    payload = json.dumps(entry_body, ensure_ascii=False, sort_keys=True)
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def append_audit(actor: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    ensure_audit_dir()
    key = load_or_create_hmac_key()
    prev = "0" * 64
    if AUDIT_LOG.exists():
        try:
            last = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-1]
            prev = json.loads(last).get("hash") or prev
        except (OSError, json.JSONDecodeError, IndexError):
            prev = "0" * 64
    args_digest = sha256_hex(json.dumps(arguments, ensure_ascii=False, sort_keys=True))[:24]
    entry: dict[str, Any] = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor,
        "tool": tool,
        "argsDigest": args_digest,
        "prevHash": prev,
    }
    entry["mac"] = entry_hmac(entry, key)
    entry["hash"] = sha256_hex(json.dumps(entry, ensure_ascii=False, sort_keys=True) + prev)
    with AUDIT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    try:
        os.chmod(AUDIT_LOG, 0o600)
    except OSError:
        pass
    return entry


def validate_audit(path: pathlib.Path | None = None) -> dict[str, Any]:
    """Validate keyed HMAC chain; report tampered and deleted/missing links."""
    log = path or AUDIT_LOG
    result: dict[str, Any] = {
        "mode": "keyed-HMAC-SHA256 append-only",
        "keyPath": str(HMAC_KEY_FILE),
        "logPath": str(log),
        "ok": True,
        "entriesChecked": 0,
        "tampered": [],
        "deletedOrGap": [],
        "confidence": "Observed",
        "limitation": "持有本机 HMAC 密钥的进程仍可重写整条链；MCP 不提供删除接口。",
    }
    if not log.is_file():
        result["ok"] = True
        result["note"] = "尚无审计日志"
        return result
    try:
        key = load_or_create_hmac_key()
    except OSError as exc:
        result["ok"] = False
        result["warning"] = f"无法读取 HMAC 密钥：{exc}"
        return result
    lines = log.read_text(encoding="utf-8").splitlines()
    prev = "0" * 64
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
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
            # Pre-HMAC legacy lines: do not treat as tamper; report separately.
            result.setdefault("legacyUnsigned", []).append({"index": idx, "tool": entry.get("tool")})
        else:
            expected_mac = entry_hmac(body, key)
            if entry.get("mac") != expected_mac:
                result["ok"] = False
                result["tampered"].append({"index": idx, "reason": "mac_mismatch", "tool": entry.get("tool")})
        prev = entry.get("hash") or prev
    if result.get("legacyUnsigned") and not result["tampered"] and not result["deletedOrGap"]:
        result["note"] = "含升级前无 HMAC 的旧行；新写入均带密钥 MAC。"
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
