"""Content indicators for one agent exchange.

Findings keep the rule, direction, count and first offset. They never include
the matched text.
"""
import json
import os
import re
from pathlib import Path

POLICY_PATH = Path(os.environ.get("AGENTREINS_SECURITY_POLICY", "~/Library/Application Support/AgentReins/security-policy.json")).expanduser()
_policy_stamp = None
_policy_cache = {"rules": [], "approvedModelHosts": []}

RULES = (
    ("credential-outbound", "request", "high",
     r"(?:sk-(?:proj-|or-v1-)[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})"),
    ("private-key-outbound", "request", "high",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("instruction-override-inbound", "response", "review",
     r"(?i)(?:ignore (?:all |the )?(?:previous|prior|system) instructions|忽略(?:之前|上述|系统)(?:的)?(?:指令|规则))"),
    ("download-execute-inbound", "response", "review",
     r"(?i)(?:curl|wget)[^\r\n]{0,400}\|\s*(?:bash|sh)\b"),
)


def load_policy():
    global _policy_stamp, _policy_cache
    try:
        stamp = POLICY_PATH.stat().st_mtime_ns
        if stamp != _policy_stamp:
            raw = POLICY_PATH.read_bytes()
            if len(raw) > 262144:
                raise ValueError("policy too large")
            value = json.loads(raw)
            rules = value.get("rules", [])
            if not isinstance(rules, list) or len(rules) > 100:
                raise ValueError("invalid rules")
            for rule in rules:
                if not isinstance(rule.get("value"), str) or not 3 <= len(rule["value"]) <= 4096:
                    raise ValueError("invalid literal")
                if rule.get("kind") not in ("keyword", "secret"):
                    raise ValueError("invalid kind")
            hosts = value.get("approvedModelHosts", [])
            if not isinstance(hosts, list) or not all(isinstance(item, str) for item in hosts):
                raise ValueError("invalid hosts")
            _policy_cache = {"rules": rules, "approvedModelHosts": hosts}
            _policy_stamp = stamp
        return _policy_cache, None
    except FileNotFoundError:
        return {"rules": [], "approvedModelHosts": []}, None
    except (ValueError, TypeError, AttributeError, OSError):
        return {"rules": [], "approvedModelHosts": []}, "自定义策略读取失败；本次仅执行内置规则"


def _remember(found, rule, direction, severity, offset):
    key = (rule, direction)
    item = found.get(key)
    if item is None:
        found[key] = {
            "rule": rule, "direction": direction, "severity": severity,
            "count": 1, "characterOffset": offset,
            "basis": "captured_body_pattern", "status": "needs_review",
        }
        return
    item["count"] += 1
    if offset is not None and (item["characterOffset"] is None or offset < item["characterOffset"]):
        item["characterOffset"] = offset


def _scan_text(text, direction, found, base_offset=0):
    if not text:
        return
    for rule, rule_direction, severity, pattern in RULES:
        if rule_direction != direction:
            continue
        for match in re.finditer(pattern, text):
            _remember(found, rule, direction, severity, base_offset + match.start())


def _split_trace(path):
    """Raw curl/git trace text, split by send and receive, before any redaction."""
    request, response, current = [], [], None
    with path.open(errors="replace") as source:
        for line in source:
            if "=> Send" in line:
                current = request
            elif "<= Recv" in line:
                current = response
            if current is not None:
                current.append(line)
    return "".join(request), "".join(response)


def audit(request_text, response_text, response_present, host=None, scope="decoded_body_only", trace_files=(), inspection_truncated=False):
    request_text = request_text or ""
    response_text = response_text or ""
    found = {}
    _scan_text(request_text, "request", found)
    _scan_text(response_text, "response", found)
    request_bytes = len(request_text.encode("utf-8"))
    response_bytes = len(response_text.encode("utf-8")) if response_present or response_text else 0
    request_parts = [request_text]
    for path in trace_files:
        file_path = Path(path)
        if not file_path.is_file():
            continue
        request_part, response_part = _split_trace(file_path)
        _scan_text(request_part, "request", found, request_bytes)
        _scan_text(response_part, "response", found, response_bytes)
        request_parts.append(request_part)
        request_bytes += len(request_part.encode("utf-8"))
        response_bytes += len(response_part.encode("utf-8"))
        if response_part:
            response_present = True
    findings = list(found.values())
    policy, policy_error = load_policy()
    try:
        semantic = json.dumps(json.loads(request_text), ensure_ascii=False)
    except (ValueError, TypeError):
        semantic = request_text
    for index, rule in enumerate(policy["rules"]):
        if rule.get("enabled", True) is False:
            continue
        value = rule["value"]
        count = semantic.count(value)
        offset = semantic.find(value)
        scanned = len(semantic)
        for part in request_parts[1:]:
            part_count = part.count(value)
            if part_count:
                found_at = part.find(value)
                if offset < 0 or scanned + found_at < offset:
                    offset = scanned + found_at
                count += part_count
            scanned += len(part)
        if count:
            findings.append({
                "rule": "custom-" + str(index + 1), "direction": "request",
                "severity": "high" if rule["kind"] == "secret" else "review",
                "count": count, "characterOffset": offset,
                "basis": "normalized_json_literal", "status": "needs_review",
                "label": str(rule.get("name", "自定义敏感数据"))[:120],
                "recommendation": "如为有效密钥，请撤销或轮换，并检查使用记录" if rule["kind"] == "secret" else "核对接收方与授权范围，确认是否允许外发",
            })
    hosts = policy["approvedModelHosts"]
    if host and host.lower() in [item.lower() for item in hosts]:
        destination = "approved"
    elif hosts:
        destination = "unapproved"
    else:
        destination = "not_configured"
    return {
        "version": "content-rules-v2",
        "policyError": policy_error,
        "destinationHost": host,
        "destinationPolicy": destination,
        "findings": findings,
        "requestBytesInspected": request_bytes,
        "responseBytesInspected": response_bytes if response_present else None,
        "inspectionTruncated": bool(inspection_truncated),
        "scope": scope,
        "verdict": "review" if findings else "no_rule_match",
    }
