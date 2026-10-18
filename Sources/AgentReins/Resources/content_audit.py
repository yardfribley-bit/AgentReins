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


def audit(request_text, response_text, response_present, host=None, scope="decoded_body_only"):
    request_text = request_text or ""
    response_text = response_text or ""
    findings = []
    texts = {"request": request_text, "response": response_text}
    for rule, direction, severity, pattern in RULES:
        count, first = 0, None
        for match in re.finditer(pattern, texts[direction]):
            count += 1
            if first is None:
                first = match.start()
        if count:
            findings.append({
                "rule": rule, "direction": direction, "severity": severity,
                "count": count, "characterOffset": first,
                "basis": "captured_body_pattern", "status": "needs_review",
            })
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
        if count:
            findings.append({
                "rule": "custom-" + str(index + 1), "direction": "request",
                "severity": "high" if rule["kind"] == "secret" else "review",
                "count": count, "characterOffset": semantic.find(value),
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
        "requestBytesInspected": len(request_text.encode("utf-8")),
        "responseBytesInspected": len(response_text.encode("utf-8")) if response_present else None,
        "scope": scope,
        "verdict": "review" if findings else "no_rule_match",
    }
