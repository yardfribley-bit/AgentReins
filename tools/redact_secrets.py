"""Shared secret redaction for MCP evidence.py and transport-audit auto.py.

Masks omit sha256 prefixes and lengths. Unit tests assert each original is absent.
"""
from __future__ import annotations

import re
from typing import Any

# curl -u / -uX / --user= / --user 'a:b c'
RE_USERPASS_EQ = re.compile(
    r"(?i)(-uX?|--user|--username)(=)(\S+:\S+)"
)
RE_USERPASS_SPACE = re.compile(
    r"(?i)(-uX?|--user|--username)(\s+)(['\"]?)([^\s'\"]+:[^\s'\"]+(?:\s+[^\s'\"]+)*)\3"
)
RE_USERPASS_SIMPLE = re.compile(
    r"(?i)(-uX?)(\s+)(\S+:\S+)"
)
# export SECRET= / password= / client_secret=
RE_PASSWORD = re.compile(
    r"(?i)((?:export\s+)?(?:password|passwd|pwd|secret|client_secret|[_A-Z0-9]*(?:_PASS|_SECRET))\s*[=:]\s*)([^\s'\"&,;]+)"
)
RE_PASSWORD_QUOTED = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|client_secret)\s*[=:]\s*)(['\"])([^'\"]+)\2"
)
# AWS
RE_AWS_AKIA = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_AWS_SECRET_QUOTED = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)(['\"])([A-Za-z0-9/+=]{20,})\2"
)
RE_AWS_SECRET = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"
)
# Bearer (including short) + Authorization: Basic
RE_BEARER = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._\-+/=]{4,})")
RE_BASIC = re.compile(r"(?i)(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+)")
# URL userinfo including password with @ (take last @ before host) and postgres:// etc.
RE_URL_USERINFO = re.compile(
    r"((?:https?|postgres|postgresql|mysql|mongodb|redis|amqp)://)([^/\s]+?)@"
)
# --password x / mysql -pSECRET
RE_PASSWORD_FLAG = re.compile(r"(?i)(--password|-p)(\s+|=)(\S+)")
RE_MYSQL_P = re.compile(r"(?i)(\s-p)([^\s\-][^\s]*)")
RE_GENERIC_TOKEN = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"api[_-]?key\s*[:=]\s*\S+|token\s*[:=]\s*\S+)"
)

SENSITIVE_KEYS = re.compile(
    r"(?i)^(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client_secret|authorization|credential|.*_pass|.*_secret)$"
)


def _mask(kind: str, _raw: str = "") -> str:
    """Mask without sha256 prefix or length (review requirement)."""
    return f"[{kind}:REDACTED]"


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text

    def sub_keep1(kind: str):
        return lambda m: m.group(1) + _mask(kind, m.group(m.lastindex or 1))

    def sub_url_userinfo(m: re.Match[str]) -> str:
        # Only redact when credentials are present (contain ':').
        creds = m.group(2)
        if ":" not in creds:
            return m.group(0)
        return m.group(1) + _mask("url_userinfo") + "@"

    out = RE_URL_USERINFO.sub(sub_url_userinfo, out)
    out = RE_USERPASS_EQ.sub(lambda m: m.group(1) + m.group(2) + _mask("userpass"), out)
    out = RE_USERPASS_SPACE.sub(
        lambda m: m.group(1) + m.group(2) + (m.group(3) or "") + _mask("userpass") + (m.group(3) or ""),
        out,
    )
    out = RE_USERPASS_SIMPLE.sub(lambda m: m.group(1) + m.group(2) + _mask("userpass"), out)
    out = RE_PASSWORD_QUOTED.sub(
        lambda m: m.group(1) + m.group(2) + _mask("password") + m.group(2), out
    )
    out = RE_PASSWORD.sub(lambda m: m.group(1) + _mask("password"), out)
    out = RE_PASSWORD_FLAG.sub(lambda m: m.group(1) + m.group(2) + _mask("password"), out)
    out = RE_MYSQL_P.sub(lambda m: m.group(1) + _mask("password"), out)
    out = RE_BASIC.sub(lambda m: m.group(1) + _mask("basic"), out)
    out = RE_BEARER.sub(lambda m: m.group(1) + _mask("bearer"), out)
    out = RE_AWS_AKIA.sub(lambda m: _mask("aws_access_key"), out)
    out = RE_AWS_SECRET_QUOTED.sub(
        lambda m: m.group(1) + m.group(2) + _mask("aws_secret") + m.group(2), out
    )
    out = RE_AWS_SECRET.sub(lambda m: m.group(1) + _mask("aws_secret"), out)
    out = RE_GENERIC_TOKEN.sub(
        lambda m: _mask(
            "api_key"
            if m.group(0).startswith("sk-")
            else "github_token"
            if m.group(0).startswith(("ghp_", "github_pat_"))
            else "credential"
        ),
        out,
    )
    return out


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.match(str(key)) or "secret" in str(key).lower() or "password" in str(key).lower():
                if isinstance(item, str):
                    out[key] = _mask("key:" + str(key))
                else:
                    out[key] = redact_obj(item)
            else:
                out[key] = redact_obj(item)
        return out
    return value
