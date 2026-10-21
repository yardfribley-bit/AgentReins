"""Shared secret redaction for MCP evidence.py, Swift MCP, and transport-audit auto.py.

Masks omit sha256 prefixes and lengths. Shared vectors live in
tools/redact_vectors.json — Python and Swift must both pass them.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# curl -u / -uX / --user= / --user 'a:b c' (including glued -uX:Y)
RE_USERPASS_EQ = re.compile(r"(?i)(-uX?|--user|--username)(=)(\S+:\S+)")
RE_USERPASS_GLUED = re.compile(r"(?i)(-uX)([^\s:=][^:\s]*:[^\s]+)")
RE_USERPASS_SPACE = re.compile(
    r"(?i)(-uX?|--user|--username)(\s+)(['\"])([^'\"]+:[^'\"]+)\3"
)
RE_USERPASS_SIMPLE = re.compile(r"(?i)(-uX?|--user|--username)(\s+)(\S+:\S+)")

# Env / JSON-ish assignments
RE_API_TOKEN_EQ = re.compile(
    r"(?i)((?:export\s+)?(?:API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|TOKEN)\s*=\s*)([^\s'\"&,;]+)"
)
RE_PASSWORD = re.compile(
    r"(?i)((?:export\s+)?(?:password|passwd|pwd|secret|client_secret|db_password|"
    r"[_A-Z0-9]*(?:_PASS|_SECRET|_PASSWORD))\s*[=:]\s*)([^\s'\"&,;]+)"
)
RE_PASSWORD_QUOTED = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|client_secret|db_password)\s*[=:]\s*)(['\"])([^'\"]+)\2"
)
RE_JSON_SECRET = re.compile(
    r'(?i)("(?:password|passwd|pwd|secret|client_secret|db_password)"\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")'
)

# AWS
RE_AWS_AKIA = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_AWS_SECRET_QUOTED = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)(['\"])([A-Za-z0-9/+=]{20,})\2"
)
RE_AWS_SECRET = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"
)

# Bearer (including short) + Authorization: Basic + Cookie + x-api-key
RE_BEARER = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._\-+/=]{4,})")
RE_BASIC = re.compile(r"(?i)(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+)")
RE_COOKIE = re.compile(r"(?i)((?:Cookie|Set-Cookie)\s*[:=]\s*)([^\r\n]+)")
RE_X_API_KEY = re.compile(r"(?i)((?:X-Api-Key|x-api-key)\s*[:=]\s*)(\S+)")

# URL userinfo — password may contain @; greedy takes last @ before host. Include mongodb+srv.
RE_URL_USERINFO = re.compile(
    r"((?:https?|postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://)([^/\s]+)@"
)

# --password x  OR  mysql/sshpass -pSECRET (NOT mkdir -p / ssh -p PORT / git add -p / find -print)
RE_PASSWORD_FLAG = re.compile(r"(?i)(--password)(\s+|=)(\S+)")
RE_MYSQL_SSHPASS_P = re.compile(
    r"(?i)(\b(?:mysql|mysqldump|sshpass|mariadb)\b(?:\s+\S+){0,6}\s+-p)([^\s\-]+)"
)

RE_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
RE_GENERIC_TOKEN = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
)

SENSITIVE_KEYS = re.compile(
    r"(?i)^(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client_secret|authorization|credential|cookie|x-api-key|db_password|.*_pass|.*_secret)$"
)


def _mask(kind: str, _raw: str = "") -> str:
    return f"[{kind}:REDACTED]"


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text

    def sub_url_userinfo(m: re.Match[str]) -> str:
        creds = m.group(2)
        if ":" not in creds:
            return m.group(0)
        return m.group(1) + _mask("url_userinfo") + "@"

    out = RE_PEM.sub(_mask("pem"), out)
    out = RE_URL_USERINFO.sub(sub_url_userinfo, out)
    out = RE_USERPASS_EQ.sub(lambda m: m.group(1) + m.group(2) + _mask("userpass"), out)
    out = RE_USERPASS_GLUED.sub(lambda m: m.group(1) + _mask("userpass"), out)
    out = RE_USERPASS_SPACE.sub(
        lambda m: m.group(1) + m.group(2) + m.group(3) + _mask("userpass") + m.group(3),
        out,
    )
    out = RE_USERPASS_SIMPLE.sub(lambda m: m.group(1) + m.group(2) + _mask("userpass"), out)
    out = RE_JSON_SECRET.sub(lambda m: m.group(1) + _mask("password") + m.group(3), out)
    out = RE_PASSWORD_QUOTED.sub(
        lambda m: m.group(1) + m.group(2) + _mask("password") + m.group(2), out
    )
    out = RE_API_TOKEN_EQ.sub(lambda m: m.group(1) + _mask("token"), out)
    out = RE_PASSWORD.sub(lambda m: m.group(1) + _mask("password"), out)
    out = RE_PASSWORD_FLAG.sub(lambda m: m.group(1) + m.group(2) + _mask("password"), out)
    out = RE_MYSQL_SSHPASS_P.sub(lambda m: m.group(1) + _mask("password"), out)
    out = RE_COOKIE.sub(lambda m: m.group(1) + _mask("cookie"), out)
    out = RE_X_API_KEY.sub(lambda m: m.group(1) + _mask("api_key"), out)
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
            key_l = str(key).lower()
            if SENSITIVE_KEYS.match(str(key)) or "secret" in key_l or "password" in key_l or key_l in (
                "cookie",
                "x-api-key",
                "authorization",
            ):
                if isinstance(item, str):
                    out[key] = _mask("key:" + str(key))
                elif isinstance(item, list):
                    out[key] = [_mask("key:" + str(key)) if isinstance(x, str) else redact_obj(x) for x in item]
                else:
                    out[key] = redact_obj(item)
            else:
                out[key] = redact_obj(item)
        return out
    return value


def load_vectors() -> list[dict[str, Any]]:
    path = Path(__file__).with_name("redact_vectors.json")
    return json.loads(path.read_text(encoding="utf-8"))


def run_vector_checks() -> list[str]:
    """Return list of failure messages (empty = pass)."""
    failures: list[str] = []
    for i, case in enumerate(load_vectors()):
        kind = case.get("kind", "text")
        name = case.get("name", f"case-{i}")
        if kind == "text":
            raw = case["input"]
            out = redact_text(raw)
            for secret in case.get("must_absent", []):
                if secret and secret in out:
                    failures.append(f"{name}: secret still present: {secret!r}")
            for keep in case.get("must_keep", []):
                if keep and keep not in out:
                    failures.append(f"{name}: false positive removed: {keep!r}")
        elif kind == "obj":
            out = redact_obj(case["input"])
            blob = json.dumps(out, ensure_ascii=False)
            for secret in case.get("must_absent", []):
                if secret and secret in blob:
                    failures.append(f"{name}: obj secret still present: {secret!r}")
    return failures


if __name__ == "__main__":
    fails = run_vector_checks()
    if fails:
        print("REDACT_VECTOR_FAIL", len(fails))
        for f in fails:
            print(f)
        raise SystemExit(1)
    print("REDACT_VECTOR_OK", len(load_vectors()))
