"""Shared secret redaction — shlex tokenize then tool-aware parse (en_4088c393).

Masks omit sha256 prefixes and lengths. Shared vectors live in
tools/redact_vectors.json — Python and Swift must both pass them.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

# Free-text fallbacks (after tool-aware pass)
RE_BEARER = re.compile(r"(?i)(Bearer\s+)(\S+)")
RE_BASIC = re.compile(r"(?i)(Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+)")
RE_COOKIE = re.compile(r"(?i)((?:Cookie|Set-Cookie)\s*[:=]\s*)([^\r\n]*?)(?=(?:\s+https?://)|\s*$|\r|\n)")
RE_X_API_KEY = re.compile(r"(?i)((?:X-Api-Key|x-api-key)\s*[:=]\s*)(\S+)")
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
RE_AWS_AKIA = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
RE_AWS_SECRET_QUOTED = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)(['\"])([A-Za-z0-9/+=]{20,})\2"
)
RE_AWS_SECRET = re.compile(
    r"(?i)((?:aws_)?secret(?:_?access)?_?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})"
)
RE_URL_USERINFO = re.compile(
    r"((?:https?|postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://)([^/\s]+)@"
)
RE_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
RE_GENERIC_TOKEN = re.compile(
    r"(?i)(sk-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"
)
RE_PASSWORD_FLAG = re.compile(r"(?i)(--password)(\s+|=)(\S+)")
# Conservative glued userpass when shlex fails
RE_USERPASS_FALLBACK = re.compile(
    r"(?i)(-u|--user|--username)(=|\s+)?(\S+:\S+)"
)

SENSITIVE_KEYS = re.compile(
    r"(?i)^(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client_secret|authorization|credential|cookie|x-api-key|db_password|"
    r"mcp-session-id|session-id|session_id|jsessionid|.*_pass|.*_secret)$"
)

HEADER_PREFIXES = (
    "authorization:",
    "proxy-authorization:",
    "cookie:",
    "set-cookie:",
    "mcp-session-id:",
    "x-session-id:",
    "session-id:",
    "x-csrf-token:",
    "csrf-token:",
    "x-xsrf-token:",
)

# Free-text session / CSRF header redaction (WorkBuddy P2 / en_d595e9da).
RE_SESSION_HEADER = re.compile(
    r"(?i)((?:Mcp-Session-Id|X-Session-Id|Session-Id|X-CSRF-Token|CSRF-Token|X-XSRF-Token)\s*[:=]\s*)(\S+)"
)

RE_COOKIE_PAIR = re.compile(
    r"(?i)\b((?:sessionid|jsessionid|phpsessid|mcp-session-id|session_id)=)([^;\s&]+)"
)
RE_JSON_SESSION = re.compile(
    r'(?i)("(?:Mcp-Session-Id|X-Session-Id|Session-Id|session[_-]?id)"\s*:\s*")([^"\\]*(?:\\.[^"\\]*)*)(")'
)
RE_URL_SESSION_QUERY = re.compile(
    r"(?i)([?&](?:session[_-]?id|jsessionid|phpsessid|sid)=)([^&\s\"']+)"
)


def _mask(kind: str, _raw: str = "") -> str:
    return f"[{kind}:REDACTED]"


def _redact_url(token: str) -> str:
    try:
        parts = urlsplit(token)
    except ValueError:
        return token
    if not parts.scheme or not parts.netloc or "@" not in parts.netloc:
        return token
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, _mask("url_userinfo") + "@" + host, parts.path, parts.query, parts.fragment))


def _is_sensitive_header(value: str) -> bool:
    low = value.lower().lstrip()
    if any(low.startswith(p) for p in HEADER_PREFIXES):
        return True
    if re.match(r"(?i)x-[\w-]*(key|token|session|csrf|xsrf)\s*:", low):
        return True
    if re.match(r"(?i)(?:mcp-)?session-id\s*:", low):
        return True
    return False


def _redact_header_value(value: str) -> str:
    # Keep header name (+ auth scheme when present); wipe the secret. No minimum length.
    if ":" in value:
        name, rest = value.split(":", 1)
        rest_s = rest.strip()
        auth = re.match(r"(?i)(Bearer|Basic)\s+(\S+)\s*$", rest_s)
        if auth:
            kind = "bearer" if auth.group(1).lower() == "bearer" else "basic"
            return f"{name}: {auth.group(1)} {_mask(kind)}"
        low = name.lower().strip()
        if any(k in low for k in ("session", "csrf", "xsrf", "cookie")):
            return name + ": " + _mask("session" if "cookie" not in low else "cookie")
        return name + ": " + _mask("header")
    return _mask("header")


def _tool_name(argv: list[str]) -> str:
    if not argv:
        return ""
    base = Path(argv[0]).name.lower()
    return base


def redact_argv_tokens(argv: list[str]) -> list[str]:
    """Tool-aware argv redaction after shlex.split."""
    if not argv:
        return argv
    out = list(argv)
    tool = _tool_name(out)
    i = 0
    while i < len(out):
        tok = out[i]
        # URL userinfo anywhere
        if "://" in tok and "@" in tok:
            out[i] = _redact_url(tok)
        if tool == "curl":
            if tok in ("-u", "--user", "--username") and i + 1 < len(out):
                out[i + 1] = _mask("userpass")
                i += 2
                continue
            if tok.startswith("-u") and tok != "-u" and ":" in tok[2:]:
                out[i] = "-u" + _mask("userpass")
                i += 1
                continue
            if tok.startswith("--user=") or tok.startswith("--username="):
                key, _, _ = tok.partition("=")
                out[i] = key + "=" + _mask("userpass")
                i += 1
                continue
            if tok in ("-b", "--cookie", "--cookie-jar") and i + 1 < len(out):
                out[i + 1] = _mask("cookie")
                i += 2
                continue
            if tok.startswith("-b") and tok != "-b" and not tok.startswith("--"):
                out[i] = "-b" + _mask("cookie")
                i += 1
                continue
            if tok.startswith("--cookie=") or tok.startswith("--cookie-jar="):
                key, _, _ = tok.partition("=")
                out[i] = key + "=" + _mask("cookie")
                i += 1
                continue
            if tok in ("-H", "--header") and i + 1 < len(out):
                if _is_sensitive_header(out[i + 1]):
                    out[i + 1] = _redact_header_value(out[i + 1])
                i += 2
                continue
            if tok.startswith("--header=") or tok.startswith("-H="):
                key, _, val = tok.partition("=")
                if _is_sensitive_header(val):
                    out[i] = key + "=" + _redact_header_value(val)
                i += 1
                continue
        if tool == "sshpass":
            if tok == "-p" and i + 1 < len(out):
                out[i + 1] = _mask("password")
                i += 2
                continue
            if tok.startswith("-p") and tok != "-p":
                out[i] = "-p" + _mask("password")
                i += 1
                continue
        if tool in ("mysql", "mysqldump", "mariadb"):
            # Only glued -pSECRET and --password=X (space form is DB name / prompt).
            if tok.startswith("-p") and tok != "-p" and not tok.startswith("--"):
                out[i] = "-p" + _mask("password")
                i += 1
                continue
            if tok.startswith("--password="):
                out[i] = "--password=" + _mask("password")
                i += 1
                continue
        i += 1
    return out


def redact_command_line(text: str) -> str:
    """shlex-first command redaction; on failure use conservative regex wipe."""
    try:
        argv = shlex.split(text, posix=True)
    except ValueError:
        # Unbalanced quotes — wipe anything that looks like a secret.
        out = text
        out = RE_USERPASS_FALLBACK.sub(lambda m: (m.group(1) + (m.group(2) or "") + _mask("userpass")), out)
        out = RE_BEARER.sub(lambda m: m.group(1) + _mask("bearer"), out)
        out = RE_PASSWORD_FLAG.sub(lambda m: m.group(1) + m.group(2) + _mask("password"), out)
        return out
    if not argv:
        return text
    red = redact_argv_tokens(argv)
    # Prefer joining with spaces (lossy vs original quoting, but secrets gone).
    return " ".join(shlex.quote(t) if any(c in t for c in " \t\n\"'") else t for t in red)


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    # If it looks like a shell command line, prefer tool-aware pass first.
    stripped = text.lstrip()
    if stripped.startswith(("curl ", "sshpass ", "mysql ", "mysqldump ", "mariadb ")) or re.match(
        r"^(?:/usr/bin/|/bin/)?(?:curl|sshpass|mysql)\b", stripped
    ):
        out = redact_command_line(text)

    def sub_url_userinfo(m: re.Match[str]) -> str:
        creds = m.group(2)
        if ":" not in creds:
            return m.group(0)
        return m.group(1) + _mask("url_userinfo") + "@"

    out = RE_PEM.sub(_mask("pem"), out)
    out = RE_URL_USERINFO.sub(sub_url_userinfo, out)
    # Generic glued -uUSER:PASS (covers cases outside full command parse)
    out = re.sub(
        r"(?i)(-u)([^\s:=/-][^:\s]*:[^\s]+)",
        lambda m: m.group(1) + _mask("userpass"),
        out,
    )
    out = re.sub(
        r"(?i)(-uX?|--user|--username)(=)(\S+:\S+)",
        lambda m: m.group(1) + m.group(2) + _mask("userpass"),
        out,
    )
    out = re.sub(
        r"(?i)(-uX?|--user|--username)(\s+)(['\"])([^'\"]+:[^'\"]+)\3",
        lambda m: m.group(1) + m.group(2) + m.group(3) + _mask("userpass") + m.group(3),
        out,
    )
    out = re.sub(
        r"(?i)(-uX?|--user|--username)(\s+)(\S+:\S+)",
        lambda m: m.group(1) + m.group(2) + _mask("userpass"),
        out,
    )
    out = RE_JSON_SECRET.sub(lambda m: m.group(1) + _mask("password") + m.group(3), out)
    out = RE_PASSWORD_QUOTED.sub(
        lambda m: m.group(1) + m.group(2) + _mask("password") + m.group(2), out
    )
    out = RE_API_TOKEN_EQ.sub(lambda m: m.group(1) + _mask("token"), out)
    out = RE_PASSWORD.sub(lambda m: m.group(1) + _mask("password"), out)
    out = RE_PASSWORD_FLAG.sub(lambda m: m.group(1) + m.group(2) + _mask("password"), out)

    def _sshpass_space(m: re.Match[str]) -> str:
        if m.group(3) is not None:
            return m.group(1) + m.group(2) + "'" + _mask("password") + "'"
        if m.group(4) is not None:
            return m.group(1) + m.group(2) + '"' + _mask("password") + '"'
        return m.group(1) + m.group(2) + _mask("password")

    out = re.sub(
        r"(?i)(\b(?:mysql|mysqldump|sshpass|mariadb)\b(?:\s+\S+){0,6}\s+-p)(\s+)(?:'([^']*)'|\"([^\"]*)\"|(\S+))",
        _sshpass_space,
        out,
    )
    out = re.sub(
        r"(?i)(\b(?:mysql|mysqldump|sshpass|mariadb)\b(?:\s+\S+){0,6}\s+-p)([^\s\-]+)",
        lambda m: m.group(1) + _mask("password"),
        out,
    )
    out = RE_COOKIE.sub(lambda m: m.group(1) + _mask("cookie"), out)
    out = RE_COOKIE_PAIR.sub(lambda m: m.group(1) + _mask("session"), out)
    out = RE_JSON_SESSION.sub(lambda m: m.group(1) + _mask("session") + m.group(3), out)
    out = RE_URL_SESSION_QUERY.sub(lambda m: m.group(1) + _mask("session"), out)
    out = RE_SESSION_HEADER.sub(lambda m: m.group(1) + _mask("session"), out)
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


def run_vector_checks() -> tuple[int, int, list[str]]:
    """Return (leaks, over_redactions, failure messages)."""
    leaks = 0
    overs = 0
    failures: list[str] = []
    for i, case in enumerate(load_vectors()):
        kind = case.get("kind", "text")
        name = case.get("name", f"case-{i}")
        if kind == "text":
            raw = case["input"]
            out = redact_text(raw)
            for secret in case.get("must_absent", []):
                if secret and secret in out:
                    leaks += 1
                    failures.append(f"{name}: secret still present: {secret!r}")
            for keep in case.get("must_keep", []):
                if keep and keep not in out:
                    overs += 1
                    failures.append(f"{name}: false positive removed: {keep!r}")
        elif kind == "obj":
            out = redact_obj(case["input"])
            blob = json.dumps(out, ensure_ascii=False)
            for secret in case.get("must_absent", []):
                if secret and secret in blob:
                    leaks += 1
                    failures.append(f"{name}: obj secret still present: {secret!r}")
    return leaks, overs, failures


if __name__ == "__main__":
    leaks, overs, fails = run_vector_checks()
    total = len(load_vectors())
    print(f"REDACT leaks={leaks} over={overs} total={total}")
    if fails:
        for f in fails:
            print(f)
        raise SystemExit(1)
    print("REDACT_VECTOR_OK", total)
