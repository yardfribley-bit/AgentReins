"""Default-deny hard gate for supervised agent trees.

What this module actually stops
- Non-loopback egress that reaches the audit proxy (mitmproxy addon calls
  ``enforce_proxy_flow`` and kills the flow or installs a 403 before upstream).
- Non-loopback egress and credential-path reads that reach the PATH wrappers
  in ``tools/transport-audit`` (the wrapper returns before ``exec``).

What this module does not stop
- Network Extension is not installed.
- In-process Read/Edit tools that never spawn a wrapped command.
- Absolute paths that skip the PATH entry (``/usr/bin/curl``).
- QUIC, and git remotes that are not visible in argv.
- A review click. ``enforced`` is true only after kill/Response.make or a
  wrapper refusal. The UI must not say 已阻断 for a review row alone.

Allowlist entries count only when ``actor`` is ``user`` and ``reason`` is
non-empty. Loopback (localhost, ::1, 127.0.0.0/8) is allowed and is not an
inbox item. Heartbeat paths and repeats are denied the same way, but they
never enter 待我处理.

The audit file is append-only (``O_APPEND``), tier ``keep`` (value-tier: do
not trim). There is no delete API. ``actor=agent`` cannot write. An enforcer
cannot create an allowlist entry; only a user decision can.
Same-user processes can still forge files on disk. This is not a kernel boundary.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

TIER_KEEP = "keep"
ZERO_PREV = "0" * 64
DEFAULT_REASON = "安装时写入的默认允许：包注册表或模型服务"
# Exact hosts. A fresh install and an empty rules file both get this list.
# Unlisted egress stays denied. Credential paths are not in this list.
DEFAULT_EGRESS_HOSTS = (
    "github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "registry.npmjs.org", "registry.yarnpkg.org", "registry.yarnpkg.com",
    "pypi.org", "files.pythonhosted.org",
    "crates.io", "static.crates.io", "proxy.golang.org", "sum.golang.org",
    "cdn.jsdelivr.net", "unpkg.com", "formulae.brew.sh", "ghcr.io",
    "docker.io", "registry-1.docker.io",
    "api.openai.com", "api.anthropic.com", "api2.cursor.sh",
    "cursor.com", "www.cursor.com", "chatgpt.com", "claude.ai", "openrouter.ai",
    "copilot.tencent.com",
)
HEARTBEAT_PATHS = frozenset({
    "/health", "/healthz", "/ready", "/readyz", "/heartbeat",
    "/ping", "/live", "/livez", "/status",
})
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$"
)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_KEYCHAIN_CMD_RE = re.compile(
    r"(?i)(?:dump-keychain|find-generic-password|find-internet-password|find-certificate)"
)


def gate_root(root=None):
    if root:
        return Path(root)
    raw = os.environ.get("AGENTREINS_HARDGATE_ROOT")
    if raw:
        return Path(raw).expanduser()
    return Path.home() / "Library" / "Application Support" / "AgentReins" / "hardgate"


def audit_path(root=None):
    return gate_root(root) / "audit.jsonl"


def allowlist_path(root=None):
    return gate_root(root) / "allowlist.json"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _prepare_dir(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _lock(root):
    root = _prepare_dir(root)
    fd = os.open(str(root / "audit.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _unlock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _read(path):
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return b""


def _last_chunk(data):
    if not data:
        return b""
    if data.endswith(b"\n"):
        body = data[:-1]
        start = body.rfind(b"\n") + 1
        return data[start:]
    start = data.rfind(b"\n") + 1
    return data[start:]


def previous_hash(data):
    chunk = _last_chunk(data)
    if not chunk:
        return ZERO_PREV
    if not chunk.endswith(b"\n"):
        chunk += b"\n"
    return _sha256(chunk)


def verify_chain(data):
    if not data:
        return True
    prev = ZERO_PREV
    start = 0
    saw = False
    while start < len(data):
        end = data.find(b"\n", start)
        if end < 0:
            return False
        chunk = data[start:end + 1]
        if chunk.strip() == b"":
            return False
        try:
            obj = json.loads(chunk.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        if obj.get("prev") != prev or obj.get("tier") != TIER_KEEP:
            return False
        prev = _sha256(chunk)
        start = end + 1
        saw = True
    return saw or data == b""


def load_allowlist(root=None):
    path = allowlist_path(root)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    if len(raw) > 1_048_576:
        return []
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return []
    entries = value.get("entries") if isinstance(value, dict) else None
    if not isinstance(entries, list):
        return []
    kept = []
    for entry in entries:
        if _usable_allow(entry):
            kept.append(entry)
    return kept


def _usable_allow(entry):
    if not isinstance(entry, dict):
        return False
    if entry.get("actor") not in ("user", "default"):
        return False
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return False
    subject = entry.get("subject")
    kind = entry.get("kind")
    return _valid_subject(subject, kind)


def _valid_subject(subject, kind):
    if not isinstance(subject, str) or not isinstance(kind, str):
        return False
    if "\n" in subject or "\r" in subject or not 6 <= len(subject) <= 300:
        return False
    if kind == "egress" and subject.startswith("host:") and subject[5:].strip():
        return " " not in subject and "/" not in subject
    if kind == "credential-read" and subject.startswith("path:") and len(subject) > 5:
        return True
    return False


def is_allowed(subject, allowlist):
    for entry in allowlist or []:
        if _usable_allow(entry) and entry.get("subject") == subject:
            return True
    return False


def load_rows(root=None):
    data = _read(audit_path(root))
    rows = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line.decode("utf-8")))
        except (UnicodeDecodeError, ValueError):
            continue
    return rows


def seen_subjects(root=None, rows=None):
    found = set()
    for row in rows if rows is not None else load_rows(root):
        subject = row.get("subject")
        if isinstance(subject, str) and subject:
            found.add(subject)
    return found


def is_loopback(host):
    if not host:
        return False
    text = str(host).strip().lower().strip("[]").rstrip(".")
    if text in ("localhost", "localhost.localdomain", "ip6-localhost", "::1", "0:0:0:0:0:0:0:1"):
        return True
    if not _IPV4_RE.match(text):
        return False
    parts = [int(p) for p in text.split(".")]
    if any(p > 255 for p in parts):
        return False
    return parts[0] == 127


def is_telemetry_host(host):
    """Product telemetry. Still denied. Not an inbox item."""
    name = str(host or "").strip().lower().rstrip(".")
    if name.startswith("host:"):
        name = name[5:]
    return "telemetry" in name


def is_config_key(token):
    """git/npm config keys such as user.name. Not a destination."""
    text = str(token or "")
    if not text or "://" in text or "@" in text or "/" in text or text.startswith("-"):
        return False
    return re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+", text) is not None


def config_keys(tool, args):
    names = [str(item) for item in (args or [])]
    if str(tool or "") not in ("git", "npm", "yarn", "pnpm", "pip"):
        return set()
    if "config" not in names:
        return set()
    return {item for item in names if is_config_key(item)}


def is_heartbeat_path(path):
    if not path:
        return False
    text = str(path).split("?", 1)[0].split("#", 1)[0]
    if len(text) > 1 and text.endswith("/"):
        text = text[:-1]
    return text.lower() in HEARTBEAT_PATHS


def host_from_destination(dest):
    if dest is None:
        return None
    text = str(dest).strip()
    if not text or any(ch.isspace() for ch in text):
        return None
    if "://" in text:
        rest = text.split("://", 1)[1]
        rest = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    else:
        rest = text.split("/", 1)[0]
    if "@" in rest:
        rest = rest.split("@", 1)[1]
    if rest.startswith("["):
        end = rest.find("]")
        if end < 0:
            return None
        host = rest[1:end]
    elif rest.count(":") > 1:
        host = rest
    elif ":" in rest:
        host, _, _tail = rest.partition(":")
    else:
        host = rest
    host = host.strip().lower().rstrip(".")
    if not host or "/" in host or " " in host:
        return None
    if host.startswith("."):
        return None
    return host


def _path_chunks(arg):
    text = str(arg)
    yield text
    for part in re.split(r"[\s'\"|&;<>]+", text):
        if part:
            yield part


def _credential_marker(low):
    if re.search(r"(^|[\\/])\.env($|\.)", low) or low == ".env":
        return True
    if "/.ssh" in low or low.endswith("/.ssh") or low == ".ssh" or low.startswith(".ssh/"):
        return True
    if low.endswith("/id_rsa") or low.endswith("/id_ed25519") or low.endswith("/id_ecdsa") or low in ("id_rsa", "id_ed25519", "id_ecdsa"):
        return True
    if "/.aws" in low or low.endswith("/.aws") or low == ".aws" or low.startswith(".aws/"):
        return True
    if "keychain" in low:
        return True
    if "/.config/gcloud" in low or low.startswith(".config/gcloud") or "/.config/configstore" in low:
        return True
    if "/.azure" in low or low.startswith(".azure/") or low == ".azure":
        return True
    if "/.config/gh" in low or low.startswith(".config/gh"):
        return True
    if "/.kube/config" in low or low.endswith(".kube/config"):
        return True
    if low.endswith("/.docker/config.json") or low.endswith(".docker/config.json"):
        return True
    if low.endswith("/.netrc") or low == ".netrc" or low.endswith(".netrc"):
        return True
    if low.endswith("/.npmrc") or low == ".npmrc" or low.endswith("/.pypirc") or low == ".pypirc":
        return True
    if low.endswith("/credentials.json") or low == "credentials.json":
        return True
    if low.endswith(".pem"):
        return True
    return False


def _expand_path(chunk, cwd, home):
    text = str(chunk).strip().strip("'\"")
    if not text:
        return None
    if text.startswith("file://"):
        text = text[7:]
        if text.startswith("localhost"):
            text = text[len("localhost"):]
    elif "://" in text:
        return None
    if text.startswith("~/"):
        text = str(home) + text[1:]
    if not os.path.isabs(text):
        text = os.path.join(str(cwd), text)
    return os.path.normpath(text)


def credential_subjects(argv, cwd, home):
    found = []
    seen = set()
    for arg in argv or []:
        for chunk in _path_chunks(arg):
            subject = _one_credential(chunk, cwd, home)
            if subject and subject not in seen:
                seen.add(subject)
                found.append(subject)
    return found


def _one_credential(chunk, cwd, home):
    text = str(chunk).strip().strip("'\"")
    # A shell snippet is split into chunks first. The whole line is not itself a path.
    if not text or any(ch.isspace() for ch in text):
        return None
    if text.startswith("-") and "=" in text:
        text = text.split("=", 1)[1].strip().strip("'\"")
    if not text:
        return None
    low = text.lower()
    command = _KEYCHAIN_CMD_RE.search(text) or _KEYCHAIN_CMD_RE.search(str(chunk))
    if command and not any(tok in low for tok in (".ssh", ".aws", ".env", ".pem", "keychains", ".keychain")):
        return "path:keychain"
    if "://" in low and not low.startswith("file:"):
        return None
    if not _credential_marker(low):
        return None
    expanded = _expand_path(text, cwd, home)
    if not expanded:
        if "keychain" in low:
            return "path:keychain"
        return None
    norm = expanded.lower()
    if "keychain" in norm or "keychain" in low:
        if any(tok in norm for tok in ("keychains", ".keychain")):
            return "path:" + norm
        if not _credential_marker(norm):
            return "path:keychain"
    if not _credential_marker(norm):
        return None
    return "path:" + norm


def _hosts_in_token(token):
    text = str(token).strip()
    if not text or text.startswith("-"):
        return []
    hosts = []
    if text.lower().startswith("file:"):
        return []
    for match in _URL_RE.findall(text):
        host = host_from_destination(match)
        if host:
            hosts.append(host)
    if hosts:
        return hosts
    if text.startswith(".") or text.startswith("/") or text.startswith("~"):
        return []
    if "/" in text and "://" not in text and "@" not in text:
        return []
    host = host_from_destination(text)
    if not host:
        return []
    if _IPV4_RE.match(host) or _HOST_RE.match(host) or is_loopback(host) or host == "::1":
        return [host]
    return []


def gh_host(args, env):
    env = env or {}
    host = None
    repo = None
    for index, arg in enumerate(args or []):
        if arg == "--hostname" and index + 1 < len(args):
            host = args[index + 1]
        elif str(arg).startswith("--hostname="):
            host = str(arg).split("=", 1)[1]
        elif arg in ("--repo", "-R") and index + 1 < len(args):
            repo = args[index + 1]
        elif str(arg).startswith("--repo="):
            repo = str(arg).split("=", 1)[1]
    if host and "/" not in str(host):
        return host_from_destination(host)
    if repo and not host:
        base = env.get("GH_HOST") or "github.com"
        name = base if str(base).startswith("api.") else base
        return host_from_destination(name)
    if args and "api" in list(args):
        base = env.get("GH_HOST") or "github.com"
        name = base if str(base).startswith("api.") else "api." + str(base)
        return host_from_destination(name)
    return None


def iter_egress_targets(tool, args, extra_destination=None, env=None):
    """Yield (host, path) pairs visible in this command. Path may be empty."""
    seen = set()

    def add(dest, path=""):
        host = host_from_destination(dest) if dest and "://" not in str(dest) else host_from_destination(dest)
        if not host or host in seen:
            return
        # A URL in dest carries the path; bare hosts do not.
        url_path = path
        text = str(dest or "")
        if "://" in text:
            after = text.split("://", 1)[1]
            slash = after.find("/")
            url_path = after[slash:] if slash >= 0 else "/"
            url_path = url_path.split("?", 1)[0].split("#", 1)[0] or "/"
        seen.add(host)
        yield_list.append((host, url_path or ""))

    yield_list = []
    if extra_destination:
        add(extra_destination)
    config_only_urls = str(tool or "") in ("git", "npm", "yarn", "pnpm", "pip") and "config" in [str(item) for item in (args or [])]
    ignored = config_keys(tool, args)
    for arg in args or []:
        if config_only_urls and "://" not in str(arg):
            continue
        if str(arg) in ignored:
            continue
        for match in _URL_RE.findall(str(arg)):
            add(match)
        for host in _hosts_in_token(arg):
            if host not in seen:
                seen.add(host)
                yield_list.append((host, ""))
    if tool == "gh":
        host = gh_host(args, env)
        if host and host not in seen:
            seen.add(host)
            yield_list.append((host, ""))
    return yield_list


def classify_egress(host, path, allowlist, seen):
    subject = "host:" + str(host).lower()
    heartbeat = is_heartbeat_path(path)
    if is_loopback(host):
        return {
            "action": "allow", "kind": "egress", "subject": subject, "loopback": True,
            "inbox": False, "heartbeat": False, "record": False, "enforced": False,
        }
    if is_allowed(subject, allowlist):
        return {
            "action": "pass", "kind": "egress", "subject": subject, "loopback": False,
            "inbox": False, "heartbeat": heartbeat, "record": True, "enforced": False,
            "reason": "allowlist",
        }
    telemetry = is_telemetry_host(host)
    inbox = (not heartbeat) and (not telemetry) and subject not in (seen or set())
    if telemetry:
        detail = "遥测，保持拒绝，不进入待我处理"
    elif inbox:
        detail = "第一次外联到新主机"
    elif heartbeat:
        detail = "心跳，不进入待我处理"
    else:
        detail = "重复目标，保持拒绝"
    row = {
        "action": "deny", "kind": "egress", "subject": subject, "loopback": False,
        "inbox": inbox, "heartbeat": heartbeat, "record": True, "enforced": False,
        "reason": "default-deny egress",
        "detail": detail,
    }
    if telemetry:
        row["noise"] = "telemetry"
    return row


def classify_credential(subject, allowlist, seen):
    if is_allowed(subject, allowlist):
        return {
            "action": "pass", "kind": "credential-read", "subject": subject,
            "inbox": False, "heartbeat": False, "record": True, "enforced": False,
            "reason": "allowlist",
        }
    inbox = subject not in (seen or set())
    return {
        "action": "deny", "kind": "credential-read", "subject": subject,
        "inbox": inbox, "heartbeat": False, "record": True, "enforced": False,
        "reason": "default-deny credential path",
        "detail": "第一次读取凭据路径" if inbox else "重复凭据路径，保持拒绝",
    }


def classify_argv(tool, args, cwd, home, allowlist, seen, extra_destination=None, env=None):
    decisions = []
    local_seen = set(seen or ())
    for host, path in iter_egress_targets(tool, args, extra_destination=extra_destination, env=env):
        row = classify_egress(host, path, allowlist, local_seen)
        decisions.append(row)
        if row.get("record"):
            local_seen.add(row["subject"])
    for subject in credential_subjects(args, cwd, home):
        row = classify_credential(subject, allowlist, local_seen)
        decisions.append(row)
        if row.get("record"):
            local_seen.add(row["subject"])
    return decisions


def _reject_writer(record, actor):
    if actor == "agent" or (isinstance(record, dict) and record.get("actor") == "agent"):
        raise PermissionError("agent cannot write the hard-gate store")
    if actor not in ("user", "enforcer"):
        raise PermissionError("agent cannot write the hard-gate store")
    action = (record or {}).get("action")
    if action == "allow" and actor != "user":
        raise PermissionError("only a user decision can allow")
    if action not in ("allow", "deny", "pass"):
        raise ValueError("bad action")
    claimed = (record or {}).get("actor")
    if claimed not in (None, actor):
        raise PermissionError("actor mismatch")


def _append_unlocked(root, record, actor):
    _reject_writer(record, actor)
    path = audit_path(root)
    existing = _read(path)
    body = {
        "v": 1,
        "at": record.get("at") or _now(),
        "action": record["action"],
        "kind": record["kind"],
        "subject": record["subject"],
        "reason": str(record.get("reason") or "")[:500],
        "actor": actor,
        "mechanism": record.get("mechanism"),
        "enforced": bool(record.get("enforced")),
        "inbox": bool(record.get("inbox")),
        "heartbeat": bool(record.get("heartbeat")),
        "tier": TIER_KEEP,
        "prev": previous_hash(existing),
    }
    if record.get("detail"):
        body["detail"] = str(record["detail"])[:200]
    if record.get("noise"):
        body["noise"] = str(record["noise"])[:40]
    if record.get("agent"):
        body["agent"] = str(record["agent"])[:80]
    if record.get("session"):
        body["session"] = str(record["session"])[:120]
    line = (json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(path), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return body


def append_record(root, record, actor):
    """Append one keep-tier row. Refuses actor ``agent`` and enforcer allows."""
    root = gate_root(root)
    fd = _lock(root)
    try:
        return _append_unlocked(root, record, actor)
    finally:
        _unlock(fd)


def _read_allowlist_doc(root):
    path = allowlist_path(root)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _write_allowlist(root, entries, customized=None):
    path = allowlist_path(root)
    if customized is None:
        current = _read_allowlist_doc(root) or {}
        customized = bool(current.get("customized"))
    payload = {"customized": bool(customized), "entries": list(entries), "version": 1}
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
    directory = str(gate_root(root))
    tmp = tempfile.NamedTemporaryFile(dir=directory, delete=False)
    try:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        os.fchmod(tmp.fileno(), 0o600)
        tmp.close()
        os.replace(tmp.name, path)
    finally:
        if os.path.exists(tmp.name):
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def user_allow(root, subject, kind, reason):
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("reason required")
    if not _valid_subject(subject, kind):
        raise ValueError("bad subject")
    root = gate_root(root)
    fd = _lock(root)
    try:
        row = _append_unlocked(root, {
            "action": "allow", "kind": kind, "subject": subject, "reason": reason,
            "actor": "user", "mechanism": None, "enforced": False, "inbox": False, "heartbeat": False,
        }, actor="user")
        entries = [e for e in load_allowlist(root) if e.get("subject") != subject]
        entries.append({
            "actor": "user", "decidedAt": row["at"], "kind": kind,
            "reason": reason, "subject": subject,
        })
        _write_allowlist(root, entries, customized=True)
        return row
    finally:
        _unlock(fd)


def user_deny(root, subject, kind, reason):
    reason = (reason or "保持拒绝").strip() or "保持拒绝"
    if not _valid_subject(subject, kind):
        raise ValueError("bad subject")
    root = gate_root(root)
    fd = _lock(root)
    try:
        row = _append_unlocked(root, {
            "action": "deny", "kind": kind, "subject": subject, "reason": reason,
            "actor": "user", "mechanism": None, "enforced": False, "inbox": False, "heartbeat": False,
            "detail": "用户保持拒绝",
        }, actor="user")
        entries = [e for e in load_allowlist(root) if e.get("subject") != subject]
        _write_allowlist(root, entries, customized=True)
        return row
    finally:
        _unlock(fd)


def default_allow_entries(now=None):
    stamp = now or _now()
    return [{
        "actor": "default", "decidedAt": stamp, "kind": "egress",
        "reason": DEFAULT_REASON, "subject": "host:" + host,
    } for host in DEFAULT_EGRESS_HOSTS]


def rules_document():
    return {
        "version": 1,
        "customized": False,
        "rules": [
            {
                "id": "default-deny-egress",
                "kind": "egress",
                "action": "block",
                "severity": "high",
                "message": "被监督的 Agent 访问允许名单之外的主机",
                "allowHosts": list(DEFAULT_EGRESS_HOSTS),
                "naturalLanguage": "未列出的外联默认拒绝。允许名单是包注册表和模型服务。",
            },
            {
                "id": "default-deny-credential-read",
                "kind": "credential-read",
                "action": "block",
                "severity": "high",
                "message": "被监督的 Agent 读取凭据路径",
                "naturalLanguage": "凭据路径默认拒绝，不在默认允许名单里。",
            },
        ],
    }


def seed_rules_file(path):
    """Fill an empty installed rules.json. A customized file is left alone."""
    path = Path(path)
    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            doc = None
        if isinstance(doc, dict) and doc.get("customized") is True:
            return False
        rules = doc.get("rules") if isinstance(doc, dict) else None
        if isinstance(rules, list) and rules:
            return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules_document(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def installed_rules_paths():
    """The two files a launch may find. The app reads AgentReins; older installs use AgentGuard."""
    support = Path.home() / "Library" / "Application Support"
    return [
        support / "AgentReins" / "rules.json",
        support / "AgentGuard" / "rules.json",
    ]


def live_gate_root():
    return Path.home() / "Library" / "Application Support" / "AgentReins" / "hardgate"


def seed_installed_rules(paths):
    """Fill each empty, non-customized rules file. Returns True if any file was written."""
    wrote = False
    for path in paths:
        if seed_rules_file(path):
            wrote = True
    return wrote


def ensure_seeded(root=None):
    """Write the default egress allowlist when the file is missing or still empty.

    On the real install (not a test root) also seed empty rules.json. Wrappers
    used to seed only the allowlist, so rules stayed {"rules":[],"version":1}
    until someone ran seed_rules_file by hand.
    """
    root = gate_root(root)
    try:
        if root.resolve() == live_gate_root().resolve():
            seed_installed_rules(installed_rules_paths())
    except OSError:
        pass
    fd = _lock(root)
    try:
        doc = _read_allowlist_doc(root)
        if isinstance(doc, dict) and doc.get("customized") is True:
            return False
        entries = doc.get("entries") if isinstance(doc, dict) else None
        if isinstance(entries, list) and entries:
            return False
        _write_allowlist(root, default_allow_entries(), customized=False)
        return True
    finally:
        _unlock(fd)


def commit_wrapper(tool, args, cwd, home, root=None, extra_destination=None, env=None, agent=None, session=None):
    """Classify and, on deny, record enforced=True. Caller must not exec when this returns 126."""
    root = gate_root(root)
    ensure_seeded(root)
    fd = _lock(root)
    try:
        allow = load_allowlist(root)
        seen = seen_subjects(root)
        decisions = classify_argv(
            tool, args, cwd, home, allow, seen,
            extra_destination=extra_destination, env=env,
        )
        denies = [d for d in decisions if d.get("action") == "deny"]
        for decision in decisions:
            if not decision.get("record"):
                continue
            decision["actor"] = "enforcer"
            decision["mechanism"] = "transport-wrapper"
            decision["enforced"] = decision.get("action") == "deny"
            if agent:
                decision["agent"] = agent
            if session:
                decision["session"] = session
            try:
                _append_unlocked(root, decision, actor="enforcer")
            except OSError:
                if decision.get("action") == "deny":
                    decision["enforced"] = True
        if denies:
            return 126, decisions
        return None, decisions
    finally:
        _unlock(fd)


def enforce_proxy_flow(flow, root=None):
    """Deny non-allowlisted non-loopback before upstream. Returns True when the flow must not proceed."""
    root = gate_root(root)
    ensure_seeded(root)
    request = getattr(flow, "request", None)
    host = host_from_destination(getattr(request, "pretty_host", None) or getattr(request, "host", None))
    raw_path = getattr(request, "path", "") or "/"
    path = str(raw_path).split("?", 1)[0]
    if not host:
        fired = try_block_flow(flow)
        _record_proxy(root, {
            "action": "deny", "kind": "egress", "subject": "host:unknown",
            "reason": "missing host", "inbox": False, "heartbeat": False, "record": True,
            "enforced": fired, "mechanism": "audit-proxy" if fired else None, "actor": "enforcer",
        })
        return True
    fd = _lock(root)
    try:
        decision = classify_egress(host, path, load_allowlist(root), seen_subjects(root))
    finally:
        _unlock(fd)
    if decision.get("action") != "deny":
        if decision.get("record"):
            decision["enforced"] = False
            decision["mechanism"] = "audit-proxy"
            decision["actor"] = "enforcer"
            _record_proxy(root, decision)
        return False
    fired = try_block_flow(flow)
    decision["enforced"] = bool(fired)
    decision["mechanism"] = "audit-proxy" if fired else None
    decision["actor"] = "enforcer"
    _record_proxy(root, decision)
    meta = getattr(flow, "metadata", None)
    if isinstance(meta, dict):
        meta["agentreins_hard_gate"] = {
            "action": "deny",
            "enforced": bool(fired),
            "mechanism": decision["mechanism"],
            "subject": decision["subject"],
        }
    return True


def _record_proxy(root, decision):
    try:
        append_record(root, decision, actor="enforcer")
    except OSError:
        pass


def try_block_flow(flow):
    """True only when mitmproxy accepted a 403 or ``flow.kill()`` ran."""
    fired = False
    try:
        from mitmproxy import http
        flow.response = http.Response.make(
            403,
            "AgentReins denied this egress before it was forwarded.\n".encode("utf-8"),
            {"Content-Type": "text/plain; charset=utf-8", "X-AgentReins-Hard-Gate": "deny"},
        )
        fired = True
    except Exception:
        pass
    kill = getattr(flow, "kill", None)
    if callable(kill):
        try:
            kill()
            fired = True
        except Exception:
            pass
    return fired


def open_inbox(rows, allowlist=None):
    """First-seen denies only. Heartbeats, repeats, and later user decisions stay out."""
    closed = set()
    for entry in allowlist or []:
        if _usable_allow(entry):
            closed.add(entry.get("subject"))
    for row in rows or []:
        if row.get("actor") == "user" and row.get("action") in ("allow", "deny"):
            closed.add(row.get("subject"))
    picked = []
    seen = set()
    for row in rows or []:
        subject = row.get("subject")
        if row.get("tier") != TIER_KEEP:
            continue
        if row.get("inbox") is not True or row.get("heartbeat") is True:
            continue
        if row.get("action") != "deny":
            continue
        if row.get("noise") == "telemetry" or is_telemetry_host(subject):
            continue
        if subject in closed or subject in seen:
            continue
        seen.add(subject)
        picked.append(row)
    return picked
