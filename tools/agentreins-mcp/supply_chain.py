#!/usr/bin/env python3
"""Pre-install look at newly added MCP servers, skills, rules, and plugins.

The scan is a fixed list of config files plus one directory level of skill,
rule, and plugin folders. It does not walk session logs, node_modules, or
project trees. Env values are dropped before anything is stored. Decisions
are local. This module never writes Claude, Cursor, Codex, or WorkBuddy
config files.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

SCHEMA = "agentreins.supply-chain.v1"
HEAD_BYTES = 256 * 1024
TAIL_BYTES = 64 * 1024
SKILL_BYTES = 16 * 1024
DIR_LIST_CAP = 40
PROJECT_CAP = 6
SKIP_NAMES = {
    "node_modules", ".git", "cache", "__pycache__", "dist", ".venv", "venv",
    "skills-cursor", "sessions", "projects", "logs",
}
CRED_PARTS = (
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY",
    "PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY", "SESSION",
)
SECRET_VALUE = re.compile(
    r"(?i)(ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_\-]{12,}"
    r"|AKIA[0-9A-Z]{12,}|xox[baprs]-[A-Za-z0-9\-]{8,}|bearer\s+[A-Za-z0-9._\-]{8,}"
    r"|(token|password|secret|api[_-]?key)\s*=\s*\S+)"
)
CURL_PIPE = re.compile(
    r"(?i)(\b(curl|wget)\b[^\n|]{0,300}\|\s*(sudo\s+)?(sh|bash|zsh)\b)"
    r"|(\b(sh|bash|zsh)\b[^\n]{0,40}<\(\s*(curl|wget)\b)"
)
URL_RE = re.compile(r"https?://[^\s\"'`<>]+", re.I)
CRED_WORD = re.compile(
    r"\b([A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY))\b"
)
AUTH_HEADERS = {
    "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token",
}
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def store_path(explicit: str | os.PathLike[str] | None = None) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit)
    env = os.environ.get("AGENTREINS_SUPPLY_STORE")
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / "Library" / "Application Support" / "AgentReins" / "supply-chain.json"


def empty_doc() -> dict[str, Any]:
    return {
        "version": 1,
        "baselined": False,
        "scannedAt": "",
        "entries": [],
        "pending": [],
        "decisions": [],
        "alerts": [],
    }


def load(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    file = store_path(path)
    try:
        raw = file.read_text(encoding="utf-8")
    except OSError:
        return empty_doc()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return empty_doc()
    if not isinstance(doc, dict):
        return empty_doc()
    base = empty_doc()
    base.update({k: doc.get(k, base[k]) for k in base})
    return base


def _write(path: pathlib.Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(payload + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_text(value: str) -> str:
    return SECRET_VALUE.sub("[redacted]", value)


def is_credential_name(name: str) -> bool:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", name.upper()) if p]
    blob = "_".join(parts)
    if any(part in blob for part in CRED_PARTS):
        return True
    return blob.endswith("_KEY") or blob.endswith("_AUTH")


def read_capped(path: pathlib.Path, limit: int = HEAD_BYTES) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def read_head_tail(path: pathlib.Path) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    try:
        with path.open("rb") as handle:
            head = handle.read(HEAD_BYTES)
            tail = b""
            if size > HEAD_BYTES + 1024:
                handle.seek(max(0, size - TAIL_BYTES))
                tail = handle.read(TAIL_BYTES)
    except OSError:
        return ""
    return head.decode("utf-8", "replace") + ("\n" + tail.decode("utf-8", "replace") if tail else "")


def list_children(path: pathlib.Path, limit: int = DIR_LIST_CAP) -> list[str]:
    names: list[str] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(names) >= limit:
                    break
                name = entry.name
                if name in SKIP_NAMES or name.startswith("."):
                    continue
                names.append(name)
    except OSError:
        return []
    return names


def _json_value(text: str, index: int) -> tuple[Any, int]:
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        return None, index
    if text[index] != "{":
        return None, index
    start = index
    depth = 0
    in_str = False
    esc = False
    for pos in range(index, len(text)):
        ch = text[pos]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = text[start:pos + 1]
                try:
                    return json.loads(blob), pos + 1
                except json.JSONDecodeError:
                    return None, pos + 1
    return None, len(text)


def mcp_maps_from_text(text: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        found.extend(_walk_mcp(parsed, 0))
        if found:
            return found
    key = '"mcpServers"'
    start = 0
    while True:
        at = text.find(key, start)
        if at < 0:
            break
        brace = text.find("{", at + len(key))
        if brace < 0:
            break
        obj, nxt = _json_value(text, brace)
        start = nxt if nxt > brace else at + len(key)
        if isinstance(obj, dict):
            found.append(obj)
    return found


def _walk_mcp(obj: Any, depth: int) -> list[dict[str, Any]]:
    if depth > 8 or not isinstance(obj, dict):
        return []
    found: list[dict[str, Any]] = []
    servers = obj.get("mcpServers")
    if isinstance(servers, dict):
        found.append(servers)
    for key, value in obj.items():
        if key == "mcpServers" or not isinstance(value, dict):
            continue
        found.extend(_walk_mcp(value, depth + 1))
    return found


def _toml_string(text: str, index: int) -> tuple[str, int]:
    quote = text[index]
    index += 1
    chars: list[str] = []
    while index < len(text):
        ch = text[index]
        if ch == "\\" and index + 1 < len(text):
            chars.append(text[index + 1])
            index += 2
            continue
        if ch == quote:
            return "".join(chars), index + 1
        chars.append(ch)
        index += 1
    return "".join(chars), index


def _toml_value(text: str) -> Any:
    text = text.strip().rstrip(",")
    if not text:
        return ""
    if text[0] in {'"', "'"}:
        value, _ = _toml_string(text, 0)
        return value
    if text.startswith("["):
        return _toml_array(text)
    if text.startswith("{"):
        keys = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=", text)
        return {key: "" for key in keys}
    if text in {"true", "false"}:
        return text == "true"
    return text.strip('"')


def _toml_array(text: str) -> list[str]:
    out: list[str] = []
    index = 1
    while index < len(text):
        ch = text[index]
        if ch in {'"', "'"}:
            value, index = _toml_string(text, index)
            out.append(value)
            continue
        index += 1
    return out


def parse_codex_mcp(text: str) -> list[dict[str, Any]]:
    servers: dict[str, dict[str, Any]] = {}
    current: tuple[str, str | None] | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            parts = [p.strip() for p in line[1:-1].split(".")]
            if len(parts) >= 2 and parts[0] == "mcp_servers" and parts[1]:
                name = parts[1]
                servers.setdefault(name, {})
                section = parts[2] if len(parts) >= 3 else None
                if section in {"env"}:
                    current = (name, "env")
                elif section in {"headers", "http_headers"}:
                    current = (name, "headers")
                else:
                    current = (name, None)
            else:
                current = None
            continue
        if current is None or "=" not in line:
            continue
        name, section = current
        key, raw_value = line.split("=", 1)
        key = key.strip()
        value = _toml_value(raw_value.strip())
        spec = servers[name]
        if section == "env":
            spec.setdefault("env", {})[key] = ""
        elif section == "headers":
            spec.setdefault("headers", {})[key] = ""
        elif key == "env" and isinstance(value, dict):
            spec["env"] = {k: "" for k in value}
        elif key in {"headers", "http_headers"} and isinstance(value, dict):
            spec["headers"] = {k: "" for k in value}
        elif key == "args" and isinstance(value, list):
            spec["args"] = value
        elif key in {"command", "url", "bearer_token_env_var"} and isinstance(value, str):
            spec[key] = value
        elif key == "enabled" and isinstance(value, bool):
            spec["enabled"] = value
        elif key == "disabled" and isinstance(value, bool):
            spec["disabled"] = value
    return [{"name": name, **spec} for name, spec in servers.items()]


def host_of(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    return host


def safe_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return redact_text(url.split("?", 1)[0])[:300]
    if not parts.scheme or not parts.hostname:
        return redact_text(url.split("?", 1)[0])[:300]
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    return f"{parts.scheme}://{parts.hostname}{port}{path}"[:300]


def is_loopback(host: str) -> bool:
    host = host.lower().strip("[]")
    return host in LOOPBACK or host.startswith("127.")


def hosts_in_text(text: str) -> list[str]:
    found: list[str] = []
    for match in URL_RE.findall(text):
        host = host_of(match)
        if host and host not in found:
            found.append(host)
    return found[:8]


def _npm_spec(args: list[str]) -> str:
    skip = {"exec", "dlx", "x", "install", "i", "add", "run"}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"--package", "-p"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("-") and not arg.startswith("@-"):
            index += 1
            continue
        if arg in skip:
            index += 1
            continue
        return arg
    return ""


def _split_npm(spec: str) -> tuple[str, str | None]:
    if spec.startswith("@"):
        if spec.count("@") >= 2:
            name, ver = spec.rsplit("@", 1)
            return name, ver
        return spec, None
    if "@" in spec:
        name, ver = spec.rsplit("@", 1)
        return name, ver
    return spec, None


def _pinned(version: str | None) -> bool:
    if not version:
        return False
    token = version.strip().lower()
    if token in {"", "latest", "next", "*", "stable"}:
        return False
    return True


def _pypi_spec(args: list[str]) -> str:
    skip_flags = {"-m", "-c", "--from"}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"install", "-m"} or arg.startswith("-"):
            if arg in skip_flags or arg.startswith("-"):
                index += 1
                continue
        if arg in {"install", "run", "tool"}:
            index += 1
            continue
        return arg
    return ""


def classify_origin(command: str, args: list[str], url: str) -> tuple[str, str, bool]:
    """Returns originKind, Chinese origin line, and whether the version is unpinned."""
    if url:
        shown = safe_url(url)
        return "remote-url", f"远程地址 {shown}", False
    for arg in args:
        if arg.startswith(("git+", "git@")) or (arg.endswith(".git") and "://" in arg):
            return "git", f"Git 地址 {safe_url(arg) if '://' in arg else redact_text(arg)[:180]}", False
    base = pathlib.Path(command).name.lower()
    if base in {"npx", "npm", "bunx", "pnpm", "yarn"}:
        spec = _npm_spec(args)
        if spec:
            name, ver = _split_npm(spec)
            if _pinned(ver):
                return "npm", f"npm 包 {name}，版本 {ver}", False
            if ver and ver.lower() in {"latest", "next", "*"}:
                return "npm", f"npm 包 {name}，写了 {ver}", True
            return "npm", f"npm 包 {name}，没有钉版本", True
    if base in {"uvx", "uv", "pipx", "pip", "python", "python3"}:
        spec = _pypi_spec(args)
        if spec and not spec.startswith("-"):
            if "==" in spec:
                name, ver = spec.split("==", 1)
                return "pypi", f"PyPI 包 {name}，版本 {ver}", False
            name, ver = _split_npm(spec)
            if _pinned(ver):
                return "pypi", f"PyPI 包 {name}，版本 {ver}", False
            return "pypi", f"PyPI 包 {spec}，没有钉版本", True
    if command.startswith(("/", "./", "~")):
        return "local", f"本机路径 {redact_text(command)[:180]}", False
    if command:
        return "command", f"看不出发布者，启动命令是 {redact_text(command)[:80]}", False
    return "unknown", "看不出从哪来", False


def broad_args(args: list[str], home: str) -> list[str]:
    try:
        root = str(pathlib.Path(home).expanduser().resolve())
    except OSError:
        root = home
    exact = {
        "/", "/*", "~", "~/", "$HOME", "${HOME}", "/Users", "/home", "/private",
        "/Volumes", "/tmp", "/var", "/etc", root, root + "/",
    }
    hits: list[str] = []
    for arg in args:
        raw = arg.strip()
        if not raw:
            continue
        if raw in exact or raw.rstrip("/") in exact or raw.rstrip("/") == root:
            hits.append(raw)
            continue
        if raw.startswith("~"):
            expanded = str(pathlib.Path(raw).expanduser())
            if expanded.rstrip("/") == root or expanded in {"/", "/Users", "/home"}:
                hits.append(raw)
    return hits


def _env_rows(spec: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
    for key in list(env)[:40]:
        name = str(key)[:80]
        rows.append({"name": name, "credential": is_credential_name(name)})
    bearer = spec.get("bearer_token_env_var")
    if isinstance(bearer, str) and bearer.strip():
        name = bearer.strip()[:80]
        if not any(row["name"] == name for row in rows):
            rows.append({"name": name, "credential": is_credential_name(name)})
    return rows


def _header_names(spec: dict[str, Any]) -> list[str]:
    headers = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
    return [str(key)[:80] for key in list(headers)[:20]]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if not isinstance(item, (dict, list))][:32]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def fingerprint_of(body: dict[str, Any]) -> str:
    encoded = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _slug(agent: str, kind: str, name: str) -> str:
    agent_slug = {
        "Claude Code": "claude",
        "Cursor": "cursor",
        "Codex": "codex",
        "WorkBuddy": "workbuddy",
        "通用": "agents",
    }.get(agent, "local")
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")[:80] or "item"
    return f"{agent_slug}:{kind}:{cleaned}"


def build_flags(command_line: str, origin_unpinned: bool, args: list[str], home: str,
                env_rows: list[dict[str, Any]], url: str, header_names: list[str],
                bearer: str) -> list[dict[str, str]]:
    flags: list[dict[str, str]] = []
    if CURL_PIPE.search(command_line):
        flags.append({"id": "curl-pipe", "text": "启动命令里有 curl 或 wget 再管道给 shell，装进去就会执行别人的脚本"})
    if origin_unpinned or re.search(r"(?i)@latest\b", command_line):
        flags.append({"id": "unpinned", "text": "版本没有钉死，装到的是当时的最新包"})
    wide = broad_args(args, home)
    if wide:
        shown = "、".join(redact_text(item)[:80] for item in wide[:4])
        flags.append({"id": "broad-fs", "text": f"参数里有很宽的目录（{shown}），等于把一大片文件交给它"})
    secret_names = [row["name"] for row in env_rows if row.get("credential")]
    if secret_names:
        shown = "、".join(secret_names[:6])
        flags.append({"id": "credential-env", "text": f"环境变量 {shown} 的名字像凭据，值没有记下"})
    if url.lower().startswith("http://") and not is_loopback(host_of(url)):
        authed = bool(bearer) or any(name.lower() in AUTH_HEADERS for name in header_names) or bool(secret_names)
        if not authed:
            flags.append({"id": "remote-http-no-auth", "text": "远程地址是 http，而且没有看到鉴权"})
    return flags


def entry_from_spec(agent: str, name: str, spec: dict[str, Any], config_path: str, home: str,
                    used: set[str]) -> dict[str, Any] | None:
    if spec.get("disabled") is True or spec.get("enabled") is False:
        return None
    command = redact_text(str(spec.get("command") or ""))[:200]
    args = [redact_text(item)[:500] for item in _string_list(spec.get("args"))]
    url = str(spec.get("url") or spec.get("serverUrl") or "")
    safe = safe_url(url) if url else ""
    env_rows = _env_rows(spec)
    headers = _header_names(spec)
    bearer = str(spec.get("bearer_token_env_var") or "")
    origin_kind, origin, unpinned = classify_origin(command, args, safe)
    command_line = " ".join([command, *args]).strip()
    hosts = hosts_in_text(" ".join([safe, command_line]))
    flags = build_flags(command_line, unpinned, args, home, env_rows, safe or url, headers, bearer)
    kind_name = "MCP"
    env_txt = "、".join(row["name"] for row in env_rows) if env_rows else "没有"
    host_txt = "、".join(hosts) if hosts else "看不出来"
    flag_txt = "；".join(flag["text"] for flag in flags) if flags else "没有标红旗"
    run = command_line or "没有单独的启动命令"
    summary = (
        f"{agent} 新加了{kind_name}「{name}」。来源：{origin}。会运行：{run}。"
        f"环境变量：{env_txt}。会连：{host_txt}。{flag_txt}"
    )
    body = {
        "args": args,
        "command": command,
        "env": env_rows,
        "hosts": hosts,
        "kind": "mcp",
        "name": name,
        "originKind": origin_kind,
        "url": safe,
    }
    entry_id = _alloc(_slug(agent, "mcp", name), config_path, used)
    return {
        "id": entry_id,
        "agent": agent,
        "kind": "mcp",
        "name": name[:120],
        "configPath": config_path,
        "originKind": origin_kind,
        "origin": origin,
        "command": command,
        "args": args,
        "env": env_rows,
        "hosts": hosts,
        "flags": flags,
        "summary": summary[:800],
        "fingerprint": fingerprint_of(body),
    }


def _alloc(base: str, config_path: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    extra = hashlib.sha256(config_path.encode("utf-8")).hexdigest()[:6]
    minted = f"{base}-{extra}"
    used.add(minted)
    return minted


def _front_name(text: str, fallback: str) -> str:
    if text.startswith("---"):
        end = text.find("\n---", 3)
        block = text[3:end] if end > 0 else text[:400]
        match = re.search(r"(?m)^name:\s*['\"]?([^'\"\n]+)", block)
        if match:
            return match.group(1).strip()[:80] or fallback
    return fallback


def entry_from_text(agent: str, kind: str, name: str, text: str, config_path: str, home: str,
                    used: set[str]) -> dict[str, Any]:
    redacted = redact_text(text)
    display = _front_name(text, name)
    hosts = hosts_in_text(redacted)
    flags: list[dict[str, str]] = []
    if CURL_PIPE.search(redacted):
        flags.append({"id": "curl-pipe", "text": "说明里有 curl 或 wget 再管道给 shell"})
    if re.search(r"(?i)@latest\b", redacted) or re.search(r"(?i)\bnpx\s+-y\s+[^\s@]+(\s|$)", redacted):
        flags.append({"id": "unpinned", "text": "说明里用了没有钉死的包，装到的是当时的最新包"})
    creds = []
    for match in CRED_WORD.findall(text):
        if match not in creds:
            creds.append(match)
    if creds:
        flags.append({"id": "credential-env", "text": f"说明里点了凭据名字 {'、'.join(creds[:6])}，值没有记下"})
    kind_name = {"skill": "技能", "rule": "规则", "plugin": "插件"}.get(kind, kind)
    origin = f"本机路径 {config_path}"
    host_txt = "、".join(hosts) if hosts else "看不出来"
    flag_txt = "；".join(flag["text"] for flag in flags) if flags else "没有标红旗"
    summary = (
        f"{agent} 新加了{kind_name}「{display}」。来源：{origin}。会运行：没有单独的启动命令。"
        f"环境变量：没有。会连：{host_txt}。{flag_txt}"
    )
    body = {
        "args": [],
        "command": "",
        "hosts": hosts,
        "kind": kind,
        "name": display,
        "originKind": "local",
        "path": config_path,
        "flags": [flag["id"] for flag in flags],
    }
    return {
        "id": _alloc(_slug(agent, kind, display), config_path, used),
        "agent": agent,
        "kind": kind,
        "name": display[:120],
        "configPath": config_path,
        "originKind": "local",
        "origin": origin,
        "command": "",
        "args": [],
        "env": [],
        "hosts": hosts,
        "flags": flags,
        "summary": summary[:800],
        "fingerprint": fingerprint_of(body),
    }


def entries_from_mcp_file(path: pathlib.Path, agent: str, home: str, used: set[str]) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    if path.suffix == ".toml" or path.name == "config.toml":
        specs = parse_codex_mcp(read_capped(path, HEAD_BYTES))
        out = []
        for spec in specs:
            name = str(spec.get("name") or "mcp")
            built = entry_from_spec(agent, name, spec, str(path), home, used)
            if built:
                out.append(built)
        return out
    text = read_head_tail(path)
    out = []
    for servers in mcp_maps_from_text(text):
        for name, spec in list(servers.items())[:40]:
            if not isinstance(spec, dict):
                continue
            built = entry_from_spec(agent, str(name), spec, str(path), home, used)
            if built:
                out.append(built)
    return out


def entries_from_skill_dir(path: pathlib.Path, agent: str, kind: str, home: str, used: set[str]) -> list[dict[str, Any]]:
    if not path.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for name in list_children(path, DIR_LIST_CAP):
        child = path / name
        if kind == "rule":
            if child.is_file() and name.endswith((".md", ".mdc")):
                out.append(entry_from_text(agent, "rule", child.stem, read_capped(child, SKILL_BYTES), str(child), home, used))
            elif child.is_dir() and (child / "RULE.md").is_file():
                rule = child / "RULE.md"
                out.append(entry_from_text(agent, "rule", name, read_capped(rule, SKILL_BYTES), str(rule), home, used))
            continue
        skill = child / "SKILL.md" if child.is_dir() else None
        if skill and skill.is_file():
            out.append(entry_from_text(agent, "skill", name, read_capped(skill, SKILL_BYTES), str(skill), home, used))
        elif child.is_file() and name.endswith(".md"):
            out.append(entry_from_text(agent, "skill", child.stem, read_capped(child, SKILL_BYTES), str(child), home, used))
    return out


def entries_from_plugin_dir(path: pathlib.Path, agent: str, home: str, used: set[str]) -> list[dict[str, Any]]:
    if not path.is_dir():
        return []
    out: list[dict[str, Any]] = []
    for name in list_children(path, DIR_LIST_CAP):
        child = path / name
        if not child.is_dir():
            continue
        for rel in ("plugin.json", ".claude-plugin/plugin.json"):
            manifest = child / rel
            if not manifest.is_file():
                continue
            text = read_capped(manifest, 32 * 1024)
            try:
                doc = json.loads(text)
            except json.JSONDecodeError:
                doc = None
            if isinstance(doc, dict) and isinstance(doc.get("mcpServers"), dict):
                for server_name, spec in list(doc["mcpServers"].items())[:20]:
                    if isinstance(spec, dict):
                        built = entry_from_spec(agent, str(server_name), spec, str(manifest), home, used)
                        if built:
                            out.append(built)
            else:
                label = name
                if isinstance(doc, dict) and isinstance(doc.get("name"), str):
                    label = doc["name"][:80]
                out.append(entry_from_text(agent, "plugin", label, text[:2000], str(manifest), home, used))
            break
        skill = child / "SKILL.md"
        if skill.is_file():
            out.append(entry_from_text(agent, "skill", name, read_capped(skill, SKILL_BYTES), str(skill), home, used))
        nested = child / "skills"
        if nested.is_dir():
            out.extend(entries_from_skill_dir(nested, agent, "skill", home, used))
    return out


def discover_projects(home: pathlib.Path) -> list[pathlib.Path]:
    root = home / ".claude" / "projects"
    scored: list[tuple[float, str]] = []
    try:
        with os.scandir(root) as iterator:
            for entry in iterator:
                if len(scored) >= 80:
                    break
                if not entry.is_dir(follow_symlinks=False):
                    continue
                try:
                    scored.append((entry.stat(follow_symlinks=False).st_mtime, entry.name))
                except OSError:
                    continue
    except OSError:
        return []
    scored.sort(reverse=True)
    found: list[pathlib.Path] = []
    for _, name in scored:
        if not name.startswith("-"):
            continue
        decoded = "/" + name[1:].replace("-", "/")
        if decoded.count("/") < 2:
            continue
        if os.path.isdir(decoded):
            found.append(pathlib.Path(decoded))
        if len(found) >= PROJECT_CAP:
            break
    return found


def _dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for entry in entries:
        if entry["id"] in seen:
            continue
        seen.add(entry["id"])
        out.append(entry)
    return out


def scan(home: str | os.PathLike[str], projects: list[str | os.PathLike[str]] | None = None) -> list[dict[str, Any]]:
    root = pathlib.Path(home)
    home_s = str(root)
    chosen = [pathlib.Path(p) for p in projects] if projects is not None else discover_projects(root)
    chosen = chosen[:PROJECT_CAP]
    used: set[str] = set()
    entries: list[dict[str, Any]] = []
    configs = [
        (root / ".claude.json", "Claude Code"),
        (root / ".claude" / "settings.json", "Claude Code"),
        (root / ".claude" / "mcp.json", "Claude Code"),
        (root / ".cursor" / "mcp.json", "Cursor"),
        (root / ".codex" / "config.toml", "Codex"),
        (root / ".workbuddy" / "mcp.json", "WorkBuddy"),
        (root / ".codebuddy" / "mcp.json", "WorkBuddy"),
    ]
    for path, agent in configs:
        entries.extend(entries_from_mcp_file(path, agent, home_s, used))
    skill_dirs = [
        (root / ".claude" / "skills", "Claude Code", "skill"),
        (root / ".cursor" / "skills", "Cursor", "skill"),
        (root / ".codex" / "skills", "Codex", "skill"),
        (root / ".agents" / "skills", "通用", "skill"),
        (root / ".workbuddy" / "skills", "WorkBuddy", "skill"),
    ]
    for path, agent, kind in skill_dirs:
        entries.extend(entries_from_skill_dir(path, agent, kind, home_s, used))
    for path, agent in ((root / ".claude" / "plugins", "Claude Code"), (root / ".cursor" / "plugins", "Cursor")):
        entries.extend(entries_from_plugin_dir(path, agent, home_s, used))
    for project in chosen:
        entries.extend(entries_from_mcp_file(project / ".mcp.json", "Claude Code", home_s, used))
        entries.extend(entries_from_mcp_file(project / ".cursor" / "mcp.json", "Cursor", home_s, used))
        entries.extend(entries_from_mcp_file(project / ".codex" / "config.toml", "Codex", home_s, used))
        entries.extend(entries_from_skill_dir(project / ".claude" / "skills", "Claude Code", "skill", home_s, used))
        entries.extend(entries_from_skill_dir(project / ".cursor" / "skills", "Cursor", "skill", home_s, used))
        entries.extend(entries_from_skill_dir(project / ".cursor" / "rules", "Cursor", "rule", home_s, used))
        entries.extend(entries_from_skill_dir(project / ".agents" / "skills", "通用", "skill", home_s, used))
        entries.extend(entries_from_skill_dir(project / ".codex" / "skills", "Codex", "skill", home_s, used))
    return _dedupe(entries)


def _closed(entry: dict[str, Any], decisions: list[dict[str, Any]]) -> bool:
    for decision in decisions:
        if decision.get("id") == entry["id"] and decision.get("fingerprint") == entry["fingerprint"]:
            if decision.get("state") in {"approved", "rejected"}:
                return True
    return False


def observe(home: str | os.PathLike[str], store: str | os.PathLike[str] | None = None,
            projects: list[str | os.PathLike[str]] | None = None, now: datetime | None = None) -> dict[str, Any]:
    file = store_path(store)
    current = scan(home, projects)
    doc = load(file)
    stamp = iso(now)
    decisions = list(doc.get("decisions") or [])
    alerts = list(doc.get("alerts") or [])
    if not doc.get("baselined"):
        for entry in current:
            entry["firstSeenAt"] = stamp
            entry["changedAt"] = stamp
        _write(file, {
            "version": 1,
            "baselined": True,
            "scannedAt": stamp,
            "entries": current,
            "pending": [],
            "decisions": decisions,
            "alerts": alerts,
        })
        return load(file)
    previous = {entry["id"]: entry for entry in doc.get("entries") or [] if isinstance(entry, dict)}
    pending: list[str] = []
    merged: list[dict[str, Any]] = []
    for entry in current:
        old = previous.get(entry["id"])
        if old and old.get("fingerprint") == entry["fingerprint"]:
            entry["firstSeenAt"] = old.get("firstSeenAt") or stamp
            entry["changedAt"] = old.get("changedAt") or stamp
        else:
            entry["firstSeenAt"] = (old or {}).get("firstSeenAt") or stamp
            entry["changedAt"] = stamp
            if not _closed(entry, decisions):
                pending.append(entry["id"])
        merged.append(entry)
    _write(file, {
        "version": 1,
        "baselined": True,
        "scannedAt": stamp,
        "entries": merged,
        "pending": pending,
        "decisions": decisions,
        "alerts": alerts,
    })
    return load(file)


def _find(doc: dict[str, Any], entry_id: str) -> dict[str, Any] | None:
    for entry in doc.get("entries") or []:
        if isinstance(entry, dict) and entry.get("id") == entry_id:
            return entry
    return None


def approve(entry_id: str, note: str, store: str | os.PathLike[str] | None = None, now: datetime | None = None) -> dict[str, Any]:
    cleaned = (note or "").strip()
    if not cleaned:
        raise ValueError("允许要留一句原因")
    file = store_path(store)
    doc = load(file)
    entry = _find(doc, entry_id)
    if entry is None:
        raise KeyError(entry_id)
    decision = {
        "id": entry_id,
        "state": "approved",
        "note": cleaned[:500],
        "decidedAt": iso(now),
        "fingerprint": entry.get("fingerprint") or "",
        "summary": entry.get("summary") or "",
        "blocked": False,
        "alerted": False,
        "configEdited": False,
    }
    doc["decisions"] = [item for item in doc.get("decisions") or []
                        if not (item.get("id") == entry_id and item.get("fingerprint") == decision["fingerprint"])]
    doc["decisions"].insert(0, decision)
    doc["pending"] = [item for item in doc.get("pending") or [] if item != entry_id]
    _write(file, doc)
    return decision


def reject(entry_id: str, note: str = "", store: str | os.PathLike[str] | None = None, now: datetime | None = None) -> dict[str, Any]:
    cleaned = (note or "").strip() or "拒绝"
    file = store_path(store)
    doc = load(file)
    entry = _find(doc, entry_id)
    if entry is None:
        raise KeyError(entry_id)
    stamp = iso(now)
    decision = {
        "id": entry_id,
        "state": "rejected",
        "note": cleaned[:500],
        "decidedAt": stamp,
        "fingerprint": entry.get("fingerprint") or "",
        "summary": entry.get("summary") or "",
        "blocked": False,
        "alerted": True,
        "configEdited": False,
    }
    kind = {"skill": "技能", "rule": "规则", "plugin": "插件"}.get(str(entry.get("kind")), "MCP")
    alert = {
        "id": "supply-alert:" + entry_id,
        "entryId": entry_id,
        "agent": entry.get("agent") or "",
        "title": f"拒绝了新加的{kind}：{entry.get('name') or entry_id}",
        "summary": entry.get("summary") or "",
        "at": stamp,
        "blocked": False,
        "disposition": "已记下，未拦截",
        "flags": [flag.get("id") for flag in entry.get("flags") or [] if isinstance(flag, dict)],
    }
    doc["decisions"] = [item for item in doc.get("decisions") or []
                        if not (item.get("id") == entry_id and item.get("fingerprint") == decision["fingerprint"])]
    doc["decisions"].insert(0, decision)
    doc["alerts"] = [item for item in doc.get("alerts") or [] if item.get("id") != alert["id"]]
    doc["alerts"].insert(0, alert)
    doc["pending"] = [item for item in doc.get("pending") or [] if item != entry_id]
    _write(file, doc)
    return decision


def tool_payload(agent: str | None = None, limit: int | None = None, offset: int | None = None,
                 store: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    doc = load(store)
    by_id = {entry["id"]: entry for entry in doc.get("entries") or [] if isinstance(entry, dict) and entry.get("id")}
    pending = [by_id[item] for item in doc.get("pending") or [] if item in by_id]
    if agent and agent != "all":
        pending = [entry for entry in pending if entry.get("agent") == agent]
    start = max(0, offset or 0)
    page = pending[start:] if limit is None else pending[start:start + max(0, limit)]
    decisions = doc.get("decisions") or []
    alerts = doc.get("alerts") or []
    if agent and agent != "all":
        decisions = [item for item in decisions if _agent_of(item, by_id) in {agent, ""}]
        alerts = [item for item in alerts if item.get("agent") in {agent, None, ""}]
    return {
        "schema": SCHEMA,
        "readOnly": True,
        "configEdited": False,
        "enforced": False,
        "blocked": False,
        "disposition": "只展示。允许和拒绝记在本机。没有改写任何 agent 的 MCP 配置。拒绝只标出来并告警，没有拦住进程。",
        "scannedAt": doc.get("scannedAt") or "",
        "baselined": bool(doc.get("baselined")),
        "pending": page,
        "decisions": decisions,
        "alerts": alerts,
        "total": len(pending),
        "offset": start,
        "limit": limit,
    }


def _agent_of(decision: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> str:
    entry = by_id.get(decision.get("id") or "")
    if entry:
        return str(entry.get("agent") or "")
    return ""
