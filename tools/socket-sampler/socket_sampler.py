#!/usr/bin/env python3
"""Per-process socket sampler for AI coding agents (proxy-independent).

The audit proxy only sees traffic that honours HTTP(S)_PROXY. This sampler
looks at the sockets each monitored agent process tree actually holds, using
built-in macOS tools only (``ps`` and ``lsof -F``), so direct sockets (Node/Go/
Rust clients that ignore proxy variables, model API calls, git over ssh, scp,
raw TCP/UDP) become visible next to proxied traffic.

Evidence labels
  * socket row (pid, protocol, local/remote ip:port, state): Observed
    (it was present in a sample).
  * realDestination
      proxy_observed  host from the AgentReins audit proxy / V2rayU route log,
                      joined on exact loopback client port + time    Correlated
      argv_parsed     host parsed from the transport-audit argv of the same
                      process (or an ancestor) and forward-resolved to this
                      exact remote IP                                 Correlated
      dns_inferred    reverse DNS (PTR) of the remote IP               Inferred
      socket_sampled  no hostname; the remote IP itself                Observed
      proxy_unjoined  loopback proxy hop, real destination not found   Unknown

Limitation (written into every ledger): this is sampling, not interception.
A connection that opens and closes between two samples is missed. DNS
queries made through the system resolver (mDNSResponder) are not owned by the
agent process and are not visible here. Payloads are never read.

Read-only with respect to the agent: no proxy, environment or socket changes.
Process arguments are used only to recognise agents and are never stored.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
from typing import Any, Iterable

SCHEMA = 1
SAMPLER_VERSION = "socket-sampler/1"
SUPPORT = pathlib.Path.home() / "Library/Application Support/AgentGuard"
DEFAULT_LEDGER = pathlib.Path(os.environ.get("AGENTREINS_SOCKET_LEDGER", str(SUPPORT / "socket-ledger.json")))
DEFAULT_TRANSPORT = pathlib.Path(os.environ.get("AGENTREINS_TRANSPORT_ROOT", str(SUPPORT / "transport-audit")))
DEFAULT_ROUTES = [
    pathlib.Path(os.environ.get(
        "AGENTREINS_WORKBUDDY_ROUTE_JSONL",
        str(pathlib.Path.home() / "Library/Application Support/AgentReins/workbuddy-network-routes.jsonl"))),
]
DEFAULT_V2RAY_LOG = pathlib.Path.home() / ".V2rayU/v2ray-core.log"
AUDIT_PROXY_PORTS = (18891, 18893)
MAX_ROWS = 3000
MAX_AGE_SECONDS = 7 * 24 * 3600
ROUTE_JOIN_SECONDS = 15.0
LSOF = "/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else "lsof"
PS = "/bin/ps" if os.path.exists("/bin/ps") else "ps"

LIMITATION = (
    "按进程定时采样（lsof），不是逐包拦截：两次采样之间开始又结束的短连接会漏掉；"
    "经系统解析器（mDNSResponder）发出的 DNS 查询不属于 agent 进程，这里看不到；不读取任何正文。"
)


# ---------------------------------------------------------------- utilities

def utc_iso(ts: float | None = None) -> str:
    value = _dt.datetime.fromtimestamp(time.time() if ts is None else ts, tz=_dt.timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def split_endpoint(value: str) -> tuple[str, int | None]:
    """'1.2.3.4:443' / '[2606::1]:443' / '*:5353' -> (host, port)."""
    value = value.strip()
    if value.startswith("["):
        close = value.find("]")
        host = value[1:close]
        rest = value[close + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    elif value.count(":") > 1:  # bare IPv6 without brackets (lsof does not do this, be lenient)
        host, _, port = value.rpartition(":")
    else:
        host, _, port = value.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return host, None


def join_endpoint(host: str, port: int | None) -> str:
    if port is None:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def ip_scope(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return "private"
    return "public"


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        return True
    except ValueError:
        return False


# ------------------------------------------------------------ process tree

AGENT_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    # Matched only against the executable path and argv[0]/argv[1] basenames
    # (a script runner such as node). Project paths mentioning an agent are
    # not ownership evidence.
    ("Codex", re.compile(r"(?i)^(codex|codex-[\w.-]+)$")),
    ("Codex", re.compile(r"(?i)/Codex\.app/")),
    ("WorkBuddy", re.compile(r"(?i)^(workbuddy|codebuddy)$")),
    ("WorkBuddy", re.compile(r"(?i)/(WorkBuddy|CodeBuddy)\.app/")),
    ("Cursor", re.compile(r"(?i)^cursor-agent$")),
    ("Cursor", re.compile(r"(?i)/Cursor\.app/")),
    ("Claude", re.compile(r"(?i)^claude$")),
]
SELF_NAMES = ("AgentReins", "socket_sampler", "lsof")


def parse_ps_comm(text: str) -> dict[int, dict[str, Any]]:
    """Parse ``ps -axww -o pid=,ppid=,lstart=,comm=`` (lstart is 5 tokens)."""
    procs: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 7)
        if len(parts) < 8:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        lstart = " ".join(parts[2:7])
        start = None
        try:
            local = _dt.datetime.strptime(lstart, "%a %b %d %H:%M:%S %Y").astimezone()
            start = local.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
        path = parts[7].strip()
        procs[pid] = {"pid": pid, "ppid": ppid, "startAt": start, "path": path,
                      "name": os.path.basename(path) or path}
    return procs


def parse_ps_args(text: str) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) < 2:
            continue
        try:
            out[int(parts[0])] = parts[1].split()[:2]
        except ValueError:
            continue
    return out


def snapshot_processes() -> dict[int, dict[str, Any]]:
    comm = subprocess.run([PS, "-axww", "-o", "pid=,ppid=,lstart=,comm="],
                          capture_output=True, text=True, timeout=10, check=False).stdout
    argv = subprocess.run([PS, "-axww", "-o", "pid=,args="],
                          capture_output=True, text=True, timeout=10, check=False).stdout
    procs = parse_ps_comm(comm)
    heads = parse_ps_args(argv)
    for pid, proc in procs.items():
        proc["argvHead"] = heads.get(pid, [])
    return procs


def agent_of(proc: dict[str, Any]) -> str | None:
    path = str(proc.get("path") or "")
    if any(marker in path for marker in SELF_NAMES):
        return None
    candidates = [path, os.path.basename(path)]
    for token in proc.get("argvHead") or []:
        candidates.extend([token, os.path.basename(token)])
    for agent, pattern in AGENT_MARKERS:
        if any(pattern.search(c) for c in candidates if c):
            return agent
    return None


def agent_tree(procs: dict[int, dict[str, Any]], roots: dict[int, str] | None = None,
               discover: bool = True) -> dict[int, str]:
    """Return {pid: agent} for every root and its descendants."""
    children: dict[int, list[int]] = {}
    for pid, proc in procs.items():
        children.setdefault(proc["ppid"], []).append(pid)
    owners: dict[int, str] = {}
    queue: list[tuple[int, str]] = []
    for pid, agent in (roots or {}).items():
        if pid in procs:
            owners[pid] = agent
            queue.append((pid, agent))
    if discover:
        for pid, proc in procs.items():
            if pid in owners:
                continue
            agent = agent_of(proc)
            if agent:
                owners[pid] = agent
                queue.append((pid, agent))
    index = 0
    while index < len(queue):
        pid, agent = queue[index]
        index += 1
        for child in children.get(pid, []):
            if child not in owners and child != pid:
                owners[child] = agent
                queue.append((child, agent))
    return owners


# ------------------------------------------------------------------- lsof

def parse_lsof(text: str) -> list[dict[str, Any]]:
    """Parse ``lsof -F pcRftPTn`` output into socket records.

    One record per file descriptor. Unconnected sockets (no ``->``) and
    listeners are returned with ``remote=None`` so callers can drop them.
    """
    records: list[dict[str, Any]] = []
    proc: dict[str, Any] = {}
    cur: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal cur
        if cur and cur.get("name"):
            records.append(cur)
        cur = None

    for raw in text.splitlines():
        if not raw:
            continue
        tag, value = raw[0], raw[1:]
        if tag == "p":
            flush()
            proc = {"pid": int(value) if value.isdigit() else None}
        elif tag == "c":
            proc["command"] = value
        elif tag == "R":
            proc["ppid"] = int(value) if value.isdigit() else None
        elif tag == "f":
            flush()
            cur = {"pid": proc.get("pid"), "ppid": proc.get("ppid"), "command": proc.get("command"), "fd": value}
        elif cur is None:
            continue
        elif tag == "t":
            cur["family"] = value
        elif tag == "P":
            cur["protocol"] = value.upper()
        elif tag == "n":
            cur["name"] = value
        elif tag == "T" and value.startswith("ST="):
            cur["state"] = value[3:]
    flush()
    out = []
    for rec in records:
        name = rec["name"].split(" (", 1)[0]
        if "->" in name:
            local, remote = name.split("->", 1)
        else:
            local, remote = name, None
        lh, lp = split_endpoint(local)
        rec["local"] = join_endpoint(lh, lp)
        if remote:
            rh, rp = split_endpoint(remote)
            rec["remoteIP"], rec["remotePort"] = rh, rp
            rec["remote"] = join_endpoint(rh, rp)
        else:
            rec["remoteIP"], rec["remotePort"], rec["remote"] = None, None, None
        rec["localPort"] = lp
        rec.setdefault("protocol", "TCP" if rec.get("state") else "UNKNOWN")
        out.append(rec)
    return out


def run_lsof(pids: Iterable[int]) -> tuple[list[dict[str, Any]], str | None]:
    targets = sorted(set(int(p) for p in pids))
    if not targets:
        return [], None
    proc = subprocess.run([LSOF, "-nP", "-w", "-a", "-p", ",".join(map(str, targets)), "-i", "-F", "pcRftPTn"],
                          capture_output=True, text=True, timeout=20, check=False)
    # lsof exits 1 when the selection has no sockets; that is a clean empty sample.
    failure = None
    if proc.returncode not in (0, 1) or (proc.returncode == 1 and proc.stdout.strip() and proc.stderr.strip()):
        failure = f"lsof exit {proc.returncode}; coverage unknown for this sample"
    return parse_lsof(proc.stdout), failure


# ---------------------------------------------------------- proxy routes

def load_audit_proxy_routes(paths: Iterable[pathlib.Path], max_bytes: int = 4 * 1024 * 1024) -> list[dict[str, Any]]:
    """AgentReins audit proxy (mitmdump addon) route journal: clientAddress + host."""
    routes = []
    for path in paths:
        try:
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - max_bytes))
                data = fh.read().decode("utf-8", "replace")
        except OSError:
            continue
        lines = data.splitlines()
        if size > max_bytes and lines:
            lines = lines[1:]
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            client = rec.get("clientAddress")
            host = str(rec.get("host") or "").strip().lower()
            if not client or not host or not re.fullmatch(r"[a-z0-9.\-_:\[\]]+", host):
                continue
            ch, cp = split_endpoint(str(client))
            ts = parse_iso(rec.get("observedAt"))
            if cp is None or ts is None or ip_scope(ch) != "loopback":
                continue
            routes.append({"clientPort": cp, "host": host.strip("[]"), "port": rec.get("remotePort"),
                           "ts": ts, "proxy": "AgentReins audit proxy"})
    return routes


V2RAY_LINE = re.compile(
    r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? from (?:tcp:)?(?:127\.0\.0\.1|\[::1\]):(\d+) accepted //(?:tcp:)?([^:\s]+):(\d+)",
    re.M)


def load_v2ray_routes(path: pathlib.Path, max_bytes: int = 262_144) -> list[dict[str, Any]]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - max_bytes))
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    routes = []
    for m in V2RAY_LINE.finditer(text):
        try:
            ts = _dt.datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S").astimezone().timestamp()
        except ValueError:
            continue
        routes.append({"clientPort": int(m.group(2)), "host": m.group(3).lower(), "port": int(m.group(4)),
                       "ts": ts, "proxy": "V2rayU"})
    return routes


def match_route(row: dict[str, Any], routes: list[dict[str, Any]]) -> dict[str, Any] | None:
    port = row.get("localPort")
    first = parse_iso(row.get("firstSeen")) or 0
    last = parse_iso(row.get("lastSeen")) or first
    hits = [r for r in routes if r["clientPort"] == port
            and first - ROUTE_JOIN_SECONDS <= r["ts"] <= last + ROUTE_JOIN_SECONDS]
    if not hits:
        return None
    hosts = {(r["host"], r.get("port")) for r in hits}
    if len({h for h, _ in hosts}) != 1:
        return None  # a reused client port with conflicting hosts is ambiguous
    return max(hits, key=lambda r: r["ts"])


# ----------------------------------------------------- transport argv join

def load_transport_hosts(root: pathlib.Path, limit: int = 300) -> dict[int, dict[str, Any]]:
    """pid -> {host, tool, call} from transport-audit manifests (argv already redacted)."""
    out: dict[int, dict[str, Any]] = {}
    try:
        runs = sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    except OSError:
        return out
    for run in runs:
        try:
            manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        pid = manifest.get("pid")
        host = host_from_args(manifest.get("args") or [])
        if isinstance(pid, int) and host:
            out[pid] = {"host": host, "tool": manifest.get("tool"), "call": manifest.get("call") or run.name}
    return out


def host_from_args(args: list[Any]) -> str | None:
    for arg in args:
        s = str(arg)
        if s.startswith("-"):
            continue
        m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]+\]|[A-Za-z0-9.-]+)", s, re.I)
        if m:
            return m.group(1).strip("[]").lower()
        m = re.match(r"^(?:[^@\s/]+@)([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::|$)", s)
        if m:
            return m.group(1).lower()
    return None


# ---------------------------------------------------------------- resolver

class Resolver:
    def __init__(self, cache: dict[str, Any] | None = None, timeout: float = 1.5, enabled: bool = True):
        self.cache = cache if cache is not None else {}
        self.timeout = timeout
        self.enabled = enabled
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def _cached(self, key: str) -> Any:
        hit = self.cache.get(key)
        if hit and time.time() - hit.get("at", 0) < 3600:
            return hit
        return None

    def ptr(self, ip: str) -> str | None:
        key = "ptr:" + ip
        hit = self._cached(key)
        if hit is not None:
            return hit.get("name")
        if not self.enabled:
            return None
        try:
            name = self.pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=self.timeout)
        except Exception:
            name = None
        self.cache[key] = {"name": name.lower().rstrip(".") if name else None, "at": time.time()}
        return self.cache[key]["name"]

    def forward(self, host: str) -> list[str]:
        key = "a:" + host
        hit = self._cached(key)
        if hit is not None:
            return hit.get("ips") or []
        if not self.enabled:
            return []
        try:
            infos = self.pool.submit(socket.getaddrinfo, host, None).result(timeout=self.timeout)
            ips = sorted({i[4][0] for i in infos})
        except Exception:
            ips = []
        self.cache[key] = {"ips": ips, "at": time.time()}
        return ips


# -------------------------------------------------------------- the merge

def row_key(proc: dict[str, Any], sock: dict[str, Any]) -> str:
    return "|".join(str(x) for x in (sock["pid"], proc.get("startAt"), sock.get("protocol"), sock["local"], sock["remote"]))


def merge_sample(ledger: dict[str, Any], sockets: list[dict[str, Any]], procs: dict[int, dict[str, Any]],
                 owners: dict[int, str], observed_at: float) -> list[dict[str, Any]]:
    rows = {r["key"]: r for r in ledger.get("connections", []) if r.get("key")}
    touched = []
    for sock in sockets:
        pid = sock.get("pid")
        if pid not in owners or not sock.get("remote") or sock.get("remotePort") in (None, 0):
            continue
        if sock.get("state") == "LISTEN" or sock.get("remoteIP") in ("*", ""):
            continue
        proc = procs.get(pid, {})
        key = row_key(proc, sock)
        row = rows.get(key)
        now = utc_iso(observed_at)
        if row is None:
            row = {
                "id": hashlib.sha256(key.encode()).hexdigest()[:16], "key": key,
                "agent": owners[pid], "pid": pid, "ppid": sock.get("ppid") or proc.get("ppid"),
                "processName": proc.get("name") or sock.get("command"), "processPath": proc.get("path"),
                "processStartAt": proc.get("startAt"),
                "protocol": sock.get("protocol"), "family": sock.get("family"),
                "localAddress": sock["local"], "localPort": sock.get("localPort"),
                "remoteAddress": sock["remote"], "remoteIP": sock["remoteIP"], "remotePort": sock["remotePort"],
                "firstSeen": now, "sampleCount": 0, "evidence": "Observed", "source": "lsof",
            }
            rows[key] = row
        row["lastSeen"] = now
        row["state"] = sock.get("state") or ("CONNECTED" if row.get("protocol") == "UDP" else None)
        row["sampleCount"] = int(row.get("sampleCount", 0)) + 1
        touched.append(row)
    ledger["connections"] = list(rows.values())
    return touched


def resolve_destinations(rows: list[dict[str, Any]], routes: list[dict[str, Any]],
                         transport_hosts: dict[int, dict[str, Any]], procs: dict[int, dict[str, Any]],
                         resolver: Resolver, proxy_ports: Iterable[int] = AUDIT_PROXY_PORTS) -> None:
    proxy_ports = set(proxy_ports)
    for row in rows:
        ip = row.get("remoteIP") or ""
        scope = ip_scope(ip)
        row["scope"] = scope
        route = match_route(row, routes) if scope == "loopback" else None
        via_proxy = bool(route) or (scope == "loopback" and row.get("remotePort") in proxy_ports)
        row["viaProxy"] = via_proxy
        row["transportPeer"] = row.get("remoteAddress")
        if route:
            row.update(realDestination=route["host"], realDestinationPort=route.get("port"),
                       destinationSource="proxy_observed", destinationEvidence="Correlated",
                       proxy={"name": route["proxy"], "listener": row.get("remoteAddress"),
                              "clientPort": row.get("localPort"), "routeObservedAt": utc_iso(route["ts"])},
                       destinationBasis="exact loopback client port + time join with proxy route log")
            continue
        if via_proxy:
            if row.get("destinationSource") != "proxy_observed":
                row.update(realDestination=None, destinationSource="proxy_unjoined", destinationEvidence="Unknown",
                           proxy={"name": "AgentReins audit proxy", "listener": row.get("remoteAddress"),
                                  "clientPort": row.get("localPort")},
                           destinationBasis="loopback hop to the audit proxy; no route record for this client port yet")
            continue
        if scope == "loopback":
            row.update(realDestination=ip, destinationSource="local", destinationEvidence="Observed",
                       destinationBasis="loopback peer (local service, not the audit proxy)")
            continue
        if row.get("destinationSource") in ("argv_parsed", "dns_inferred") and row.get("realDestination"):
            continue  # already resolved on an earlier sample
        # argv join: same pid or nearest ancestor ran through transport-audit
        hint = None
        cursor, hops = row.get("pid"), 0
        while cursor and hops < 8 and hint is None:
            hint = transport_hosts.get(cursor)
            cursor = (procs.get(cursor) or {}).get("ppid")
            hops += 1
        if hint and ip in resolver.forward(hint["host"]):
            row.update(realDestination=hint["host"], destinationSource="argv_parsed", destinationEvidence="Correlated",
                       transportCall=hint.get("call"), forwardConfirmed=True,
                       destinationBasis="argv host of transport call %s forward-resolves to this remote IP" % hint.get("call"))
            continue
        name = resolver.ptr(ip) if scope == "public" else None
        if name:
            confirmed = ip in resolver.forward(name)
            row.update(realDestination=name, destinationSource="dns_inferred", destinationEvidence="Inferred",
                       forwardConfirmed=confirmed,
                       destinationBasis="reverse DNS (PTR) of the remote IP%s; not the name the agent asked for"
                       % (", forward-confirmed" if confirmed else ", not forward-confirmed"))
        else:
            row.update(realDestination=ip, destinationSource="socket_sampled", destinationEvidence="Observed",
                       destinationBasis="remote IP of the sampled socket; no hostname recovered")


# ------------------------------------------------------------ ledger I/O

def load_ledger(path: pathlib.Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("schema") == SCHEMA:
            return data
    except (OSError, ValueError):
        pass
    return {"schema": SCHEMA, "connections": [], "dnsCache": {}, "samples": {}}


def save_ledger(path: pathlib.Path, ledger: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cutoff = time.time() - MAX_AGE_SECONDS
    rows = [r for r in ledger.get("connections", []) if (parse_iso(r.get("lastSeen")) or 0) >= cutoff]
    rows.sort(key=lambda r: r.get("lastSeen") or "", reverse=True)
    ledger["connections"] = rows[:MAX_ROWS]
    cache = ledger.get("dnsCache") or {}
    ledger["dnsCache"] = {k: v for k, v in cache.items() if time.time() - v.get("at", 0) < 3600}
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, path)


def sample_once(ledger_path: pathlib.Path, roots: dict[int, str] | None = None, discover: bool = True,
                interval: float | None = None, resolve: bool = True,
                route_paths: Iterable[pathlib.Path] = DEFAULT_ROUTES,
                v2ray_log: pathlib.Path = DEFAULT_V2RAY_LOG,
                transport_root: pathlib.Path = DEFAULT_TRANSPORT) -> dict[str, Any]:
    lock_path = ledger_path.with_name(ledger_path.name + ".lock")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger = load_ledger(ledger_path)
        observed_at = time.time()
        procs = snapshot_processes()
        owners = agent_tree(procs, roots, discover)
        sockets, failure = run_lsof(owners.keys())
        touched = merge_sample(ledger, sockets, procs, owners, observed_at)
        routes = load_audit_proxy_routes(route_paths) + load_v2ray_routes(v2ray_log)
        resolver = Resolver(ledger.setdefault("dnsCache", {}), enabled=resolve)
        resolve_destinations(touched, routes, load_transport_hosts(transport_root), procs, resolver)
        resolver.pool.shutdown(wait=False)
        stats = ledger.setdefault("samples", {})
        stats["count"] = int(stats.get("count", 0)) + 1
        stats.setdefault("firstAt", utc_iso(observed_at))
        stats["lastAt"] = utc_iso(observed_at)
        stats["lastProcessCount"] = len(owners)
        stats["lastAgents"] = sorted(set(owners.values()))
        stats["lastSocketCount"] = len(touched)
        if failure:
            stats["failures"] = int(stats.get("failures", 0)) + 1
            stats["lastFailure"] = failure
        ledger["sampler"] = SAMPLER_VERSION
        ledger["coverage"] = {
            "method": "per-process socket sampling via lsof -i (TCP+UDP), independent of proxy settings",
            "intervalSeconds": interval,
            "missesShorterThanSeconds": interval,
            "limitation": LIMITATION,
            "confidence": "Observed" if not failure else "Unknown",
        }
        save_ledger(ledger_path, ledger)
        return {"observedAt": utc_iso(observed_at), "processes": len(owners), "sockets": touched, "failure": failure}


def parse_roots(values: list[str]) -> dict[int, str]:
    roots = {}
    for value in values or []:
        pid, _, agent = value.partition(":")
        roots[int(pid)] = agent or "Unknown"
    return roots


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--ledger", type=pathlib.Path, default=DEFAULT_LEDGER)
    ap.add_argument("--root-pid", action="append", default=[], help="PID[:Agent] to monitor with its descendants")
    ap.add_argument("--no-discover", action="store_true", help="only monitor --root-pid trees")
    ap.add_argument("--interval", type=float, default=3.0)
    ap.add_argument("--duration", type=float, default=0, help="watch for N seconds (0 = forever)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse/forward DNS lookups")
    ap.add_argument("--json", action="store_true", help="print each sample's touched rows as JSON")
    args = ap.parse_args(argv)
    roots = parse_roots(args.root_pid)
    deadline = time.time() + args.duration if args.duration else None
    while True:
        started = time.time()
        result = sample_once(args.ledger, roots, not args.no_discover, args.interval, not args.no_dns)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
        if args.once or (deadline and time.time() >= deadline):
            return 0 if not result.get("failure") else 2
        time.sleep(max(0.05, args.interval - (time.time() - started)))


if __name__ == "__main__":
    sys.exit(main())
