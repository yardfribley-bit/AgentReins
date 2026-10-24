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

Honest coverage: the ledger reports the *measured* cycle (p50/p95 of the real
period, gaps between successful rounds across restarts) and every failed,
timed-out or partial round, restart gap and stop with reason + UTC time. The
configured interval is only reported as configuredIntervalSeconds.

Tamper evidence: every ledger snapshot is HMAC-signed with the same Keychain
key as the MCP evidence chain (see sign_snapshot / verify_snapshot).

Read-only with respect to the agent: no proxy, environment or socket changes.
Process arguments are used only to recognise agents and are never stored.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import fcntl
import hashlib
import hmac
import ipaddress
import json
import math
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Iterable

SCHEMA = 1
SAMPLER_VERSION = "socket-sampler/2"
HERE = pathlib.Path(__file__).resolve().parent
SUPPORT = pathlib.Path.home() / "Library/Application Support/AgentGuard"
DEFAULT_LEDGER_HOME = SUPPORT / "socket-ledger.json"
DEFAULT_LEDGER = pathlib.Path(os.environ.get("AGENTREINS_SOCKET_LEDGER", str(DEFAULT_LEDGER_HOME)))
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


class SampleError(Exception):
    """One sampling stage failed; the round is counted as failed, never dropped silently."""

    def __init__(self, stage: str, kind: str, reason: str):
        super().__init__(f"{stage}: {reason}")
        self.stage, self.kind, self.reason = stage, kind, reason


def run_tool(cmd: list[str], timeout: float, stage: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=max(0.2, timeout), check=False)
    except subprocess.TimeoutExpired:
        raise SampleError(stage, "timeout", "%s timed out after %.1fs" % (os.path.basename(cmd[0]), timeout)) from None
    except OSError as exc:
        raise SampleError(stage, "error", "%s: %s" % (os.path.basename(cmd[0]), exc.__class__.__name__)) from None


def lstart_to_utc(lstart: str) -> str | None:
    """`ps -o lstart` is local wall time; convert to real UTC (never stamp Z on local time)."""
    try:
        local = _dt.datetime.strptime(" ".join(lstart.split()), "%a %b %d %H:%M:%S %Y").astimezone()
    except ValueError:
        return None
    return local.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ps_basic(text: str) -> dict[int, dict[str, Any]]:
    """Parse ``ps -axo pid=,ppid=,comm=`` (cheap: no lstart, no argv)."""
    out: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        path = parts[2].strip()
        out[pid] = {"pid": pid, "ppid": ppid, "path": path, "name": os.path.basename(path) or path}
    return out


def parse_ps_detail(text: str) -> dict[int, dict[str, Any]]:
    """Parse ``ps -ww -o pid=,lstart=,args= -p ...`` (lstart is always 5 tokens)."""
    out: dict[int, dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 6)
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        args = parts[6] if len(parts) > 6 else ""
        out[pid] = {"startAt": lstart_to_utc(" ".join(parts[1:6])), "argvHead": args.split()[:2]}
    return out


class ProcessTable:
    """Process tree with per-pid caching.

    Every round runs only ``ps -axo pid=,ppid=,comm=``. Start time and argv[0..1]
    are fetched once per new (pid, executable) with a single
    ``ps -ww -o pid=,lstart=,args= -p <new pids>`` call and then cached, so the
    expensive lstart/args columns are not recomputed for ~500 processes every
    round (the 10 s ``ps -axww ... lstart`` timeouts seen on a real Mac).
    """

    FULL_SCAN_THRESHOLD = 300

    def __init__(self) -> None:
        self.cache: dict[int, dict[str, Any]] = {}

    def _detail(self, pids: list[int], timeout: float) -> dict[int, dict[str, Any]]:
        if not pids:
            return {}
        if len(pids) > self.FULL_SCAN_THRESHOLD:
            cmd = [PS, "-axww", "-o", "pid=,lstart=,args="]
        else:
            cmd = [PS, "-ww", "-o", "pid=,lstart=,args=", "-p", ",".join(map(str, sorted(pids)))]
        # ps exits 1 when some pids already exited; the rest of its output is valid.
        return parse_ps_detail(run_tool(cmd, timeout, "ps-detail").stdout)

    def snapshot(self, timeout: float = 5.0) -> dict[int, dict[str, Any]]:
        started = time.monotonic()
        proc = run_tool([PS, "-axo", "pid=,ppid=,comm="], timeout, "ps")
        basic = parse_ps_basic(proc.stdout)
        if not basic:
            raise SampleError("ps", "error", "ps returned no processes (exit %s)" % proc.returncode)
        for pid in [p for p in self.cache if p not in basic]:
            del self.cache[pid]
        new = [pid for pid, row in basic.items() if self.cache.get(pid, {}).get("path") != row["path"]]
        remaining = max(0.5, timeout - (time.monotonic() - started))
        detail = self._detail(new, remaining)
        for pid in new:
            info = detail.get(pid, {})
            self.cache[pid] = {"path": basic[pid]["path"], "startAt": info.get("startAt"),
                               "argvHead": info.get("argvHead", [])}
        procs = {}
        for pid, row in basic.items():
            cached = self.cache.get(pid, {})
            procs[pid] = dict(row, startAt=cached.get("startAt"), argvHead=cached.get("argvHead", []))
        return procs

    def add_late(self, rows: dict[int, dict[str, Any]], procs: dict[int, dict[str, Any]], timeout: float) -> None:
        """Processes that appeared after the ps snapshot but already hold sockets (seen by lsof)."""
        detail = self._detail(sorted(rows), timeout)
        for pid, row in rows.items():
            info = detail.get(pid, {})
            entry = {"pid": pid, "ppid": row.get("ppid"), "path": row.get("command") or "?",
                     "name": row.get("command") or "?", "startAt": info.get("startAt"),
                     "argvHead": info.get("argvHead", []), "lateChild": True}
            procs[pid] = entry
            self.cache[pid] = {"path": entry["path"], "startAt": entry["startAt"], "argvHead": entry["argvHead"]}


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


def run_lsof_all(timeout: float = 8.0) -> tuple[list[dict[str, Any]], str | None]:
    """One ``lsof -i`` call for every Internet socket visible to this user.

    Filtering by the agent PID set happens in Python. Compared with
    ``lsof -a -p <tree>`` this also sees sockets of children forked after the
    ps snapshot (attributed through lsof's own PPID field).
    Returns (sockets, partial_reason).
    """
    proc = run_tool([LSOF, "-nP", "-w", "-i", "-F", "pcRftPTn"], timeout, "lsof")
    if proc.returncode not in (0, 1):
        raise SampleError("lsof", "error", "lsof exit %s" % proc.returncode)
    partial = None
    # lsof exits 1 both for "no sockets" (empty output) and for partial failures.
    if proc.returncode == 1 and proc.stdout.strip() and proc.stderr.strip():
        partial = "lsof exit 1 with errors; some processes may be missing from this sample"
    return parse_lsof(proc.stdout), partial


def attribute_sockets(sockets: list[dict[str, Any]], procs: dict[int, dict[str, Any]],
                      owners: dict[int, str]) -> dict[int, dict[str, Any]]:
    """Give sockets of processes born after the ps snapshot to the agent of their parent.

    Mutates ``owners``; returns {pid: lsof row} for those late children so the
    caller can fetch their start time.
    """
    late: dict[int, dict[str, Any]] = {}
    for sock in sockets:
        pid, ppid = sock.get("pid"), sock.get("ppid")
        if pid is None or pid in owners or pid in procs:
            continue
        if ppid in owners:
            owners[pid] = owners[ppid]
            late[pid] = sock
    return late


# ---------------------------------------------------------- proxy routes

_FILE_CACHE: dict[tuple[str, str], tuple[tuple[int, int], list[dict[str, Any]]]] = {}


def _cached_parse(kind: str, path: pathlib.Path, parse: Any) -> list[dict[str, Any]]:
    """Re-parse a route log only when its size/mtime changed (it was re-read every round before)."""
    try:
        st = path.stat()
    except OSError:
        return []
    sig = (st.st_size, st.st_mtime_ns)
    hit = _FILE_CACHE.get((kind, str(path)))
    if hit and hit[0] == sig:
        return hit[1]
    value = parse(path)
    _FILE_CACHE[(kind, str(path))] = (sig, value)
    return value


def load_audit_proxy_routes(paths: Iterable[pathlib.Path], max_bytes: int = 4 * 1024 * 1024) -> list[dict[str, Any]]:
    """AgentReins audit proxy (mitmdump addon) route journal: clientAddress + host."""
    routes: list[dict[str, Any]] = []
    for path in paths:
        routes.extend(_cached_parse("audit", pathlib.Path(path), lambda p: _parse_audit_routes(p, max_bytes)))
    return routes


def _parse_audit_routes(path: pathlib.Path, max_bytes: int) -> list[dict[str, Any]]:
    routes = []
    for path in (path,):
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
    return _cached_parse("v2ray", pathlib.Path(path), lambda p: _parse_v2ray_routes(p, max_bytes))


def _parse_v2ray_routes(path: pathlib.Path, max_bytes: int) -> list[dict[str, Any]]:
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
    return TransportIndex(root, limit).hosts()


class TransportIndex:
    """Incremental pid -> argv host index over transport-audit runs (only new run folders are read)."""

    def __init__(self, root: pathlib.Path, limit: int = 300) -> None:
        self.root, self.limit = root, limit
        self.cache: dict[str, tuple[float, dict[str, Any] | None]] = {}

    def hosts(self) -> dict[int, dict[str, Any]]:
        try:
            entries = [e for e in os.scandir(self.root) if e.is_dir(follow_symlinks=False)]
        except OSError:
            return {}
        names = {e.name for e in entries}
        for name in [n for n in self.cache if n not in names]:
            del self.cache[name]
        now = time.time()
        for entry in entries:
            hit = self.cache.get(entry.name)
            # Manifests get their pid shortly after start: retry recent runs that had none yet.
            if hit is not None and (hit[1] is not None or now - hit[0] > 600):
                continue
            try:
                manifest = json.loads((pathlib.Path(entry.path) / "manifest.json").read_text(encoding="utf-8"))
                mtime = entry.stat(follow_symlinks=False).st_mtime
            except (OSError, ValueError):
                continue
            pid = manifest.get("pid")
            host = host_from_args(manifest.get("args") or [])
            value = {"pid": pid, "host": host, "tool": manifest.get("tool"), "call": manifest.get("call") or entry.name} \
                if isinstance(pid, int) and host else None
            self.cache[entry.name] = (mtime, value)
        newest = sorted(self.cache.items(), key=lambda kv: kv[1][0], reverse=True)[:self.limit]
        return {v["pid"]: {k: v[k] for k in ("host", "tool", "call")} for _, (_, v) in newest if v}


PROXY_VALUE_OPTIONS = {"-x", "--proxy", "--preproxy", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
                       "--proxy1.0", "--connect-to", "--resolve", "-e", "--referer", "-H", "--header"}


def host_from_args(args: list[Any]) -> str | None:
    """First destination host in argv; values of proxy/header options are not destinations."""
    skip = False
    for arg in args:
        s = str(arg)
        if skip:
            skip = False
            continue
        if s in PROXY_VALUE_OPTIONS:
            skip = True
            continue
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
    def __init__(self, cache: dict[str, Any] | None = None, timeout: float = 1.5, enabled: bool = True,
                 budget: float | None = None):
        self.cache = cache if cache is not None else {}
        self.timeout = timeout
        self.enabled = enabled
        # Total time this round may spend on lookups; the rest are retried next round (not cached as misses).
        self.deadline = time.monotonic() + budget if budget is not None else None
        self.deferred = 0
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    def close(self) -> None:
        self.pool.shutdown(wait=False)

    def _time_left(self) -> float | None:
        if self.deadline is None:
            return self.timeout
        left = self.deadline - time.monotonic()
        if left <= 0.01:
            self.deferred += 1
            return None
        return min(self.timeout, left)

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
        wait = self._time_left()
        if wait is None:
            return None
        try:
            name = self.pool.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=wait)
        except concurrent.futures.TimeoutError:
            if wait < self.timeout:
                self.deferred += 1
                return None  # cut short by the round budget: retry later, do not cache a miss
            name = None
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
        wait = self._time_left()
        if wait is None:
            return []
        try:
            infos = self.pool.submit(socket.getaddrinfo, host, None).result(timeout=wait)
            ips = sorted({i[4][0] for i in infos})
        except concurrent.futures.TimeoutError:
            if wait < self.timeout:
                self.deferred += 1
                return []
            ips = []
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
    return empty_ledger()


def empty_ledger() -> dict[str, Any]:
    return {"schema": SCHEMA, "connections": [], "dnsCache": {}, "samples": {}}


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def prune_ledger(ledger: dict[str, Any], now: float | None = None) -> None:
    now = time.time() if now is None else now
    cutoff = now - MAX_AGE_SECONDS
    rows = [r for r in ledger.get("connections", []) if (parse_iso(r.get("lastSeen")) or 0) >= cutoff]
    rows.sort(key=lambda r: r.get("lastSeen") or "", reverse=True)
    ledger["connections"] = rows[:MAX_ROWS]
    cache = ledger.get("dnsCache") or {}
    ledger["dnsCache"] = {k: v for k, v in cache.items() if now - v.get("at", 0) < 3600}


def ledger_bytes(ledger: dict[str, Any]) -> bytes:
    return json.dumps(ledger, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def save_ledger(path: pathlib.Path, ledger: dict[str, Any]) -> bytes:
    """Prune and atomically replace the ledger (0600). Returns the exact bytes written."""
    prune_ledger(ledger)
    data = ledger_bytes(ledger)
    _atomic_write(path, data)
    return data


# ------------------------------------------------------- tamper evidence
#
# Same primitive as tools/agentreins-mcp/evidence.py: HMAC-SHA256 with the
# integrity key that lives in the macOS Keychain (via the same keychain helper).
# The ledger is a snapshot rewritten every round, so each snapshot gets a
# sidecar `<ledger>.mac` = {seq, prevHash, fileSha256, mac, hash}: the MAC binds
# the exact ledger bytes, seq/prevHash chain consecutive snapshots, and a seal
# copy of the latest sidecar lives outside the AgentGuard directory (the
# integrity seals directory) so rolling the ledger back to an older signed
# snapshot, stripping the sidecar, or editing rows is detectable.
# A tampered ledger found at start-up is never re-signed: it is moved aside
# (kept for review) and the new ledger records that event inside its signed body.

LEDGER_MAC_SCHEMA = 1


def canonical(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sidecar_path(ledger_path: pathlib.Path) -> pathlib.Path:
    return ledger_path.with_name(ledger_path.name + ".mac")


def default_seal_path(ledger_path: pathlib.Path, integrity_dir: pathlib.Path | None) -> pathlib.Path:
    """The default ledger is sealed outside its directory; custom (e.g. CI) ledgers next to themselves."""
    if integrity_dir is not None and ledger_path.resolve() == DEFAULT_LEDGER_HOME.resolve():
        return integrity_dir / "seals" / "socket-ledger.seal"
    return ledger_path.with_name(ledger_path.name + ".seal")


def sign_snapshot(data: bytes, seq: int, prev_hash: str, key: bytes, at: str | None = None) -> dict[str, Any]:
    body = {"schema": LEDGER_MAC_SCHEMA, "seq": int(seq), "prevHash": prev_hash,
            "fileSha256": hashlib.sha256(data).hexdigest(), "at": at or utc_iso()}
    body["mac"] = hmac.new(key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    body["hash"] = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    return body


def verify_snapshot(data: bytes | None, side: dict[str, Any] | None, seal: dict[str, Any] | None,
                    key: bytes | None) -> dict[str, Any]:
    """Pure check shared by the sampler (start-up) and the MCP (evidence.py mirrors it).

    state: verified | unsigned | tampered | unverifiable | missing
    """
    def bad(reason: str, **extra: Any) -> dict[str, Any]:
        return dict({"state": "tampered", "ok": False, "reason": reason, "confidence": "Unknown"}, **extra)

    sealed = isinstance(seal, dict) and not seal.get("unsigned")
    if data is None:
        if sealed:
            return bad("ledger_deleted_after_signed", sealSeq=seal.get("seq"))
        return {"state": "missing", "ok": None, "confidence": "Unknown", "reason": "no ledger"}
    if not isinstance(side, dict):
        if sealed:
            return bad("ledger_mac_missing_after_signed", sealSeq=seal.get("seq"))
        return {"state": "unsigned", "ok": None, "confidence": "Unknown",
                "reason": "no .mac sidecar (sampler older than tamper evidence, or never signed)"}
    if side.get("unsigned"):
        if sealed:
            return bad("unsigned_snapshot_after_signed", sealSeq=seal.get("seq"))
        return {"state": "unsigned", "ok": None, "confidence": "Unknown",
                "reason": str(side.get("reason") or "integrity key unavailable to the sampler")}
    if key is None:
        return {"state": "unverifiable", "ok": None, "confidence": "Unknown",
                "reason": "integrity key not available to this reader", "seq": side.get("seq")}
    body = {k: side[k] for k in ("schema", "seq", "prevHash", "fileSha256", "at") if k in side}
    expected = hmac.new(key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(side.get("mac") or ""), expected):
        return bad("ledger_mac_mismatch", seq=side.get("seq"))
    if side.get("fileSha256") != hashlib.sha256(data).hexdigest():
        return bad("ledger_content_modified", seq=side.get("seq"))
    with_mac = dict(body, mac=side.get("mac"))
    if side.get("hash") != hashlib.sha256(canonical(with_mac).encode("utf-8")).hexdigest():
        return bad("ledger_sidecar_hash_mismatch", seq=side.get("seq"))
    seq = int(side.get("seq") or 0)
    if sealed:
        seal_body = {k: seal[k] for k in ("schema", "seq", "prevHash", "fileSha256", "at") if k in seal}
        seal_mac = hmac.new(key, canonical(seal_body).encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(seal.get("mac") or ""), seal_mac):
            return bad("ledger_seal_mac_mismatch", seq=seq)
        sseq = int(seal.get("seq") or 0)
        if sseq > seq:
            return bad("ledger_rolled_back", seq=seq, sealSeq=sseq)
        if sseq == seq and seal.get("hash") != side.get("hash"):
            return bad("ledger_seal_mismatch", seq=seq, sealSeq=sseq)
        # A crash between writing the sidecar and the seal leaves the seal exactly one behind.
        if sseq < seq and not (sseq == seq - 1 and side.get("prevHash") == seal.get("hash")):
            return bad("ledger_seal_behind", seq=seq, sealSeq=sseq)
    elif seq > 1:
        return bad("ledger_seal_missing", seq=seq)
    return {"state": "verified", "ok": True, "confidence": "Observed", "seq": seq, "signedAt": side.get("at"),
            "reason": "HMAC over the exact ledger bytes verified; sequence matches the external seal"}


def _read_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _read_bytes(path: pathlib.Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def load_integrity_key() -> tuple[bytes | None, pathlib.Path | None, str | None]:
    """(key, integrity_dir, reason). Uses evidence.py so the key is the same Keychain item as the MCP."""
    for candidate in (HERE.parent / "agentreins-mcp",):
        if (candidate / "evidence.py").is_file() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    try:
        import evidence  # noqa: WPS433
    except Exception as exc:  # pragma: no cover - packaging problem, reported in the ledger
        return None, None, "evidence.py not importable: %s" % exc.__class__.__name__
    try:
        # Every helper call is bounded (evidence.KEYCHAIN_HELPER_TIMEOUT) and the helper never waits for a
        # Keychain prompt, so this cannot hang the sampler; any failure means "sample unsigned".
        key = evidence.load_or_create_hmac_key()
    except Exception as exc:
        return None, evidence.INTEGRITY_DIR, "integrity key unavailable: %s: %s" % (exc.__class__.__name__,
                                                                                    str(exc)[:160])
    return key, evidence.INTEGRITY_DIR, None


# --------------------------------------------------------- honest coverage

ROUND_WINDOW = 300
FAILURE_LOG_MAX = 100


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(math.ceil(pct / 100.0 * len(ordered))) - 1))
    return ordered[index]


def measured_coverage(samples: dict[str, Any], interval: float | None) -> dict[str, Any]:
    """Cadence from what actually happened (rounds persisted across restarts), not the configured interval.

    rounds: [startEpoch, durationSeconds, ok]. A connection that exists only
    between two successful lsof snapshots is missed, so the gap between
    consecutive *successful* rounds is what bounds detection.
    """
    rounds = [r for r in samples.get("rounds") or [] if isinstance(r, list) and len(r) >= 3]
    ok_starts = [r[0] for r in rounds if r[2]]
    periods = [b[0] - a[0] for a, b in zip(rounds, rounds[1:]) if b[0] > a[0]]
    gaps = [b - a for a, b in zip(ok_starts, ok_starts[1:]) if b > a]
    durations = [r[1] for r in rounds]
    r2 = lambda v: None if v is None else round(v, 2)  # noqa: E731
    p95 = _percentile(gaps, 95)
    enough = len(gaps) >= 5
    return {
        "configuredIntervalSeconds": interval,
        "intervalSeconds": r2(_percentile(periods, 50)),
        "observedCycleSecondsP50": r2(_percentile(periods, 50)),
        "observedCycleSecondsP95": r2(_percentile(periods, 95)),
        "successGapSecondsP95": r2(p95),
        "maxFirstDetectionDelaySeconds": r2(max(gaps) if gaps else None),
        "roundDurationSecondsP50": r2(_percentile(durations, 50)),
        "roundDurationSecondsP95": r2(_percentile(durations, 95)),
        # Connections shorter than this may be missed (p95 of measured gaps between successful rounds).
        "missesShorterThanSeconds": r2(p95),
        "windowRounds": len(rounds),
        "windowFailedRounds": sum(1 for r in rounds if not r[2]),
        "windowFrom": utc_iso(rounds[0][0]) if rounds else None,
        "measurementConfidence": "Observed" if enough else "Unknown",
        "measurementNote": ("实测：最近 %d 轮的实际周期与成功采样间隔（跨重启保留）" % len(rounds)) if enough
        else "实测样本不足 6 轮，尚不能给出周期；不要按配置间隔理解覆盖",
    }


# ------------------------------------------------------------- the sampler

class Sampler:
    """Long-lived sampler state: process cache, in-memory ledger, signing chain."""

    def __init__(self, ledger_path: pathlib.Path, roots: dict[int, str] | None = None, discover: bool = True,
                 interval: float | None = None, resolve: bool = True,
                 route_paths: Iterable[pathlib.Path] = DEFAULT_ROUTES,
                 v2ray_log: pathlib.Path = DEFAULT_V2RAY_LOG,
                 transport_root: pathlib.Path = DEFAULT_TRANSPORT,
                 key: bytes | None = None, key_reason: str | None = None,
                 seal_path: pathlib.Path | None = None,
                 dns_budget: float = 0.4, round_budget: float | None = None) -> None:
        self.ledger_path = ledger_path
        self.lock_path = ledger_path.with_name(ledger_path.name + ".lock")
        self.side_path = sidecar_path(ledger_path)
        self.seal_path = seal_path or ledger_path.with_name(ledger_path.name + ".seal")
        self.roots, self.discover, self.interval, self.resolve = roots, discover, interval, resolve
        self.route_paths, self.v2ray_log = list(route_paths), v2ray_log
        self.transport = TransportIndex(transport_root)
        self.key, self.key_reason = key, key_reason
        self.dns_budget = dns_budget
        self.round_budget = round_budget if round_budget else max(4.0, 3 * (interval or 2.0))
        self.procs = ProcessTable()
        self.ledger: dict[str, Any] | None = None
        self.written: tuple[int, int, int] | None = None
        self.chain: tuple[int, str] = (0, "0" * 64)
        self.started_at = time.time()
        ledger_path.parent.mkdir(parents=True, exist_ok=True)

    # -- persistence
    def _stat(self) -> tuple[int, int, int] | None:
        try:
            st = self.ledger_path.stat()
            return (st.st_ino, st.st_size, st.st_mtime_ns)
        except OSError:
            return None

    def _event(self, ledger: dict[str, Any], kind: str, stage: str, reason: str, at: float | None = None,
               count: bool = True, **extra: Any) -> None:
        stats = ledger.setdefault("samples", {})
        log = stats.setdefault("failureLog", [])
        log.append(dict({"at": utc_iso(at), "kind": kind, "stage": stage, "reason": reason}, **extra))
        del log[:-FAILURE_LOG_MAX]
        if count:
            stats["failures"] = int(stats.get("failures", 0)) + 1
            stats["lastFailure"] = "%s/%s: %s" % (stage, kind, reason)
            stats["lastFailureAt"] = utc_iso(at)

    def _load(self) -> dict[str, Any]:
        """Reload only if someone else replaced the file since we wrote it. Verify before continuing a chain."""
        if self.ledger is not None and self._stat() == self.written:
            return self.ledger
        data = _read_bytes(self.ledger_path)
        side = _read_json(self.side_path)
        seal = _read_json(self.seal_path)
        check = verify_snapshot(data, side, seal, self.key) if self.key else None
        seal_ok = isinstance(seal, dict) and not seal.get("unsigned") and isinstance(seal.get("seq"), int)
        if check and check["state"] == "tampered":
            # Never re-sign tampered content: keep it aside for review, start clean, record the event.
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            kept = None
            if data is not None:
                kept = self.ledger_path.with_name("%s.tampered-%s" % (self.ledger_path.name, stamp))
                os.replace(self.ledger_path, kept)
                if self.side_path.exists():
                    os.replace(self.side_path, kept.with_name(kept.name + ".mac"))
            ledger = empty_ledger()
            ledger["integrityEvents"] = [{"at": utc_iso(), "kind": "tamper_detected_at_load",
                                          "reason": check["reason"], "quarantinedAs": kept.name if kept else None}]
            self._event(ledger, "integrity", "load", check["reason"])
            self.chain = (int(seal["seq"]), str(seal.get("hash"))) if seal_ok else (0, "0" * 64)
            return ledger
        ledger = load_ledger(self.ledger_path) if data is not None else empty_ledger()
        if isinstance(side, dict) and not side.get("unsigned") and isinstance(side.get("seq"), int):
            self.chain = (int(side["seq"]), str(side.get("hash")))
        elif seal_ok:
            self.chain = (int(seal["seq"]), str(seal.get("hash")))
        return ledger

    def _save(self, ledger: dict[str, Any]) -> None:
        seq, prev = self.chain
        if self.key and "integritySince" not in ledger:
            # Rows that existed before the first signature are only protected from this moment on.
            ledger["integritySince"] = utc_iso()
        data = save_ledger(self.ledger_path, ledger)
        if self.key:
            side = sign_snapshot(data, seq + 1, prev, self.key)
            text = (canonical(side) + "\n").encode("utf-8")
            _atomic_write(self.side_path, text)
            _atomic_write(self.seal_path, text)
            self.chain = (side["seq"], side["hash"])
        else:
            _atomic_write(self.side_path, (canonical({"unsigned": True, "reason": self.key_reason or
                                                      "integrity key unavailable"}) + "\n").encode("utf-8"))
        self.ledger = ledger
        self.written = self._stat()

    # -- lifecycle events
    def note_start(self) -> None:
        """A restart after a gap (crash, launchd restart, machine asleep) is recorded, not hidden."""
        with open(self.lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            ledger = self._load()
            stats = ledger.setdefault("samples", {})
            last = parse_iso(stats.get("lastAt"))
            now = time.time()
            stats["samplerStartedAt"] = utc_iso(now)
            stats["samplerPid"] = os.getpid()
            stats["starts"] = int(stats.get("starts", 0)) + 1
            limit = 2 * (self.interval or 2.0)
            if last is not None and now - last > limit:
                prev_stop = (stats.get("failureLog") or [{}])[-1]
                clean = prev_stop.get("kind") == "stopped" and (parse_iso(prev_stop.get("at")) or 0) >= last
                self._event(ledger, "restart_gap", "start",
                            "no sample for %.1fs before this start%s" % (now - last, " (after a clean stop)" if clean
                                                                         else " (previous sampler exited or was killed)"),
                            at=now, gapFrom=stats.get("lastAt"), gapSeconds=round(now - last, 1))
            if self.key is None and self.key_reason:
                # The key load failed (helper timeout / needs approval / error): sampling continues unsigned,
                # and the Keychain problem is a counted failure with its reason, never silent.
                self._event(ledger, "key_unavailable", "keychain", self.key_reason, at=now)
            self._save(ledger)

    def note_stop(self, reason: str) -> None:
        try:
            with open(self.lock_path, "a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                ledger = self._load()
                self._event(ledger, "stopped", "signal", reason, count=False)
                self._save(ledger)
        except Exception:
            pass

    # -- one round
    def sample(self) -> dict[str, Any]:
        with open(self.lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            ledger = self._load()
            observed_at = time.time()
            t0 = time.monotonic()
            failure: SampleError | None = None
            partial = None
            touched: list[dict[str, Any]] = []
            owners: dict[int, str] = {}
            deferred = 0
            try:
                budget = self.round_budget
                procs = self.procs.snapshot(timeout=min(5.0, budget * 0.5))
                owners = agent_tree(procs, self.roots, self.discover)
                left = budget - (time.monotonic() - t0)
                if left <= 0.2:
                    raise SampleError("ps", "timeout", "process snapshot used the whole round budget")
                sockets, partial = run_lsof_all(timeout=min(8.0, left))
                late = attribute_sockets(sockets, procs, owners)
                if late:
                    self.procs.add_late(late, procs, timeout=1.5)
                touched = merge_sample(ledger, sockets, procs, owners, observed_at)
                routes = load_audit_proxy_routes(self.route_paths) + load_v2ray_routes(self.v2ray_log)
                resolver = Resolver(ledger.setdefault("dnsCache", {}), enabled=self.resolve, budget=self.dns_budget)
                resolve_destinations(touched, routes, self.transport.hosts(), procs, resolver)
                resolver.close()
                deferred = resolver.deferred
            except SampleError as exc:
                failure = exc
            except Exception as exc:  # any bug in one round must not kill the sampler or vanish
                failure = SampleError("round", "error", "%s: %s" % (exc.__class__.__name__, str(exc)[:200]))
            duration = time.monotonic() - t0
            stats = ledger.setdefault("samples", {})
            ok = failure is None and partial is None
            rounds = stats.setdefault("rounds", [])
            rounds.append([round(observed_at, 3), round(duration, 3), ok])
            del rounds[:-ROUND_WINDOW]
            stats["count"] = int(stats.get("count", 0)) + 1
            stats.setdefault("firstAt", utc_iso(observed_at))
            if failure is None:
                stats["lastAt"] = utc_iso(observed_at)
                stats["lastProcessCount"] = len(owners)
                stats["lastAgents"] = sorted(set(owners.values()))
                stats["lastSocketCount"] = len(touched)
                stats["dnsDeferred"] = deferred
            if failure is not None:
                self._event(ledger, failure.kind, failure.stage, failure.reason, at=observed_at)
            elif partial:
                self._event(ledger, "partial", "lsof", partial, at=observed_at)
            ledger["sampler"] = SAMPLER_VERSION
            cov = measured_coverage(stats, self.interval)
            cov.update({
                "method": "per-process socket sampling: ps -axo pid,ppid,comm each round (lstart/args cached per "
                          "new pid) + one lsof -i (TCP+UDP) for all sockets filtered to agent trees; "
                          "independent of proxy settings",
                "limitation": LIMITATION,
                "failures": int(stats.get("failures", 0)),
                "confidence": "Observed" if ok and cov["measurementConfidence"] == "Observed" else "Unknown",
            })
            ledger["coverage"] = cov
            try:
                self._save(ledger)
            except OSError as exc:
                self.ledger = None  # force reload next round
                raise SampleError("save", "error", "ledger write failed: %s" % exc.__class__.__name__) from None
            return {"observedAt": utc_iso(observed_at), "processes": len(owners), "sockets": touched,
                    "failure": None if failure is None else "%s/%s: %s" % (failure.stage, failure.kind, failure.reason),
                    "partial": partial, "durationSeconds": round(duration, 3)}


def sample_once(ledger_path: pathlib.Path, roots: dict[int, str] | None = None, discover: bool = True,
                interval: float | None = None, resolve: bool = True,
                route_paths: Iterable[pathlib.Path] = DEFAULT_ROUTES,
                v2ray_log: pathlib.Path = DEFAULT_V2RAY_LOG,
                transport_root: pathlib.Path = DEFAULT_TRANSPORT,
                key: bytes | None = None, seal_path: pathlib.Path | None = None) -> dict[str, Any]:
    return Sampler(ledger_path, roots, discover, interval, resolve, route_paths, v2ray_log, transport_root,
                   key=key, seal_path=seal_path).sample()


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
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--duration", type=float, default=0, help="watch for N seconds (0 = forever)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--no-dns", action="store_true", help="skip reverse/forward DNS lookups")
    ap.add_argument("--json", action="store_true", help="print each sample's touched rows as JSON")
    args = ap.parse_args(argv)
    roots = parse_roots(args.root_pid)
    key, integrity_dir, key_reason = load_integrity_key()
    sampler = Sampler(args.ledger, roots, not args.no_discover, args.interval, not args.no_dns,
                      key=key, key_reason=key_reason, seal_path=default_seal_path(args.ledger, integrity_dir))
    stop = {"flag": False}

    def on_signal(signum, _frame):  # launchd sends SIGTERM on bootout / stop
        stop["flag"] = True
        sampler.note_stop("signal %d" % signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_signal)
    sampler.note_start()
    deadline = time.time() + args.duration if args.duration else None
    last: dict[str, Any] = {}
    while not stop["flag"]:
        started = time.monotonic()
        try:
            last = sampler.sample()
        except SampleError as exc:  # ledger could not be written; say so on stderr and keep going
            print("socket-sampler: %s" % exc, file=sys.stderr, flush=True)
            last = {"failure": str(exc)}
        if args.json:
            print(json.dumps(last, ensure_ascii=False, sort_keys=True), flush=True)
        if args.once or (deadline and time.time() >= deadline):
            return 0 if not last.get("failure") else 2
        time.sleep(max(0.05, args.interval - (time.monotonic() - started)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
