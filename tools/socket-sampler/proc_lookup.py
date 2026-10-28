#!/usr/bin/env python3
"""Resolve a live local TCP client to its PID, parent chain and agent.

Used by the audit proxy (while the client socket is still open) and by the
socket sampler (agent-tree scoped collection). No client-supplied pid header
is read: the owner comes from the kernel.

Backends
  * Linux: /proc/net/tcp{,6} plus /proc/<pid>/fd (procfs). This is what tests run.
  * macOS processes: libproc proc_listpids + PROC_PIDTBSDINFO + proc_pidpath.
  * macOS sockets: libproc PROC_PIDFDSOCKETINFO when the ctypes layout matches
    the running kernel's socket_fdinfo size; otherwise one scoped ``lsof``
    (``-iTCP:<port>`` or ``-p <agent tree> -i``), never a whole-machine ``lsof -i``.

A miss is explicit (``via proxy · attribution lost``). Nothing is guessed from
a nearby socket or from a header.
"""
from __future__ import annotations

import ctypes
import datetime as _dt
import os
import re
import socket
import subprocess
import sys
from typing import Any, Callable, Iterable

LOST_STATE = "via proxy · attribution lost"
ATTRIBUTED_STATE = "via proxy · attributed"

# Same executable / argv[0..1] markers as socket_sampler.AGENT_MARKERS.
AGENT_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("Codex", re.compile(r"(?i)^(codex|codex-[\w.-]+)$")),
    ("Codex", re.compile(r"(?i)/Codex\.app/")),
    ("WorkBuddy", re.compile(r"(?i)^(workbuddy|codebuddy)$")),
    ("WorkBuddy", re.compile(r"(?i)/(WorkBuddy|CodeBuddy)\.app/")),
    ("Cursor", re.compile(r"(?i)^cursor-agent$")),
    ("Cursor", re.compile(r"(?i)/Cursor\.app/")),
    ("Claude", re.compile(r"(?i)^claude$")),
]
SELF_NAMES = ("AgentReins", "socket_sampler", "lsof", "mitmdump")

TCP_STATE = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

LsofRunner = Callable[[list[int], float], tuple[list[dict[str, Any]], str | None]]


class ProcUnavailable(OSError):
    """Fast backend cannot run; the caller may fall back to scoped lsof."""


def utc_from_epoch(seconds: float | None) -> str | None:
    if not seconds:
        return None
    value = _dt.datetime.fromtimestamp(seconds, tz=_dt.timezone.utc)
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def lost_attribution(detail: str | None = None) -> dict[str, Any]:
    """Explicit miss. pid/agent stay empty so a caller cannot mistake them for a guess."""
    return {
        "attributionState": LOST_STATE,
        "attribution": "lost",
        "clientPid": None,
        "clientPpid": None,
        "clientAgent": None,
        "clientProcess": None,
        "clientPath": None,
        "clientStartAt": None,
        "parentChain": [],
        "attributionBasis": None,
        "attributionDetail": detail or "client socket was not owned by a resolvable process",
    }


def _chain_record(pid: int, proc: dict[str, Any], agent: str | None) -> dict[str, Any]:
    return {
        "attributionState": ATTRIBUTED_STATE,
        "attribution": "observed",
        "clientPid": pid,
        "clientPpid": proc.get("ppid"),
        "clientAgent": agent,
        "clientProcess": proc.get("name"),
        "clientPath": proc.get("path"),
        "clientStartAt": proc.get("startAt"),
        "parentChain": proc.get("parentChain") or [],
        "attributionBasis": proc.get("basis"),
        "attributionDetail": "kernel socket owner while the client connection was open; "
                             "a client-supplied pid header is not accepted",
    }


# ------------------------------------------------------------------- procfs

def _decode_proc_addr(text: str) -> tuple[str, int]:
    ip_hex, _, port_hex = text.partition(":")
    port = int(port_hex, 16) if port_hex else 0
    if len(ip_hex) == 8:
        raw = bytes.fromhex(ip_hex)
        return ".".join(str(b) for b in raw[::-1]), port
    groups = []
    raw = bytes.fromhex(ip_hex)
    for index in range(0, len(raw), 4):
        groups.append(raw[index:index + 4][::-1])
    packed = b"".join(groups)
    if len(packed) == 16:
        return socket.inet_ntop(socket.AF_INET6, packed), port
    return ip_hex, port


def _read_proc_net(path: str, protocol: str) -> list[dict[str, Any]]:
    rows = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return rows
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local_ip, local_port = _decode_proc_addr(parts[1])
        remote_ip, remote_port = _decode_proc_addr(parts[2])
        state = TCP_STATE.get(parts[3].upper(), parts[3]) if protocol == "TCP" else None
        try:
            inode = parts[9]
        except IndexError:
            continue
        if inode in ("", "0"):
            continue
        rows.append({
            "protocol": protocol,
            "localIP": local_ip,
            "localPort": local_port,
            "remoteIP": remote_ip,
            "remotePort": remote_port,
            "state": state,
            "inode": inode,
            "family": "IPv6" if ":" in local_ip else "IPv4",
        })
    return rows


def procfs_tables() -> dict[str, dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, protocol in (("/proc/net/tcp", "TCP"), ("/proc/net/tcp6", "TCP"),
                           ("/proc/net/udp", "UDP"), ("/proc/net/udp6", "UDP")):
        rows.extend(_read_proc_net(path, protocol))
    return {row["inode"]: row for row in rows}


def _cmdline(pid: int) -> list[str]:
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
    return parts[:2]


def _exe(pid: int) -> str:
    try:
        return os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return ""


_BOOT_EPOCH: float | None = None


def _boot_epoch() -> float | None:
    global _BOOT_EPOCH
    if _BOOT_EPOCH is not None:
        return _BOOT_EPOCH
    try:
        with open("/proc/stat", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("btime "):
                    _BOOT_EPOCH = float(line.split()[1])
                    return _BOOT_EPOCH
    except (OSError, ValueError):
        pass
    _BOOT_EPOCH = 0.0
    return _BOOT_EPOCH


def _proc_stat(pid: int) -> tuple[str, int, float | None]:
    """(comm, ppid, start_epoch) from /proc/pid/stat. comm may contain spaces or parentheses."""
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return "?", 0, None
    end = text.rfind(")")
    start = text.find("(")
    if end < 0 or start < 0:
        return "?", 0, None
    comm = text[start + 1:end]
    rest = text[end + 2:].split()
    ppid = int(rest[1]) if len(rest) > 1 and rest[1].lstrip("-").isdigit() else 0
    start_epoch = None
    if len(rest) > 19:
        try:
            ticks = int(rest[19])
            hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
            boot = _boot_epoch() or 0
            if hz:
                start_epoch = boot + ticks / float(hz)
        except (ValueError, OSError, KeyError):
            start_epoch = None
    return comm or "?", ppid, start_epoch


def _one_proc(pid: int, basis: str = "procfs") -> dict[str, Any] | None:
    if pid <= 0 or not os.path.isdir("/proc/%d" % pid):
        return None
    comm, ppid, started = _proc_stat(pid)
    path = _exe(pid) or comm
    return {
        "pid": pid, "ppid": ppid or None, "path": path,
        "name": os.path.basename(path) or comm, "startAt": utc_from_epoch(started),
        "argvHead": _cmdline(pid), "basis": basis,
    }


def snapshot_processes(timeout: float = 2.0) -> dict[int, dict[str, Any]]:
    """Every visible process: pid, ppid, path, name, startAt, argvHead.

    Linux reads /proc. macOS uses libproc. Raises ProcUnavailable when neither works
    so the sampler can fall back to ps.
    """
    del timeout  # procfs/libproc are bounded by the kernel, not a tool timeout
    if os.path.isdir("/proc"):
        procs: dict[int, dict[str, Any]] = {}
        try:
            names = os.listdir("/proc")
        except OSError as exc:
            raise ProcUnavailable(str(exc)) from exc
        for name in names:
            if not name.isdigit():
                continue
            info = _one_proc(int(name))
            if info:
                procs[info["pid"]] = info
        if procs:
            return procs
        raise ProcUnavailable("procfs returned no processes")
    procs = _libproc_processes()
    if procs:
        return procs
    raise ProcUnavailable("libproc process list unavailable")


def _fd_inodes(pid: int) -> list[tuple[str, str]]:
    root = "/proc/%d/fd" % pid
    found = []
    try:
        fds = os.listdir(root)
    except OSError:
        return found
    for fd in fds:
        try:
            target = os.readlink("%s/%s" % (root, fd))
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            found.append((fd, target[8:-1]))
    return found


def procfs_sockets(pids: Iterable[int], procs: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """Sockets held by ``pids`` only. Listeners and unconnected UDP are omitted."""
    table = procfs_tables()
    out = []
    for pid in pids:
        proc = procs.get(pid) or {}
        for fd, inode in _fd_inodes(pid):
            row = table.get(inode)
            if not row:
                continue
            if row["protocol"] == "TCP" and row["state"] == "LISTEN":
                continue
            if row["protocol"] == "UDP" and (row["remotePort"] in (None, 0) or row["remoteIP"] in ("0.0.0.0", "::")):
                continue
            local = _endpoint(row["localIP"], row["localPort"])
            remote = _endpoint(row["remoteIP"], row["remotePort"])
            out.append({
                "pid": pid,
                "ppid": proc.get("ppid"),
                "command": proc.get("name"),
                "fd": fd,
                "family": row["family"],
                "protocol": row["protocol"],
                "state": row["state"] if row["protocol"] == "TCP" else None,
                "local": local,
                "localPort": row["localPort"],
                "remoteIP": row["remoteIP"],
                "remotePort": row["remotePort"],
                "remote": remote,
            })
    return out


def _endpoint(host: str, port: int | None) -> str:
    if port is None:
        return host
    return "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)


def _parent_chain(pid: int, limit: int = 8) -> tuple[list[dict[str, Any]], str | None]:
    chain = []
    agent = None
    seen: set[int] = set()
    cursor: int | None = pid
    while cursor and cursor > 0 and cursor not in seen and len(chain) < limit:
        seen.add(cursor)
        info = _one_proc(cursor) or _libproc_one(cursor)
        if not info:
            break
        found = agent_of(info)
        if agent is None and found:
            agent = found
        chain.append({"pid": info["pid"], "ppid": info.get("ppid"), "name": info.get("name"),
                      "path": info.get("path")})
        parent = info.get("ppid")
        cursor = int(parent) if isinstance(parent, int) and parent > 0 else None
    return chain, agent


def _procfs_attribute(client_port: int, server_port: int) -> dict[str, Any]:
    table = procfs_tables()
    wanted = [
        row for row in table.values()
        if row["protocol"] == "TCP" and row["state"] not in ("LISTEN", "TIME_WAIT")
        and row["localPort"] == client_port and row["remotePort"] == server_port
    ]
    if not wanted:
        return lost_attribution("no established socket with local port %s and peer %s" % (client_port, server_port))
    inodes = {row["inode"] for row in wanted}
    owners: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError as exc:
        return lost_attribution("procfs unreadable: %s" % exc.__class__.__name__)
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        for _fd, inode in _fd_inodes(pid):
            if inode in inodes:
                owners.append(pid)
                break
    owners = sorted(set(owners))
    if len(owners) != 1:
        return lost_attribution("socket owner count is %d; not guessing" % len(owners))
    return _finish_owner(owners[0], "procfs")


def _finish_owner(pid: int, basis: str) -> dict[str, Any]:
    info = _one_proc(pid, basis) or _libproc_one(pid)
    if not info:
        return lost_attribution("pid %d exited before its path could be read" % pid)
    chain, agent = _parent_chain(pid)
    info["parentChain"] = chain
    info["basis"] = basis
    # agent_of on the socket owner first; parent chain covers a python child of WorkBuddy.
    own = agent_of(info)
    info_agent = own or agent
    return _chain_record(pid, info, info_agent)


def attribute_client(client_port: int, server_port: int) -> dict[str, Any]:
    """PID, parent chain and agent for the process whose socket is client_port → server_port.

    Always returns a dict. On failure ``attributionState`` is ``via proxy · attribution lost``
    and ``clientPid`` is null.
    """
    try:
        client_port = int(client_port)
        server_port = int(server_port)
    except (TypeError, ValueError):
        return lost_attribution("client port is not an integer")
    if client_port <= 0 or client_port > 65535 or server_port <= 0 or server_port > 65535:
        return lost_attribution("client or proxy port missing")
    if os.path.exists("/proc/net/tcp"):
        return _procfs_attribute(client_port, server_port)
    found = _libproc_attribute(client_port, server_port)
    if found is not None and found.get("attribution") == "observed":
        return found
    lsof_hit = _lsof_port_attribute(client_port, server_port)
    if lsof_hit.get("attribution") == "observed":
        return lsof_hit
    if found is not None and found.get("attribution") == "lost":
        return found
    return lsof_hit


# ------------------------------------------------------------------- libproc

def _libproc():
    if sys.platform != "darwin":
        return None
    try:
        return ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


PROC_PIDTBSDINFO = 3
PROC_PIDLISTFDS = 1
PROC_PIDFDSOCKETINFO = 3
PROC_ALL_PIDS = 1
PROX_FDTYPE_SOCKET = 2
SOCKINFO_TCP = 2
TSI_S_LISTEN = 1


class _VinfoStat(ctypes.Structure):
    _fields_ = [
        ("vst_dev", ctypes.c_uint32),
        ("vst_mode", ctypes.c_uint16),
        ("vst_nlink", ctypes.c_uint16),
        ("vst_ino", ctypes.c_uint64),
        ("vst_uid", ctypes.c_uint32),
        ("vst_gid", ctypes.c_uint32),
        ("vst_atime", ctypes.c_int64),
        ("vst_atimensec", ctypes.c_int64),
        ("vst_mtime", ctypes.c_int64),
        ("vst_mtimensec", ctypes.c_int64),
        ("vst_ctime", ctypes.c_int64),
        ("vst_ctimensec", ctypes.c_int64),
        ("vst_birthtime", ctypes.c_int64),
        ("vst_birthtimensec", ctypes.c_int64),
        ("vst_size", ctypes.c_int64),
        ("vst_blocks", ctypes.c_int64),
        ("vst_blksize", ctypes.c_int32),
        ("vst_flags", ctypes.c_uint32),
        ("vst_gen", ctypes.c_uint32),
        ("vst_rdev", ctypes.c_uint32),
        ("vst_qspare", ctypes.c_int64 * 2),
    ]


class _SockbufInfo(ctypes.Structure):
    _fields_ = [
        ("sbi_cc", ctypes.c_uint32),
        ("sbi_hiwat", ctypes.c_uint32),
        ("sbi_mbcnt", ctypes.c_uint32),
        ("sbi_mbmax", ctypes.c_uint32),
        ("sbi_lowat", ctypes.c_uint32),
        ("sbi_flags", ctypes.c_short),
        ("sbi_timeo", ctypes.c_short),
    ]


class _In4In6(ctypes.Structure):
    _fields_ = [("pad", ctypes.c_uint32 * 3), ("addr", ctypes.c_uint32)]


class _InSockInfo(ctypes.Structure):
    _fields_ = [
        ("insi_fport", ctypes.c_int),
        ("insi_lport", ctypes.c_int),
        ("insi_gencnt", ctypes.c_uint64),
        ("insi_flags", ctypes.c_uint32),
        ("insi_flow", ctypes.c_uint32),
        ("insi_vflag", ctypes.c_uint8),
        ("insi_ip_ttl", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 2),
        ("rfu_1", ctypes.c_uint32),
        ("insi_faddr", _In4In6),
        ("insi_laddr", _In4In6),
        ("in4_tos", ctypes.c_uint8),
        ("_pad2", ctypes.c_uint8 * 3),
    ]


class _TcpSockInfo(ctypes.Structure):
    _fields_ = [
        ("tcpsi_ini", _InSockInfo),
        ("tcpsi_state", ctypes.c_int),
        ("tcpsi_timer", ctypes.c_int * 4),
        ("tcpsi_mss", ctypes.c_int),
        ("tcpsi_flags", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
    ]


class _SocketInfoUnion(ctypes.Union):
    _fields_ = [("pri_tcp", _TcpSockInfo), ("raw", ctypes.c_byte * 512)]


class _SocketInfo(ctypes.Structure):
    _fields_ = [
        ("soi_stat", _VinfoStat),
        ("soi_so", ctypes.c_uint64),
        ("soi_pcb", ctypes.c_uint64),
        ("soi_type", ctypes.c_int),
        ("soi_protocol", ctypes.c_int),
        ("soi_family", ctypes.c_int),
        ("soi_options", ctypes.c_short),
        ("soi_linger", ctypes.c_short),
        ("soi_state", ctypes.c_short),
        ("soi_qlen", ctypes.c_short),
        ("soi_incqlen", ctypes.c_short),
        ("soi_qlimit", ctypes.c_short),
        ("soi_timeo", ctypes.c_short),
        ("soi_error", ctypes.c_ushort),
        ("soi_oobmark", ctypes.c_uint32),
        ("soi_rcv", _SockbufInfo),
        ("soi_snd", _SockbufInfo),
        ("soi_kind", ctypes.c_int),
        ("rfu_1", ctypes.c_uint32),
        ("soi_proto", _SocketInfoUnion),
    ]


class _ProcFileInfo(ctypes.Structure):
    _fields_ = [
        ("fi_openflags", ctypes.c_uint32),
        ("fi_status", ctypes.c_uint32),
        ("fi_offset", ctypes.c_int64),
        ("fi_type", ctypes.c_int32),
        ("fi_guardflags", ctypes.c_uint32),
    ]


class _SocketFdInfo(ctypes.Structure):
    _fields_ = [("pfi", _ProcFileInfo), ("psi", _SocketInfo)]


class _ProcFdInfo(ctypes.Structure):
    _fields_ = [("proc_fd", ctypes.c_int32), ("proc_fdtype", ctypes.c_uint32)]


_LAYOUT_OK: bool | None = None


def _libproc_layout_ok(lib) -> bool:
    """True only when PROC_PIDFDSOCKETINFO accepts our ctypes sizeof (kernel layout matches)."""
    global _LAYOUT_OK
    if _LAYOUT_OK is not None:
        return _LAYOUT_OK
    probe = _ProcBsdInfo()
    size = lib.proc_pidinfo(os.getpid(), PROC_PIDTBSDINFO, 0, ctypes.byref(probe), ctypes.sizeof(probe))
    _LAYOUT_OK = int(size) == ctypes.sizeof(probe) and int(probe.pbi_pid) == os.getpid()
    return _LAYOUT_OK


def _libproc_processes() -> dict[int, dict[str, Any]]:
    lib = _libproc()
    if lib is None or not _libproc_layout_ok(lib):
        return {}
    lib.proc_listpids.restype = ctypes.c_int
    lib.proc_pidinfo.restype = ctypes.c_int
    lib.proc_pidpath.restype = ctypes.c_int
    bytes_needed = lib.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
    if bytes_needed <= 0:
        return {}
    count = max(bytes_needed // ctypes.sizeof(ctypes.c_int), 1) + 16
    buf = (ctypes.c_int * count)()
    wrote = lib.proc_listpids(PROC_ALL_PIDS, 0, buf, ctypes.sizeof(buf))
    if wrote <= 0:
        return {}
    procs = {}
    for index in range(wrote // ctypes.sizeof(ctypes.c_int)):
        pid = int(buf[index])
        info = _libproc_one(pid, lib)
        if info:
            procs[pid] = info
    return procs


def _libproc_one(pid: int, lib=None) -> dict[str, Any] | None:
    if sys.platform != "darwin" or pid <= 0:
        return None
    lib = lib or _libproc()
    if lib is None or not _libproc_layout_ok(lib):
        return None
    info = _ProcBsdInfo()
    size = lib.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info))
    if int(size) != ctypes.sizeof(info) or int(info.pbi_pid) != pid:
        return None
    path_buf = ctypes.create_string_buffer(4096)
    npath = lib.proc_pidpath(pid, path_buf, 4096)
    path = path_buf.value.decode("utf-8", "replace") if npath > 0 else ""
    comm = info.pbi_name.split(b"\0", 1)[0].decode("utf-8", "replace") or \
        info.pbi_comm.split(b"\0", 1)[0].decode("utf-8", "replace")
    if not path:
        path = comm
    return {
        "pid": pid,
        "ppid": int(info.pbi_ppid) or None,
        "path": path,
        "name": os.path.basename(path) or comm or "?",
        "startAt": utc_from_epoch(int(info.pbi_start_tvsec) or None),
        "argvHead": [],
        "basis": "libproc",
    }


def _ports_match(ini: _InSockInfo, client_port: int, server_port: int) -> bool:
    local_raw = int(ini.insi_lport) & 0xFFFF
    foreign_raw = int(ini.insi_fport) & 0xFFFF
    local = socket.ntohs(local_raw)
    foreign = socket.ntohs(foreign_raw)
    if local == client_port and foreign == server_port:
        return True
    # Some SDKs already store host order. Accept that only as a pair, never a single side.
    return local_raw == client_port and foreign_raw == server_port


def _libproc_attribute(client_port: int, server_port: int) -> dict[str, Any] | None:
    """None when libproc socket layout is unavailable (caller uses scoped lsof).

    A resolved owner or an explicit lost result is returned only after the kernel
    accepted our socket_fdinfo size, so a mismatched struct cannot invent a pid.
    """
    lib = _libproc()
    if lib is None or not _libproc_layout_ok(lib):
        return None
    lib.proc_pidinfo.restype = ctypes.c_int
    lib.proc_pidfdinfo.restype = ctypes.c_int
    lib.proc_listpids.restype = ctypes.c_int
    bytes_needed = lib.proc_listpids(PROC_ALL_PIDS, 0, None, 0)
    if bytes_needed <= 0:
        return None
    count = bytes_needed // ctypes.sizeof(ctypes.c_int) + 8
    buf = (ctypes.c_int * count)()
    wrote = lib.proc_listpids(PROC_ALL_PIDS, 0, buf, ctypes.sizeof(buf))
    if wrote <= 0:
        return None
    socket_size = ctypes.sizeof(_SocketFdInfo)
    fd_size = ctypes.sizeof(_ProcFdInfo)
    matches: list[int] = []
    self_pid = os.getpid()
    for index in range(wrote // ctypes.sizeof(ctypes.c_int)):
        pid = int(buf[index])
        if pid <= 0 or pid == self_pid:
            continue
        fb = lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, None, 0)
        if fb <= 0 or fb > 1024 * 1024:
            continue
        nfd = fb // fd_size + 2
        fds = (_ProcFdInfo * nfd)()
        got = lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ctypes.byref(fds), ctypes.sizeof(fds))
        if got <= 0:
            continue
        for slot in range(got // fd_size):
            if int(fds[slot].proc_fdtype) != PROX_FDTYPE_SOCKET:
                continue
            info = _SocketFdInfo()
            nb = lib.proc_pidfdinfo(pid, int(fds[slot].proc_fd), PROC_PIDFDSOCKETINFO,
                                    ctypes.byref(info), socket_size)
            if int(nb) != socket_size:
                # Layout does not match this kernel: do not interpret bytes as a pid.
                return None
            if int(info.psi.soi_kind) != SOCKINFO_TCP:
                continue
            if int(info.psi.soi_proto.pri_tcp.tcpsi_state) == TSI_S_LISTEN:
                continue
            if _ports_match(info.psi.soi_proto.pri_tcp.tcpsi_ini, client_port, server_port):
                matches.append(pid)
                break
    matches = sorted(set(matches))
    if len(matches) != 1:
        return lost_attribution("libproc socket owner count is %d; not guessing" % len(matches))
    return _finish_owner(matches[0], "libproc")


# ------------------------------------------------------------------- scoped lsof

def _lsof_bin() -> str:
    return "/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else "lsof"


def _lsof_port_attribute(client_port: int, server_port: int) -> dict[str, Any]:
    """One ``lsof -iTCP:<client port>``. The whole machine is not walked with ``lsof -i``."""
    cmd = [_lsof_bin(), "-nP", "-w", "-iTCP:%d" % client_port, "-sTCP:ESTABLISHED", "-F", "pcRn"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return lost_attribution("scoped lsof failed: %s" % exc.__class__.__name__)
    if proc.returncode not in (0, 1):
        return lost_attribution("scoped lsof exit %s" % proc.returncode)
    owners = []
    pid = None
    for raw in proc.stdout.splitlines():
        if not raw:
            continue
        tag, value = raw[0], raw[1:]
        if tag == "p" and value.isdigit():
            pid = int(value)
        elif tag == "n" and "->" in value and pid:
            local, _, remote = value.partition("->")
            local = local.split(" (", 1)[0]
            remote = remote.split(" (", 1)[0]
            try:
                lport = int(local.rsplit(":", 1)[-1])
                rport = int(remote.rsplit(":", 1)[-1])
            except ValueError:
                continue
            if lport == client_port and rport == server_port:
                owners.append(pid)
    owners = sorted(set(owners))
    if len(owners) != 1:
        return lost_attribution("scoped lsof owner count is %d; not guessing" % len(owners))
    return _finish_owner(owners[0], "lsof-port")


def scoped_lsof_command(pids: list[int]) -> list[str]:
    return [_lsof_bin(), "-nP", "-w", "-a", "-p", ",".join(str(p) for p in pids), "-i", "-F", "pcRftPTn"]
