#!/usr/bin/env python3
"""Live check (CI, macOS runner): a real child process opens direct sockets with
every proxy variable removed; the sampler must attribute them to the right PID.

Nothing here is synthetic: the sockets are real, lsof/ps are the system tools,
and the printed ledger rows are what the sampler wrote. Exit code != 0 on any
mismatch. A short-lived `git ls-remote` is also sampled and reported (captured
or missed) to show the sampling limitation honestly; it does not fail the run.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
SAMPLER = HERE / "socket_sampler.py"
sys.path.insert(0, str(HERE))
from socket_sampler import LSOF  # noqa: E402
PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy")
HOST = os.environ.get("LIVE_SOCKET_HOST", "github.com")

CHILD = r'''
import socket, sys, time
t = socket.create_connection((sys.argv[1], 443), timeout=10)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(("1.1.1.1", 53))
print("READY", flush=True)
time.sleep(20)
'''


def clean_env():
    env = os.environ.copy()
    for key in PROXY_VARS:
        env.pop(key, None)
    return env


def children_of(pid):
    out = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True).stdout
    return [int(a) for a, b in (l.split() for l in out.splitlines() if l.strip()) if int(b) == pid]


def main():
    env = clean_env()
    work = pathlib.Path(tempfile.mkdtemp(prefix="socket-live-"))
    ledger = work / "ledger.json"
    # root shell -> python grandchild (the `; true` keeps bash from exec'ing python)
    root = subprocess.Popen(["/bin/bash", "-c", f'{sys.executable} -c "$0" {HOST}; true', CHILD],
                            env=env, stdout=subprocess.PIPE, text=True)
    unrelated = subprocess.Popen([sys.executable, "-c", CHILD, HOST], env=env, stdout=subprocess.PIPE, text=True)
    try:
        assert root.stdout.readline().strip() == "READY", "child could not connect directly"
        assert unrelated.stdout.readline().strip() == "READY"
        kids = children_of(root.pid)
        assert len(kids) == 1, kids
        child = kids[0]
        raw = subprocess.run([LSOF, "-nP", "-w", "-a", "-p", str(child), "-i", "-F", "pcRftPTn"],
                             capture_output=True, text=True).stdout
        print("RAW_LSOF_CHILD (%s, live):\n%s" % (sys.platform, raw))
        run = subprocess.run([sys.executable, str(SAMPLER), "--ledger", str(ledger), "--root-pid", f"{root.pid}:CI-Live",
                              "--no-discover", "--interval", "0.5", "--duration", "2", "--json"],
                             env=env, capture_output=True, text=True, timeout=60)
        assert run.returncode == 0, run.stderr
        data = json.loads(ledger.read_text())
        rows = data["connections"]
        tcp = [r for r in rows if r["pid"] == child and r["protocol"] == "TCP" and r["remotePort"] == 443]
        udp = [r for r in rows if r["pid"] == child and r["protocol"] == "UDP" and r["remotePort"] == 53]
        assert tcp, "direct TCP socket of the child was not captured"
        assert udp, "connected UDP socket of the child was not captured"
        t = tcp[0]
        assert t["ppid"] == root.pid, (t["ppid"], root.pid)
        assert t["viaProxy"] is False and t["evidence"] == "Observed" and t["agent"] == "CI-Live", t
        assert t["state"] == "ESTABLISHED", t["state"]
        assert t["sampleCount"] >= 2, t["sampleCount"]
        assert t["firstSeen"].endswith("Z") and t["lastSeen"].endswith("Z")
        assert not [r for r in rows if r["pid"] == unrelated.pid], "unrelated process leaked into the ledger"
        assert data["coverage"]["missesShorterThanSeconds"] == 0.5
        print("LIVE_DIRECT_TCP", json.dumps({k: t.get(k) for k in (
            "agent", "pid", "ppid", "processName", "protocol", "localAddress", "remoteAddress", "state",
            "viaProxy", "realDestination", "destinationSource", "destinationEvidence", "firstSeen", "lastSeen",
            "sampleCount")}, sort_keys=True))
        print("LIVE_DIRECT_UDP", json.dumps({k: udp[0].get(k) for k in (
            "pid", "protocol", "remoteAddress", "viaProxy", "realDestination", "destinationSource")}, sort_keys=True))
    finally:
        for p in (root, unrelated):
            p.kill()
        for kid in children_of(root.pid):
            try:
                os.kill(kid, 9)
            except OSError:
                pass

    # Short-lived command: report honestly whether a 0.2 s sampler caught it.
    short_ledger = work / "short.json"
    shell = subprocess.Popen(["/bin/bash", "-c", "sleep 1; git ls-remote https://github.com/git/git HEAD >/dev/null 2>&1; sleep 1"],
                             env=env)
    subprocess.run([sys.executable, str(SAMPLER), "--ledger", str(short_ledger), "--root-pid", f"{shell.pid}:CI-Live",
                    "--no-discover", "--interval", "0.2", "--duration", "4"], env=env, capture_output=True, timeout=60)
    shell.wait(timeout=30)
    short = json.loads(short_ledger.read_text()).get("connections", [])
    captured = [r for r in short if r.get("remotePort") == 443]
    print("SHORT_LIVED_GIT_LS_REMOTE captured=%s rows=%d (sampling may miss short connections; not a failure)"
          % (bool(captured), len(captured)))
    print("LIVE_SOCKET_SAMPLING_OK")


if __name__ == "__main__":
    main()
