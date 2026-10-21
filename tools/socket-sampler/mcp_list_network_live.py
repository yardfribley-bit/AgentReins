#!/usr/bin/env python3
"""Live end-to-end (CI, macOS): packaged sampler -> ledger -> packaged Swift MCP list_network.

A real child process opens a direct TCP socket with proxy variables removed;
the packaged sampler records it; AgentReinsMCP (stdio) must return that row in
list_network.sockets with the same pid and viaProxy=false.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

app = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "AgentReins.app").resolve()
mcp = app / "Contents/MacOS/AgentReinsMCP"
sampler = app / "Contents/Resources/socket-sampler/socket_sampler.py"
host = os.environ.get("LIVE_SOCKET_HOST", "github.com")
env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
work = pathlib.Path(tempfile.mkdtemp(prefix="mcp-socket-"))
ledger = work / "socket-ledger.json"
env["AGENTREINS_SOCKET_LEDGER"] = str(ledger)
env["AGENTREINS_TRANSPORT_ROOT"] = str(work / "transport")

child = subprocess.Popen([sys.executable, "-c",
    "import socket,sys,time\ns=socket.create_connection((sys.argv[1],443),timeout=10)\nprint('READY',flush=True)\ntime.sleep(20)", host],
    env=env, stdout=subprocess.PIPE, text=True)
try:
    assert child.stdout.readline().strip() == "READY"
    run = subprocess.run([sys.executable, str(sampler), "--ledger", str(ledger), "--root-pid", f"{child.pid}:CI-Live",
                          "--no-discover", "--once"], env=env, capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    proc = subprocess.Popen([str(mcp)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)

    def call(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if "id" in obj else None

    call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ci-socket-live", "version": "1"}}})
    call({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    res = call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "list_network", "arguments": {"agent": "CI-Live"}}})
    proc.terminate()
    out = res["result"]["structuredContent"]
    rows = [r for r in out["sockets"] if r.get("pid") == child.pid and r.get("remotePort") == 443]
    assert rows, json.dumps(out)[:2000]
    row = rows[0]
    assert row["viaProxy"] is False and row["evidence"] == "Observed" and row["protocol"] == "TCP", row
    assert out["socketCoverage"]["state"] == "sampling", out["socketCoverage"]
    # Tamper evidence: if the packaged sampler signed the ledger (Keychain key via AgentReinsKeychainHelper),
    # the packaged Swift MCP must verify that exact signature with the same key.
    side = json.loads((ledger.parent / (ledger.name + ".mac")).read_text())
    integrity = out["socketCoverage"]["integrity"]
    print("LEDGER_INTEGRITY", json.dumps({"sidecarSigned": "mac" in side, "state": integrity.get("state"),
                                          "reason": integrity.get("reason")}))
    if "mac" in side:
        assert integrity["state"] == "verified", integrity
    else:
        assert integrity["state"] == "unsigned", integrity
    assert out["socketSummary"]["ledgerIntegrity"] == integrity["state"]
    assert out["socketSummary"]["total"] >= 1
    print("MCP_LIST_NETWORK_SOCKET_OK", json.dumps({k: row.get(k) for k in (
        "pid", "ppid", "processName", "protocol", "remoteAddress", "viaProxy", "realDestination",
        "destinationSource", "destinationEvidence", "firstSeen")}, sort_keys=True))
finally:
    child.kill()
