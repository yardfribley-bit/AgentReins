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
import time

app = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "AgentReins.app").resolve()
mcp = app / "Contents/MacOS/AgentReinsMCP"
sampler = app / "Contents/Resources/socket-sampler/socket_sampler.py"
host = os.environ.get("LIVE_SOCKET_HOST", "github.com")
env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
work = pathlib.Path(tempfile.mkdtemp(prefix="mcp-socket-"))
ledger = work / "socket-ledger.json"
env["AGENTREINS_SOCKET_LEDGER"] = str(ledger)
env["AGENTREINS_TRANSPORT_ROOT"] = str(work / "transport")

MIN_ROUNDS = 3
WAIT_SECONDS = 60.0
sampler_log = work / "sampler.log"


def ledger_state() -> dict:
    try:
        return json.loads(ledger.read_text())
    except (OSError, ValueError):
        return {}


def diagnostics(sampler_proc) -> str:
    """Everything needed to tell 'sampler died', 'sampler hung' and 'MCP was slow' apart."""
    data = ledger_state()
    samples = data.get("samples") or {}
    side = work / (ledger.name + ".mac")
    try:
        side_text = side.read_text()
        side_info = {"present": True, "signed": "mac" in json.loads(side_text),
                     "unsignedReason": json.loads(side_text).get("reason")}
    except (OSError, ValueError):
        side_info = {"present": False}
    try:
        log = sampler_log.read_text()[-4000:]
    except OSError:
        log = "<no sampler log>"
    return "\n".join([
        "--- sampler returncode: %s" % (sampler_proc.poll() if sampler_proc else None),
        "--- ledger samples: " + json.dumps({k: samples.get(k) for k in (
            "count", "firstAt", "lastAt", "failures", "lastFailure", "starts", "samplerStartedAt")}),
        "--- ledger failureLog: " + json.dumps((samples.get("failureLog") or [])[-10:], ensure_ascii=False),
        "--- ledger coverage: " + json.dumps(data.get("coverage") or {}, ensure_ascii=False)[:1500],
        "--- sidecar: " + json.dumps(side_info),
        "--- now: %.3f" % time.time(),
        "--- sampler stdout/stderr (tail):\n" + log,
    ])


child = subprocess.Popen([sys.executable, "-c",
    "import socket,sys,time\ns=socket.create_connection((sys.argv[1],443),timeout=10)\nprint('READY',flush=True)\ntime.sleep(120)", host],
    env=env, stdout=subprocess.PIPE, text=True)
sampler_proc = None
try:
    assert child.stdout.readline().strip() == "READY"
    # Keep the packaged sampler running (as the LaunchAgent does) so "sampling" is a true statement when
    # the MCP answers; wait for >= MIN_ROUNDS real rounds instead of trusting a single --once round.
    with open(sampler_log, "w") as log:
        sampler_proc = subprocess.Popen(
            [sys.executable, str(sampler), "--ledger", str(ledger), "--root-pid", f"{child.pid}:CI-Live",
             "--no-discover", "--interval", "0.5", "--duration", "110"],
            env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + WAIT_SECONDS
    while time.time() < deadline:
        count = int((ledger_state().get("samples") or {}).get("count") or 0)
        if count >= MIN_ROUNDS or sampler_proc.poll() is not None:
            break
        time.sleep(0.25)
    count = int((ledger_state().get("samples") or {}).get("count") or 0)
    assert sampler_proc.poll() is None, "packaged sampler exited early\n" + diagnostics(sampler_proc)
    assert count >= MIN_ROUNDS, "sampler wrote %d rounds in %.0fs\n%s" % (count, WAIT_SECONDS, diagnostics(sampler_proc))
    print("SAMPLER_ROUNDS", count, "after", round(WAIT_SECONDS - (deadline - time.time()), 1), "s")

    proc = subprocess.Popen([str(mcp)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)

    def call(obj):
        proc.stdin.write(json.dumps(obj) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if "id" in obj else None

    call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "ci-socket-live", "version": "1"}}})
    call({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    t0 = time.time()
    res = call({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "list_network", "arguments": {"agent": "CI-Live"}}})
    mcp_seconds = round(time.time() - t0, 2)
    proc.terminate()
    print("MCP_LIST_NETWORK_SECONDS", mcp_seconds)
    out = res["result"]["structuredContent"]
    rows = [r for r in out["sockets"] if r.get("pid") == child.pid and r.get("remotePort") == 443]
    assert rows, json.dumps(out)[:2000] + "\n" + diagnostics(sampler_proc)
    row = rows[0]
    assert row["viaProxy"] is False and row["evidence"] == "Observed" and row["protocol"] == "TCP", row
    assert out["socketCoverage"]["state"] == "sampling", (
        json.dumps(out["socketCoverage"], ensure_ascii=False)[:2000] + "\nMCP call took %ss\n" % mcp_seconds
        + diagnostics(sampler_proc))
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
        # Unsigned must be explained, and the Keychain problem must be a counted failure in the ledger.
        samples = ledger_state().get("samples") or {}
        assert [e for e in samples.get("failureLog") or [] if e.get("kind") == "key_unavailable"], samples
    assert out["socketSummary"]["ledgerIntegrity"] == integrity["state"]
    assert out["socketSummary"]["total"] >= 1
    print("MCP_LIST_NETWORK_SOCKET_OK", json.dumps({k: row.get(k) for k in (
        "pid", "ppid", "processName", "protocol", "remoteAddress", "viaProxy", "realDestination",
        "destinationSource", "destinationEvidence", "firstSeen")}, sort_keys=True))
finally:
    if sampler_proc is not None and sampler_proc.poll() is None:
        sampler_proc.terminate()
        try:
            sampler_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            sampler_proc.kill()
    child.kill()
