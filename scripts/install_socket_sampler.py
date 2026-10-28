#!/usr/bin/env python3
"""Install / remove the per-user LaunchAgent that runs tools/socket-sampler.

The sampler reads agent process trees (Codex, Cursor, WorkBuddy, Claude) with
libproc or procfs and, on macOS, lsof scoped to those pids. It does not run
lsof -i for the whole machine. It writes ~/Library/Application Support/AgentGuard/socket-ledger.json.
It changes nothing about agents, proxies or sockets.

  python3 scripts/install_socket_sampler.py            # install + load
  python3 scripts/install_socket_sampler.py --interval 2
  python3 scripts/install_socket_sampler.py --uninstall
  python3 scripts/install_socket_sampler.py --print    # show the plist only
"""
from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import subprocess
import sys

LABEL = "com.agentreins.socket-sampler"
HERE = pathlib.Path(__file__).resolve().parent
CANDIDATES = [HERE.parent / "tools" / "socket-sampler" / "socket_sampler.py", HERE / "socket_sampler.py"]
PLIST = pathlib.Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
LOG = pathlib.Path.home() / "Library/Logs/AgentReins/socket-sampler.log"


def plist(interval: float) -> dict:
    sampler = next((p for p in CANDIDATES if p.is_file()), None)
    if sampler is None:
        raise SystemExit("socket_sampler.py not found next to this installer")
    python = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
    return {
        "Label": LABEL,
        "ProgramArguments": [python, str(sampler), "--interval", str(interval)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
        "StandardOutPath": str(LOG),
        "StandardErrorPath": str(LOG),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--print", action="store_true")
    args = ap.parse_args()
    uid = str(os.getuid())
    if args.uninstall:
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(PLIST)], check=False)
        PLIST.unlink(missing_ok=True)
        print("removed", PLIST)
        return 0
    data = plist(args.interval)
    if args.print:
        sys.stdout.write(plistlib.dumps(data).decode())
        return 0
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(PLIST)], check=False, capture_output=True)
    PLIST.write_bytes(plistlib.dumps(data))
    subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(PLIST)], check=True)
    print("installed", PLIST, "interval", args.interval)
    return 0


if __name__ == "__main__":
    sys.exit(main())
