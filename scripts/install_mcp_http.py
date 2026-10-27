#!/usr/bin/env python3
"""Install / remove the per-user LaunchAgent that serves AgentReins MCP on loopback HTTP.

The agent runs the packaged AgentReinsMCP binary:

  /Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP --http --port 18977

Any process of the same user can then call http://127.0.0.1:18977/mcp.
The listener binds 127.0.0.1 only. Default auth is none (Host, Origin, and
same-user peer checks). Pass --require-token to also require a bearer token
stored at ~/Library/Application Support/AgentGuard/mcp-http.token (mode 0600).
The token is created on install, not printed, and not written into the plist.

  python3 scripts/install_mcp_http.py
  python3 scripts/install_mcp_http.py --port 18977
  python3 scripts/install_mcp_http.py --require-token
  python3 scripts/install_mcp_http.py --binary /path/to/AgentReinsMCP
  python3 scripts/install_mcp_http.py --uninstall
  python3 scripts/install_mcp_http.py --print
"""
from __future__ import annotations

import argparse
import os
import pathlib
import plistlib
import secrets
import sys

LABEL = "com.agentreins.mcp-http"
APPLICATIONS_BIN = pathlib.Path("/Applications/AgentReins.app/Contents/MacOS/AgentReinsMCP")
PLIST = pathlib.Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
LOG = pathlib.Path.home() / "Library/Logs/AgentReins/mcp-http.log"
TOKEN = pathlib.Path.home() / "Library/Application Support/AgentGuard/mcp-http.token"
HERE = pathlib.Path(__file__).resolve().parent


def bundled_binary() -> pathlib.Path | None:
    """When this installer lives inside AgentReins.app, use that bundle's binary."""
    if HERE.name != "agentreins-mcp" or HERE.parent.name != "Resources":
        return None
    contents = HERE.parent.parent
    if contents.name != "Contents":
        return None
    return contents / "MacOS" / "AgentReinsMCP"


def resolve_binary(explicit: str | None) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit).expanduser()
    bundled = bundled_binary()
    if bundled is not None:
        return bundled
    return APPLICATIONS_BIN


def plist(binary: pathlib.Path, port: int, require_token: bool) -> dict:
    args = [str(binary), "--http", "--port", str(port)]
    if require_token:
        args.append("--require-token")
    return {
        "Label": LABEL,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 10,
        "StandardOutPath": str(LOG),
        "StandardErrorPath": str(LOG),
    }


def ensure_token() -> None:
    TOKEN.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(TOKEN.parent, 0o700)
    except OSError:
        pass
    if TOKEN.exists():
        try:
            os.chmod(TOKEN, 0o600)
        except OSError:
            pass
        return
    fd = os.open(str(TOKEN), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (secrets.token_hex(32) + "\n").encode())
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the AgentReins loopback HTTP MCP LaunchAgent")
    ap.add_argument("--port", type=int, default=18977)
    ap.add_argument("--binary", default=None, help="AgentReinsMCP executable (default: this .app, else /Applications)")
    ap.add_argument("--require-token", action="store_true",
                    help="Require Authorization: Bearer and create mcp-http.token if it is missing")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--print", action="store_true", help="Write the plist to stdout and do not install")
    args = ap.parse_args()
    if args.print and args.uninstall:
        print("--print and --uninstall are mutually exclusive", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535:
        print("port must be 1...65535", file=sys.stderr)
        return 2
    binary = resolve_binary(args.binary)
    data = plist(binary, args.port, args.require_token)
    if args.print:
        sys.stdout.buffer.write(plistlib.dumps(data))
        return 0
    if args.uninstall:
        uid = str(os.getuid())
        import subprocess
        subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(PLIST)], check=False)
        PLIST.unlink(missing_ok=True)
        print("removed", PLIST)
        return 0
    if not binary.is_file():
        print(f"AgentReinsMCP not found at {binary}; pass --binary", file=sys.stderr)
        return 1
    import subprocess
    uid = str(os.getuid())
    if args.require_token:
        ensure_token()
        print("bearer token file", TOKEN, "(mode 0600, contents not printed)")
    PLIST.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["launchctl", "bootout", f"gui/{uid}", str(PLIST)], check=False, capture_output=True)
    PLIST.write_bytes(plistlib.dumps(data))
    subprocess.run(["launchctl", "bootstrap", f"gui/{uid}", str(PLIST)], check=True)
    print("installed", PLIST, "port", args.port, "auth", "bearer" if args.require_token else "none")
    print("endpoint http://127.0.0.1:%s/mcp" % args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
