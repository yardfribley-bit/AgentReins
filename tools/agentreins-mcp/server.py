#!/usr/bin/env python3
"""AgentReins supervisor MCP — read-only stdio server for Codex.

Configure in ~/.codex/config.toml:

[mcp_servers.agentreins]
command = "python3"
args = ["/absolute/path/to/AgentGuardApp/tools/agentreins-mcp/server.py"]

No write tools. Evidence comes from existing transport-audit captures.
"""
from __future__ import annotations

import json
import pathlib
import sys
from typing import Any

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evidence import (
    KeychainUnavailable,
    append_audit,
    get_coverage,
    get_execution,
    list_agents,
    list_alerts,
    list_mcp_audit,
    list_network,
)

PROTOCOL = "2024-11-05"
SERVER_NAME = "agentreins-supervisor"
SERVER_VERSION = "0.1.0"
ACTOR = "Codex"

TOOLS = [
    {
        "name": "list_agents",
        "description": "List observed agents (Cursor/Codex/WorkBuddy), sessions and execution ids. Read-only.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_alerts",
        "description": "List risk alerts (S02/S03/S04/S07/INB) with execution id and confidence. Read-only.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "description": "Agent name filter, or all"},
                "since": {"type": "string", "description": "ISO timestamp lower bound"},
                "rule": {"type": "string", "description": "Rule id filter, e.g. S02"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_execution",
        "description": "Get one execution: command args, destination, downloads sha256, auditBypass. Secrets redacted.",
        "inputSchema": {
            "type": "object",
            "properties": {"execution_id": {"type": "string"}},
            "required": ["execution_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_network",
        "description": "Outbound network: transport-audit commands plus per-process sampled TCP/UDP sockets (proxied or not), with realDestination/transportPeer. Read-only, redacted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string"},
                "since": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_coverage",
        "description": "Rule coverage and blind spots (S01/S06). Unknown when not observed.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "list_mcp_audit",
        "description": "Recent supervisor MCP read audit entries (hash-chained append-only log).",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
            "additionalProperties": False,
        },
    },
]


def respond(msg_id: Any, result: Any) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def respond_error(msg_id: Any, code: int, message: str) -> None:
    sys.stdout.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}},
            ensure_ascii=False,
        )
        + "\n"
    )
    sys.stdout.flush()


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in {t["name"] for t in TOOLS}:
        raise ValueError(f"unknown or disallowed tool: {name}")
    # Hard deny any write-shaped names even if somehow requested.
    banned = ("write", "delete", "update", "set_", "save", "dismiss", "accept", "whitelist", "mute")
    lowered = name.lower()
    if any(b in lowered for b in banned):
        raise PermissionError("write tools are not available")
    try:
        append_audit(ACTOR, name, arguments or {})
    except KeychainUnavailable:
        # Same as the Swift MCP: without the Keychain key nothing is signed (never a throwaway key) and the
        # read is still answered; validate_audit / get_coverage report status key_unavailable.
        pass
    if name == "list_agents":
        return list_agents()
    if name == "list_alerts":
        return list_alerts(
            agent=arguments.get("agent"),
            since=arguments.get("since"),
            rule=arguments.get("rule"),
        )
    if name == "get_execution":
        eid = arguments.get("execution_id")
        if not eid:
            raise ValueError("execution_id required")
        return get_execution(str(eid))
    if name == "list_network":
        return list_network(agent=arguments.get("agent"), since=arguments.get("since"))
    if name == "get_coverage":
        return get_coverage()
    if name == "list_mcp_audit":
        limit = int(arguments.get("limit") or 30)
        return list_mcp_audit(limit=limit)
    raise ValueError(name)


def handle(message: dict[str, Any]) -> None:
    method = message.get("method")
    msg_id = message.get("id")
    params = message.get("params") or {}
    if method == "initialize":
        respond(
            msg_id,
            {
                "protocolVersion": params.get("protocolVersion") or PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Read-only AgentReins supervisor MCP. Use list_alerts/get_execution to review Cursor. "
                    "No write/delete/whitelist tools exist. Secrets are redacted."
                ),
            },
        )
        return
    if method == "notifications/initialized" or method == "initialized":
        return
    if method == "ping":
        respond(msg_id, {})
        return
    if method == "tools/list":
        respond(msg_id, {"tools": TOOLS})
        return
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            result = call_tool(str(name), arguments if isinstance(arguments, dict) else {})
            respond(
                msg_id,
                {
                    "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}],
                    "structuredContent": result,
                    "isError": False,
                },
            )
        except Exception as exc:  # noqa: BLE001 — surface to MCP client
            respond(
                msg_id,
                {
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                    "isError": True,
                },
            )
        return
    if msg_id is not None:
        respond_error(msg_id, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        handle(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
