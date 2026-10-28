#!/usr/bin/env python3
"""Loopback HTTP MCP tests.

Installer checks always run. Transport checks need the packaged (or built) AgentReinsMCP
binary and macOS libproc, so `python3 -m unittest discover` before packaging skips them.
CI runs this file again with the binary path after `package_app.sh`:

  python3 tools/agentreins-mcp/test_http_transport.py AgentReins.app/Contents/MacOS/AgentReinsMCP
"""
from __future__ import annotations

import json
import os
import pathlib
import plistlib
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import http.client
from concurrent.futures import ThreadPoolExecutor

REPO = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPO / "scripts" / "install_mcp_http.py"
TOOLS = {"list_agents", "list_alerts", "get_execution", "list_network", "get_coverage", "list_mcp_audit"}


class InstallerPlistTests(unittest.TestCase):
    def test_print_plist_shape(self) -> None:
        out = subprocess.check_output([sys.executable, str(INSTALLER), "--print", "--port", "18977"])
        data = plistlib.loads(out)
        self.assertEqual(data["Label"], "com.agentreins.mcp-http")
        args = data["ProgramArguments"]
        self.assertTrue(str(args[0]).endswith("AgentReinsMCP"), args)
        self.assertEqual(args[1:], ["--http", "--port", "18977"])
        self.assertTrue(data["RunAtLoad"])
        self.assertTrue(data["KeepAlive"])
        self.assertEqual(data["ProcessType"], "Background")
        self.assertEqual(data["ThrottleInterval"], 10)
        self.assertTrue(str(data["StandardOutPath"]).endswith("mcp-http.log"), data["StandardOutPath"])
        self.assertEqual(data["StandardOutPath"], data["StandardErrorPath"])

    def test_print_require_token_flag_writes_nothing(self) -> None:
        home = pathlib.Path(tempfile.mkdtemp(prefix="ar-mcp-install-"))
        env = os.environ.copy()
        env["HOME"] = str(home)
        out = subprocess.check_output(
            [sys.executable, str(INSTALLER), "--print", "--require-token", "--port", "18977"],
            env=env,
        )
        data = plistlib.loads(out)
        self.assertIn("--require-token", data["ProgramArguments"])
        self.assertFalse((home / "Library/LaunchAgents/com.agentreins.mcp-http.plist").exists())
        self.assertFalse((home / "Library/Application Support/AgentGuard/mcp-http.token").exists())

    def test_print_rejects_bad_port(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(INSTALLER), "--print", "--port", "0"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)


class Running:
    def __init__(self, exe: str, port: int, extra_args: list[str] | None = None, extra_env: dict | None = None):
        self.port = port
        self.endpoint = pathlib.Path(tempfile.mkdtemp(prefix="ar-mcp-endpoint-")) / "mcp-endpoint.json"
        self.log_f = tempfile.NamedTemporaryFile(prefix="ar-mcp-http-", suffix=".log", delete=False)
        env = os.environ.copy()
        env["AGENTREINS_MCP_ENDPOINT_FILE"] = str(self.endpoint)
        env.pop("AGENTREINS_MCP_REQUIRE_TOKEN", None)
        env.pop("AGENTREINS_MCP_PORT", None)
        if extra_env:
            env.update(extra_env)
        cmd = [exe, "--http", "--port", str(port), *(extra_args or [])]
        self.proc = subprocess.Popen(cmd, stdout=self.log_f, stderr=subprocess.STDOUT, env=env)

    def log(self) -> str:
        self.log_f.flush()
        return pathlib.Path(self.log_f.name).read_text(encoding="utf-8", errors="replace")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(15)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.log_f.close()


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_exchange(port: int, method: str, path: str, body: bytes | None = None,
                  headers: dict | None = None, timeout: float = 30):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        status = resp.status
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return status, hdrs, raw
    finally:
        conn.close()


class Client:
    def __init__(self, port: int, name: str = "http-smoke", version: str = "1",
                 protocol: str = "2025-03-26", token: str | None = None):
        self.port = port
        self.session = None
        self.protocol = protocol
        self.token = token
        self.name = name
        self.version = version
        self._next = 1

    def headers(self, extra: dict | None = None, session: bool = True) -> dict:
        hdrs = {
            "Host": "127.0.0.1:%d" % self.port,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if session and self.session:
            hdrs["Mcp-Session-Id"] = self.session
            hdrs["MCP-Protocol-Version"] = self.protocol
        if self.token:
            hdrs["Authorization"] = "Bearer " + self.token
        if extra:
            hdrs.update(extra)
        return hdrs

    def post(self, payload, extra: dict | None = None, session: bool = True, timeout: float = 60):
        status, hdrs, raw = http_exchange(
            self.port, "POST", "/mcp",
            body=json.dumps(payload).encode(),
            headers=self.headers(extra, session=session),
            timeout=timeout,
        )
        return status, hdrs, raw

    def initialize(self) -> None:
        status, hdrs, raw = self.post({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": self.protocol,
                "capabilities": {},
                "clientInfo": {"name": self.name, "version": self.version},
            },
        }, session=False)
        self.assert_ok = (status, raw)
        if status != 200:
            raise AssertionError("initialize HTTP %s %s" % (status, raw[:500]))
        body = json.loads(raw)
        if "error" in body:
            raise AssertionError(body)
        if body["result"]["protocolVersion"] != self.protocol:
            raise AssertionError(body["result"])
        sid = hdrs.get("mcp-session-id")
        if not sid:
            raise AssertionError("missing Mcp-Session-Id: %s" % hdrs)
        self.session = sid
        note_status, _, note_raw = self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        if note_status != 202 or note_raw not in (b"",):
            raise AssertionError("notification %s %r" % (note_status, note_raw[:200]))

    def call(self, tool: str, arguments: dict, timeout: float = 60):
        self._next += 1
        status, _, raw = self.post({
            "jsonrpc": "2.0",
            "id": self._next,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }, timeout=timeout)
        if status != 200:
            raise AssertionError("tools/call %s HTTP %s %s" % (tool, status, raw[:500]))
        return json.loads(raw)


class HTTPTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        env = os.environ.get("AGENTREINS_MCP_BIN")
        if not env:
            self.skipTest("set AGENTREINS_MCP_BIN (packaged AgentReinsMCP) to run HTTP transport tests")
        if not os.path.isfile(env) or not os.access(env, os.X_OK):
            self.fail("AGENTREINS_MCP_BIN is not an executable: %s" % env)
        if sys.platform != "darwin":
            self.skipTest("HTTP MCP peer checks need macOS libproc")
        self.bin = env

    def test_initialize_tools_and_coverage(self) -> None:
        port = free_port()
        server = Running(self.bin, port)
        try:
            self.wait_health(server)
            endpoint = json.loads(server.endpoint.read_text(encoding="utf-8"))
            self.assertEqual(endpoint["state"], "listening")
            self.assertEqual(endpoint["auth"], "none")
            self.assertEqual(endpoint["url"], "http://127.0.0.1:%d/mcp" % port)
            self.assertEqual(endpoint["port"], port)
            mode = server.endpoint.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, oct(mode))

            client = Client(port, protocol="2024-11-05")
            client.initialize()
            status, _, raw = client.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            self.assertEqual(status, 200, raw)
            listed = json.loads(raw)["result"]["tools"]
            names = {t["name"] for t in listed}
            self.assertEqual(names, TOOLS)
            by_name = {t["name"]: t for t in listed}
            for tool in ("list_agents", "list_alerts", "list_network", "list_mcp_audit"):
                props = by_name[tool]["inputSchema"]["properties"]
                for key in ("limit", "offset", "cursor", "since", "until"):
                    self.assertIn(key, props, tool)

            cov = client.call("get_coverage", {})["result"]
            self.assertFalse(cov["isError"], cov)
            structured = cov["structuredContent"]
            self.assertIn("rules", structured)
            self.assertEqual(structured["mcpEndpoint"]["state"], "listening")
            self.assertTrue(structured["mcpEndpoint"]["processAlive"])
            net = client.call("list_network", {})["result"]
            self.assertFalse(net["isError"], net)
            self.assertIn("network", net["structuredContent"])
            self.assertIn("sockets", net["structuredContent"])
            agents = client.call("list_agents", {"limit": 1})["result"]["structuredContent"]
            self.assertIn("total", agents)
            self.assertIn("truncated", agents)
            self.assertIn("nextCursor", agents)
            self.assertIn("传输审计", agents.get("note", ""))
            self.assertNotIn("运输审计", json.dumps(agents, ensure_ascii=False))
            for agent in agents.get("agents") or []:
                self.assertIn("sessionCount", agent)
                self.assertIn("executionCount", agent)
                self.assertLessEqual(len(agent.get("executionIds") or []), 40)
                self.assertLessEqual(len(agent.get("sessions") or []), 40)
        finally:
            server.stop()

    def test_bind_is_ipv4_loopback_only(self) -> None:
        port = free_port()
        server = Running(self.bin, port)
        try:
            self.wait_health(server)
            listing = self.lsof_listen(port)
            rows = [ln for ln in listing.splitlines() if "LISTEN" in ln]
            self.assertTrue(rows, listing or server.log())
            for row in rows:
                self.assertIn("127.0.0.1:%d" % port, row, listing)
                self.assertNotIn("*:%d" % port, row, listing)
                self.assertNotIn("[::]", row, listing)
            self.assertFalse(self.can_connect("::1", port, socket.AF_INET6), "IPv6 loopback accepted")
            other = self.non_loopback_ip()
            if other:
                self.assertFalse(self.can_connect(other, port, socket.AF_INET), "non-loopback %s accepted" % other)
        finally:
            server.stop()

    def test_host_origin_content_type_and_methods(self) -> None:
        port = free_port()
        server = Running(self.bin, port)
        try:
            self.wait_health(server)
            host = {"Host": "127.0.0.1:%d" % port}
            status, _, raw = http_exchange(port, "POST", "/mcp", body=b"{}", headers={
                "Host": "evil.com:%d" % port, "Content-Type": "application/json",
            })
            self.assertEqual(status, 403, raw)
            status, _, raw = http_exchange(port, "POST", "/mcp", body=b"{}", headers={
                **host, "Content-Type": "application/json", "Origin": "http://evil.com",
            })
            self.assertEqual(status, 403, raw)
            status, _, raw = http_exchange(port, "GET", "/healthz", headers={
                "Host": "localhost:%d" % port,
            })
            self.assertEqual(status, 200, raw)
            status, _, raw = http_exchange(port, "POST", "/mcp", body=b"{}", headers={
                **host, "Content-Type": "text/plain",
            })
            self.assertIn(status, (415, 403), raw)
            status, _, raw = http_exchange(port, "GET", "/mcp", headers=host)
            self.assertEqual(status, 405, raw)
            status, _, raw = http_exchange(port, "POST", "/mcp",
                                           body=json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]).encode(),
                                           headers={**host, "Content-Type": "application/json"})
            self.assertEqual(status, 400, raw)
            self.assertEqual(json.loads(raw)["error"]["code"], -32600)

            client = Client(port)
            client.initialize()
            status, _, raw = client.post({"jsonrpc": "2.0", "id": 7, "method": "resources/list", "params": {}})
            self.assertEqual(status, 200, raw)
            self.assertEqual(json.loads(raw)["error"]["code"], -32601)
            denied = client.call("write_file", {})["result"]
            self.assertTrue(denied["isError"], denied)
            deleted = client.call("delete_agent", {})["result"]
            self.assertTrue(deleted["isError"], deleted)
            status, hdrs, raw = http_exchange(port, "DELETE", "/mcp", headers={
                **host, "Mcp-Session-Id": client.session,
            })
            self.assertEqual(status, 204, raw)
            status, _, raw = client.post({"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}})
            self.assertEqual(status, 404, raw)
            status, _, raw = http_exchange(port, "POST", "/mcp",
                                           body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                                           headers={**host, "Content-Type": "application/json",
                                                    "MCP-Protocol-Version": "1999-01-01"})
            self.assertEqual(status, 400, raw)
        finally:
            server.stop()

    def test_port_in_use(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)
        server = Running(self.bin, port)
        try:
            try:
                rc = server.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.fail("server stayed up while port was taken\n" + server.log())
            self.assertNotEqual(rc, 0, server.log())
            self.assertTrue(server.endpoint.is_file(), server.log())
            doc = json.loads(server.endpoint.read_text(encoding="utf-8"))
            self.assertEqual(doc["state"], "port_in_use", doc)
            self.assertIn("port_in_use", server.log())
        finally:
            server.stop()
            sock.close()

    def test_audit_chain_under_http_and_stdio(self) -> None:
        port = free_port()
        server = Running(self.bin, port)
        try:
            self.wait_health(server)
            client = Client(port, name="http-smoke", version="1")
            client.initialize()
            errors: list = []

            def http_call(_n: int) -> None:
                try:
                    result = client.call("get_coverage", {})["result"]
                    if result.get("isError"):
                        errors.append(result)
                except Exception as exc:  # noqa: BLE001 — collected for the assertion below
                    errors.append(repr(exc))

            def stdio_calls() -> None:
                proc = subprocess.Popen(
                    [self.bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                )
                try:
                    assert proc.stdin and proc.stdout

                    def send(obj: dict) -> None:
                        proc.stdin.write(json.dumps(obj) + "\n")
                        proc.stdin.flush()

                    def read() -> dict:
                        line = proc.stdout.readline()
                        if not line:
                            raise AssertionError("stdio closed")
                        return json.loads(line)

                    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                        "protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "stdio-peer", "version": "1"},
                    }})
                    read()
                    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                    for i in range(20):
                        send({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
                              "params": {"name": "get_coverage", "arguments": {}}})
                        body = read()
                        if body.get("result", {}).get("isError"):
                            errors.append(body)
                except Exception as exc:  # noqa: BLE001
                    errors.append("stdio: %r" % exc)
                finally:
                    proc.kill()
                    proc.wait(timeout=5)

            stdio = threading.Thread(target=stdio_calls)
            stdio.start()
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(http_call, range(20)))
            stdio.join(timeout=120)
            self.assertFalse(stdio.is_alive(), "stdio peer did not finish")
            self.assertEqual(errors, [], errors[:3])

            audited = client.call("list_mcp_audit", {"limit": 200})["result"]["structuredContent"]
            validation = audited["validation"]
            self.assertTrue(validation.get("ok"), validation)
            self.assertEqual(validation.get("status"), "ok", validation)
            server_pid = json.loads(server.endpoint.read_text(encoding="utf-8"))["pid"]
            actors = [str(e.get("actor", "")) for e in audited["entries"]]
            http_actors = [a for a in actors if a.startswith("http-smoke/1 via http pid=")]
            self.assertGreaterEqual(len(http_actors), 1, actors[-8:])
            for actor in http_actors:
                self.assertNotIn("pid=%s exe=" % server_pid, actor, actor)
                self.assertNotIn("exe=AgentReinsMCP", actor, actor)
                self.assertIn(" exe=", actor)
        finally:
            server.stop()

    def test_slow_call_does_not_block_initialize_on_another_connection(self) -> None:
        port = free_port()
        server = Running(self.bin, port, extra_env={
            "AGENTREINS_MCP_TOOL_DELAY_MS": "2000",
            "AGENTREINS_MCP_REQUEST_TIMEOUT_SECONDS": "8",
        })
        try:
            self.wait_health(server)
            first = Client(port, name="slow")
            first.initialize()
            timings: dict[str, float] = {}

            def slow() -> None:
                started = time.perf_counter()
                status, _, raw = first.post({
                    "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                    "params": {"name": "list_agents", "arguments": {}},
                }, timeout=10)
                timings["slow"] = time.perf_counter() - started
                timings["slow_status"] = status
                if status != 200:
                    timings["slow_body"] = raw[:300]

            worker = threading.Thread(target=slow)
            worker.start()
            time.sleep(0.4)
            other = Client(port, name="other")
            started = time.perf_counter()
            other.initialize()
            timings["init"] = time.perf_counter() - started
            worker.join(timeout=12)
            self.assertFalse(worker.is_alive(), "slow call did not finish")
            print("CONCURRENCY slow_s=%.3f other_initialize_s=%.3f" % (timings["slow"], timings["init"]))
            self.assertEqual(timings["slow_status"], 200, timings.get("slow_body"))
            self.assertGreaterEqual(timings["slow"], 1.8, timings)
            self.assertLess(timings["init"], 1.0, timings)
            self.assertLess(timings["init"], timings["slow"] / 2, timings)
        finally:
            server.stop()

    def test_session_lru_eviction_and_idle_expiry(self) -> None:
        port = free_port()
        server = Running(self.bin, port, extra_env={
            "AGENTREINS_MCP_MAX_SESSIONS": "3",
            "AGENTREINS_MCP_SESSION_TTL_SECONDS": "60",
        })
        try:
            self.wait_health(server)
            clients = [Client(port, name="s%d" % i) for i in range(3)]
            for client in clients:
                client.initialize()
            newest = Client(port, name="s3")
            newest.initialize()
            status, _, raw = clients[0].post({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}})
            self.assertEqual(status, 404, raw)
            body = json.loads(raw)
            self.assertEqual(body["jsonrpc"], "2.0")
            self.assertEqual(body["id"], 9)
            self.assertEqual(body["error"]["code"], -32001)
            self.assertIn("session not found", body["error"]["message"])
            status, _, raw = clients[1].post({"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {}})
            self.assertEqual(status, 200, raw)
            self.assertIn("result", json.loads(raw))
            status, _, raw = newest.post({"jsonrpc": "2.0", "id": 5, "method": "ping", "params": {}})
            self.assertEqual(status, 200, raw)
        finally:
            server.stop()

        port = free_port()
        server = Running(self.bin, port, extra_env={"AGENTREINS_MCP_SESSION_TTL_SECONDS": "1"})
        try:
            self.wait_health(server)
            client = Client(port, name="idle")
            client.initialize()
            time.sleep(1.3)
            status, _, raw = client.post({"jsonrpc": "2.0", "id": 6, "method": "ping", "params": {}})
            self.assertEqual(status, 404, raw)
            body = json.loads(raw)
            self.assertEqual(body["jsonrpc"], "2.0")
            self.assertEqual(body["id"], 6)
            self.assertEqual(body["error"]["code"], -32001)
            Client(port, name="fresh").initialize()
        finally:
            server.stop()

    def test_request_timeout_and_disconnect_cleanup(self) -> None:
        port = free_port()
        server = Running(self.bin, port, extra_env={
            "AGENTREINS_MCP_TOOL_DELAY_MS": "3000",
            "AGENTREINS_MCP_REQUEST_TIMEOUT_SECONDS": "0.4",
        })
        try:
            self.wait_health(server)
            client = Client(port, name="timeout")
            client.initialize()
            started = time.perf_counter()
            status, _, raw = client.post({
                "jsonrpc": "2.0", "id": 21, "method": "tools/call",
                "params": {"name": "list_agents", "arguments": {}},
            }, timeout=5)
            elapsed = time.perf_counter() - started
            print("TIMEOUT elapsed_s=%.3f status=%s" % (elapsed, status))
            self.assertLess(elapsed, 2.0, raw[:300])
            body = json.loads(raw)
            self.assertEqual(status, 200, raw)
            self.assertEqual(body["id"], 21)
            self.assertEqual(body["error"]["code"], -32000)
            started = time.perf_counter()
            Client(port, name="after-timeout").initialize()
            self.assertLess(time.perf_counter() - started, 1.0)
        finally:
            server.stop()

        port = free_port()
        server = Running(self.bin, port, extra_env={
            "AGENTREINS_MCP_TOOL_DELAY_MS": "5000",
            "AGENTREINS_MCP_REQUEST_TIMEOUT_SECONDS": "30",
        })
        try:
            self.wait_health(server)
            before = server.log()
            held = Client(port, name="disconnect")
            held.initialize()
            payload = json.dumps({
                "jsonrpc": "2.0", "id": 22, "method": "tools/call",
                "params": {"name": "list_agents", "arguments": {}},
            }).encode()
            head = (
                "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                "Content-Length: %d\r\nMcp-Session-Id: %s\r\nConnection: close\r\n\r\n"
                % (port, len(payload), held.session)
            ).encode()
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                sock.sendall(head + payload)
            finally:
                sock.close()
            deadline = time.time() + 2
            while time.time() < deadline and "request abandoned" not in server.log()[len(before):]:
                time.sleep(0.05)
            suffix = server.log()[len(before):]
            self.assertIn("request abandoned", suffix, suffix[-800:])
            self.assertNotIn("peer lookup failed", suffix, suffix[-800:])
            started = time.perf_counter()
            Client(port, name="after-disconnect").initialize()
            self.assertLess(time.perf_counter() - started, 1.0)
        finally:
            server.stop()

    def test_unknown_session_is_404_with_jsonrpc_error(self) -> None:
        port = free_port()
        server = Running(self.bin, port)
        try:
            self.wait_health(server)
            client = Client(port, name="missing-session")
            client.initialize()
            status, _, raw = client.post(
                {"jsonrpc": "2.0", "id": 42, "method": "ping", "params": {}},
                extra={"Mcp-Session-Id": "not-a-session"},
            )
            self.assertEqual(status, 404, raw)
            body = json.loads(raw)
            self.assertEqual(body["jsonrpc"], "2.0")
            self.assertEqual(body["id"], 42)
            self.assertEqual(body["error"]["code"], -32001)
            self.assertNotIn("session_not_found", raw.decode())
            status, _, raw = http_exchange(port, "DELETE", "/mcp", headers={
                "Host": "127.0.0.1:%d" % port,
                "Mcp-Session-Id": "also-missing",
            })
            self.assertEqual(status, 404, raw)
            body = json.loads(raw)
            self.assertEqual(body["error"]["code"], -32001)
            self.assertIsNone(body["id"])
        finally:
            server.stop()

    def test_stdio_still_default(self) -> None:
        proc = subprocess.Popen([self.bin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            assert proc.stdin and proc.stdout
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "stdio-smoke", "version": "1"}},
            }) + "\n")
            proc.stdin.flush()
            init = json.loads(proc.stdout.readline())
            self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")
            self.assertEqual(init["result"]["serverInfo"]["version"], "0.2.0-swift")
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
            proc.stdin.flush()
            tools = json.loads(proc.stdout.readline())
            self.assertEqual({t["name"] for t in tools["result"]["tools"]}, TOOLS)
        finally:
            proc.kill()
            proc.wait(timeout=5)

    def test_optional_bearer_token(self) -> None:
        token_path = pathlib.Path(tempfile.mkdtemp(prefix="ar-mcp-token-")) / "mcp-http.token"
        token_path.write_text("test-token-value\n", encoding="utf-8")
        os.chmod(token_path, 0o600)
        port = free_port()
        server = Running(
            self.bin, port,
            extra_args=["--require-token"],
            extra_env={"AGENTREINS_MCP_TOKEN_FILE": str(token_path)},
        )
        try:
            self.wait_health(server)
            doc = json.loads(server.endpoint.read_text(encoding="utf-8"))
            self.assertEqual(doc["auth"], "bearer")
            host = {
                "Host": "127.0.0.1:%d" % port,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            body = json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "tok", "version": "1"}},
            }).encode()
            status, _, raw = http_exchange(port, "POST", "/mcp", body=body, headers=host)
            self.assertEqual(status, 401, raw)
            status, hdrs, raw = http_exchange(port, "POST", "/mcp", body=body, headers={
                **host, "Authorization": "Bearer test-token-value",
            })
            self.assertEqual(status, 200, raw)
            self.assertEqual(json.loads(raw)["result"]["protocolVersion"], "2025-03-26")
            self.assertTrue(hdrs.get("mcp-session-id"))
        finally:
            server.stop()

    def wait_health(self, server: Running, timeout: float = 20) -> None:
        deadline = time.time() + timeout
        last = b""
        while time.time() < deadline:
            if server.proc.poll() is not None:
                self.fail("server exited %s\n%s" % (server.proc.returncode, server.log()))
            try:
                status, _, raw = http_exchange(
                    server.port, "GET", "/healthz",
                    headers={"Host": "127.0.0.1:%d" % server.port},
                    timeout=1,
                )
                last = raw
                if status == 200:
                    body = json.loads(raw)
                    self.assertTrue(body["ok"])
                    self.assertEqual(body["version"], "0.2.0-swift")
                    self.assertNotIn("agents", body)
                    return
            except OSError:
                pass
            time.sleep(0.05)
        self.fail("healthz timeout last=%r\n%s" % (last[:300], server.log()))

    @staticmethod
    def lsof_listen(port: int) -> str:
        candidates = ["/usr/sbin/lsof", "lsof"]
        for exe in candidates:
            if exe.startswith("/") and not os.path.exists(exe):
                continue
            proc = subprocess.run([exe, "-nP", "-iTCP:%d" % port, "-sTCP:LISTEN"],
                                  capture_output=True, text=True)
            if proc.stdout:
                return proc.stdout
        return ""

    @staticmethod
    def can_connect(host: str, port: int, family: int) -> bool:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            return False
        sock.settimeout(1)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    @staticmethod
    def non_loopback_ip() -> str | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
        except OSError:
            return None
        finally:
            sock.close()
        if ip.startswith("127."):
            return None
        return ip


if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        os.environ["AGENTREINS_MCP_BIN"] = os.path.abspath(sys.argv.pop(1))
    unittest.main()
