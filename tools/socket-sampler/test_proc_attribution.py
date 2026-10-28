"""F-2 request-time attribution and F-1 scoped sampling / miss-rate reporting.

The proxy side is exercised without mitmproxy: a short-lived client connects to a
local listener (standing in for 127.0.0.1:18891) and is resolved while the socket
is still open. A closed port must come back as ``via proxy · attribution lost``
with no guessed pid.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import proc_lookup  # noqa: E402
import socket_sampler as ss  # noqa: E402

CAPTURE = HERE.parents[1] / "Sources" / "AgentReins" / "Resources" / "workbuddy_network_capture.py"


def load_capture():
    spec = importlib.util.spec_from_file_location("workbuddy_network_capture", CAPTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Attribution(unittest.TestCase):
    def test_short_lived_client_is_attributed_from_the_open_socket(self) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        port = server.getsockname()[1]
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import socket,sys,time\n"
             "s=socket.create_connection(('127.0.0.1', int(sys.argv[1])))\n"
             "s.send(b'x')\n"
             "time.sleep(30)\n",
             str(port)],
        )
        try:
            conn, _ = server.accept()
            try:
                peer_port = conn.getpeername()[1]
                started = time.perf_counter()
                fields = proc_lookup.attribute_client(peer_port, port)
                self.assertLess(time.perf_counter() - started, 1.0, fields)
                self.assertEqual(fields["attributionState"], proc_lookup.ATTRIBUTED_STATE)
                self.assertEqual(fields["clientPid"], child.pid)
                self.assertEqual(fields["clientPpid"], os.getpid())
                self.assertEqual(fields["parentChain"][0]["pid"], child.pid)
                self.assertIn(fields["attributionBasis"], ("procfs", "libproc", "lsof-port"))
                self.assertNotEqual(fields["clientPid"], os.getpid())
            finally:
                conn.close()
        finally:
            child.kill()
            child.wait(timeout=5)
            server.close()
        lost = proc_lookup.attribute_client(peer_port, port)
        self.assertEqual(lost["attributionState"], proc_lookup.LOST_STATE)
        self.assertIsNone(lost["clientPid"])
        self.assertIsNone(lost["clientAgent"])
        self.assertEqual(lost["parentChain"], [])

    def test_pid_header_is_not_consulted(self) -> None:
        capture = load_capture()
        with mock.patch.object(proc_lookup, "attribute_client", return_value=proc_lookup.lost_attribution()) as called:
            # The capture module loads proc_lookup by path; patch the function it will call.
            capture._proc_lookup = proc_lookup
            fields = capture.attribution_fields(
                ("127.0.0.1", 43111), ("127.0.0.1", 18891),
                headers={"X-AgentReins-Pid": "1", "X-Process-Pid": "4242"},
            )
        called.assert_called_once_with(43111, 18891)
        self.assertEqual(fields["attributionState"], proc_lookup.LOST_STATE)
        self.assertIsNone(fields["clientPid"])
        self.assertNotEqual(fields.get("clientPid"), 4242)


class ScopedSampler(unittest.TestCase):
    def test_round_stays_under_a_second_and_sees_the_live_socket(self) -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(5)
        client = socket.socket()
        client.connect(("127.0.0.1", server.getsockname()[1]))
        held, _ = server.accept()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                ledger = pathlib.Path(tmp) / "ledger.json"
                sampler = ss.Sampler(
                    ledger, roots={os.getpid(): "CI"}, discover=False, resolve=False,
                    route_paths=[], v2ray_log=pathlib.Path(tmp) / "none",
                    transport_root=pathlib.Path(tmp) / "t", interval=0.5, backend="auto",
                )
                started = time.perf_counter()
                out = sampler.sample()
                elapsed = time.perf_counter() - started
            self.assertLess(elapsed, 1.0, out)
            self.assertIsNone(out["failure"], out)
            # Fast path only: agent-tree scoped. Linux names procfs; macOS names libproc
            # plus lsof limited to those pids. Neither is the legacy whole-machine lsof -i.
            method = sampler.collect_method
            self.assertIn("scoped to agent trees", method)
            self.assertNotIn("legacy whole-machine", method)
            if os.path.exists("/proc/net/tcp"):
                self.assertIn("procfs sockets of the agent process tree only", method)
            else:
                self.assertIn("libproc process tree", method)
                self.assertIn("lsof scoped to those pids", method)
                self.assertIn("not lsof -i for the whole machine", method)
            rows = [r for r in out["sockets"] if r.get("pid") == os.getpid() and r.get("remotePort") == server.getsockname()[1]]
            self.assertTrue(rows, out["sockets"])
        finally:
            held.close()
            client.close()
            server.close()

    def test_effective_interval_and_miss_rate_are_measured(self) -> None:
        t = 1_700_000_000.0
        starts = [0, 3.9, 7.8, 11.7, 29.3, 33.2, 37.1, 41.0]
        rounds = [[t + x, 0.2, True] for x in starts]
        cov = ss.measured_coverage({"rounds": rounds}, 2.0)
        self.assertEqual(cov["effectiveIntervalSeconds"], cov["successGapSecondsP50"])
        self.assertEqual(cov["effectiveIntervalSecondsP95"], cov["missesShorterThanSeconds"])
        self.assertEqual(cov["referenceShortConnectionSeconds"], 1.5)
        self.assertGreater(cov["estimatedMissRate"], 0.5)
        self.assertLess(cov["estimatedMissRate"], 1.0)
        self.assertIn("1.5", cov["estimatedMissRateBasis"])

    def test_legacy_plist_interval_is_applied_as_the_fast_default(self) -> None:
        applied, note = ss.resolve_interval(2.0)
        self.assertEqual(applied, ss.DEFAULT_INTERVAL)
        self.assertEqual(ss.DEFAULT_INTERVAL, 0.5)
        self.assertIn("2.0", note or "")
        self.assertEqual(ss.resolve_interval(0.5), (0.5, None))
        self.assertEqual(ss.resolve_interval(1.5), (1.5, None))
        self.assertEqual(ss.resolve_interval(3.0)[0], 3.0)

    def test_sampler_sources_have_no_runtime_union_aliases(self) -> None:
        """Python 3.9 evaluates `X | Y` in assignments. Annotations are postponed; aliases are not."""
        import ast
        for path in HERE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            bad = _runtime_union_lines(tree)
            self.assertEqual(bad, [], "%s has runtime X | Y at %s" % (path.name, bad))


def _runtime_union_lines(tree: ast.AST) -> list[int]:
    """Line numbers of `X | Y` that execute at runtime (not annotations)."""
    bad: list[int] = []

    def is_typeish(node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        if isinstance(node, ast.Name):
            return True
        if isinstance(node, (ast.Subscript, ast.Tuple)):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return is_typeish(node.left) or is_typeish(node.right)
        return False

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for stmt in node.body:
                self.visit(stmt)
            for deco in node.decorator_list:
                self.visit(deco)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self.visit(node.value)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            if isinstance(node.op, ast.BitOr) and (is_typeish(node.left) or is_typeish(node.right)):
                bad.append(node.lineno)
            self.generic_visit(node)

    Visitor().visit(tree)
    return bad


if __name__ == "__main__":
    unittest.main()
