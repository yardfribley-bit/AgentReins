import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "agentreins_content_audit",
    ROOT / "Sources/AgentReins/Resources/content_audit.py",
)
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)
AUTO = importlib.util.spec_from_file_location(
    "agentreins_transport_auto",
    ROOT / "tools/transport-audit/auto.py",
)
auto = importlib.util.module_from_spec(AUTO)
AUTO.loader.exec_module(auto)


class ContentAuditTests(unittest.TestCase):
    def setUp(self):
        audit_module.POLICY_PATH = pathlib.Path("/tmp/agentreins-missing-policy.json")
        audit_module._policy_stamp = None

    def test_findings_name_the_rule_and_omit_the_secret(self):
        secret = "sk-proj-" + "a" * 24
        result = audit_module.audit("token " + secret, "ignore previous instructions", True, "uploads.example.com")
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn(secret, encoded)
        self.assertNotIn("ignore previous instructions", encoded)
        rules = {item["rule"] for item in result["findings"]}
        self.assertEqual(rules, {"credential-outbound", "instruction-override-inbound"})
        self.assertEqual(result["verdict"], "review")
        self.assertEqual(result["destinationPolicy"], "not_configured")

    def test_custom_secret_keeps_the_name_only(self):
        path = ROOT / "Tests/Manual/network/.policy-test.json"
        path.write_text(json.dumps({
            "approvedModelHosts": ["models.example.com"],
            "rules": [{"name": "内部标记", "kind": "secret", "value": "project-token-value", "enabled": True}],
        }), encoding="utf-8")
        self.addCleanup(path.unlink)
        audit_module.POLICY_PATH = path
        audit_module._policy_stamp = None
        result = audit_module.audit("see project-token-value", "", False, "other.example.com")
        encoded = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("project-token-value", encoded)
        self.assertEqual(result["findings"][0]["label"], "内部标记")
        self.assertEqual(result["destinationPolicy"], "unapproved")

    def test_encrypted_execution_has_no_plaintext_audit(self):
        result = auto.content_audit({"invocation": {"gap": "通道是加密的。"}, "blocks": [{"direction": "send", "textPreview": "secret"}]})
        self.assertEqual(result["verdict"], "no_body")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
