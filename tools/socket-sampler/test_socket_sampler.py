"""Unit tests for the proxy-independent socket sampler (fixtures only, no network)."""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import socket_sampler as ss  # noqa: E402

FX = HERE / "fixtures"
T0 = ss.parse_iso("2026-10-21T16:18:30Z")


class FakeResolver(ss.Resolver):
    def __init__(self, ptr=None, forward=None):
        super().__init__({}, enabled=False)
        self._ptr, self._fwd = ptr or {}, forward or {}

    def ptr(self, ip):
        return self._ptr.get(ip)

    def forward(self, host):
        return self._fwd.get(host, [])


def linux_sample():
    procs = ss.parse_ps_comm((FX / "ps_linux_recorded.txt").read_text())
    socks = ss.parse_lsof((FX / "lsof_linux_recorded.txt").read_text())
    return procs, socks


def macos_sample():
    procs = ss.parse_ps_comm((FX / "ps_macos_format.txt").read_text())
    heads = ss.parse_ps_args((FX / "ps_macos_args.txt").read_text())
    for pid, p in procs.items():
        p["argvHead"] = heads.get(pid, [])
    socks = ss.parse_lsof((FX / "lsof_macos_format.txt").read_text())
    return procs, socks


class ParseTests(unittest.TestCase):
    def test_recorded_lsof_fields(self):
        _, socks = linux_sample()
        self.assertEqual(len(socks), 5)
        listener, direct, proxied, udp, child = socks
        self.assertEqual((listener["state"], listener["remote"]), ("LISTEN", None))
        self.assertEqual(direct["pid"], 774418)
        self.assertEqual(direct["ppid"], 774410)
        self.assertEqual(direct["protocol"], "TCP")
        self.assertEqual(direct["remote"], "198.18.0.1:443")
        self.assertEqual(direct["state"], "ESTABLISHED")
        self.assertEqual(proxied["localPort"], 51100)
        self.assertEqual(proxied["remote"], "127.0.0.1:18891")
        self.assertEqual((udp["protocol"], udp["remote"], udp.get("state")), ("UDP", "1.1.1.1:53", None))
        self.assertEqual((child["pid"], child["ppid"], child["state"]), (774419, 774418, "SYN_SENT"))

    def test_macos_format_ipv6_and_unconnected_udp(self):
        _, socks = macos_sample()
        v6 = [s for s in socks if s["family"] == "IPv6" and s["remote"]]
        self.assertEqual(v6[0]["remoteIP"], "2606:4700::6810:84e5")
        self.assertEqual(v6[0]["remote"], "[2606:4700::6810:84e5]:443")
        self.assertEqual(v6[0]["local"], "[fd00::20]:53110")
        mdns = [s for s in socks if s["local"] == "*:5353"][0]
        self.assertIsNone(mdns["remote"])
        helper = [s for s in socks if s["pid"] == 4188][0]
        self.assertEqual(helper["command"], "Cursor Helper (Plugin)")

    def test_ps_lstart_is_utc(self):
        procs, _ = linux_sample()
        self.assertTrue(procs[774418]["startAt"].endswith("Z"))
        procs, _ = macos_sample()
        self.assertTrue(procs[4188]["path"].endswith("Cursor Helper (Plugin)"))
        self.assertEqual(procs[4188]["name"], "Cursor Helper (Plugin)")


class TreeTests(unittest.TestCase):
    def test_discovery_follows_descendants_and_skips_unrelated(self):
        procs, _ = macos_sample()
        owners = ss.agent_tree(procs)
        self.assertEqual(owners.get(4100), "Cursor")
        self.assertEqual(owners.get(4188), "Cursor")
        self.assertEqual(owners.get(4250), "Cursor")   # ssh child of the plugin host
        self.assertEqual(owners.get(5000), "Codex")    # node running .../bin/codex (argv[1])
        self.assertEqual(owners.get(5001), "Codex")
        self.assertNotIn(777, owners)                  # Safari
        self.assertNotIn(1, owners)

    def test_project_path_in_args_is_not_ownership(self):
        procs = {10: {"pid": 10, "ppid": 1, "path": "/usr/bin/vim", "name": "vim",
                      "argvHead": ["vim", "/Users/me/codex/notes.md"]}}
        self.assertEqual(ss.agent_tree(procs), {})

    def test_explicit_root_only(self):
        procs, _ = linux_sample()
        owners = ss.agent_tree(procs, {774418: "CI"}, discover=False)
        self.assertEqual(owners, {774418: "CI", 774419: "CI"})


class MergeTests(unittest.TestCase):
    def merged(self, routes=(), resolver=None, transport=None):
        procs, socks = linux_sample()
        owners = ss.agent_tree(procs, {774418: "Codex"}, discover=False)
        ledger = {"connections": []}
        touched = ss.merge_sample(ledger, socks, procs, owners, T0)
        ss.resolve_destinations(touched, list(routes), transport or {}, procs, resolver or FakeResolver())
        return ledger, {r["remoteAddress"]: r for r in touched}

    def test_listener_dropped_direct_kept_with_via_proxy_false(self):
        _, rows = self.merged()
        self.assertEqual(set(rows), {"198.18.0.1:443", "127.0.0.1:18891", "1.1.1.1:53", "198.18.0.1:80"})
        direct = rows["198.18.0.1:443"]
        self.assertFalse(direct["viaProxy"])
        self.assertEqual(direct["pid"], 774418)
        self.assertEqual(direct["evidence"], "Observed")
        self.assertEqual(direct["destinationSource"], "socket_sampled")
        self.assertEqual(direct["realDestination"], "198.18.0.1")
        udp = rows["1.1.1.1:53"]
        self.assertEqual((udp["protocol"], udp["viaProxy"], udp["state"]), ("UDP", False, "CONNECTED"))
        child = rows["198.18.0.1:80"]
        self.assertEqual((child["pid"], child["ppid"], child["state"]), (774419, 774418, "SYN_SENT"))

    def test_proxied_socket_gets_real_destination_from_route_log(self):
        routes = ss.load_audit_proxy_routes([FX / "workbuddy-network-routes.jsonl"])
        self.assertEqual(len(routes), 2)  # non-loopback client address rejected
        _, rows = self.merged(routes=routes)
        hop = rows["127.0.0.1:18891"]
        self.assertTrue(hop["viaProxy"])
        self.assertEqual(hop["transportPeer"], "127.0.0.1:18891")
        self.assertEqual(hop["realDestination"], "api.openai.com")
        self.assertEqual(hop["destinationSource"], "proxy_observed")
        self.assertEqual(hop["destinationEvidence"], "Correlated")

    def test_proxied_without_route_is_unknown_not_loopback(self):
        _, rows = self.merged()
        hop = rows["127.0.0.1:18891"]
        self.assertTrue(hop["viaProxy"])
        self.assertIsNone(hop["realDestination"])
        self.assertEqual((hop["destinationSource"], hop["destinationEvidence"]), ("proxy_unjoined", "Unknown"))

    def test_conflicting_route_hosts_are_ambiguous(self):
        routes = [{"clientPort": 51100, "host": "a.example", "port": 443, "ts": T0, "proxy": "p"},
                  {"clientPort": 51100, "host": "b.example", "port": 443, "ts": T0 + 1, "proxy": "p"}]
        _, rows = self.merged(routes=routes)
        self.assertEqual(rows["127.0.0.1:18891"]["destinationSource"], "proxy_unjoined")

    def test_reverse_dns_is_inferred(self):
        _, rows = self.merged(resolver=FakeResolver(ptr={"1.1.1.1": "one.one.one.one"},
                                                    forward={"one.one.one.one": ["1.1.1.1"]}))
        udp = rows["1.1.1.1:53"]
        self.assertEqual(udp["realDestination"], "one.one.one.one")
        self.assertEqual((udp["destinationSource"], udp["destinationEvidence"]), ("dns_inferred", "Inferred"))
        self.assertTrue(udp["forwardConfirmed"])
        # 198.18/15 is not public: no PTR lookup, IP kept
        self.assertEqual(rows["198.18.0.1:443"]["destinationSource"], "socket_sampled")

    def test_argv_join_requires_forward_resolution_to_same_ip(self):
        transport = {774419: {"host": "example.org", "tool": "curl", "call": "run-1"}}
        _, rows = self.merged(transport=transport, resolver=FakeResolver(forward={"example.org": ["198.18.0.1"]}))
        child = rows["198.18.0.1:80"]
        self.assertEqual((child["realDestination"], child["destinationSource"]), ("example.org", "argv_parsed"))
        self.assertEqual(child["transportCall"], "run-1")
        _, rows = self.merged(transport=transport, resolver=FakeResolver(forward={"example.org": ["203.0.113.1"]}))
        self.assertEqual(rows["198.18.0.1:80"]["destinationSource"], "socket_sampled")

    def test_repeated_samples_update_last_seen_and_count(self):
        procs, socks = linux_sample()
        owners = ss.agent_tree(procs, {774418: "Codex"}, discover=False)
        ledger = {"connections": []}
        ss.merge_sample(ledger, socks, procs, owners, T0)
        ss.merge_sample(ledger, socks, procs, owners, T0 + 3)
        row = [r for r in ledger["connections"] if r["remoteAddress"] == "198.18.0.1:443"][0]
        self.assertEqual(row["sampleCount"], 2)
        self.assertEqual(row["firstSeen"], "2026-10-21T16:18:30.000Z")
        self.assertEqual(row["lastSeen"], "2026-10-21T16:18:33.000Z")
        self.assertEqual(len(ledger["connections"]), 4)

    def test_macos_tree_filter_excludes_unrelated_socket(self):
        procs, socks = macos_sample()
        owners = ss.agent_tree(procs)
        ledger = {"connections": []}
        touched = ss.merge_sample(ledger, socks, procs, owners, T0)
        pids = {r["pid"] for r in touched}
        self.assertNotIn(777, pids)
        self.assertEqual(pids, {4100, 4188, 4250})
        ssh = [r for r in touched if r["pid"] == 4250][0]
        self.assertEqual((ssh["agent"], ssh["remotePort"], ssh["ppid"]), ("Cursor", 22, 4188))
        self.assertFalse(any(r["remoteAddress"] is None for r in touched))


class LedgerTests(unittest.TestCase):
    def test_save_is_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "ledger.json"
            now = ss.utc_iso()
            rows = [{"key": str(i), "lastSeen": now} for i in range(ss.MAX_ROWS + 5)]
            rows.append({"key": "old", "lastSeen": "2000-01-01T00:00:00Z"})
            ss.save_ledger(path, {"schema": 1, "connections": rows, "dnsCache": {}})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            data = json.loads(path.read_text())
            self.assertEqual(len(data["connections"]), ss.MAX_ROWS)
            self.assertNotIn("old", {r["key"] for r in data["connections"]})


if __name__ == "__main__":
    unittest.main()
