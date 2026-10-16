"""Live UDP syslog routing: WS-1 stamps every datagram ``generic_syslog``.

Regression for the bug where WS-2 treated that WS-1 label as an authoritative
product claim, so content detection never ran for live syslog: forwarded sshd
auth logs normalized as generic Kernel/Process (1002) events and the SSH
brute-force rule never fired; %ASA- and CEF lines dead-lettered.

Payloads are built with WS-1's real ``build_raw_event`` so the test pins the
exact producer shape, not a hand-written imitation. Zero infra (memory bus).

Run: python services/ws2-normalization/test_syslog_udp_routing.py
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
os.environ["BUS_BACKEND"] = "memory"
sys.path.insert(0, str(SERVICES / "ws1-collectors"))  # for `collectors`
sys.path.insert(0, str(SERVICES))                     # for `shared`
sys.path.insert(0, str(HERE))                         # ws2 `main` / `parsers` win

from shared.bus import Bus  # noqa: E402
from collectors.syslog_udp_server import build_raw_event  # noqa: E402
from parsers import resolve  # noqa: E402
from parsers.cisco_asa import CiscoAsaParser  # noqa: E402
from parsers.generic_syslog import GenericSyslogParser  # noqa: E402
import main as ws2  # noqa: E402

ATTACKER_IP = "203.0.113.77"
FORWARDER_IP = "198.51.100.10"   # the Linux host relaying its auth log over UDP

SSH_FAIL = ("<38>Oct 15 10:00:{s:02d} web01 sshd[2154]: Failed password for "
            "invalid user admin from " + ATTACKER_IP + " port 5{s:04d} ssh2")
ASA_DENY = ("<164>Oct 15 10:00:01 fw01 : %ASA-4-106023: Deny tcp src "
            "outside:203.0.113.5/51000 dst inside:10.0.0.10/22 by access-group acl_out")
CEF_LINE = ("CEF:0|Acme|Firewall|1.0|100|Failed login|7|"
            "src=203.0.113.9 suser=admin outcome=failure")
PLAIN_SYSLOG = "<13>Oct 15 10:00:02 app01 myapp[77]: disk usage at 91%"


def _udp(line: str) -> dict:
    """A raw.events payload exactly as WS-1's UDP listener builds it."""
    payload = build_raw_event(line)
    assert payload["source_type"] == "generic_syslog"  # the label under test
    return payload


class TestGenericSyslogLabelRouting(unittest.TestCase):
    def _normalize(self, payload):
        event, errors = ws2.normalize_one(payload)
        self.assertIsNotNone(event, errors)
        self.assertEqual(errors, [])
        return event

    def test_1_sshd_line_routes_to_linux_ssh(self):
        payload = _udp(SSH_FAIL.format(s=0))
        event = self._normalize(payload)
        self.assertEqual(event["siem"]["source_type"], "linux_ssh")
        self.assertEqual((event["class_uid"], event["activity_id"]), (3002, 4))
        self.assertEqual(event["type_uid"], 300204)  # derived by base_event
        self.assertEqual(event["src_endpoint"]["ip"], ATTACKER_IP)
        # WS-1 envelope metadata survives the re-route
        meta = payload["meta"]
        self.assertEqual(event["siem"]["ingest_id"], meta["ingest_id"])
        self.assertEqual(event["siem"]["trace_id"], meta["trace_id"])
        self.assertEqual(event["siem"]["tenant"], meta["tenant_id"])
        self.assertEqual(event["metadata"]["logged_time"], meta["received_at"] * 1000)

    def test_2_asa_line_routes_to_cisco_asa(self):
        event = self._normalize(_udp(ASA_DENY))
        self.assertEqual(event["siem"]["source_type"], "cisco_asa")
        self.assertEqual((event["class_uid"], event["activity_id"]), (4001, 6))
        self.assertEqual(event["src_endpoint"]["ip"], "203.0.113.5")

    def test_3_cef_line_routes_to_cef(self):
        event = self._normalize(_udp(CEF_LINE))
        self.assertEqual(event["siem"]["source_type"], "cef")
        self.assertEqual((event["class_uid"], event["activity_id"]), (3002, 4))

    def test_3b_syslog_wrapped_cef_routes_to_cef(self):
        # CEF appliances relay through syslog with an RFC 3164 header in front.
        line = "<134>Oct 15 10:00:04 relay01 " + CEF_LINE
        event = self._normalize(_udp(line))
        self.assertEqual(event["siem"]["source_type"], "cef")
        self.assertEqual((event["class_uid"], event["activity_id"]), (3002, 4))
        self.assertEqual(event["status"], "Failure")

    def test_3c_malformed_hostile_lines_never_raise(self):
        for line in ("<999999999999999999>Oct 11 22:14:15 host app: x", "CEF:0|",
                     "<134>Oct 11 22:14:15 relay01 CEF:", "%ASA-not-a-severity: crafted",
                     "\x00" * 4096):
            with self.subTest(line=line[:40]):
                payload = _udp(line)
                parser = resolve(payload)
                if parser is not None:
                    parser.parse(payload)

    def test_4_plain_rfc3164_stays_generic(self):
        event = self._normalize(_udp(PLAIN_SYSLOG))
        self.assertEqual(event["siem"]["source_type"], "generic_syslog")
        self.assertEqual(event["class_uid"], 1002)

    def test_4b_sniff_hit_the_parser_declines_stays_generic(self):
        # linux_ssh does not model "Connection closed"; before this fix the UDP
        # path parsed it as generic_syslog -- it must not become a dead-letter.
        line = ("<38>Oct 15 10:00:03 web01 sshd[2154]: Connection closed by "
                + ATTACKER_IP + " port 51000 [preauth]")
        event = self._normalize(_udp(line))
        self.assertEqual(event["siem"]["source_type"], "generic_syslog")

    def test_4c_json_line_under_generic_label_is_not_structured_sniffed(self):
        payload = _udp('{"EventID": 4625}')
        self.assertIsInstance(resolve(payload), GenericSyslogParser)

    def test_5_explicit_specific_source_type_is_authoritative(self):
        # e.g. tools/agent_log_shipper.py --source-type cisco_asa: an sshd-looking
        # line must NOT be re-routed by content.
        payload = dict(_udp(SSH_FAIL.format(s=0)), source_type="cisco_asa")
        self.assertIsInstance(resolve(payload), CiscoAsaParser)


def _import_service(ws_dir: str, mod: str = "main"):
    """Import a service module with its own dir first (several share `main`);
    mirrors tools/demo_e2e.py."""
    p = str(SERVICES / ws_dir)
    while p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)
    return importlib.import_module(mod)


class TestUdpSshBurstFiresBruteForce(unittest.TestCase):
    def test_udp_shaped_sshd_burst_alerts_through_ws2_ws4(self):
        bus = Bus()
        for s in range(10):  # common_bruteforce.yml: 10 failures / 60s / src ip
            bus.produce("raw.events", key=FORWARDER_IP, payload=_udp(SSH_FAIL.format(s=s)))

        c2 = ws2.run(bus)
        self.assertEqual(c2["normalized"], 10, c2)

        for m in ("main", "engine", "scoring"):
            sys.modules.pop(m, None)
        ws4 = _import_service("ws4-detection")
        c4 = ws4.run(bus, ws4.Detector())
        self.assertGreaterEqual(c4["alerts"], 1, c4)

        alerts = [m.payload for m in bus.consume("alerts", group="cg-test-udp")]
        bf = [a for a in alerts if "brute-force" in str(a.get("rule_title", "")).lower()]
        self.assertTrue(bf, f"no brute-force alert; got {[a.get('rule_title') for a in alerts]}")
        # grouped on the attacker in the line, not the forwarding host
        self.assertEqual(bf[0]["src_endpoint"]["ip"], ATTACKER_IP)


if __name__ == "__main__":
    unittest.main(verbosity=2)
