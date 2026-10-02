"""Unit tests for the dns_query parser (v0.5 Track A4).

Run with:
    python services/ws2-normalization/parsers/test_dns_query.py
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers.dns_query import DnsQueryParser  # noqa: E402
from parsers import resolve  # noqa: E402

PARSER = DnsQueryParser()


def _raw(line, meta=None):
    return {"source_type": "dns_query", "raw": line, "meta": meta or {}}


class TestDnsQueryParser(unittest.TestCase):

    def test_query_line_parses_to_dns_activity(self):
        event = PARSER.parse(_raw(
            "Jul 20 10:15:03 dnsmasq[123]: query[A] evil-c2.example.com from 10.0.0.5"))
        self.assertIsNotNone(event)
        self.assertEqual(event["class_uid"], 4002)
        self.assertEqual(event["activity_id"], 1)
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.0.5")
        self.assertEqual(event["dst_endpoint"]["hostname"], "evil-c2.example.com")
        self.assertEqual(validate(event), [])

    def test_trailing_dot_stripped(self):
        event = PARSER.parse(_raw("query[AAAA] www.example.com. from 10.0.0.6"))
        self.assertEqual(event["dst_endpoint"]["hostname"], "www.example.com")

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw("dnsmasq[123]: reading /etc/hosts")))

    def test_non_string_raw_returns_none(self):
        self.assertIsNone(PARSER.parse(_raw({"not": "a string"})))

    def test_malformed_ip_dropped_not_placed_on_event(self):
        # 999.999.999.999 matches the loose capture regex (hex/dot/colon
        # token) but isn't a real IPv4 address -- must be dropped, not
        # placed straight into src_endpoint.ip (that would fail Contract
        # A's endpoint pattern and dead-letter the whole event).
        event = PARSER.parse(_raw(
            "query[A] evil-c2.example.com from 999.999.999.999"))
        self.assertIsNotNone(event)
        self.assertNotIn("src_endpoint", event)
        self.assertEqual(validate(event), [])

    def test_malformed_ip_falls_back_to_meta_ip(self):
        event = PARSER.parse(_raw(
            "query[A] evil-c2.example.com from 999.999.999.999",
            meta={"ip": "10.0.0.9"}))
        self.assertEqual(event["src_endpoint"]["ip"], "10.0.0.9")

    def test_content_sniff_routes_query_line_to_dns_query(self):
        parser = resolve({"source_type": "", "raw":
                          "query[A] example.com from 10.0.0.5", "meta": {}})
        self.assertIs(type(parser), DnsQueryParser)

    # -- parent_domain: the grouping key common_dns_tunnel_by_domain.yml needs --
    def test_parent_domain_is_the_registered_domain(self):
        from parsers.dns_query import parent_domain
        cases = {
            "chunk007.t3.exfil.example.invalid": "example.invalid",
            "a.b.example.co.uk": "example.co.uk",
            "www.example.com.au": "example.com.au",
            "EXAMPLE.com.": "example.com",
            "evil-c2.example.com": "example.com",
        }
        for name, want in cases.items():
            self.assertEqual(parent_domain(name), want, name)

    def test_parent_domain_never_pools_reverse_lookups_or_junk(self):
        # Every PTR query for every address would otherwise share one parent
        # ("in-addr.arpa") and read as a tunnel.
        from parsers.dns_query import parent_domain
        for name in ("5.0.0.10.in-addr.arpa", "1.0.0.0.ip6.arpa", "10.0.0.5",
                     "localhost", "", ".", "a..b", "x" * 300 + ".com"):
            self.assertIsNone(parent_domain(name), name)

    def test_event_carries_parent_domain_only_when_poolable(self):
        e = PARSER.parse(_raw("query[A] a.b.example.com from 10.0.0.5"))
        self.assertEqual(e["unmapped"]["dns"]["parent_domain"], "example.com")
        self.assertEqual(validate(e), [])
        e = PARSER.parse(_raw("query[PTR] 5.0.0.10.in-addr.arpa from 10.0.0.5"))
        self.assertNotIn("unmapped", e)


if __name__ == "__main__":
    unittest.main()
