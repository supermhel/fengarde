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

    def test_parent_domain_knows_country_specific_second_level_labels(self):
        # 2026-10-02: ne/or/go/ad/gr/lg/ed under .jp (and the other common
        # country-specific labels) are public suffixes; without them every
        # *.ne.jp customer pooled under the single parent "ne.jp".
        from parsers.dns_query import parent_domain
        cases = {
            "a.b.example.ne.jp": "example.ne.jp",
            "www.example.or.jp": "example.or.jp",
            "city.example.go.jp": "example.go.jp",
            "x.example.ad.jp": "example.ad.jp",
            "x.example.co.jp": "example.co.jp",       # already global, must be unchanged
            "x.example.ac.jp": "example.ac.jp",       # already global, must be unchanged
            "x.example.ne.kr": "example.ne.kr",
            "x.example.ltd.uk": "example.ltd.uk",
            "x.example.id.au": "example.id.au",
            "x.example.gob.mx": "example.gob.mx",
            "x.example.gouv.fr": "example.gouv.fr",
            "x.example.idv.tw": "example.idv.tw",
        }
        for name, want in cases.items():
            self.assertEqual(parent_domain(name), want, name)

    def test_country_specific_labels_do_not_leak_to_other_tlds(self):
        # Scoping is the point: a global "ne"/"or"/"go" would turn a registered
        # domain such as go.de into a fake suffix, so an attacker who owns it
        # could scatter one tunnel across many "parents" by varying the label in
        # front. Under any TLD the label is not a suffix for, pooling is unchanged.
        from parsers.dns_query import parent_domain
        cases = {
            "a.b.example.ne.de": "ne.de",
            "x.go.de": "go.de",
            "chunk1.t.or.it": "or.it",
            "x.example.ltd.jp": "ltd.jp",             # 'ltd' is a .uk label, not a .jp one
            "x.example.ne.uk": "ne.uk",               # 'ne' is a .jp/.kr label, not a .uk one
            "x.example.gouv.jp": "gouv.jp",
        }
        for name, want in cases.items():
            self.assertEqual(parent_domain(name), want, name)

    def test_event_pools_a_jp_customer_under_its_own_registered_domain(self):
        # End to end through the parser: two different ne.jp customers must not
        # share a grouping key (they used to, both becoming "ne.jp").
        a = PARSER.parse(_raw("query[A] www.alpha.ne.jp from 10.0.0.5"))
        b = PARSER.parse(_raw("query[A] www.beta.ne.jp from 10.0.0.5"))
        self.assertEqual(a["unmapped"]["dns"]["parent_domain"], "alpha.ne.jp")
        self.assertEqual(b["unmapped"]["dns"]["parent_domain"], "beta.ne.jp")
        self.assertEqual(validate(a), [])

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
