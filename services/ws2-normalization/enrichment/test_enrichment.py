"""Tests for A5 enrichment (services/ws2-normalization/enrichment).

Proves enrichment is: additive (never overwrites, never removes), offline
(reads local files only), correct (exact-IP > CIDR, longest-prefix, INTERNAL
tagging), tolerant/fail-open (missing files, bad IPs, no src_endpoint all leave
the event flowing), and that an enriched event still validates against
Contract A -- i.e. downstream stays a tolerant reader.

Run: python services/ws2-normalization/enrichment/test_enrichment.py
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS2 = HERE.parent
SERVICES = WS2.parent
sys.path.insert(0, str(WS2))       # for `enrichment`, `parsers`
sys.path.insert(0, str(SERVICES))  # for `shared`

from enrichment import Enricher  # noqa: E402

_IOC = """
entries:
  - ip: "203.0.113.5"
    score: 90
    categories: [scanner, brute-force]
  - cidr: "198.51.100.0/24"
    score: 75
    categories: [botnet]
  - cidr: "198.51.100.128/25"
    score: 40
    categories: [suspicious]
"""

_GEO = """
entries:
  - cidr: "10.0.0.0/8"
    country: "INTERNAL"
  - cidr: "203.0.113.0/24"
    country: "RU"
"""


def _enricher(tmp: Path, ioc=_IOC, geo=_GEO) -> Enricher:
    ip = tmp / "ioc.yml"
    gp = tmp / "geoip.yml"
    ip.write_text(ioc, encoding="utf-8")
    gp.write_text(geo, encoding="utf-8")
    return Enricher(ioc_path=ip, geoip_path=gp)


class TestEnrichment(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.e = _enricher(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def test_exact_ioc_and_geo_added(self):
        src = self.e.enrich({"src_endpoint": {"ip": "203.0.113.5"}})["src_endpoint"]
        self.assertEqual(src["reputation"]["score"], 90)
        self.assertEqual(src["reputation"]["source"], "local-ioc")
        self.assertIn("scanner", src["reputation"]["categories"])
        self.assertEqual(src["location"], {"country": "RU", "source": "local-geoip"})

    def test_cidr_ioc_match(self):
        src = self.e.enrich({"src_endpoint": {"ip": "198.51.100.9"}})["src_endpoint"]
        self.assertEqual(src["reputation"]["score"], 75)

    def test_longest_prefix_cidr_wins(self):
        # 198.51.100.200 is in both /24 (score 75) and /25 (score 40); the more
        # specific /25 must win regardless of file order.
        src = self.e.enrich({"src_endpoint": {"ip": "198.51.100.200"}})["src_endpoint"]
        self.assertEqual(src["reputation"]["score"], 40)

    def test_internal_geo_only_no_reputation(self):
        src = self.e.enrich({"src_endpoint": {"ip": "10.0.0.6"}})["src_endpoint"]
        self.assertEqual(src["location"]["country"], "INTERNAL")
        self.assertNotIn("reputation", src)

    def test_unknown_ip_untouched(self):
        src = self.e.enrich({"src_endpoint": {"ip": "8.8.8.8"}})["src_endpoint"]
        self.assertEqual(src, {"ip": "8.8.8.8"})

    def test_never_overwrites_existing_field(self):
        pre = {"src_endpoint": {"ip": "203.0.113.5", "reputation": {"score": 1}}}
        src = self.e.enrich(pre)["src_endpoint"]
        self.assertEqual(src["reputation"], {"score": 1}, "must not clobber existing key")

    def test_no_src_endpoint_is_noop(self):
        ev = {"class_uid": 3002}
        self.assertEqual(self.e.enrich(ev), {"class_uid": 3002})

    def test_missing_ip_is_noop(self):
        ev = {"src_endpoint": {"hostname": "h1"}}
        self.assertEqual(self.e.enrich(ev)["src_endpoint"], {"hostname": "h1"})

    def test_bad_ip_fails_open(self):
        ev = {"src_endpoint": {"ip": "not-an-ip"}}
        self.assertEqual(self.e.enrich(ev)["src_endpoint"], {"ip": "not-an-ip"})

    def test_missing_data_files_disable_enrichment_no_raise(self):
        e = Enricher(ioc_path=self.tmp / "nope.yml", geoip_path=self.tmp / "nope2.yml")
        ev = {"src_endpoint": {"ip": "203.0.113.5"}}
        self.assertEqual(e.enrich(ev)["src_endpoint"], {"ip": "203.0.113.5"})

    def test_malformed_ioc_entries_skipped(self):
        bad = "entries:\n  - ip: \"1.2.3.4\"\n    score: 999\n  - cidr: \"garbage\"\n    score: 50\n"
        e = _enricher(self.tmp, ioc=bad, geo=_GEO)
        # score 999 is out of 0-100 range -> skipped; garbage cidr -> skipped
        self.assertEqual(e.enrich({"src_endpoint": {"ip": "1.2.3.4"}})["src_endpoint"],
                         {"ip": "1.2.3.4"})

    def test_enriched_event_still_validates_against_contract_a(self):
        # The whole tolerant-reader premise: adding these fields must not make an
        # otherwise-valid OCSF event invalid.
        from parsers.linux_ssh import LinuxSshParser
        from shared.ocsf import validate
        ev = LinuxSshParser().parse({
            "source_type": "linux_ssh",
            "raw": "Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid "
                   "user admin from 203.0.113.5 port 51000 ssh2",
            "meta": {}})
        self.assertIsNotNone(ev)
        errors_before = validate(ev)
        self.assertEqual(errors_before, [], f"parser output already invalid: {errors_before}")
        enriched = self.e.enrich(ev)
        self.assertIn("reputation", enriched["src_endpoint"])
        errors_after = validate(enriched)
        self.assertEqual(errors_after, [],
                         f"enriched event must still validate: {errors_after}")


if __name__ == "__main__":
    unittest.main()
