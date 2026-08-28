"""Tests for A5 enrichment (services/ws2-normalization/enrichment).

Proves enrichment is: additive (never overwrites, never removes), offline
(reads local files only), correct (exact-IP > CIDR, longest-prefix, INTERNAL
tagging), tolerant/fail-open (missing files, bad IPs, no src_endpoint all leave
the event flowing), and that an enriched event still validates against
Contract A -- i.e. downstream stays a tolerant reader. WP-2-H: the bounded
per-IP result cache populates on first sight, serves repeats without
re-scanning, stays <= cap under an attacker IP spray, evicts LRU, and caches
misses as exact live-scan equivalents.

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


def _enricher(tmp: Path, ioc=_IOC, geo=_GEO, **kwargs) -> Enricher:
    ip = tmp / "ioc.yml"
    gp = tmp / "geoip.yml"
    ip.write_text(ioc, encoding="utf-8")
    gp.write_text(geo, encoding="utf-8")
    return Enricher(ioc_path=ip, geoip_path=gp, **kwargs)


class _ScanCountingEnricher(Enricher):
    """Enricher whose `_reputation_for`/`_location_for` count real scan calls.

    Mutation-sound by construction: the counters wrap the REAL scan methods,
    which still return live results via super(). If the per-IP cache is removed
    and enrich() re-scans on every event, the counts inflate and the
    hits-reduce-scans tests go RED.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scan_calls = 0

    def _reputation_for(self, ip_str):
        self.scan_calls += 1
        return super()._reputation_for(ip_str)

    def _location_for(self, ip_str):
        self.scan_calls += 1
        return super()._location_for(ip_str)


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

    def test_fail_open_paths_warn_not_swallowed_silently(self):
        """Gap-hunt finding 4 (2026-08-26) regression: BOTH fail-open except
        paths (data-file load at construction, and the in-enrich body) used to
        swallow every exception with no log line -- a malformed IOC file or an
        enrich() bug made the whole A5 stage a silent no-op, indistinguishable
        from 'data matched nothing'. Both must now emit a WARNING while still
        failing open (event unchanged, never raises)."""
        import logging
        logger = logging.getLogger("ws2-normalization.enrichment")

        # (a) _load_entries: malformed YAML -> warn + empty data, no crash.
        bad = self.tmp / "ioc-bad.yml"
        bad.write_text("{ unclosed flow mapping", encoding="utf-8")
        with self.assertLogs(logger, level="WARNING") as cap:
            e = Enricher(ioc_path=bad, geoip_path=self.tmp / "missing-geo.yml")
        self.assertTrue(any("enrichment" in m.getMessage() for m in cap.records),
                        f"expected a warn about the bad data file, got {[m.getMessage() for m in cap.records]}")
        # fail-open preserved: the event that WOULD have matched the broken
        # file's entries still flows through untouched.
        self.assertEqual(e.enrich({"src_endpoint": {"ip": "203.0.113.5"}})["src_endpoint"],
                         {"ip": "203.0.113.5"})

        # (b) in-enrich exception -> warn + original event returned as-is.
        class _ExplodingSrc(dict):
            def __setitem__(self, k, v):
                if k == "reputation":
                    raise RuntimeError("boom")
                return super().__setitem__(k, v)

        ev = {"src_endpoint": _ExplodingSrc({"ip": "203.0.113.5"})}
        with self.assertLogs(logger, level="WARNING") as cap:
            out = self.e.enrich(ev)   # self.e has real IOC data, so the
                                      # reputation assignment actually fires
        self.assertIs(out, ev, "fail-open: the same event object must come back")
        self.assertEqual(out["src_endpoint"], {"ip": "203.0.113.5"},
                         "fail-open: event must be untouched by the exception")
        self.assertTrue(any("enrichment exception" in m.getMessage() for m in cap.records),
                        f"expected a warn about the enrich() exception, got {[m.getMessage() for m in cap.records]}")

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

    # --- WP-2-H: bounded per-IP result cache --------------------------------

    def test_ip_cache_first_lookup_populates_cache(self):
        e = _enricher(self.tmp, cache_cap=8)
        self.assertEqual(len(e._ip_cache), 0, "cache starts empty")
        out = e.enrich({"src_endpoint": {"ip": "203.0.113.5"}})
        self.assertIn("203.0.113.5", e._ip_cache,
                      "first lookup for a NEW ip must populate the cache")
        rep, loc = e._ip_cache["203.0.113.5"]
        self.assertEqual(rep["score"], 90)
        self.assertEqual(loc, {"country": "RU", "source": "local-geoip"})
        self.assertEqual(out["src_endpoint"]["reputation"]["score"], 90)

    def test_ip_cache_repeated_lookup_hits_cache_scans_decrease(self):
        # A cache hit must return the identical memoized result WITHOUT
        # re-running either scan: first lookup = 2 scan calls (rep + geo),
        # second lookup of the SAME ip = 0 additional scans.
        e = _ScanCountingEnricher(ioc_path=self.tmp / "ioc.yml",
                                  geoip_path=self.tmp / "geoip.yml",
                                  cache_cap=8)
        ev1 = {"src_endpoint": {"ip": "198.51.100.200"}}
        ev2 = {"src_endpoint": {"ip": "198.51.100.200"}}
        out1 = e.enrich(ev1)
        scans = e.scan_calls
        self.assertEqual(scans, 2,
                         "first lookup runs exactly one reputation + one geo scan")
        out2 = e.enrich(ev2)
        self.assertEqual(e.scan_calls, scans,
                         "repeated lookup of the SAME ip must hit the cache: "
                         "scan count must not grow")
        self.assertEqual(out1, out2, "cache hit must reproduce the first result")

    def test_ip_cache_bounded_under_attacker_spray(self):
        # IPs are attacker-controlled: a spray of distinct IPs must not grow
        # the cache without limit. cap=4, spray 20 -> size stays <= 4 AND holds
        # exactly 4 entries (mutation-sound: RED if the cache is removed, when
        # size would be 0 -- not 4).
        e = _enricher(self.tmp, cache_cap=4)
        for i in range(1, 21):  # 20 distinct valid IPs > cap 4
            e.enrich({"src_endpoint": {"ip": f"203.0.113.{i}"}})
        size = len(e._ip_cache)
        self.assertLessEqual(size, 4,
                             "cache must NEVER exceed its cap under a spray")
        self.assertEqual(size, 4,
                         "cache must actually be populated (bounded, not absent)")
        self.assertEqual(set(e._ip_cache), {f"203.0.113.{i}" for i in range(17, 21)},
                         "insertion-order eviction: the oldest entries go first")
        self.assertNotIn("203.0.113.1", e._ip_cache, "oldest sprayed ip evicted")

    def test_ip_cache_rehit_refreshes_recency_lru(self):
        # LRU-ish eviction: re-hitting an entry refreshes its recency so it
        # survives the eviction of the oldest UN-refreshed entry.
        e = _enricher(self.tmp, cache_cap=3)
        a, b, c, d = "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"
        for ip in (a, b, c):
            e.enrich({"src_endpoint": {"ip": ip}})
        e.enrich({"src_endpoint": {"ip": a}})   # re-hit a -> refresh recency
        e.enrich({"src_endpoint": {"ip": d}})   # over cap -> evict OLDEST (b)
        self.assertNotIn(b, e._ip_cache,
                         "LRU: the un-refreshed oldest entry must be evicted")
        for ip in (a, c, d):
            self.assertIn(ip, e._ip_cache, "recently-used entries must survive")

    def test_ip_cache_cached_miss_equals_live_miss(self):
        # A valid IP matching nothing locally is cached as a (None, None) miss
        # marker, and a repeated lookup returns the SAME untouched event a live
        # scan would -- without re-scanning (determinism requirement).
        e1 = _ScanCountingEnricher(ioc_path=self.tmp / "ioc.yml",
                                   geoip_path=self.tmp / "geoip.yml",
                                   cache_cap=8)
        ev = {"src_endpoint": {"ip": "8.8.8.8"}}
        out1 = e1.enrich(dict(ev))
        self.assertEqual(out1["src_endpoint"], {"ip": "8.8.8.8"},
                         "unknown ip gets no enrichment (live semantics)")
        self.assertIn("8.8.8.8", e1._ip_cache, "miss marker must be cached")
        self.assertEqual(e1._ip_cache["8.8.8.8"], (None, None))
        scans = e1.scan_calls
        self.assertEqual(scans, 2, "a fresh unknown ip scans both tables once")
        out2 = e1.enrich(dict(ev))
        self.assertEqual(e1.scan_calls, scans,
                         "repeated unknown ip must NOT re-scan (cached miss)")
        live = _enricher(self.tmp, cache_cap=8).enrich(dict(ev))
        self.assertEqual(out2, live,
                         "cached miss must equal a live scan (deterministic)")

    def test_ip_cache_garbage_ip_never_cached(self):
        # tenants.py discipline: invalid strings are cheap to re-validate and
        # must not be allowed to fill the attacker-controlled cache for free --
        # a spray of arbitrary garbage must leave the cache empty.
        e = _enricher(self.tmp, cache_cap=4)
        for junk in ("not-an-ip", "203.0.113", "dead::beef::", "1.2.3.4.5",
                     "203.0.113.5 "):
            e.enrich({"src_endpoint": {"ip": junk}})
        self.assertEqual(len(e._ip_cache), 0,
                         "invalid IP strings must never enter the cache")


if __name__ == "__main__":
    unittest.main()
