"""Committed synthetic attack-shaped fixtures for the corpus eval lanes.

Why they exist: the corpus replay lanes (evtx_eval.py / splunk_eval.py) grade
rules on expected-positive events -- a rule with zero attack-shaped positives
in BOTH third-party corpora reports an honest ``untested`` (tp+fn == 0), and
``untested`` rules are surfaced in the trend file, never implied passing.
``password_spray`` (common_password_spray.yml: ONE account failed from 8+
DISTINCT source IPs within a 300 s window -- the T1110.004 credential-stuffing
shape) has no such events in either corpus: it is ``untested`` on every
corpus trend row, and the ONLY untested rule on the full-corpus nightly rows
(2026-09-04, 2026-10-14).

Design constraints (each one is load-bearing):

* Attack-shaped, not cosmetic. Each fixture trips the INDEPENDENT oracle
  (``evtx_eval.oracle()`` evaluates the raw records, not the engine's logic)
  AND is replayed through the REAL WS-2 -> WS-4 pipeline, exactly like a
  corpus file. A fixture that only trips the oracle would be a mislabel;
  one that only trips the engine would be self-fulfilling.
* Labeled in every output. The pseudo-file appears as ``fixture:<name>`` in
  per_file / mismatches / deadletter output, so a reader can tell synthetic
  coverage from corpus coverage.
* Never inflates corpus stats. Fixture records are NOT counted in
  ``records_total`` / ``records_supported`` / parser-coverage denominators,
  and are graded in each lane's separate ``fixture_confusion`` (never its
  corpus ``confusion``); tools/append_trend_row.py takes them ONCE into
  ``fixture_per_rule`` / ``fixture_tested_rules``. So ``password_spray``
  stays in ``untested_rules`` -- the corpora still never exercise it -- and
  the fixture coverage is reported next to it, never folded into it.
* Deterministic. Fixed epoch-ms timestamps, fixed IPs, stable ordering --
  same-seed reruns produce identical confusion entries (the twin lanes'
  determinism discipline applies here too).

Run: the fixtures run automatically inside ``evtx_eval.py`` and
``splunk_eval.py`` (see their ``run_fixtures`` helper); nothing else invokes
this module.
"""
from __future__ import annotations

# Fixed, past, deterministic base timestamp (UTC epoch-ms). Sunday
# 2026-08-09 03:00 UTC, same convention as tools/detection_quality_eval.py's
# _OFF_HOURS_MS -- a stable weekday/hour so no rule that checks the clock can
# see the fixture differently run-to-run.
BASE_MS = 1786244400000

PASSWORD_SPRAY_USER = "carla"


def _password_spray_records() -> list[dict]:
    """10 failed logons (EventID 4625) for ONE account, each from a DISTINCT
    source IP, spaced 10 s apart (all within ~100 s << the 300 s rule window):
    the exact credential-stuffing shape common_password_spray.yml detects.
    Only password_spray is expected to fire: 10 distinct IPs means the
    per-IP bruteforce rule (10 in 60 s) and the per-host sourceless rule
    (5+ distinct usernames) both stay silent, and no 4672/4728/4732/4624
    events appear for the other oracle rules."""
    ips = [f"203.0.113.{i}" for i in range(1, 11)]
    return [
        {
            "EventID": 4625,
            "Channel": "Security",
            "Computer": "fixture-host",
            "TimeCreated": BASE_MS + i * 10_000,
            "TargetUserName": PASSWORD_SPRAY_USER,
            "TargetDomainName": "BANKCORP",
            "IpAddress": ip,
            "WorkstationName": "wks-fixture",
        }
        for i, ip in enumerate(ips)
    ]


# name -> attack-shaped record list. Add new fixtures here; the eval lanes
# pick up new entries automatically (both lanes iterate ALL).
ALL: dict[str, list[dict]] = {
    "password_spray": _password_spray_records(),
}