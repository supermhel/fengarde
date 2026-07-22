"""P1-1 (2026-07-21 audit fix plan): non-stateful alert_key tenant isolation.

The stateful branch of Rule.alert_key() was tenant-namespaced by the F1
follow-up (see engine.py's own comment on that fix), but the non-stateful
branch was not: two tenants whose ingest-less events shared a content
fingerprint (or, more simply, two tenants who happened to reuse the same
ingest_id) got the IDENTICAL alert_id. storage/opensearch.py's _search_alert()
queries alerts-* by _id and returns the first match, so one tenant's alert
could shadow (become unreachable behind) the other's -- the same class of bug
F1 fixed for the window counter and its own follow-up fixed for the stateful
alert_id, just missed here.

Run: python services/ws4-detection/test_p1_1_alert_key_tenant.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from engine import Rule  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _non_stateful_rule() -> Rule:
    return Rule({"id": "r1", "title": "t", "level": "high",
                "detection": {"s": {"class_uid": 1}, "condition": "s"},
                "siem": {"score_weight": 80}})


def test_same_ingest_id_different_tenants_get_distinct_alert_ids():
    rule = _non_stateful_rule()
    acme = {"class_uid": 1, "siem": {"ingest_id": "shared-id", "tenant": "acme"}}
    globex = {"class_uid": 1, "siem": {"ingest_id": "shared-id", "tenant": "globex"}}
    check(rule.alert_key(acme) != rule.alert_key(globex),
          "two tenants reusing the same ingest_id must get DISTINCT alert_ids "
          "-- this is the exact bug: they used to collide, letting one "
          "tenant's alert shadow the other's under find_alert()'s "
          "id-only lookup")


def test_same_content_fingerprint_different_tenants_get_distinct_alert_ids():
    """No ingest_id at all -> the content-hash fallback. Two tenants with
    IDENTICAL event content (plausible: same rule, same generic OCSF shape,
    e.g. two MSP customers both missing ingest_id on a similar event) must
    still not collide once tenant is factored in."""
    rule = _non_stateful_rule()
    base_event = {"class_uid": 1, "src_endpoint": {"ip": "10.0.0.1"}}
    acme = {**base_event, "siem": {"tenant": "acme"}}
    globex = {**base_event, "siem": {"tenant": "globex"}}
    check(rule.alert_key(acme) != rule.alert_key(globex),
          "two tenants with identical event content (no ingest_id) must get "
          "DISTINCT alert_ids via the content-hash fallback too")


def test_same_tenant_is_still_deterministic():
    """The fix must not break idempotency WITHIN one tenant -- redelivery of
    the same event must still yield the SAME alert_id (T7's whole point)."""
    rule = _non_stateful_rule()
    event = {"class_uid": 1, "siem": {"ingest_id": "abc", "tenant": "acme"}}
    check(rule.alert_key(event) == rule.alert_key(event),
          "same event, same tenant -> same alert_id (idempotent under redelivery)")


def test_default_tenant_when_absent_matches_stateful_branch_convention():
    """An event with no siem.tenant at all (pre-M4, single-tenant deployments)
    must default to "default", the same convention the ALREADY-FIXED stateful
    branch uses (engine.py's evaluate(), F1 follow-up) -- consistency, and
    every pre-M4 event/alert keeps working unchanged."""
    rule = _non_stateful_rule()
    event = {"class_uid": 1, "siem": {"ingest_id": "abc"}}  # no tenant key
    check(rule.alert_key(event) == "r1:default:abc",
          "no siem.tenant -> defaults to 'default', matching the stateful "
          "branch's own convention")


def test_alert_key_format_includes_tenant_segment():
    """Direct format check: the tenant segment is now always present,
    unconditionally, matching the stateful branch's format (no special-
    casing 'default' away)."""
    rule = _non_stateful_rule()
    key = rule.alert_key({"class_uid": 1, "siem": {"ingest_id": "x", "tenant": "acme"}})
    check(key == "r1:acme:x", f"expected 'r1:acme:x', got {key!r}")


def main():
    test_same_ingest_id_different_tenants_get_distinct_alert_ids()
    test_same_content_fingerprint_different_tenants_get_distinct_alert_ids()
    test_same_tenant_is_still_deterministic()
    test_default_tenant_when_absent_matches_stateful_branch_convention()
    test_alert_key_format_includes_tenant_segment()

    if FAILS:
        print(f"\n[FAIL] alert_key tenant isolation (P1-1): {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] alert_key tenant isolation (P1-1) tests PASS")


if __name__ == "__main__":
    main()
