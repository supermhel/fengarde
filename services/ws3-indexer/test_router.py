"""F3 (adversarial repo-wide bug hunt, 2026-07-16) — tenant_id validation
in router.py's index-name construction.

Before this fix, `tenant` flowed straight from `doc.get("tenant_id")` /
`siem.get("tenant")` into f"alerts-{tenant}-..." / f"events-{family}-{tenant}-..."
with no validation. An uppercase or space-containing tenant_id (e.g. an MSP
onboarding "Acme" or "ACME Corp") produces an OpenSearch-INVALID index name;
OpenSearchStore.index() treats the resulting 4xx as permanent, so the
document is silently dead-lettered -- that tenant gets zero detections.
This asserts route() now rejects (never normalizes) a malformed tenant_id
loudly, at the point of use, and that valid tenants (including the
"default" sentinel) are unaffected.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from router import route  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def _raises_value_error(doc: dict) -> bool:
    try:
        route(doc)
    except ValueError:
        return True
    return False


def test_invalid_tenant_rejected_on_alert_branch():
    # Note: "" is deliberately excluded -- `doc.get("tenant_id") or DEFAULT_TENANT`
    # treats an empty string the same as absent, falling through to "default"
    # (the same "missing -> default" convention documented across the codebase),
    # not a value _validated_tenant ever sees.
    for bad in ("Acme", "ACME Corp", "has space", "UPPER", "-leading-hyphen", "trailing-hyphen-"):
        alert = {"alert_id": "a-1", "time": 1750000000000, "level": "high", "tenant_id": bad}
        check(_raises_value_error(alert), f"alert with tenant_id={bad!r} should raise ValueError, didn't")


def test_invalid_tenant_rejected_on_event_branch():
    for bad in ("Acme", "ACME Corp", "has space", "UPPER"):
        event = {
            "siem": {"sector": "common", "tenant": bad, "ingest_id": "i-1"},
            "time": 1750000000000,
        }
        check(_raises_value_error(event), f"event with siem.tenant={bad!r} should raise ValueError, didn't")


def test_valid_tenants_still_route():
    # "default" sentinel -> unchanged pre-M4 naming, no tenant segment at all.
    alert = {"alert_id": "a-2", "time": 1750000000000, "level": "high", "tenant_id": "default"}
    index, doc_id = route(alert)
    check(index.startswith("alerts-") and "default" not in index,
          f"default-tenant alert must use pre-M4 naming, got {index}")

    # A normal lowercase-hyphenated tenant id -> tenant-scoped index.
    alert2 = {"alert_id": "a-3", "time": 1750000000000, "level": "high", "tenant_id": "acme-corp"}
    index2, doc_id2 = route(alert2)
    check(index2.startswith("alerts-acme-corp-"), f"tenant-scoped alert routed to {index2}")

    event = {
        "siem": {"sector": "bank", "tenant": "acme-corp", "ingest_id": "i-2"},
        "time": 1750000000000,
    }
    eidx, eid = route(event)
    check(eidx.startswith("events-bank-acme-corp-"), f"tenant-scoped event routed to {eidx}")

    # tenant_id/siem.tenant absent entirely -> defaults to "default", still routes.
    alert3 = {"alert_id": "a-4", "time": 1750000000000, "level": "high"}
    index3, _ = route(alert3)
    check(index3.startswith("alerts-") and "None" not in index3, f"missing tenant_id alert routed to {index3}")


def run():
    test_invalid_tenant_rejected_on_alert_branch()
    test_invalid_tenant_rejected_on_event_branch()
    test_valid_tenants_still_route()


def main():
    run()
    if FAILS:
        print(f"[FAIL] router tenant validation: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] F3: router.route() rejects malformed tenant_id (never normalizes) on both "
          "alert and event branches; valid/default tenants route unaffected")


if __name__ == "__main__":
    main()
