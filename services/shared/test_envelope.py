"""Envelope v1 unit tests (M1 correctness gate).

Proves: stamp_meta() is idempotent (redelivery must not regenerate trace_id),
default_tenant() reads TENANT_ID with a safe default, and Parser.base_event()
propagates trace_id/tenant from meta when present and degrades gracefully
(fresh trace_id, default tenant) when meta is absent -- the pre-v1 call
signature every existing parser test fixture still uses.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(SERVICES / "ws2-normalization"))

from shared.envelope import SCHEMA_VERSION, default_tenant, new_trace_id, stamp_meta  # noqa: E402
from parsers.base import Parser  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


class _FakeParser(Parser):
    SOURCE_TYPE = "fake"
    SECTOR = "common"


def test_stamp_meta_idempotent():
    meta = {"ingest_id": "abc"}
    stamp_meta(meta)
    first_trace, first_tenant = meta["trace_id"], meta["tenant_id"]
    stamp_meta(meta)  # simulate a redelivery / defensive re-call
    check(meta["trace_id"] == first_trace,
          "stamp_meta must not regenerate trace_id on a second call")
    check(meta["tenant_id"] == first_tenant,
          "stamp_meta must not regenerate tenant_id on a second call")


def test_default_tenant_env():
    old = os.environ.pop("TENANT_ID", None)
    try:
        check(default_tenant() == "default",
              "default_tenant() must be 'default' when TENANT_ID unset")
        os.environ["TENANT_ID"] = "acme-corp"
        check(default_tenant() == "acme-corp",
              "default_tenant() must read TENANT_ID when set")
    finally:
        if old is None:
            os.environ.pop("TENANT_ID", None)
        else:
            os.environ["TENANT_ID"] = old


def test_new_trace_id_unique():
    a, b = new_trace_id(), new_trace_id()
    check(a != b, "new_trace_id() must not repeat across calls")


def test_base_event_propagates_meta_envelope():
    p = _FakeParser()
    meta = {"trace_id": "trace-123", "tenant_id": "tenant-xyz", "ingest_id": "i1"}
    event = p.base_event(
        class_uid=3002, activity_id=1, severity_id=1, time_ms=1000,
        ingest_id="i1", meta=meta,
    )
    check(event["siem"]["trace_id"] == "trace-123",
          "base_event must propagate meta.trace_id onto siem.trace_id")
    check(event["siem"]["tenant"] == "tenant-xyz",
          "base_event must propagate meta.tenant_id onto siem.tenant")
    check(event["metadata"]["schema_version"] == SCHEMA_VERSION,
          "base_event must stamp metadata.schema_version")


def test_base_event_without_meta_still_works():
    """The pre-v1 call signature (no meta kwarg) every existing parser test
    fixture predates this change -- must keep producing a valid event."""
    p = _FakeParser()
    event = p.base_event(
        class_uid=3002, activity_id=1, severity_id=1, time_ms=1000,
    )
    check(isinstance(event["siem"]["trace_id"], str) and event["siem"]["trace_id"],
          "base_event without meta must still stamp a non-empty trace_id")
    check(event["siem"]["tenant"] == default_tenant(),
          "base_event without meta must fall back to default_tenant()")


def main():
    test_stamp_meta_idempotent()
    test_default_tenant_env()
    test_new_trace_id_unique()
    test_base_event_propagates_meta_envelope()
    test_base_event_without_meta_still_works()

    if FAILS:
        print(f"\n[FAIL] envelope: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] envelope v1 unit tests PASS")


if __name__ == "__main__":
    main()
