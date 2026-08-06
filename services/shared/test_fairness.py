"""Task M / Finding F4 (2026-08-07): FairConsumeBus round-robins one consume
batch by tenant so a flooding tenant can't occupy every consecutive turn
ahead of another tenant sharing the same topic. See fairness.py's module
docstring for why this is reorder-not-drop, not a token-bucket delay.

Run: python services/shared/test_fairness.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

from shared.bus import _MemoryBus  # noqa: E402
from shared.fairness import FairConsumeBus, default_tenant_key, event_tenant_key  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _event(tenant: str, n: int) -> dict:
    return {"siem": {"tenant": tenant}, "n": n}


def test_single_tenant_order_unchanged():
    """The common case (one tenant, or no tenant field at all): round-robin
    over exactly one bucket degenerates to plain FIFO -- byte-for-byte the
    same order a raw (unwrapped) bus would have given."""
    bus = _MemoryBus()
    for i in range(10):
        bus.produce("t", key=None, payload=_event("default", i))
    fair = FairConsumeBus(bus, tenant_key_fn=default_tenant_key)
    order = [m.payload["n"] for m in fair.consume("t")]
    check(order == list(range(10)),
          f"single-tenant order changed: {order}")


def test_flooding_tenant_does_not_starve_others_within_batch():
    """20 messages from 'flood', 3 from 'quiet', all produced before ONE
    consume() call (so they land in the same batch, same as a real burst
    landing between two _topic_worker reads). Under raw FIFO, 'quiet's 3
    messages would be positions 4, 12, 20 (wherever interleaved) or worse,
    all after 'flood' if produced-then-quiet. Under round-robin, 'quiet's
    messages must all appear within the first 2*3=6 positions -- bounded by
    the number of DISTINCT tenants in the batch, not by 'flood's volume."""
    bus = _MemoryBus()
    for i in range(20):
        bus.produce("t", key=None, payload=_event("flood", i))
    for i in range(3):
        bus.produce("t", key=None, payload=_event("quiet", i))
    fair = FairConsumeBus(bus, tenant_key_fn=default_tenant_key)
    delivered = list(fair.consume("t"))
    check(len(delivered) == 23, f"expected 23 messages total, got {len(delivered)}")
    quiet_positions = [i for i, m in enumerate(delivered)
                       if (m.payload.get("siem") or {}).get("tenant") == "quiet"]
    check(len(quiet_positions) == 3,
          f"expected all 3 'quiet' messages delivered, got {len(quiet_positions)}")
    check(max(quiet_positions, default=99) < 6,
          f"'quiet' tenant starved by 'flood': positions {quiet_positions} "
          f"(expected all within the first 6 -- 2 tenants x 3 rounds)")
    quiet_order = [delivered[i].payload["n"] for i in quiet_positions]
    check(quiet_order == [0, 1, 2],
          f"'quiet' tenant's own messages reordered relative to each other: {quiet_order}")


def test_no_message_lost_or_duplicated():
    """Round-robin must be a pure reordering: same multiset in, same multiset
    out, regardless of how many tenants or how skewed the volumes are."""
    bus = _MemoryBus()
    expected = set()
    for t, count in [("a", 7), ("b", 1), ("c", 15), ("d", 4)]:
        for i in range(count):
            key = (t, i)
            expected.add(key)
            bus.produce("t", key=None, payload=_event(t, i))
    fair = FairConsumeBus(bus, tenant_key_fn=default_tenant_key)
    delivered = {(m.payload["siem"]["tenant"], m.payload["n"]) for m in fair.consume("t")}
    check(delivered == expected,
          f"messages lost or duplicated: missing={expected - delivered} "
          f"extra={delivered - expected}")


def test_malformed_payload_falls_back_to_default_tenant():
    """A payload with no siem/tenant field (or the wrong shape) must not
    crash consume() -- it's bucketed under 'default' like an unset tenant."""
    bus = _MemoryBus()
    bus.produce("t", key=None, payload={"no_siem_field_here": True})
    bus.produce("t", key=None, payload={"siem": "not-a-dict"})  # malformed shape
    bus.produce("t", key=None, payload=_event("real", 0))
    fair = FairConsumeBus(bus, tenant_key_fn=default_tenant_key)
    delivered = list(fair.consume("t"))
    check(len(delivered) == 3, f"expected all 3 malformed/valid payloads delivered, got {len(delivered)}")


def test_event_tenant_key_reads_nested_shape():
    """WS-5's ai.requests payload nests the event: {"event": {"siem": {...}}}."""
    payload = {"event": {"siem": {"tenant": "acme"}}, "tier": "llm"}
    check(event_tenant_key(payload) == "acme",
          f"event_tenant_key misread nested shape: {event_tenant_key(payload)!r}")
    check(event_tenant_key({}) == "default",
          "event_tenant_key must default to 'default' on a missing event/siem")


def test_delegates_non_consume_methods_to_inner_bus():
    """produce/ack/depth/drain etc. must pass straight through unchanged --
    FairConsumeBus only overrides consume()."""
    bus = _MemoryBus()
    fair = FairConsumeBus(bus)
    fair.produce("t", key="k", payload=_event("x", 1))
    check(bus.depth("t") == 1, "produce() did not delegate to the inner bus")
    [msg] = list(fair.consume("t"))
    fair.ack(msg)  # must not raise -- delegates to _MemoryBus.ack (a no-op)
    check(bus.depth("t") == 0, "consume() via FairConsumeBus did not drain the inner bus")


def main():
    test_single_tenant_order_unchanged()
    test_flooding_tenant_does_not_starve_others_within_batch()
    test_no_message_lost_or_duplicated()
    test_malformed_payload_falls_back_to_default_tenant()
    test_event_tenant_key_reads_nested_shape()
    test_delegates_non_consume_methods_to_inner_bus()
    if FAILS:
        print(f"[FAIL] fairness: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] FairConsumeBus: round-robins by tenant, no loss/duplication, "
          "delegates everything else unchanged")


if __name__ == "__main__":
    main()
