"""Per-tenant fair consume ordering (Task M / Finding F4, 2026-08-07).

**The problem this solves**: `services/ws1-collectors`'s `TenantTokenBuckets`
gives per-tenant rate limiting at the ingest EDGE (proven, SSOT F4). Nothing
downstream does — `services/shared/runner.py`'s `_topic_worker` reads one
topic on ONE thread, strictly serially: `for msg in bus.consume(topic, ...):
handler(msg); ack(msg)`. If tenant A floods `normalized.events` or
`ai.requests`, every one of A's messages sits ahead of tenant B's in that
serial FIFO stream, so B's detection/triage latency degrades in lockstep with
A's volume even though B sent nothing extra.

**Why not a token-bucket delay** (the WS-1 pattern): `_topic_worker` has no
concurrency to redistribute — a `time.sleep()` while handling A's message just
makes the ONE thread idle, which delays B's message (still queued behind A's
in the same FIFO) by the same amount. Delay-based throttling only works when
there's a second thread/lane for the delayed-past work to yield to; there
isn't one here, and adding one is a much bigger change (touches
`runner.py`, shared by all 5 services) for a narrower win.

**Why not shed** (also WS-1's pattern): these are already-accepted,
already-normalized events. Dropping one to protect another tenant's latency
is an audit-completeness violation (`start_depth_watchdog`'s docstring in
`runner.py` already establishes "never drop an unconsumed event" as a hard
line for internal topics) and would silently contradict `make chaos`'s
proven zero-loss guarantee.

**What this does instead: reorder, never drop.** `FairConsumeBus` wraps a
real `Bus` and only overrides `.consume()`: it drains exactly what ONE
underlying `.consume()` call returns (MemoryBus's full queue, or Redis's
`BUS_XREADGROUP_COUNT`-bounded batch — no new unbounded buffering), buckets
those messages by tenant, and re-yields them round-robin across tenants
instead of raw arrival order. Every message is still delivered and acked
exactly as before (message objects pass through untouched, so
`_process_message`'s ack/redelivery/DLQ logic is completely unaffected) --
only the ORDER within one batch changes. A single-tenant deployment (the
common case today) has exactly one bucket, so round-robin degenerates to
plain FIFO -- byte-for-byte unchanged behavior.

**Honest scope**: this bounds how much one tenant's flood can delay another
tenant's WITHIN one consume batch (at most (num_tenants_in_batch - 1) other
tenants' messages ahead of any given message, not up to the whole flood).
It does not give per-tenant CPU/compute quotas -- the single consumer thread
still processes one message at a time, so total throughput is still shared.
That is a genuinely bigger change (multiple consumer threads/processes per
topic) and is out of scope here; see docs/mssp-quickstart.md's gap list.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable, Iterator

# R3-#68 (2026-08-27): FairConsumeBus.consume used to forward its block_ms=0
# default straight to the inner bus, where 0 means BLOCK FOREVER on
# XREADGROUP -- a fair wrapper around a blocking read that never returns
# would stall the whole _topic_worker loop (claim_pending interleaving and
# shutdown checks) indefinitely. Clamp any non-positive block to a sane
# bounded default so the wrapper can never turn a bounded read into an
# unbounded one.
_DEFAULT_BLOCK_MS = 1000


def default_tenant_key(payload: dict) -> str:
    """siem.tenant directly on the payload -- the shape WS-4 consumes
    (`normalized.events`/`scored.events`: payload IS the OCSF event)."""
    return (payload.get("siem") or {}).get("tenant") or "default"


def event_tenant_key(payload: dict) -> str:
    """siem.tenant nested under payload["event"] -- the shape WS-5 consumes
    (`ai.requests`: payload is `{"event": {...}, "tier": ..., ...}`)."""
    event = payload.get("event") or {}
    return (event.get("siem") or {}).get("tenant") or "default"


class FairConsumeBus:
    """Bus wrapper: round-robins `.consume()` by tenant, delegates everything
    else (`.produce`, `.ack`, `.claim_pending`, `.depth`, `.lag`, ...)
    unchanged to the wrapped bus via `__getattr__`."""

    def __init__(self, inner, tenant_key_fn: Callable[[dict], str] = default_tenant_key):
        self._inner = inner
        self._tenant_key_fn = tenant_key_fn

    def consume(self, topic, group=None, block_ms=0) -> Iterator:
        effective_block_ms = block_ms if block_ms and block_ms > 0 else _DEFAULT_BLOCK_MS
        buckets: "dict[str, deque]" = defaultdict(deque)
        order: list[str] = []
        seen: set = set()
        for msg in self._inner.consume(topic, group=group, block_ms=effective_block_ms):
            try:
                tenant = self._tenant_key_fn(msg.payload) or "default"
            except Exception:
                # A malformed payload must not break delivery -- fall back to
                # a shared bucket rather than raising out of consume().
                tenant = "default"
            if tenant not in seen:
                seen.add(tenant)
                order.append(tenant)
            buckets[tenant].append(msg)

        # Round-robin: one message per tenant per round, in first-seen order,
        # until every bucket this batch touched is empty. O(batch size).
        while order:
            next_round = []
            for tenant in order:
                q = buckets[tenant]
                if q:
                    yield q.popleft()
                if q:
                    next_round.append(tenant)
            order = next_round

    def __getattr__(self, name):
        # Delegate everything not explicitly overridden above (produce, ack,
        # claim_pending, drain, depth, lag, trim_acked, ...) to the real bus.
        return getattr(self._inner, name)
