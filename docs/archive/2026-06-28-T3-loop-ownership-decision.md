# T3 Decision: Bus Loop Ownership

Date: 2026-06-28
Resolves: the one UNRESOLVED decision in the v0.1 build plan (bus `consume()` fix shape)
Status: **RESOLVED — mechanism proven on real Redis.** (Was "DIRECTION CHOSEN, MECHANISM
UNPROVEN"; see [SSOT.md](../../SSOT.md) for current canonical status.) The "still needs
real-Redis confirmation" gaps below were closed in the v0.1 live-infra session: XAUTOCLAIM +
XPENDING redelivery→DLQ ran on a real broker (see build-plan §"CI + live-infra
confirmations"), and the WS-4 duplicate-alert footgun (gap 4) was fixed by deterministic
`alert_key()` (T7, `services/ws4-detection/main.py:52`). Keeping the doc below unedited as
the historical decision record.

> **AMENDMENT (Opus 4.8 review).** This doc was architecture-by-assertion — it never wrote
> the runner's read loop, and three claims below are FALSE or unspecified against the real
> `bus.py`:
> 1. "consume() stays single-semantics: blocks on Redis" — FALSE. `bus.py:70` returns on
>    the first empty read. One thread over N topics starves topics 2..N under load. The
>    runner needs per-topic threads (N+1 threads/service), unmentioned here.
> 2. "DLQs poison after N tries" — the redelivery mechanism doesn't exist. `bus.py:69`
>    reads `{">"}` (new messages only); unacked messages sit in the PEL and are never
>    redelivered. Needs `XAUTOCLAIM` + `XPENDING.times_delivered`. Untestable on MemoryBus.
> 3. Ack-after-handler + non-idempotent produce → duplicate WS-4 alerts (`uuid4()` at
>    `ws4/main.py:44`). Needs deterministic alert_id.
> The shared-runner DIRECTION may still be right, but a real-Redis spike must write the
> actual loop (threads + PEL redelivery + re-entry) before this is locked. See the build
> plan's "T3 — DIRECTION CHOSEN, MECHANISM UNPROVEN" and the expanded T6/T7.

## The question

The eng review (Issue 1) and outside voice (#7) disagreed: dual-mode `consume(once=)`
vs. services own their own loop. The 2nd outside voice sharpened it into the real
question: **who owns the long-running consume loop** — because that dictates the daemon
shape (T0), the health-thread integration (T2), and where the ack happens (T7).

## What the code decided (grounded, not theoretical)

All five batch services share one shape (`ws2/main.py:36`, `ws3/main.py:40`,
`ws4/main.py:59`, `ws5/main.py:46`, `ws1/main.py`):

```python
def run(bus, deps) -> dict:
    stats = {...}
    for msg in bus.consume(topic, group=cg):
        handle(msg.payload)
        bus.produce(out_topic, ...)
        stats[...] += 1
    return stats
```

**The deciding fact: WS-3 consumes FOUR topics** (`ws3/main.py:22,39`):
```python
TOPICS = ["normalized.events", "scored.events", "alerts", "ai.results"]
for topic in TOPICS:
    for msg in bus.consume(topic, group="cg-index"):
        ...
```
A naive blocking `consume()` blocks forever on `normalized.events` and never reaches
the other three indices. So "just make consume() block" (simple services-own-loop)
is wrong for WS-3 without per-topic threads. And dual-mode `consume(once=)` doesn't
fix the ack footgun (acking before the handler runs is possible in either mode).

## Decision: a shared service runner

Introduce **`services/shared/runner.py`**:

```python
def serve(handlers: dict[str, tuple[str, Callable]],   # topic -> (group, handler)
          *, health_port: int | None = None,
          max_redeliveries: int = 5,
          shutdown: threading.Event | None = None) -> None:
    """Own the consume loop ONCE. For each topic: block-read, dispatch to handler,
    ack AFTER the handler returns, route poison to <topic>.deadletter after
    max_redeliveries. Run a /health thread if health_port is set. Loop until
    shutdown is set (SIGTERM)."""
```

Each service `main()` collapses to:
```python
def main():
    det = Detector()
    serve({"normalized.events": ("cg-detect", det.process_and_emit)}, health_port=8004)
```

`consume()` stays single-semantics: blocks on Redis, drains-and-returns on MemoryBus
(unit tests keep using the drain path directly via `bus.drain()`).

## Why this beats both original options

| Criterion | Dual-mode | Services-own-loop | Shared runner (chosen) |
|-----------|-----------|-------------------|------------------------|
| Boilerplate across 7 services | low | HIGH (5× loop+health+shutdown) | low (one runner) |
| Ack-before-process footgun | present | present | REMOVED (runner acks post-handler, 1 place) |
| WS-3 multi-topic | breaks if blocking | hand-rolled per service | native (`{topic: handler}` map) |
| Collapses T0/T2/T7 | no | no | YES — daemon+health+ack-DLQ built once |

## Impact on the build plan

- **T0 (daemon conversion):** becomes "build `shared/runner.py`, then rewrite 5
  `main()`s as `serve(...)` calls." Far smaller than 5 hand-rolled daemons.
- **T2 (/health):** the runner starts the health thread; no per-service HTTP code
  (mirror `ws6/app.py`'s stdlib `ThreadingHTTPServer`).
- **T7 (ack-after-processing + DLQ):** built into the runner once, not 7×.
- **WS-3:** pass all four topics in the handler map; the runner reads them all.
- **WS-6:** already a daemon (its own HTTP server) — it adopts the runner only for
  its bus-consuming parts (if any), keeps `serve_forever()` for the REST API.

## Criterion that settled it

Per T3's written criteria: "choose services-own-loop UNLESS it forces meaningful
duplicated loop boilerplate across all 7 services." It does (5× daemon+health+shutdown),
AND WS-3's multi-topic case makes a raw blocking loop wrong. The shared runner removes
the duplication AND the footgun — so neither original option wins; the runner does.

## Confirmation step (before T0 lands)

Validate against BOTH backends (the criterion the 2nd outside voice flagged):
1. MemoryBus: existing contract tests still pass (runner's drain path).
2. Real Redis: one service (WS-4) runs under `serve(...)`, processes a stream, acks
   after handling, survives a forced handler exception (message redelivered, then
   DLQ'd after N), and exits cleanly on SIGTERM.

Real-Redis confirmation requires a running Redis (docker-compose from T5, or a local
instance). Decision stands on the code analysis; this step is the proof.

## Spike result (implemented)

Date: 2026-06-28. Status: **MECHANISM HOLDS on MemoryBus; Redis claim/DLQ path
written but not yet run against a live Redis** (no `redis` module / no broker on this
dev box — Python 3.13.3 at `C:/Python313/python.exe`).

### What was built (real code, not a sketch)

- **`services/shared/runner.py`** — the shared runner.
  - `serve(handlers, *, health_port=None, max_redeliveries=5, shutdown=None,
    service_name=None, claim_idle_ms=60000, idle_sleep_s=0.5,
    install_signal_handlers=True, bus_factory=None)`.
  - **One thread PER topic** (`_topic_worker`), not one thread iterating topics —
    so WS-3's four topics can't starve each other. Each worker owns its own `Bus`
    instance (Redis consumer-name isolation + thread-safety).
  - **Ack AFTER the handler returns**: `_process_message` calls `bus.ack(msg, group)`
    only on handler success; a raising handler returns `"failed"` and is left unacked.
  - **Redelivery + cap → DLQ**: each worker loop calls
    `bus.claim_pending(topic, group, claim_idle_ms, max_redeliveries)` BEFORE reading
    new messages; when the (Redis-side) delivery count exceeds `max_redeliveries`,
    `_process_message` produces to `<topic>.deadletter` and acks.
  - **Re-entry / daemon loop**: `while not shutdown.is_set()` around consume; SIGTERM
    and SIGINT set the Event; clean join of workers + health server on exit. A short
    `shutdown.wait(idle_sleep_s)` on empty reads avoids busy-spin while staying
    shutdown-responsive.
  - **Health thread**: stdlib `ThreadingHTTPServer` (mirrors `ws6/app.py`) answering
    `GET /health` → `{"status":"ok","service":<name>}`.
  - `run_once(bus, handlers, ...)` — a single-pass, no-thread drain with the same
    ack/DLQ semantics, used by the unit tests and available for batch callers.

- **`services/shared/bus.py`** (additive; existing `produce/consume/drain` API
  preserved):
  - `_RedisBus.consume` **no longer auto-acks** (the `xack` at the old line 75 is
    gone) and returns on the first empty read so the runner can interleave
    `claim_pending`.
  - `_RedisBus.ack(msg, group)` → `XACK`.
  - `_RedisBus.claim_pending(topic, group, min_idle_ms, max_redeliveries)` → uses
    `XAUTOCLAIM` to reclaim idle PEL entries and yields `(Message, times_delivered)`,
    where `times_delivered` is read from `XPENDING` (`xpending_range`) — a Redis-side
    counter that **survives a consumer restart** (not an in-memory counter).
  - `_MemoryBus.ack` stays a no-op; `_MemoryBus.claim_pending` yields nothing
    (MemoryBus removes-on-yield, so it has no PEL to replay). MemoryBus still drains.

- **`services/ws4-detection/main.py`** — `main()` rewritten to
  `serve({"normalized.events": ("cg-detect", handler)}, health_port=8004,
  service_name="ws4-detection")`. The existing `run(bus, detector)` is **untouched**
  (the contract test still imports and calls it). The shared logic was extracted into
  `detect_one(bus, detector, event)`, which both `run()`'s loop body and the runner
  handler can use.

### What is PROVEN on MemoryBus (`services/shared/test_runner.py`, all pass)

- handler called exactly once per queued message, acked on success;
- a raising handler does **not** ack and does **not** DLQ on a single failure;
- deterministic redelivery replay: `failed, failed, failed, deadlettered` at
  `max_redeliveries=3`, with the original payload preserved in the DLQ envelope;
- a flaky handler that succeeds before the cap is acked and never DLQ'd;
- multi-topic dispatch routes each topic to its own handler;
- the **threaded** `serve()` processes a queued message, serves `/health`, and exits
  cleanly when the `shutdown` Event is set.

A separate threaded smoke test ran the real WS-4 `Detector` under `serve()` end to
end: a bank-critical event produced `scored.events`, `alerts`, and `ai.requests`, and
the worker exited cleanly. `run_all_tests.sh` (all seven contract tests + the contract
validator) still passes after the changes.

### What still needs real-Redis confirmation (honest gaps)

1. **The XAUTOCLAIM + XPENDING path has not executed against a live Redis.** It is
   written, and `test_runner.py::test_redis_redelivery_and_dlq` exercises it, but that
   test **SKIPS** here (no `redis` module, no broker). Unverified specifics: the
   `XAUTOCLAIM` return-tuple shape (2-tuple on redis 6.2 vs 3-tuple on 7.x — handled
   defensively but untested), and whether `XPENDING.times_delivered` increments
   exactly as assumed across `XAUTOCLAIM` reclaims. This MUST be run under
   docker-compose Redis (T5) before T0 locks.
2. **First-delivery delivery_count = 1 is an assumption** for the live worker: the
   `consume` branch passes `delivery_count=1`, relying on `claim_pending` to carry the
   true climbing count on redeliveries. Needs Redis confirmation that a never-acked
   message's `times_delivered` is `1` after the initial `XREADGROUP`.
3. **Idle-window tuning**: `claim_idle_ms` default 60s means a crashed consumer's
   in-flight message waits up to ~60s before another worker reclaims it. Fine for the
   spike; revisit for SLA.
4. **WS-4 duplicate-alert footgun (review item 3) is NOT addressed here** — `make_alert`
   still uses `uuid4()`. Ack-after-handler with a non-idempotent produce means a
   redelivered message re-emits a new alert. Out of scope for this runner spike;
   tracked separately (deterministic `alert_id`).

### Verdict

The shared-runner **direction holds** and did **not** need a per-service-loop
fallback. Per-topic threads cleanly solve WS-3's multi-topic starvation; moving the
ack out of `consume()` into the runner removes the ack-before-process footgun in one
place; the daemon/re-entry/shutdown loop works under threads. The one genuinely
unproven piece is the Redis PEL redelivery path — the structurally hardest part — which
is implemented but awaits a live Redis to confirm against `XAUTOCLAIM`/`XPENDING`
semantics.
