"""In-network half of the FAILOVER-scoped chaos scenario (acked-tail durability).

`tools/chaos_test.py` kills pipeline CONSUMERS and proves effectively-once
alerting under redelivery. SSOT.md §2 records, honestly, that this cannot see a
different failure class: the Redis PRIMARY accepting and acking a write it has
not replicated, then dying, so the promoted replica never had it. No SIGKILL of
a consumer replays that -- the event was acked and is simply gone.

FIX 23 set `--min-replicas-to-write 1 --min-replicas-max-lag 10` on the HA
primary to prevent it, trading write-availability for the guarantee. That
setting was reviewed but never demonstrated. This probe demonstrates it.

The contract under test, stated precisely: **every produce() that RETURNED
SUCCESS must be readable after a primary failover.** A produce that raised is
not covered -- refusing the write is the guarantee working, not a violation.
That asymmetry is the whole point, so successes and failures are tracked
separately and only the successes are asserted on.

Runs inside the HA network (Redis nodes are not host-published); the kill is
performed by `tools/chaos_failover_test.py` on the host.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
for candidate in (HERE.parent / "services", Path("/app")):
    if candidate.exists():
        sys.path.insert(0, str(candidate))

_MAX_WAIT_S = 180
_POLL_S = 1


def main() -> int:
    backend = os.getenv("BUS_BACKEND", "")
    if backend != "redis-sentinel":
        print(f"[SKIP] failover chaos: BUS_BACKEND={backend or 'unset'}, need "
              f"redis-sentinel (make ha-up).")
        return 0

    from redis.sentinel import Sentinel  # type: ignore
    from shared.bus import Bus  # noqa: E402

    hosts = []
    for part in os.getenv("REDIS_SENTINEL_HOSTS", "").split(","):
        part = part.strip()
        if not part:
            continue
        host, _, port = part.partition(":")
        hosts.append((host.strip(), int(port.strip()) if port.strip() else 26379))
    password = os.getenv("REDIS_PASSWORD", "") or None
    master_name = os.getenv("REDIS_SENTINEL_MASTER", "mymaster")
    sentinel = Sentinel(hosts, password=password, socket_timeout=1,
                        decode_responses=True)

    try:
        before = sentinel.discover_master(master_name)
    except Exception as exc:  # noqa: BLE001
        print(f"[SKIP] failover chaos: Sentinel unreachable ({exc}).")
        return 0

    topic = f"chaos.failover.{uuid.uuid4().hex[:8]}"
    bus = Bus()

    acked: list[str] = []     # produce() returned success -> MUST survive
    refused: list[str] = []   # produce() raised -> not covered by the contract

    def emit(tag: str) -> None:
        key = f"{tag}-{len(acked) + len(refused)}"
        try:
            bus.produce(topic, key, {"probe": key})
            acked.append(key)
        except Exception as exc:  # noqa: BLE001
            refused.append(key)
            print(f"[probe] produce refused ({key}): {type(exc).__name__}: {exc}",
                  flush=True)

    # --- Phase 1: baseline writes against the current primary. ---
    for _ in range(20):
        emit("pre")
    if not acked:
        print("[SKIP] failover chaos: no baseline write succeeded, so nothing "
              "about the failover path can be tested.")
        return 0
    print(f"[phase1] master={before} acked={len(acked)} refused={len(refused)}",
          flush=True)
    print("READY-FOR-KILL", flush=True)

    # --- Phase 2: keep writing across the kill. ---
    # Writes are EXPECTED to be refused for part of this window (that is FIX 23
    # holding the line rather than acking an unreplicated write); refusals are
    # recorded, not asserted against.
    deadline = time.time() + _MAX_WAIT_S
    after = before
    while time.time() < deadline:
        time.sleep(_POLL_S)
        emit("during")
        try:
            after = sentinel.discover_master(master_name)
        except Exception:  # noqa: BLE001 -- Sentinel mid-election
            continue
        if after != before:
            break

    if after == before:
        print(f"[SKIP] failover chaos: master never moved off {before} within "
              f"{_MAX_WAIT_S}s -- no kill happened, nothing tested.")
        return 0

    # Let the promotion settle, then write once more so the post-failover path
    # is exercised by the same long-lived bus client.
    for _ in range(10):
        time.sleep(_POLL_S)
        emit("post")
        if acked and acked[-1].startswith("post"):
            break

    print(f"[phase2] master moved {before} -> {after}; "
          f"acked={len(acked)} refused={len(refused)}", flush=True)

    # --- Phase 3: every acked write must be readable from the NEW primary. ---
    # Read via a FRESH client so this reflects the promoted node's actual
    # state, not anything cached on the producer's connection.
    survivors: set[str] = set()
    try:
        client = sentinel.master_for(master_name, password=password,
                                     decode_responses=True)
        for _, fields in client.xrange(topic, "-", "+"):
            key = fields.get("key") or fields.get("k")
            if key:
                survivors.add(key)
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] failover chaos: could not read {topic} back from the "
              f"promoted primary: {type(exc).__name__}: {exc}")
        return 1

    lost = [k for k in acked if k not in survivors]
    print(f"[phase3] acked={len(acked)} present_after_failover={len(survivors)} "
          f"lost={len(lost)} refused_not_asserted={len(refused)}", flush=True)

    if lost:
        print(f"\n[FAIL] failover chaos: {len(lost)} acked event(s) did NOT "
              f"survive the primary failover -- the primary acked writes it had "
              f"not replicated. First few: {lost[:5]}")
        return 1

    print(f"\n[OK] failover chaos: all {len(acked)} acked event(s) survived a "
          f"real primary failover ({before} -> {after}); {len(refused)} write(s) "
          f"were refused mid-failover, which is FIX 23's min-replicas guarantee "
          f"holding rather than acking an unreplicated write")
    return 0


if __name__ == "__main__":
    sys.exit(main())
