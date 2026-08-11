"""RedisWindowCounter survives a real Sentinel primary failover -- LIVE.

Closes the gap SSOT.md recorded against the 2026-08-06 HA pass: the distributed
window counter was wired to `Sentinel.master_for()` (FIX 1 / C1) and reviewed as
code-correct, but never re-proven by an actual primary kill. The bus layer's own
failover was proven live on 2026-08-05; the COUNTER path was not, and it is a
different client with a different lifetime.

Why this cannot be a zero-infra test, and why it cannot be a fresh process per
step: the defect class is a LONG-LIVED client pinned to the address of a master
that has since been demoted. A pinned client keeps writing to the old node,
which now answers `READONLY You can't write against a read only replica`, and
the sliding window goes dark for the rest of the process lifetime -- every
stateful rule silently stops firing while every health check stays green. A
fresh client built after the failover resolves the new master trivially and
would report success without ever exercising the bug. So this test holds ONE
`master_for()` client across the kill, exactly as a running ws4-detection
process does.

Run INSIDE the HA network (the Redis nodes are not host-published and Sentinel
hands back container-internal addresses):

    docker cp services/ws4-detection/test_window_sentinel_failover_live.py \\
        infra-ws4-detection-1:/tmp/
    docker exec infra-ws4-detection-1 python /tmp/test_window_sentinel_failover_live.py

and, from the host, `docker kill` the current master while it runs. The
companion orchestrator `tools/sentinel_failover_live.py` does both halves.

Skips cleanly (never fails) when BUS_BACKEND is not redis-sentinel or Sentinel
is unreachable -- same convention as the other live lanes.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# This file is normally executed from a COPY at /tmp inside the ws4 container
# (see the module docstring), where `HERE` is /tmp and `window` is not
# importable. The container's app dir is the real source of the module under
# test -- importing the deployed copy is the point, not a convenience.
if not (HERE / "window.py").exists():
    sys.path.insert(0, "/app/ws4-detection")

FAILS: list[str] = []

# How long to keep trying after phase 1 before giving up on ever seeing a
# failover. Generous: Sentinel's own down-after + election + the client's
# reconnect all have to fit, and the HA profile's failover-timeout is 20s.
_MAX_WAIT_S = 180
_POLL_S = 2


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _sentinel_and_client():
    import redis  # type: ignore
    from redis.sentinel import Sentinel  # type: ignore

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
    # Identical construction to services/ws4-detection/main.py's HA branch --
    # if that changes, this test must change with it or it stops proving
    # anything about the code that actually runs.
    client = sentinel.master_for(master_name, redis_class=redis.Redis,
                                 password=password, decode_responses=True)
    return sentinel, client, master_name


def main() -> int:
    backend = os.getenv("BUS_BACKEND", "")
    if backend != "redis-sentinel":
        print(f"[SKIP] window sentinel failover: BUS_BACKEND={backend or 'unset'}, "
              f"need redis-sentinel. Bring up the HA profile (make ha-up).")
        return 0
    try:
        sentinel, client, master_name = _sentinel_and_client()
        before = sentinel.discover_master(master_name)
    except Exception as exc:  # noqa: BLE001
        print(f"[SKIP] window sentinel failover: Sentinel unreachable ({exc}).")
        return 0

    from window import RedisWindowCounter  # noqa: E402

    counter = RedisWindowCounter(client, namespace=f"ws4:failovertest:{os.getpid()}")
    key = "sentinel-failover-probe"
    window_ms = 600_000  # 10min -- must outlive the whole failover, so a
                         # dropped count means lost state, never expiry

    # --- Phase 1: establish the counter works against the CURRENT master. ---
    # Also the control for the negative half: if these writes fail, nothing
    # after the kill means anything.
    now = int(time.time() * 1000)
    pre_count = 0
    for i in range(5):
        pre_count = counter.hit(key, now + i, window_ms, member=f"pre-{i}")
    check(pre_count == 5,
          f"pre-failover counter should read 5, got {pre_count} -- the counter "
          f"was not working before the kill, so the post-kill result proves nothing")
    print(f"[phase1] master={before} count={pre_count}", flush=True)
    print("READY-FOR-KILL", flush=True)

    # --- Phase 2: hold THIS client while the master is killed underneath it. ---
    deadline = time.time() + _MAX_WAIT_S
    after = before
    saw_write_failure = False
    post_count = None
    while time.time() < deadline:
        time.sleep(_POLL_S)
        try:
            after = sentinel.discover_master(master_name)
        except Exception:  # noqa: BLE001 -- Sentinel itself mid-election
            continue
        if after == before:
            continue
        # Master has moved. The SAME long-lived client must now follow it.
        try:
            post_count = counter.hit(key, int(time.time() * 1000), window_ms,
                                     member="post-0")
            break
        except Exception as exc:  # noqa: BLE001
            # Expected transiently: the pooled connection to the dead master
            # has to break before master_for() re-resolves. Retry until the
            # deadline -- a permanent failure is what this test is hunting.
            saw_write_failure = True
            print(f"[phase2] post-failover write retrying after "
                  f"{type(exc).__name__}: {exc}", flush=True)

    if after == before:
        print(f"[SKIP] window sentinel failover: master never moved off {before} "
              f"within {_MAX_WAIT_S}s -- no kill was performed, so nothing about "
              f"the counter was tested. Not claiming a pass.")
        return 0

    print(f"[phase2] master moved {before} -> {after} "
          f"(transient write failure seen: {saw_write_failure})", flush=True)

    check(post_count is not None,
          f"the long-lived counter client never completed a write after the "
          f"master moved {before} -> {after} within {_MAX_WAIT_S}s -- this is the "
          f"pinned-client defect C1 describes: the window goes dark and every "
          f"stateful rule silently stops firing")

    # --- Phase 3: the pre-failover state must have survived the promotion. ---
    # A promoted replica that had not replicated the window would answer writes
    # happily while having silently lost the count -- availability restored,
    # detection state gone. Distinguishing that from a healthy failover is the
    # whole reason this asserts a VALUE and not just "the write succeeded".
    if post_count is not None:
        check(post_count == 6,
              f"post-failover count should be 6 (5 replicated + 1 new), got "
              f"{post_count} -- the promoted replica did not carry the "
              f"pre-failover window state")

    if FAILS:
        print(f"\n[FAIL] window counter across a live Sentinel failover: "
              f"{len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        return 1
    print(f"\n[OK] RedisWindowCounter survived a live Sentinel primary failover "
          f"({before} -> {after}): one long-lived master_for() client followed "
          f"the promotion and the pre-failover window state was preserved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
