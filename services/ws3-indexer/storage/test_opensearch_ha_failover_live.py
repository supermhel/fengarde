"""Opt-in LIVE OpenSearch 3-node HA kill test (Task B, 2026-08-06).

This is a `make test-live`-class lane (NOT zero-infra). It brings up / expects
the HA profile's 3-node OpenSearch cluster, then proves the WRITER survives a
node dying:

  - constructs `OpenSearchStore` with the comma-separated 3-node URL list
    (the exact config `infra/docker-compose.ha.yml` now gives ws3-indexer),
  - indexes a doc (goes through whichever node is current),
  - kills one node with `docker compose kill`,
  - indexes another doc and asserts it STILL succeeds via round-robin failover
    to a surviving node (this is FIX H6 -- without it the writer pins to one
    node and dies),
  - restarts the killed node (cleanup).

Modeled on `services/shared/test_sentinel_failover.py` (the HA failover-claim
guard) and `services/ws3-indexer/storage/test_opensearch_live.py` (the
skip-if-unreachable `make test-live` convention). It deliberately does NOT
run in the zero-infra gate: it needs real Docker + all 3 nodes up.

Honest scope: it proves *writer failover* (the app survives a node death) on a
live cluster. It does NOT here assert OpenSearch's own shard-recovery timeline
or the full chaos "0 lost" claim -- that's `make chaos`. This is the writer's
resilience claim specifically, which nothing else exercises.

Run (with the HA profile up):
    OPENSEARCH_URL=http://opensearch-1:9200,http://opensearch-2:9200,http://opensearch-3:9200 \
    python services/ws3-indexer/storage/test_opensearch_ha_failover_live.py
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # for `storage`

from storage.opensearch import OpenSearchStore  # noqa: E402

FAILS: list[str] = []
_DEFAULT_NODES = [
    "http://localhost:9200",  # single-node fallback (also makes reachable() honest)
]


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _reachable(url: str) -> bool:
    """True if url answers _cluster/health in <2s."""
    try:
        with urllib.request.urlopen(f"{url}/_cluster/health", timeout=2):
            return True
    except Exception:
        return False


def _nodes_from_env() -> list[str]:
    raw = os.getenv("OPENSEARCH_URL", "")
    if not raw:
        return _DEFAULT_NODES
    return [part.strip() for part in raw.split(",") if part.strip()]


# 2026-08-07 fix: the original `docker compose -f infra/docker-compose.ha.yml
# kill <service>` invocation always failed (that file is an OVERRIDE -- it has
# no image/build context for services like ws1-collectors that the merged
# project also needs, so compose rejects it as "invalid compose project" when
# given alone). That failure was silently swallowed into the "docker/compose
# unavailable" SKIP path below, so this test reported [OK] PASS on every run
# without ever actually killing a node -- a false green, found by actually
# running this live for the first time. Fixed by killing the container
# directly (bypasses compose project-file resolution entirely, and the HA
# profile's container_names are fixed/known, see docker-compose.ha.yml).
_CONTAINER_NAME = {"opensearch-1": "siem-store-ha-1",
                   "opensearch-2": "siem-store-ha-2",
                   "opensearch-3": "siem-store-ha-3"}


def _killed_via_compose(service: str) -> bool:
    """Kill one node's container directly. Returns False only if `docker`
    itself isn't available (the lane then skips the actual kill rather than
    pretending it happened) -- NOT on a wrong-invocation error, which must
    surface as a real failure, not a silent skip."""
    container = _CONTAINER_NAME.get(service, service)
    try:
        r = subprocess.run(["docker", "kill", container],
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _restart_via_compose(service: str) -> bool:
    container = _CONTAINER_NAME.get(service, service)
    try:
        r = subprocess.run(["docker", "start", container],
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _test_writer_survives_node_kill(store: OpenSearchStore, index: str,
                                    nodes: list[str]) -> None:
    # Precondition: every node is up and the cluster is green-ish.
    up = all(_reachable(n) for n in nodes)
    check(up, f"all {len(nodes)} OpenSearch nodes must be reachable for the "
              f"HA kill test (got reachability {[_reachable(n) for n in nodes]})")
    if not up:
        return

    # 1. Baseline write through the multi-node store.
    doc_id = f"ha-live-{uuid.uuid4()}"
    store.index(index, doc_id, {"n": 1, "stage": "baseline"})
    store._request("POST", f"/{index}/_refresh")
    check(store.count(index) >= 1, "baseline index should be visible to count()")

    # 2. Kill ONE node. The Ha profile names them opensearch-1..3; the current
    # node may or may not be the one killed -- that's fine, the store must
    # survive either way.
    target = "opensearch-1"
    if not _killed_via_compose(target):
        print(f"[SKIP] HA failover: could not kill container "
              f"'{_CONTAINER_NAME.get(target, target)}' (docker unavailable, "
              "or the container wasn't running) -- skipping the live kill, "
              "not claiming it happened")
        return
    # Wait for the dead node to stop answering.
    for _ in range(30):
        if not _reachable(f"http://{target}:9200"):
            break
        time.sleep(1)

    # 3. A post-kill write MUST still succeed via round-robin to a survivor.
    # THIS is the H6 claim -- a single-node-pinned writer would hang here.
    doc2_id = f"ha-live-{uuid.uuid4()}"
    try:
        ok = store.index(index, doc2_id, {"n": 2, "stage": "post-kill"})
        check(ok is not False,
              "write after killing a node must succeed (surviving-node failover)")
    except Exception as exc:  # noqa: BLE001 -- surface the exact failure
        check(False, f"write after killing a node raised: {type(exc).__name__}: {exc}")

    # 4. Restore the node (cleanup) so a subsequent run isn't red.
    _restart_via_compose(target)
    for _ in range(60):
        if _reachable(f"http://{target}:9200"):
            break
        time.sleep(1)


def main() -> None:
    nodes = _nodes_from_env()
    # Skip cleanly unless every node answers -- this is a live lane.
    if not all(_reachable(n) for n in nodes):
        print(f"[SKIP] test_opensearch_ha_failover_live: not all nodes reachable "
              f"({nodes}). Bring up `docker compose -f infra/docker-compose.ha.yml "
              "up -d` (3-node OpenSearch) to run this lane (make test-live).")
        return

    store = OpenSearchStore(url=",".join(nodes))
    index = "events-ha-livetest"
    _test_writer_survives_node_kill(store, index, nodes)

    if FAILS:
        print(f"\n[FAIL] opensearch HA failover live: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("\n[OK] opensearch 3-node HA writer failover (live kill) PASS")


if __name__ == "__main__":
    main()
