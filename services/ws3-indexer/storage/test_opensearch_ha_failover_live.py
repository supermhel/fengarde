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
    """The 3-node HA URL list, in ``opensearch-1,opensearch-2,opensearch-3``
    order (matches ``_CONTAINER_NAME``'s insertion order below, which is how
    ``_test_writer_survives_node_kill`` maps a container name back to its
    reachability URL).

    No single-node fallback: this test's entire point is proving a node CAN
    die without the writer dying with it, so it needs a real 3-node cluster
    or nothing meaningful is exercised. A single ``http://localhost:9200``
    fallback used to let the ordinary (non-HA) `make up` stack satisfy the
    reachability gate below, then fail post-kill for a reason that has
    nothing to do with H6 (there's no surviving node to fail over to) --
    masking the real signal. Fewer than 3 nodes -> the caller skips instead.
    """
    raw = os.getenv("OPENSEARCH_URL", "")
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


class _DockerUnavailable(Exception):
    """The `docker` binary itself couldn't be invoked -- a legitimate SKIP,
    distinct from docker running but the command failing (a real test
    failure)."""


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "version"],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _run_docker(*args: str) -> subprocess.CompletedProcess:
    """Run a `docker ...` command. Raises `_DockerUnavailable` only when the
    binary can't be invoked at all; a non-zero exit from a present `docker`
    (wrong container name, container not running, daemon reachable but
    refuses) is returned to the caller to handle as a real failure -- NOT
    swallowed here. 2026-08-07 audit: the prior version conflated the two
    (`return r.returncode == 0`), so a wrong-invocation error looked
    identical to "docker not installed" one level up and both routed to the
    same silent SKIP -> false [OK] PASS."""
    try:
        return subprocess.run(list(args), capture_output=True, text=True,
                              timeout=60)
    except FileNotFoundError as exc:
        raise _DockerUnavailable(str(exc)) from exc


def _kill_container(container: str) -> None:
    """Kill one node's container directly. Raises on any failure (docker
    unavailable, or `docker kill` itself returning non-zero) -- the caller
    decides SKIP vs FAIL based on which exception it catches."""
    r = _run_docker("docker", "kill", container)
    if r.returncode != 0:
        raise RuntimeError(
            f"docker kill {container} failed (exit {r.returncode}): "
            f"{(r.stderr or r.stdout).strip()}")


def _start_container(container: str) -> None:
    r = _run_docker("docker", "start", container)
    if r.returncode != 0:
        raise RuntimeError(
            f"docker start {container} failed (exit {r.returncode}): "
            f"{(r.stderr or r.stdout).strip()}")


def _test_writer_survives_node_kill(store: OpenSearchStore, index: str,
                                    nodes: list[str]) -> None:
    # Precondition: every node is up and the cluster is green-ish.
    up = all(_reachable(n) for n in nodes)
    check(up, f"all {len(nodes)} OpenSearch nodes must be reachable for the "
              f"HA kill test (got reachability {[_reachable(n) for n in nodes]})")
    if not up:
        return

    # Map each HA container name to the URL it was given on the command line
    # (docstring's documented order: opensearch-1,opensearch-2,opensearch-3),
    # so the reachability polling below checks the ACTUAL target node instead
    # of a hardcoded docker-network hostname that never resolves from the
    # host running this test.
    node_url = dict(zip(_CONTAINER_NAME.keys(), nodes))

    # 1. Baseline write through the multi-node store.
    doc_id = f"ha-live-{uuid.uuid4()}"
    store.index(index, doc_id, {"n": 1, "stage": "baseline"})
    store._request("POST", f"/{index}/_refresh")
    check(store.count(index) >= 1, "baseline index should be visible to count()")

    # 2. Kill ONE node. The HA profile names them opensearch-1..3; the current
    # node may or may not be the one killed -- that's fine, the store must
    # survive either way.
    target = "opensearch-1"
    target_url = node_url[target]
    container = _CONTAINER_NAME[target]
    try:
        _kill_container(container)
    except _DockerUnavailable:
        print("[SKIP] HA failover: `docker` is not available on this host "
              "-- skipping the live kill, not claiming it happened")
        return
    except RuntimeError as exc:
        # docker IS available but the kill itself failed (wrong container
        # name, container already stopped, daemon refused, ...) -- this is a
        # real problem with the test's own preconditions, not an environment
        # that legitimately has no docker. Must fail loud, not SKIP: a silent
        # skip here is exactly the false-[OK] bug this file's history (see
        # the 2026-08-07 fix comment above) already found once.
        check(False, f"could not kill container '{container}': {exc}")
        return

    # Wait for the dead node to stop answering.
    for _ in range(30):
        if not _reachable(target_url):
            break
        time.sleep(1)
    check(not _reachable(target_url),
          f"{container} ({target_url}) still answering 30s after `docker kill` "
          "-- the node was not actually taken down")

    # 3. A post-kill write MUST still succeed via round-robin to a survivor.
    # THIS is the H6 claim -- a single-node-pinned writer would hang here.
    doc2_id = f"ha-live-{uuid.uuid4()}"
    try:
        ok = store.index(index, doc2_id, {"n": 2, "stage": "post-kill"})
        check(ok is not False,
              "write after killing a node must succeed (surviving-node failover)")
    except Exception as exc:  # noqa: BLE001 -- surface the exact failure
        check(False, f"write after killing a node raised: {type(exc).__name__}: {exc}")

    # 4. Restore the node (cleanup) so a subsequent run isn't red, and so the
    # environment isn't left with a dead container. A restart failure is a
    # real problem (the next run starts one node down) -- surfaced, not
    # swallowed.
    try:
        _start_container(container)
    except RuntimeError as exc:
        check(False, f"could not restart container '{container}' after the "
                      f"test (environment left with a node down): {exc}")
        return
    for _ in range(60):
        if _reachable(target_url):
            break
        time.sleep(1)
    check(_reachable(target_url),
          f"{container} ({target_url}) did not come back reachable within 60s "
          "of `docker start` (environment left with a node down)")


def main() -> None:
    nodes = _nodes_from_env()
    # Skip cleanly unless OPENSEARCH_URL names all 3 HA nodes -- this is a
    # live lane and, unlike other node counts, killing one of fewer than 3
    # would legitimately leave no survivor to fail over to (see
    # _nodes_from_env's docstring for why there is no single-node fallback).
    if len(nodes) < 3:
        print(f"[SKIP] test_opensearch_ha_failover_live: OPENSEARCH_URL must "
              f"name all 3 HA nodes (comma-separated); got {nodes or 'none'}. "
              "Bring up `docker compose -f infra/docker-compose.ha.yml up -d` "
              "and set OPENSEARCH_URL=http://opensearch-1:9200,"
              "http://opensearch-2:9200,http://opensearch-3:9200 "
              "(make test-live).")
        return
    if not all(_reachable(n) for n in nodes):
        print(f"[SKIP] test_opensearch_ha_failover_live: not all nodes reachable "
              f"({nodes}). Bring up `docker compose -f infra/docker-compose.ha.yml "
              "up -d` (3-node OpenSearch) to run this lane (make test-live).")
        return
    if not _docker_available():
        print("[SKIP] test_opensearch_ha_failover_live: `docker` is not "
              "available on this host -- cannot perform the live kill.")
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
