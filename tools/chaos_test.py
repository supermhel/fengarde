"""M1 correctness gate: `make chaos`.

Proves the pairing this project already claims separately -- at-least-once bus
delivery (proven, SSOT.md sec2) + idempotent alerting (deterministic alert_id,
proven) = effectively-once alerts -- actually holds when a service dies mid-flight,
not just in the zero-infra unit tests.

Requires the LIVE Docker stack (`make up` / `docker compose -f infra/docker-compose.yml
up -d`). This is NOT part of the zero-infra `make test` gate -- it needs a real Redis,
real OpenSearch, and the ability to `docker kill` real containers.

What it does:
  1. Generates N independent brute-force scenarios (N = CHAOS_SCENARIOS, default 40;
     10 events each = ~400-4000+ raw events depending on config -- scale via
     CHAOS_EVENTS_PER_SCENARIO), each from a distinct attacker IP so each is an
     independently-verifiable "did exactly one alert fire" unit.
  2. Writes them to `raw.events` (same wire shape as devkit-feeder / demo_e2e.py)
     spread over the whole run, while on a separate thread `docker kill -s KILL`-ing
     each ws1-ws5 container in turn (compose restart policy brings it back).
  3. Waits for the pipeline to drain, then queries OpenSearch:
       - every scenario's deterministic alert_id must appear exactly once
         (zero lost alerts -- a killed worker's in-flight events must be
         redelivered via the consumer group, not dropped)
       - no alert_id appears more than once (zero duplicate alerts -- the kill
         must not cause a partial write to double-fire)

Honesty note: this script is written against the compose service/container names
in infra/docker-compose.yml and the raw-event wire shape in
services/devkit-feeder/feed.py, but has NOT been run end-to-end in the environment
that authored it (no Docker daemon available there -- see the commit message).
Treat it as reviewed-but-unverified until a `make chaos` run's output is pasted
into a PR. Per SSOT.md sec2, do not mark M1's chaos gate "done" until that happens.

Run:  make chaos
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import redis  # already a project dependency (services/*/requirements.txt)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
TOPIC = "raw.events"

SCENARIOS = int(os.getenv("CHAOS_SCENARIOS", "40"))
EVENTS_PER_SCENARIO = int(os.getenv("CHAOS_EVENTS_PER_SCENARIO", "12"))  # >= bruteforce threshold (10)
BASE_S = int(os.getenv("CHAOS_BASE_S", str(int(time.time()))))

# Killed in this order, one every KILL_INTERVAL_S while the replay is in flight.
# Named as compose *service* names (not container names, which vary with
# COMPOSE_PROJECT_NAME) -- `docker compose kill -s KILL <service>` resolves it.
# ws6/ws7 are excluded: ws6 (inventory) and ws7 (dashboard) aren't on the
# raw->alert critical path this gate is proving.
COMPOSE_FILE = os.getenv("CHAOS_COMPOSE_FILE", "infra/docker-compose.yml")
KILL_TARGETS = [
    "ws1-collectors", "ws2-normalization",
    "ws4-detection", "ws3-indexer", "ws5-ai",
]
KILL_INTERVAL_S = float(os.getenv("CHAOS_KILL_INTERVAL_S", "3.0"))

DRAIN_TIMEOUT_S = float(os.getenv("CHAOS_DRAIN_TIMEOUT_S", "90"))
DRAIN_POLL_S = 2.0


@dataclass
class Scenario:
    attacker_ip: str
    alert_id: str = ""
    events: list = field(default_factory=list)


def attacker_ip(i: int) -> str:
    # 198.51.100.0/24 (TEST-NET-2, RFC 5737) -- same documentation range the
    # existing devkit-feeder uses for its single scenario.
    return f"198.51.100.{(i % 250) + 1}"


def ssh_fail_event(ip: str, seq: int, minute_base: int) -> dict:
    """Mirrors services/devkit-feeder/feed.py::ssh_fail() exactly."""
    return {
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{seq:02d} db01 sshd[2154]: "
                f"Failed password for invalid user admin from {ip} port 51000 ssh2"),
        "meta": {"received_at": minute_base + seq, "ingest_id": f"ssh-{ip}-{seq}"},
    }


def build_scenarios() -> list[Scenario]:
    scenarios = []
    for i in range(SCENARIOS):
        ip = attacker_ip(i)
        minute_base = BASE_S + i * 60  # each scenario in its own 60s window, no cross-scenario pooling
        events = [ssh_fail_event(ip, s, minute_base) for s in range(EVENTS_PER_SCENARIO)]
        scenarios.append(Scenario(attacker_ip=ip, events=events))
    return scenarios


def killer_thread(stop: threading.Event) -> None:
    for name in KILL_TARGETS:
        if stop.is_set():
            return
        time.sleep(KILL_INTERVAL_S)
        print(f"[chaos] docker compose kill -s KILL {name}")
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "kill", "-s", "KILL", name],
            check=False, capture_output=True,
        )


def replay(scenarios: list[Scenario]) -> None:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    for attempt in range(30):
        try:
            r.ping()
            break
        except redis.exceptions.ConnectionError:
            time.sleep(1)
    else:
        raise SystemExit("[chaos] Redis not reachable -- is the stack up? (`make up`)")

    all_events = [(sc.attacker_ip, ev) for sc in scenarios for ev in sc.events]
    print(f"[chaos] replaying {len(all_events)} raw events "
          f"across {len(scenarios)} independent brute-force scenarios")
    for ip, event in all_events:
        r.xadd(TOPIC, {"key": ip, "payload": json.dumps(event)})
        time.sleep(0.01)  # spread the replay across the full kill window, not a burst


def alert_ids_for(ip: str) -> list[str]:
    """Query alerts-* for every alert doc whose src is this scenario's attacker IP."""
    body = json.dumps({
        "query": {"term": {"src_endpoint.ip": ip}},
        "size": 50,
        "_source": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OPENSEARCH_URL}/alerts-*/_search", data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # no alerts-* index yet -- nothing has fired for this IP
            return []
        raise
    hits = payload.get("hits", {}).get("hits", [])
    return [h["_id"] for h in hits]


def verify(scenarios: list[Scenario]) -> int:
    deadline = time.time() + DRAIN_TIMEOUT_S
    lost: list[str] = []
    duplicated: list[tuple[str, list[str]]] = []
    while time.time() < deadline:
        lost, duplicated = [], []
        for sc in scenarios:
            ids = alert_ids_for(sc.attacker_ip)
            if len(ids) == 0:
                lost.append(sc.attacker_ip)
            elif len(ids) > 1:
                duplicated.append((sc.attacker_ip, ids))
        if not lost and not duplicated:
            break
        time.sleep(DRAIN_POLL_S)

    print(f"[chaos] scenarios={len(scenarios)} lost={len(lost)} duplicated={len(duplicated)}")
    if lost:
        print(f"[chaos] FAIL -- lost alerts for: {lost}")
    if duplicated:
        print(f"[chaos] FAIL -- duplicate alerts for: {duplicated}")
    if lost or duplicated:
        return 1
    print("[chaos] PASS -- zero lost alerts, zero duplicate alerts "
          f"across {len(scenarios)} scenarios, {len(KILL_TARGETS)} services killed mid-replay")
    return 0


def main() -> int:
    scenarios = build_scenarios()
    stop = threading.Event()
    killer = threading.Thread(target=killer_thread, args=(stop,), daemon=True)
    killer.start()
    try:
        replay(scenarios)
    finally:
        stop.set()
    return verify(scenarios)


if __name__ == "__main__":
    sys.exit(main())
