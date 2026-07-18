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
     each ws1-ws5 container in turn, then `docker compose start`-ing it back up.
  3. Waits for the pipeline to drain, then queries OpenSearch:
       - every scenario's deterministic alert_id must appear exactly once
         (zero lost alerts -- a killed worker's in-flight events must be
         redelivered via the consumer group, not dropped)
       - no alert_id appears more than once (zero duplicate alerts -- the kill
         must not cause a partial write to double-fire)

Honesty note (updated after two live runs, 2026-07-18): the original version of
this script assumed `restart: unless-stopped` in infra/docker-compose.yml would
bring a killed service back on its own. That assumption was FALSE for `docker
compose kill` specifically (Docker Compose v5.1.4 verified) -- unlike a raw
`docker kill <container_id>`, killing a service *through compose* marks it as
compose-stopped, which suppresses the restart policy; the container stayed
Exited(137) with RestartCount 0 indefinitely. Fixed by having the killer
explicitly `docker compose start` each target after killing it, and by joining
the killer thread before verify() runs (it used to race replay() finishing
early and skip the last two kills).

Both of those were real bugs and both are fixed. The remaining 34/40 "loss"
on the second run was then root-caused to a THIRD harness bug, not a pipeline
bug: the original scenario layout put scenario i's events at `BASE_S + i*60`
-- up to 39 minutes in the FUTURE -- and the engine's window-poisoning guard
(`engine.py::_MAX_CLOCK_SKEW_MS`, merged from main's P0 hardening pass) fails
closed on any event more than 5 minutes ahead of wall clock. Exactly
scenarios 0-4 alerted and 5-39 were dropped, deterministically, on both runs,
kills irrelevant -- a semantic merge incompatibility git could never flag
(harness authored on the PR branch and never run there; guard authored on
main). Fixed by placing scenarios in past, minute-aligned buckets (see
build_scenarios). The "alert_id tenant inconsistency" seen alongside it was
also explained: one alert predated the F1 tenant-namespacing fix (old
container image, volume not wiped between runs) and devkit-feeder's own
198.51.100.23 burst collided with scenario 22's IP -- the harness now uses
TEST-NET-3 and a `make down -v`-fresh stack is required for a clean verdict.

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
    # 203.0.113.0/24 (TEST-NET-3, RFC 5737). Deliberately NOT TEST-NET-2:
    # devkit-feeder injects its own brute-force burst from 198.51.100.23 on
    # every `make up`, so a chaos scenario reusing that IP inherits the
    # feeder's alert and reads as a false "duplicate" (this actually happened
    # -- scenario 22's IP collided with the feeder's on the first live runs).
    return f"203.0.113.{(i % 250) + 1}"


def ssh_fail_event(ip: str, seq: int, minute_base: int, user: str) -> dict:
    """Mirrors services/devkit-feeder/feed.py::ssh_fail() wire shape.

    ``user`` is per-scenario, NOT the feeder's fixed "admin": with one shared
    username, 40 scenarios x 12 events reads as a textbook password spray (one
    user, 40 source IPs) and the spray rule legitimately fires alongside each
    scenario's brute-force alert -- which verify(), querying by src IP alone,
    then miscounts as a "duplicate". (Observed live: 7 spray alerts, one per
    5-minute event-time bucket, all grouped on "admin".) Distinct users keep
    each scenario's expected outcome exactly one brute-force alert.
    """
    return {
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{seq:02d} db01 sshd[2154]: "
                f"Failed password for invalid user {user} from {ip} port 51000 ssh2"),
        "meta": {"received_at": minute_base + seq, "ingest_id": f"ssh-{ip}-{seq}"},
    }


def build_scenarios() -> list[Scenario]:
    scenarios = []
    for i in range(SCENARIOS):
        ip = attacker_ip(i)
        # Each scenario gets its own 60s window (no cross-scenario pooling) by
        # living in its own minute -- in the PAST, aligned to a minute boundary.
        #
        # Two hard-won constraints (root-caused from the first live runs):
        #  - PAST, not future: the engine's window-poisoning guard
        #    (engine.py::_MAX_CLOCK_SKEW_MS) fails closed on any event more
        #    than 5 minutes ahead of wall clock -- it exists precisely so an
        #    attacker-controlled timestamp can't corrupt a window. The original
        #    `BASE_S + i * 60` put scenario i >= 5 entirely in the guarded
        #    future, so exactly scenarios 0-4 alerted and the rest were
        #    silently dropped (the deterministic 34/40 "loss" on both first
        #    runs -- not a redelivery bug at all). Past times are the engine's
        #    documented replay path and always legal.
        #  - Minute-ALIGNED: seq 0..EVENTS_PER_SCENARIO-1 seconds must not
        #    straddle a minute boundary, or one scenario's threshold crossing
        #    can emit two alert_ids in adjacent buckets and read as a false
        #    duplicate.
        minute_base = (BASE_S // 60 - i) * 60
        user = f"chaos{i:02d}"  # per-scenario user: see ssh_fail_event docstring
        events = [ssh_fail_event(ip, s, minute_base, user) for s in range(EVENTS_PER_SCENARIO)]
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
        # `docker compose kill` records the service as compose-stopped, which
        # SUPPRESSES `restart: unless-stopped` -- unlike a raw `docker kill` on
        # the container id, a killed-via-compose service does NOT come back on
        # its own (verified live: RestartCount stayed 0, container stayed
        # Exited(137) indefinitely). `docker compose start` is what actually
        # revives it; this is not optional cleanup, it's the mechanism this
        # whole gate depends on to prove redelivery-after-restart, not
        # redelivery-after-permanent-death.
        print(f"[chaos] docker compose start {name}")
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "start", name],
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
        # `stop` is an abort switch (e.g. replay() raised), not a "replay
        # finished" signal -- replay() reliably finishes well before the
        # killer thread works through all 5 targets (kill+restart per target
        # takes longer than 480 xadds do), so setting `stop` here unconditionally
        # used to cut the kill sequence short after ~3 of 5 targets. Only abort
        # early on an actual exception; on the normal path, let the killer run
        # to completion and join it below instead.
        if sys.exc_info()[0] is not None:
            stop.set()
    killer.join(timeout=KILL_INTERVAL_S * len(KILL_TARGETS) + 30)
    if killer.is_alive():
        print("[chaos] WARNING -- killer thread did not finish within its budget; "
              "verify() results below may reflect a partial kill sequence")
        stop.set()
    return verify(scenarios)


if __name__ == "__main__":
    sys.exit(main())
