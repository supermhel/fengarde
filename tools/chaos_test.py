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
# ws7 is excluded: it's HTTP-read-only, no bus code anywhere in the service.
#
# ws6 is ALSO excluded, but the ORIGINAL comment here ("aren't on the
# raw->alert critical path") was false for it and went stale silently: since
# 2026-08-05 (bus_consumer.py, wired live via BUS_BACKEND=redis in
# infra/docker-compose.yml) ws6-inventory DOES consume off the bus
# (assets.updates) and CAN produce onto raw.events -- the exact topic this
# harness replays into and verify() reads alerts back from. It stays
# excluded for a real reason, just not the one originally written: these
# scenarios are SSH brute-force bursts over 203.0.113.0/24, never an
# assets.updates observation, so ws6's raw.events-producing path (gated on
# `is_new_device`, see bus_consumer.py::make_handler) never fires during a
# chaos run -- killing ws6 here would exercise nothing verify() can observe,
# which is the "test that can't fail" anti-pattern this project explicitly
# guards against (eval/attack/test_fire_check.py's convention) rather than
# real coverage. Separately and more importantly: ws6's OWN crash-recovery
# has NO test anywhere (no /health route, no healthcheck in compose, the
# bus_consumer thread is unsupervised) -- that gap is real but is not what
# adding it to this list would prove; tracked as its own item, not solved by
# a mechanical KILL_TARGETS addition. Corrected 2026-08-23.
#
# ws8-correlation (cg-correlate on `alerts` -> `incidents`, shipped 2026-08-18)
# WAS missing here with no exclusion comment -- an oversight, not a decision:
# unlike ws6/ws7 it IS bus-connected on a path this gate cares about (it
# consumes the very `alerts` topic verify() reads). Added 2026-08-23.
# Caveat (read before trusting a green run as WS-8 coverage): these scenarios
# are single-tactic brute-force bursts, so none cross the >=2-distinct-MITRE-
# tactic threshold ws8 needs to promote an incident -- killing ws8 here proves
# it dies and restarts cleanly without wedging the `cg-correlate` consumer
# group or the rest of the pipeline, NOT exactly-once incident promotion
# under kill. That needs its own multi-tactic-per-entity scenario + an
# incidents-* verify() query; tracked as a separate gap, not solved by this
# one-line addition.
#
# ws9-resolver (entity resolver, added to infra/docker-compose.yml 2026-09-02,
# ADR-009) consumes the same `alerts` topic verify() reads to build the
# entity graph (entity.updates) -- bus-connected on a path this gate cares
# about, same reasoning as ws8-correlation above. Added 2026-09-02. Same
# caveat as ws8: this proves ws9 dies/restarts cleanly under kill without
# wedging its `alerts` consumer group, not entity-state correctness under
# kill (e.g. a merge landing mid-restart) -- that needs its own
# entity_state()-diffing assertion, tracked as a separate gap.
COMPOSE_FILE = os.getenv("CHAOS_COMPOSE_FILE", "infra/docker-compose.yml")
KILL_TARGETS = [
    "ws1-collectors", "ws2-normalization",
    "ws4-detection", "ws3-indexer", "ws5-ai", "ws8-correlation",
    "ws9-resolver",
]
KILL_INTERVAL_S = float(os.getenv("CHAOS_KILL_INTERVAL_S", "3.0"))
# Pause between replay pulses (see replay()); each full pulse of the scenario
# corpus takes ~EVENTS_PER_SCENARIO*SCENARIOS*0.01s, so with the default 480
# events that is ~5s of traffic per pulse.
REPLAY_PULSE_GAP_S = float(os.getenv("CHAOS_REPLAY_PULSE_GAP_S", "4.0"))

DRAIN_TIMEOUT_S = float(os.getenv("CHAOS_DRAIN_TIMEOUT_S", "90"))
DRAIN_POLL_S = 2.0

# Redis consumer-group claim timeout: a stalled worker's in-flight message is
# only redelivered (and a partial write is only able to double-fire) after the
# claim_idle_ms idleness threshold -- redis-py's redis.conf default is 60000ms
# (configurable via CHAOS_CLAIM_IDLE_MS if the deployment has tuned it). The
# "zero duplicate alerts" half of verify() must not be judged until this window
# has had a chance to elapse and a stale worker's redelivery actually land --
# otherwise it is a tautology evaluated while redelivery is still impossible.
CLAIM_IDLE_MS = int(os.getenv("CHAOS_CLAIM_IDLE_MS", "60000"))
DEDUP_SETTLE_S = CLAIM_IDLE_MS / 1000.0 + 10.0  # window + margin


@dataclass
class Scenario:
    attacker_ip: str
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


# Failures collected from the killer thread (docker compose kill/start return
# codes were previously inspected by NOBODY -- a renamed service, wrong compose
# file, or Docker-engine error silently turned every kill into a no-op while
# verify() printed PASS on top of an untouched stack). Appends are atomic under
# the GIL; read only after the killer thread has been joined.
KILL_ERRORS: list[str] = []


def killer_thread(stop: threading.Event, kills_done: threading.Event) -> None:
    try:
        for name in KILL_TARGETS:
            if stop.is_set():
                return
            time.sleep(KILL_INTERVAL_S)
            print(f"[chaos] docker compose kill -s KILL {name}")
            k = subprocess.run(
                ["docker", "compose", "-f", COMPOSE_FILE, "kill", "-s", "KILL", name],
                check=False, capture_output=True,
            )
            if k.returncode != 0:
                # A no-op kill (service renamed since this list was written, or
                # the wrong compose file) means this target was never actually
                # killed -- continuing would misreport coverage as a pass.
                KILL_ERRORS.append(
                    f"docker compose kill {name} failed rc={k.returncode} "
                    f"(renamed service / wrong CHAOS_COMPOSE_FILE / docker down?): "
                    f"{(k.stderr or k.stdout).decode(errors='replace').strip()[:300]}"
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
            s = subprocess.run(
                ["docker", "compose", "-f", COMPOSE_FILE, "start", name],
                check=False, capture_output=True,
            )
            if s.returncode != 0:
                KILL_ERRORS.append(
                    f"docker compose start {name} failed rc={s.returncode} "
                    f"(environment left one service down; a restart is required "
                    f"before the next run): "
                    f"{(s.stderr or s.stdout).decode(errors='replace').strip()[:300]}"
                )
    finally:
        # Always signal: replay() stops pulsing on this, verify() runs after.
        kills_done.set()


def replay(scenarios: list[Scenario], kills_done: threading.Event) -> None:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    for attempt in range(30):
        try:
            r.ping()
            break
        except redis.exceptions.ConnectionError:
            time.sleep(1)
    else:
        # kills_done must be set on every exit path: main() joins us before
        # verify(), and a hung replay must not leave the killer waiting on a
        # join that never comes.
        kills_done.set()
        raise SystemExit("[chaos] Redis not reachable -- is the stack up? (`make up`)")

    all_events = [(sc.attacker_ip, ev) for sc in scenarios for ev in sc.events]
    print(f"[chaos] replaying {len(all_events)} raw events "
          f"across {len(scenarios)} independent brute-force scenarios")
    # Keep re-pulsing until the killer has cycled EVERY target, so live traffic
    # overlaps the whole kill sequence -- a single ~5s pulse used to finish long
    # before the ~25s of kills across 6 targets, which meant "killed mid-replay"
    # only ever held for the first two kills and the redelivery paths for the
    # later targets were never exercised under load. Re-pulses are idempotent by
    # construction (deterministic alert_id -> the indexer dedups), which is
    # exactly the property this gate exists to prove, so they cannot manufacture
    # a false duplicate or a false loss.
    pulse = 0
    while not kills_done.is_set():
        pulse += 1
        if pulse > 1:
            print(f"[chaos] replay pulse #{pulse} -- kill sequence still in flight")
        for ip, event in all_events:
            r.xadd(TOPIC, {"key": ip, "payload": json.dumps(event)})
            time.sleep(0.01)  # spread the replay across the full kill window, not a burst
        if not kills_done.is_set():
            time.sleep(REPLAY_PULSE_GAP_S)


def alert_ids_for(ip: str) -> list[tuple[str, str | None]]:
    """Query alerts-* for every alert doc whose src is this scenario's attacker
    IP. Returns [(doc_id, alert_id)] -- the alert_id is the engine's
    deterministic id (rule+group+window bucket); ALL docs for one scenario must
    carry the SAME alert_id (one deterministic alert per window), which is the
    property that makes at-least-once redelivery safe."""
    body = json.dumps({
        "query": {"term": {"src_endpoint.ip": ip}},
        "size": 50,
        "_source": ["alert_id"],
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
    return [(h["_id"], (h.get("_source") or {}).get("alert_id")) for h in hits]


def verify(scenarios: list[Scenario]) -> int:
    if DRAIN_TIMEOUT_S <= 0:
        # A zero/negative drain budget would loop zero times and vacuously
        # PASS on never-queried state -- fail the misconfiguration instead.
        print(f"[chaos] FAIL -- CHAOS_DRAIN_TIMEOUT_S={DRAIN_TIMEOUT_S} is not a "
              f"positive number of seconds; refusing to run a vacuous verdict")
        return 1
    # Total budget = DRAIN_TIMEOUT_S for alerts to surface PLUS DEDUP_SETTLE_S
    # for the redelivery settle window: the dedup verdict must not be judged
    # before a killed worker's stalled message could have been redelivered
    # (claim_idle_ms) and double-fired. Polling for "zero duplicates" before
    # that window has elapsed is a tautology, not a verdict.
    deadline = time.time() + DRAIN_TIMEOUT_S + DEDUP_SETTLE_S
    # None until the first poll: a misconfigured (zero/negative) DRAIN_TIMEOUT_S
    # must FAIL ("drain never ran"), not vacuously PASS on empty lists.
    lost: list[str] | None = None
    duplicated: list[tuple[str, list[str]]] | None = None
    distinct_alert_ids: list[tuple[str, list[str]]] = []
    all_found_at: float | None = None  # when lost last became empty (for the settle wait)
    while time.time() < deadline:
        lost = []
        duplicated = []
        distinct_alert_ids = []
        for sc in scenarios:
            docs = alert_ids_for(sc.attacker_ip)  # [(doc_id, alert_id)]
            if len(docs) == 0:
                lost.append(sc.attacker_ip)
            elif len(docs) > 1:
                duplicated.append((sc.attacker_ip, [doc_id for doc_id, _ in docs]))
            ids = {aid for _, aid in docs if aid}
            if len(ids) > 1:
                distinct_alert_ids.append((sc.attacker_ip, sorted(ids)))
        if lost:
            all_found_at = None
        elif all_found_at is None:
            all_found_at = time.time()
        # Clean only once every alert is present AND has stayed single-doc
        # through the whole redelivery window -- see deadline comment.
        if (not lost and not duplicated
                and all_found_at is not None
                and time.time() - all_found_at >= DEDUP_SETTLE_S):
            break
        time.sleep(DRAIN_POLL_S)

    if lost is None or duplicated is None:
        print("[chaos] FAIL -- drain never ran (zero OpenSearch polls); "
              "is CHAOS_DRAIN_TIMEOUT_S misconfigured to zero/negative?")
        return 1

    print(f"[chaos] scenarios={len(scenarios)} lost={len(lost)} "
          f"duplicated={len(duplicated)} distinct_alert_ids={len(distinct_alert_ids)}")
    ok = True
    if lost:
        ok = False
        print(f"[chaos] FAIL -- lost alerts for: {lost}")
    if duplicated:
        ok = False
        print(f"[chaos] FAIL -- duplicate alerts for: {duplicated}")
    if distinct_alert_ids:
        ok = False
        print(f"[chaos] FAIL -- scenario fired MULTIPLE distinct alert_ids "
              f"(deterministic alert_id broken): {distinct_alert_ids}")
    if (not lost and not duplicated and all_found_at is not None
            and time.time() - all_found_at < DEDUP_SETTLE_S):
        # Everything surfaced, but the deadline cut the redelivery window
        # short -- "zero duplicates" was never actually re-checked after a
        # redelivery could have happened.
        ok = False
        print(f"[chaos] FAIL -- all alerts found but the {DEDUP_SETTLE_S:.0f}s "
              f"redelivery settle window (CLAIM_IDLE_MS={CLAIM_IDLE_MS} + margin) "
              f"had not elapsed by the deadline; the zero-duplicate verdict is "
              f"inconclusive (raise CHAOS_DRAIN_TIMEOUT_S)")
    if ok:
        print("[chaos] PASS -- zero lost alerts, zero duplicate alerts, one "
              f"deterministic alert_id per scenario across {len(scenarios)} "
              f"scenarios, {len(KILL_TARGETS)} services killed mid-replay")
        return 0
    return 1


def main() -> int:
    scenarios = build_scenarios()
    stop = threading.Event()
    # kills_done is the hand-off between the killer, the replay thread (it stops
    # pulsing), and main (it verifies after both have finished). The killer sets
    # it in a finally, so no exit path can hang the join below.
    kills_done = threading.Event()
    killer = threading.Thread(target=killer_thread, args=(stop, kills_done), daemon=True)
    replay_thread = threading.Thread(target=replay, args=(scenarios, kills_done), daemon=True)
    killer.start()
    replay_thread.start()

    # `stop` is an abort switch (e.g. replay() raised), not a "replay finished"
    # signal -- replay() now runs in its own thread and keeps pulsing until the
    # killer has cycled every target, so killing happens under live traffic by
    # construction (see replay()). Only abort early on an actual exception; on
    # the normal path, both threads run to completion and we join them below.
    replay_thread.join(timeout=KILL_INTERVAL_S * len(KILL_TARGETS) + 90)
    killer.join(timeout=KILL_INTERVAL_S * len(KILL_TARGETS) + 90)
    kills_done.set()  # in case either thread is still alive after the joins
    if replay_thread.is_alive():
        print("[chaos] WARNING -- replay thread did not finish within its budget")
        stop.set()
    if killer.is_alive():
        print("[chaos] WARNING -- killer thread did not finish within its budget; "
              "verify() results below may reflect a partial kill sequence")
        stop.set()
        killer.join(timeout=5)
    replay_thread.join(timeout=5)

    if KILL_ERRORS:
        print(f"[chaos] FAIL -- {len(KILL_ERRORS)} kill/restart command(s) failed; "
              "the stack was NOT exercised the way this gate requires:")
        for err in KILL_ERRORS:
            print(f"   - {err}")
        return 1
    return verify(scenarios)


if __name__ == "__main__":
    sys.exit(main())
