"""fengarde-bench-live: EPS + p50/p99 latency against the REAL Docker/Redis/
OpenSearch stack (M2 public proof artifact, live-stack sibling of
tools/fengarde_bench.py).

Closes the two "still-open TODO" items tools/fengarde_bench.py's own
docstring used to name: a live-stack EPS number (not just the CPU-bound
zero-infra baseline) and a real p50/p99 ingest->alert latency number. Needs
`docker compose -f infra/docker-compose.yml up -d` (or `make up`) already
running -- this is NOT part of the zero-infra `make test` gate, same
opt-in-and-skip-cleanly convention as `make test-live`/`make chaos`.

Method
------
EPS: produce N events onto the real `raw.events` Redis stream, the exact
wire shape `services/devkit-feeder/feed.py` uses (`XADD raw.events
{"key": <key>, "payload": json.dumps(event)}`), then poll OpenSearch's
`events-*/_count` until it stops growing (2 consecutive stable polls, or a
hard timeout) and report N / elapsed-since-first-produce. This measures the
REAL 5-container pipeline (ws2 normalize -> ws4 detect -> ws3 index)
draining a real backlog through real Redis Streams consumer groups and real
OpenSearch indexing. WS-1's UDP listener is deliberately bypassed (events
go straight onto the bus, same as devkit-feeder) to isolate WS-2/4/3
throughput from WS-1's separately-scoped ingest-edge concern
(B2 backpressure, already load-tested live -- see SSOT.md).

Latency: fire K independent brute-force bursts (10 events each, unique
attacker IP per burst so stateful windows never overlap), and for each
burst poll `alerts-*/_count` filtered to that IP (`q=src_endpoint.ip:"IP"`)
until it's >=1, recording wall time from "burst fully produced" to "alert
visible in OpenSearch". p50/p99 are computed over the K samples.

Honest scope
------------
Polling resolution bounds precision (default 200ms interval) -- this is a
real, reproducible, live-infra number bounded by an explicit, documented
floor, NOT sub-100ms latency instrumentation. It also measures OpenSearch
QUERY visibility (refresh_interval), not the moment the document was
written -- a real, small, disclosed extra delay on top of true
produce-to-index latency, not hidden in the number. Same "not a fixed
reference box" caveat tools/fengarde_bench.py's README numbers carry: this
runs on whatever machine invokes it, not the roadmap's defined 4 vCPU / 8 GB
reference VPS -- a real, reproducible number for THIS host, not a portable
absolute claim. Every produced event's ``ingest_id`` is tagged with a
per-invocation random prefix specifically so re-running this tool never
silently re-indexes (updates) the SAME OpenSearch documents a prior run
already created and reads as "no progress" -- found live 2026-08-19, see
measure_eps()'s own comment.

Run:  python tools/fengarde_bench_live.py --events 5000 --latency-bursts 20
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

import redis

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from fengarde_bench import generate_events  # noqa: E402

REDIS_URL = "redis://localhost:6379/0"
OPENSEARCH_URL = "http://localhost:9200"
TOPIC = "raw.events"


def _redis_client() -> redis.Redis:
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _os_get(path: str) -> dict:
    with urllib.request.urlopen(f"{OPENSEARCH_URL}{path}", timeout=10) as resp:
        return json.loads(resp.read())


def _events_count() -> int:
    try:
        return _os_get("/events-*/_count")["count"]
    except urllib.error.HTTPError as e:
        if e.code == 404:  # no events-* index yet
            return 0
        raise


def _alerts_count_for_ip(ip: str) -> int:
    query = f'src_endpoint.ip:"{ip}"'
    try:
        return _os_get(f"/alerts-*/_count?q={urllib.parse.quote(query)}")["count"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0
        raise


def produce_events(r: redis.Redis, events: list[dict]) -> None:
    pipe = r.pipeline()
    for e in events:
        pipe.xadd(TOPIC, {"key": e["meta"].get("ingest_id", ""), "payload": json.dumps(e)})
    pipe.execute()


def measure_eps(n: int, mixed: bool, poll_interval_s: float, timeout_s: float) -> dict:
    r = _redis_client()
    r.ping()
    baseline = _events_count()
    events = generate_events(n, mixed)
    # generate_events() is fully deterministic in (n, mixed) -- same ip cycle,
    # same seq range, same ingest_id pattern every call. Fine for the
    # zero-infra bench (nothing persists across runs), but against a REAL
    # OpenSearch cluster it means a second invocation with the same --events
    # re-indexes (updates) the SAME documents from the first run instead of
    # creating new ones -- found live 2026-08-19: a rerun measured near-zero
    # doc-count growth and read as a stalled pipeline, when the real cause
    # was correct idempotent dedup-by-_id doing exactly what it's designed
    # to do. Tag every event's ingest_id with a per-invocation prefix so
    # each run is always genuinely new documents.
    # Per-event index `i`, not just a run-level prefix: generic_syslog events
    # carry NO ingest_id from generate_events() at all (their parser derives
    # one deterministically from the raw line, services/ws2-normalization/
    # parsers/generic_syslog.py::_deterministic_ingest_id) -- prefixing an
    # absent value would leave every generic_syslog event in ONE run
    # colliding with each other, not just across runs.
    run_tag = uuid.uuid4().hex[:8]
    for i, e in enumerate(events):
        e["meta"]["ingest_id"] = f"livebench-{run_tag}-{i}"

    t0 = time.perf_counter()
    produce_events(r, events)
    t_produce_done = time.perf_counter()

    target = baseline + n
    last_count = _events_count()
    stable_polls = 0
    deadline = time.perf_counter() + timeout_s
    while time.perf_counter() < deadline:
        time.sleep(poll_interval_s)
        count = _events_count()
        if count >= target:
            break
        stable_polls = stable_polls + 1 if count == last_count else 0
        last_count = count
        if stable_polls >= 5:  # backlog stopped draining before reaching target
            break
    t_drained = time.perf_counter()

    final_count = _events_count()
    normalized_seen = min(final_count - baseline, n)
    elapsed_since_produce_start = t_drained - t0
    return {
        "n_events": n,
        "mixed_sources": mixed,
        "normalized_seen": normalized_seen,
        "reached_target": final_count >= target,
        "produce_seconds": round(t_produce_done - t0, 4),
        "drain_seconds": round(t_drained - t_produce_done, 4),
        "total_seconds": round(elapsed_since_produce_start, 4),
        "live_sustained_eps": round(normalized_seen / elapsed_since_produce_start, 1)
        if elapsed_since_produce_start > 0 else None,
    }


def _ssh_burst(ip: str, base_s: int, count: int = 10) -> list[dict]:
    return [{
        "source_type": "linux_ssh",
        "raw": (f"Jun 10 13:55:{i % 60:02d} db01 sshd[2154]: "
                f"Failed password for invalid user admin from {ip} port 51000 ssh2"),
        "meta": {"received_at": base_s + i, "ingest_id": f"bench-live-{ip}-{i}"},
    } for i in range(count)]


# RFC 5737 documentation ranges -- three /24s give 3*254 = 762 distinct valid
# IPv4 addresses to rotate through, so each latency burst gets its own
# never-before-seen attacker IP within one run (no cross-burst window overlap).
_TEST_NET_POOLS = ("203.0.113.", "198.51.100.", "192.0.2.")


def _burst_ip(i: int) -> str:
    pool = _TEST_NET_POOLS[(i // 254) % len(_TEST_NET_POOLS)]
    return f"{pool}{(i % 254) + 1}"


def measure_latency(k: int, poll_interval_s: float, timeout_s: float) -> dict:
    r = _redis_client()
    r.ping()
    samples_ms: list[float] = []
    for i in range(k):
        ip = _burst_ip(i)
        # Count BEFORE producing, and wait for an INCREASE, not just ">=1":
        # the TEST-NET pool (762 addresses) can repeat across separate
        # script invocations, and a prior run may have already left a real
        # alert for this exact ip -- ">=1" would then read as an instant
        # (false) near-zero latency without this run's burst having been
        # processed at all.
        baseline = _alerts_count_for_ip(ip)
        base_s = int(time.time()) - 120  # in the past, clear of the 5-min anti-poisoning guard
        burst = _ssh_burst(ip, base_s)

        produce_events(r, burst)
        t_burst_done = time.perf_counter()

        deadline = time.perf_counter() + timeout_s
        seen = False
        while time.perf_counter() < deadline:
            if _alerts_count_for_ip(ip) > baseline:
                seen = True
                break
            time.sleep(poll_interval_s)
        t_seen = time.perf_counter()
        if seen:
            samples_ms.append((t_seen - t_burst_done) * 1000)
        else:
            print(f"  [WARN] burst {i + 1}/{k} (ip={ip}) never produced a visible alert "
                  f"within {timeout_s}s -- excluded from the latency sample, not silently "
                  f"averaged in as 0", file=sys.stderr)

    if not samples_ms:
        return {"k_bursts": k, "samples_collected": 0, "p50_ms": None, "p99_ms": None}
    samples_ms.sort()
    return {
        "k_bursts": k,
        "samples_collected": len(samples_ms),
        "p50_ms": round(statistics.median(samples_ms), 1),
        "p99_ms": round(samples_ms[min(len(samples_ms) - 1, int(len(samples_ms) * 0.99))], 1),
        "min_ms": round(samples_ms[0], 1),
        "max_ms": round(samples_ms[-1], 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", type=int, default=5000)
    ap.add_argument("--mixed", action="store_true")
    ap.add_argument("--latency-bursts", type=int, default=20)
    ap.add_argument("--poll-interval", type=float, default=0.2)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skip-eps", action="store_true")
    ap.add_argument("--skip-latency", action="store_true")
    args = ap.parse_args()

    try:
        _redis_client().ping()
    except Exception as exc:
        print(f"[SKIP] cannot reach Redis at {REDIS_URL} -- is the stack up "
              f"('make up' / docker compose -f infra/docker-compose.yml up -d)? ({exc})")
        return 0
    try:
        _os_get("/")
    except Exception as exc:
        print(f"[SKIP] cannot reach OpenSearch at {OPENSEARCH_URL} -- is the stack up? ({exc})")
        return 0

    result: dict = {}
    if not args.skip_eps:
        print(f"Measuring live-stack EPS ({args.events} events"
              f"{', mixed sources' if args.mixed else ''})...")
        result["eps"] = measure_eps(args.events, args.mixed, args.poll_interval, args.timeout)
    if not args.skip_latency:
        print(f"Measuring ingest->alert latency ({args.latency_bursts} bursts)...")
        result["latency"] = measure_latency(args.latency_bursts, args.poll_interval, args.timeout)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print()
    print("fengarde-bench-live -- REAL Docker/Redis/OpenSearch stack "
          "(see this file's module docstring for honest scope)")
    if "eps" in result:
        e = result["eps"]
        print(f"  live sustained EPS: {e['live_sustained_eps']} "
              f"({e['normalized_seen']}/{e['n_events']} events reached events-*, "
              f"reached_target={e['reached_target']})")
        print(f"    produce={e['produce_seconds']}s drain={e['drain_seconds']}s "
              f"total={e['total_seconds']}s")
    if "latency" in result:
        latn = result["latency"]
        print(f"  ingest->alert latency: p50={latn['p50_ms']}ms p99={latn['p99_ms']}ms "
              f"({latn['samples_collected']}/{latn['k_bursts']} bursts produced a visible alert)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
