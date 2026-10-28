"""Old (MULTI pipeline) vs new (single EVALSHA) RedisWindowCounter on a REAL Redis.

Two checks, both comparing use_lua=False (the pre-2026-10-28 pipelines, the
reference) with use_lua=True on identical input:

 1. Counter parity: a randomized stream of hit()/hit_distinct() calls with
    out-of-order and stale timestamps, repeated members/values, several keys and
    short windows (so entries age out and keys expire). Every returned count must
    be equal, and after each batch the stored zset (members + scores) and the
    key TTLs (+-1 s) must match key by key.
 2. Detector parity: the real WS-4 Detector (all 46 rules) fed the same normalized
    event stream (brute force bursts, password spray / credential stuffing across
    many IPs, port-scan-like fan-out, out-of-order and a replayed second pass for
    at-least-once redelivery) once per counter variant. The alert_id sequences must
    be identical, non-empty, and the replay must add no new alert_id.

Runs in CI's redis-integration job (REDIS_URL set); without REDIS_URL it says so
and exits 0, like test_window_redis_live.py (a documented live-only test).

Run: REDIS_URL=redis://localhost:6379/0 python services/ws4-detection/test_window_lua_live.py
"""
from __future__ import annotations

import os
import random
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "tools"))

from shared.window import RedisWindowCounter  # noqa: E402


def counter_parity(client, ns: str) -> list[str]:
    fails: list[str] = []
    old = RedisWindowCounter(client, namespace=ns + ":old", use_lua=False)
    new = RedisWindowCounter(client, namespace=ns + ":new", use_lua=True)
    rng = random.Random(2810)
    base = 1_750_000_000_000
    keys = [f"k{i}" for i in range(5)]
    for batch in range(8):
        for i in range(250):
            k = rng.choice(keys)
            window = rng.choice([2_000, 5_000, 60_000])
            t = base + rng.randrange(0, 40_000)        # arbitrary order incl. stale repeats
            if rng.random() < 0.5:
                m = f"m{rng.randrange(40)}"            # repeated members overwrite
                a, b = old.hit(k, t, window, m), new.hit(k, t, window, m)
                kind = "hit"
            else:
                v = f"v{rng.randrange(12)}"
                a, b = old.hit_distinct("d" + k, t, window, v), new.hit_distinct("d" + k, t, window, v)
                kind = "distinct"
            if a != b:
                fails.append(f"batch {batch} op {i} {kind} key={k} t={t - base} w={window}: old={a} new={b}")
                return fails
        for zk in ([f"{ns}:{{}}:{k}" for k in keys] + [f"{ns}:{{}}:d:d{k}" for k in keys]):
            ko, kn = zk.format("old"), zk.format("new")
            zo = client.zrange(ko, 0, -1, withscores=True)
            zn = client.zrange(kn, 0, -1, withscores=True)
            if zo != zn:
                fails.append(f"batch {batch} zset {zk}: old={zo[:4]}.. new={zn[:4]}..")
                return fails
            to, tn = client.ttl(ko), client.ttl(kn)
            if abs(to - tn) > 1:
                fails.append(f"batch {batch} ttl {zk}: old={to} new={tn}")
                return fails
    return fails


def _events(ws2, n_noise: int) -> list[dict]:
    import time
    base = int(time.time()) - 600
    raw = []
    def ssh(ip, user, t, i):
        return {"source_type": "linux_ssh", "raw": (f"Jun 10 13:55:{i % 60:02d} db01 sshd[2154]: Failed password for "
                f"invalid user {user} from {ip} port 51000 ssh2"),
                "meta": {"received_at": t, "ingest_id": f"par-{ip}-{user}-{i}"}}
    i = 0
    for burst in range(6):                                   # per-source brute force
        for _ in range(14):
            raw.append(ssh(f"203.0.113.{burst + 1}", "admin", base + i % 50, i)); i += 1
    for ip in range(40):                                     # one account from many sources (stuffing)
        raw.append(ssh(f"198.51.100.{ip + 1}", "victim", base + 100 + ip, i)); i += 1
    for _ in range(25):                                      # same source, many accounts
        raw.append(ssh("192.0.2.77", f"user{i}", base + 200 + i % 30, i)); i += 1
    for j in range(n_noise):                                 # benign background, unique sources
        raw.append(ssh(f"10.1.{j // 250}.{j % 250 + 1}", f"svc{j}", base + 300 + j % 120, i)); i += 1
    random.Random(7).shuffle(raw)                            # out-of-order arrival
    events = []
    for r in raw:
        ev, errs = ws2.normalize_one(r)
        if ev is not None and not errs:
            events.append(ev)
    return events


class _Sink:
    def __init__(self):
        self.alerts: list[str] = []

    def produce(self, topic, key=None, payload=None, **_):
        if topic == "alerts":
            self.alerts.append(payload["alert_id"])


def detector_parity(client, ns: str) -> list[str]:
    import fengarde_loadtest as L
    _fb, ws2, _ws3, ws4 = L._load_stages()
    events = _events(ws2, 400)
    results = {}
    for variant, use_lua in (("old", False), ("new", True)):
        det = ws4.Detector()
        counter = RedisWindowCounter(client, namespace=f"{ns}:det:{variant}", use_lua=use_lua)
        det._window_counter = counter
        for r in det.rules:
            if r.stateful:
                r.set_counter(counter)
        sink = _Sink()
        for ev in events:
            ws4.detect_one(sink, det, dict(ev))
        first = list(sink.alerts)
        for ev in events:                                    # at-least-once redelivery: same stream again
            ws4.detect_one(sink, det, dict(ev))
        results[variant] = (first, sink.alerts[len(first):])
    fails = []
    (o1, o2), (n1, n2) = results["old"], results["new"]
    if not o1:
        fails.append("reference run produced no alerts: the stream proves nothing")
    if o1 != n1:
        fails.append(f"alert_id sequence differs: old={len(o1)} new={len(n1)} "
                     f"(first diff at {next((i for i, (x, y) in enumerate(zip(o1, n1)) if x != y), 'len')})")
    if set(n2) - set(n1):
        fails.append(f"redelivery produced alert_ids not seen in the first pass: {sorted(set(n2) - set(n1))[:3]}")
    if o2 != n2:
        fails.append(f"redelivery alert sequence differs: old={len(o2)} new={len(n2)}")
    print(f"  detector parity: {len(events)} events, {len(o1)} alerts first pass "
          f"({len(set(o1))} distinct ids), {len(o2)} on replay (old) / {len(n2)} (new)")
    return fails


def main() -> int:
    url = os.environ.get("REDIS_URL")
    if not url:
        print("[SKIP] REDIS_URL unset: old-vs-new window-counter parity not run (CI redis-integration runs it)")
        return 1 if os.environ.get("FENGARDE_E2E_STRICT") == "1" else 0
    import redis  # noqa: PLC0415 -- only the live path needs the client

    client = redis.Redis.from_url(url, decode_responses=True)
    ns = f"luaparity:{uuid.uuid4().hex[:8]}"
    fails = counter_parity(client, ns) + detector_parity(client, ns)
    for k in client.scan_iter(f"{ns}:*"):
        client.delete(k)
    if fails:
        print("[FAIL] window counter Lua vs pipeline parity:\n - " + "\n - ".join(fails))
        return 1
    print("[OK] RedisWindowCounter single-EVALSHA path == MULTI pipeline path (counts, zsets, TTLs, "
          "Detector alert_ids, redelivery) on a real Redis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
