"""fengarde-loadtest-live: ramp + soak against the real Redis/OpenSearch stack.

Needs the isolated compose project from benchmark/loadtest.md already up
(infra/docker-compose.loadtest.yml: own project name, remapped ports). Skips
cleanly (exit 0, "[SKIP]") if Redis/OpenSearch are unreachable, same
convention as tools/fengarde_bench_live.py.

Events are paced onto the real `raw.events` stream (WS-1 is bypassed, same as
devkit-feeder / fengarde_bench_live). A background sampler records, every
--sample-s seconds: stream lengths and per-consumer-group read/lag/pending
(XINFO GROUPS), OpenSearch doc counts + JVM heap + indexing totals, Redis
memory, and per-container CPU/memory (`docker stats`). Per-stage rate is the
delta of each group's entries-read; the stage with the lag that grows first
(and the highest CPU) is the bottleneck.

Phases:
  ramp   one step per --rates entry, --step-s seconds each, no drain between
         steps; then stop producing and time the backlog drain. The drain rate
         is the cleanest capacity estimate (backlog => stage runs flat out).
  soak   after waiting for lag==0, hold --soak-rate for --soak-min minutes.

Output: <out>.json (summary) and <out>.samples.jsonl (raw time series).

Run:  python tools/fengarde_loadtest_live.py --redis-port 16379 --os-port 19200 \\
          --project fgloadtest --out benchmark/raw/live-2026-10-28
"""
from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import redis

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import fengarde_bench as fb  # noqa: E402

TOPICS = ["raw.events", "normalized.events", "scored.events", "alerts", "ai.requests",
          "incidents", "entity.updates"]
SERVICES = ["redis", "opensearch", "ws2-normalization", "ws3-indexer", "ws4-detection",
            "ws5-ai", "ws8-correlation", "ws9-resolver"]


def os_get(base: str, path: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(f"{base}{path}", timeout=timeout) as r:
        return json.loads(r.read())


def os_count(base: str, pattern: str) -> int:
    try:
        return os_get(base, f"/{pattern}/_count")["count"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 0
        raise


def make_chunk(start: int, count: int, tag: str) -> list[dict]:
    """Realistic mix (see tools/fengarde_loadtest.py): ~60% syslog, ~20% ssh
    fail, ~20% ASA deny from mostly-unique sources, one 10-line brute-force
    burst per 500 events. received_at = now (never in the future)."""
    now = int(time.time())
    out = []
    for j in range(count):
        i = start + j
        if i % 500 < 10:
            e = fb._ssh_fail(f"203.0.113.{(i // 500) % 250 + 1}", i, now - i)
        else:
            ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            k = i % 5
            if k == 0:
                e = fb._ssh_fail(ip, i, now - i)
                e["raw"] = e["raw"].replace("invalid user admin", f"invalid user svc{i}")
            elif k == 1:
                e = fb._asa_deny(ip, i, now - i)
            else:
                e = fb._generic(ip, i, now - i)
        e["meta"]["received_at"] = now
        e["meta"]["ingest_id"] = f"lt-{tag}-{i}"
        out.append(e)
    return out


class Sampler(threading.Thread):
    def __init__(self, r, base, project, interval, sink_path):
        super().__init__(daemon=True)
        self.r, self.base, self.project, self.interval = r, base, project, interval
        self.sink = open(sink_path, "w", encoding="utf-8")
        self.stop_evt = threading.Event()
        self.samples: list[dict] = []
        self.produced = 0
        self.phase = "init"
        self._docker: dict = {}
        self._docker_t = 0.0

    def docker_stats(self) -> dict:
        if time.time() - self._docker_t < 5:
            return self._docker
        try:
            p = subprocess.run(["docker", "stats", "--no-stream", "--format",
                                "{{json .}}"], capture_output=True, text=True, timeout=25)
            d = {}
            for line in p.stdout.splitlines():
                j = json.loads(line)
                if not j["Name"].startswith(self.project + "-"):
                    continue
                svc = j["Name"][len(self.project) + 1:].rsplit("-", 1)[0]
                mem = j["MemUsage"].split("/")[0].strip()
                cpu = float(j["CPUPerc"].rstrip("%"))
                if svc in d:  # several replicas of one service: sum CPU
                    d[svc] = {"cpu_pct": d[svc]["cpu_pct"] + cpu, "mem": d[svc]["mem"] + "+" + mem}
                else:
                    d[svc] = {"cpu_pct": cpu, "mem": mem}
            self._docker = d
        except Exception as exc:  # noqa: BLE001 - sampler must never die
            self._docker = {"error": str(exc)[:100]}
        self._docker_t = time.time()
        return self._docker

    def groups(self) -> dict:
        g = {}
        for t in TOPICS:
            try:
                info = self.r.xinfo_groups(t)
            except redis.ResponseError:
                continue
            g[t] = {"len": self.r.xlen(t),
                    "groups": {x["name"]: {"read": x.get("entries-read"), "lag": x.get("lag"),
                                           "pending": x["pending"]} for x in info}}
        return g

    def one(self) -> dict:
        s = {"t": round(time.time(), 2), "phase": self.phase, "produced": self.produced}
        try:
            s["streams"] = self.groups()
            s["redis_mem_mb"] = round(self.r.info("memory")["used_memory"] / 1048576, 1)
            s["events_docs"] = os_count(self.base, "events-*")
            s["alerts_docs"] = os_count(self.base, "alerts-*")
            ns = os_get(self.base, "/_nodes/stats/jvm,indices")["nodes"]
            n = next(iter(ns.values()))
            s["os_heap_pct"] = n["jvm"]["mem"]["heap_used_percent"]
            s["os_heap_used_mb"] = round(n["jvm"]["mem"]["heap_used_in_bytes"] / 1048576)
            ix = n["indices"]["indexing"]
            s["os_index_total"] = ix["index_total"]
            s["os_index_time_ms"] = ix["index_time_in_millis"]
            s["os_index_failed"] = ix.get("index_failed", 0)
            s["os_gc_old_ms"] = n["jvm"]["gc"]["collectors"]["old"]["collection_time_in_millis"]
            s["os_write_rejected"] = n.get("thread_pool", {}).get("write", {}).get("rejected")
        except Exception as exc:  # noqa: BLE001
            s["error"] = str(exc)[:150]
        s["docker"] = self.docker_stats()
        return s

    def run(self):
        while not self.stop_evt.is_set():
            t0 = time.time()
            s = self.one()
            self.samples.append(s)
            self.sink.write(json.dumps(s) + "\n")
            self.sink.flush()
            self.stop_evt.wait(max(0.0, self.interval - (time.time() - t0)))


def grp(sample: dict, topic: str, group: str, key: str):
    try:
        return sample["streams"][topic]["groups"][group][key]
    except (KeyError, TypeError):
        return None


def total_lag(sample: dict) -> int | None:
    """Sum of consumer-group lag + pending across every stream; None if the
    sample is unusable (error / Redis could not report lag)."""
    tot = 0
    for t, v in sample.get("streams", {}).items():
        for g in v["groups"].values():
            if g["lag"] is None:
                return None
            tot += g["lag"] + g["pending"]
    return tot


def produce_paced(r, rate: int, seconds: float, tag: str, start: int, smp: Sampler) -> int:
    """Open-loop producer: batches of rate/10 every 100 ms, catching up if late."""
    batch = max(1, rate // 10)
    t0 = time.perf_counter()
    sent = 0
    n_batches = 0
    while time.perf_counter() - t0 < seconds:
        due = t0 + n_batches * (batch / rate)
        now = time.perf_counter()
        if due > now:
            time.sleep(due - now)
        pipe = r.pipeline(transaction=False)
        for e in make_chunk(start + sent, batch, tag):
            pipe.xadd("raw.events", {"key": e["meta"]["ingest_id"], "payload": json.dumps(e)})
        pipe.execute()
        sent += batch
        smp.produced = start + sent
        n_batches += 1
    return sent


def window_rates(samples: list[dict], t_lo: float, t_hi: float) -> dict:
    """Per-stage rates (events/s) between the first and last sample in [t_lo,t_hi]."""
    w = [s for s in samples if t_lo <= s["t"] <= t_hi and "error" not in s]
    if len(w) < 2:
        return {}
    a, b = w[0], w[-1]
    dt = b["t"] - a["t"]

    def rate(x, y):
        return round((y - x) / dt, 1) if (x is not None and y is not None and dt > 0) else None

    ws3_read = lambda s: sum((grp(s, t, "cg-index", "read") or 0) for t in TOPICS)  # noqa: E731
    cpu = {}
    for svc in SERVICES:
        v = [s["docker"].get(svc, {}).get("cpu_pct") for s in w if isinstance(s.get("docker"), dict)]
        v = [x for x in v if x is not None]
        if v:
            cpu[svc] = {"mean": round(statistics.mean(v), 1), "max": round(max(v), 1)}
    return {
        "window_s": round(dt, 1),
        "produced_eps": rate(a["produced"], b["produced"]),
        "ws2_normalize_eps": rate(grp(a, "raw.events", "cg-normalize", "read"),
                                  grp(b, "raw.events", "cg-normalize", "read")),
        "ws4_detect_eps": rate(grp(a, "normalized.events", "cg-detect", "read"),
                               grp(b, "normalized.events", "cg-detect", "read")),
        "ws3_index_msgs_per_s": rate(ws3_read(a), ws3_read(b)),
        "os_events_docs_per_s": rate(a["events_docs"], b["events_docs"]),
        "os_alert_docs_per_s": rate(a["alerts_docs"], b["alerts_docs"]),
        "os_index_ops_per_s": rate(a["os_index_total"], b["os_index_total"]),
        "lag_start": total_lag(a), "lag_end": total_lag(b),
        "raw_lag_end": grp(b, "raw.events", "cg-normalize", "lag"),
        "norm_lag_end": grp(b, "normalized.events", "cg-detect", "lag"),
        "os_heap_pct_max": max(s["os_heap_pct"] for s in w),
        "os_heap_used_mb_max": max(s["os_heap_used_mb"] for s in w),
        "os_index_failed_end": b["os_index_failed"],
        "os_write_rejected_end": b.get("os_write_rejected"),
        "redis_mem_mb_max": max(s["redis_mem_mb"] for s in w),
        "container_cpu_pct": cpu,
    }


def wait_drained(smp: Sampler, timeout_s: float) -> float | None:
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        time.sleep(2)
        s = smp.samples[-1] if smp.samples else None
        if s and "error" not in s and total_lag(s) == 0:
            return round(time.time() - t0, 1)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--redis-port", type=int, default=16379)
    ap.add_argument("--os-port", type=int, default=19200)
    ap.add_argument("--project", default="fgloadtest", help="compose project (docker stats filter)")
    ap.add_argument("--rates", type=int, nargs="*", default=[100, 200, 400, 800, 1600, 3200])
    ap.add_argument("--step-s", type=float, default=60)
    ap.add_argument("--soak-rate", type=int, default=0, help="0 = skip soak")
    ap.add_argument("--soak-min", type=float, default=10)
    ap.add_argument("--sample-s", type=float, default=3)
    ap.add_argument("--drain-timeout-s", type=float, default=900)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    base = f"http://127.0.0.1:{a.os_port}"
    r = redis.Redis(host="127.0.0.1", port=a.redis_port, decode_responses=True)
    try:
        r.ping()
        os_get(base, "/")
    except Exception as exc:  # noqa: BLE001
        print(f"[SKIP] stack not reachable (redis :{a.redis_port}, opensearch :{a.os_port}): {exc}")
        return 0

    a.out.parent.mkdir(parents=True, exist_ok=True)
    smp = Sampler(r, base, a.project, a.sample_s, f"{a.out}.samples.jsonl")
    smp.start()
    tag = uuid.uuid4().hex[:8]
    cursor = 0
    summary: dict = {"date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run_tag": tag,
                     "params": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(a).items()},
                     "steps": []}

    print(f"[ramp] rates={a.rates} step={a.step_s}s", flush=True)
    for rate in a.rates:
        smp.phase = f"ramp-{rate}"
        t_lo = time.time()
        sent = produce_paced(r, rate, a.step_s, tag, cursor, smp)
        cursor += sent
        t_hi = time.time()
        st = {"offered_eps": rate, "events_sent": sent,
              **window_rates(smp.samples, t_lo + 5, t_hi)}  # skip 5 s warm-in
        summary["steps"].append(st)
        print(json.dumps(st), flush=True)

    smp.phase = "drain"
    t_stop = time.time()
    backlog = total_lag(smp.samples[-1]) if smp.samples else None
    drain_s = wait_drained(smp, a.drain_timeout_s)
    summary["drain"] = {"backlog_msgs_at_stop": backlog, "drain_seconds": drain_s,
                        **(window_rates(smp.samples, t_stop, time.time()) if drain_s else {})}
    print("[drain]", json.dumps(summary["drain"]), flush=True)

    if a.soak_rate:
        smp.phase = "soak"
        print(f"[soak] {a.soak_rate} eps for {a.soak_min} min", flush=True)
        t_lo = time.time()
        sent = produce_paced(r, a.soak_rate, a.soak_min * 60, tag, cursor, smp)
        cursor += sent
        t_hi = time.time()
        soak = {"offered_eps": a.soak_rate, "minutes": a.soak_min, "events_sent": sent,
                **window_rates(smp.samples, t_lo + 5, t_hi)}
        # per-minute achieved os_events_docs_per_s to show it held, not just the mean
        per_min = []
        t = t_lo + 5
        while t + 60 <= t_hi:
            w = window_rates(smp.samples, t, t + 60)
            if w:
                per_min.append({"os_events_docs_per_s": w["os_events_docs_per_s"],
                                "ws4_detect_eps": w["ws4_detect_eps"], "lag_end": w["lag_end"],
                                "heap_pct_max": w["os_heap_pct_max"]})
            t += 60
        soak["per_minute"] = per_min
        summary["soak"] = soak
        smp.phase = "post-soak-drain"
        summary["soak"]["post_drain_seconds"] = wait_drained(smp, a.drain_timeout_s)
        print("[soak]", json.dumps({k: v for k, v in soak.items() if k != "per_minute"}), flush=True)

    smp.stop_evt.set()
    smp.join(timeout=15)
    summary["total_events_sent"] = cursor
    Path(f"{a.out}.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[done] wrote {a.out}.json", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
