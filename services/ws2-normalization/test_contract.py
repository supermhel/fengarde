"""WS-2 contract test — zero infrastructure.

For each registered parser:
  * parse its raw sample,
  * assert it validates against Contract A (shared.ocsf.validate == []),
  * assert the derived type_uid invariant holds,
  * assert the produced sector/class match expectations.
Also runs the full bus loop and checks normalized.events output.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.bus import Bus  # noqa: E402
from shared.ocsf import validate  # noqa: E402
from parsers import get_parser, known_sources  # noqa: E402
import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    samples = json.loads((HERE / "mocks" / "raw_samples.json").read_text())["samples"]
    expected = {
        "cisco_asa": (4001, "common"),
        "active_directory": (3002, "bank"),
        "vmware_vsphere": (6003, "datacenter"),
        "linux_ssh": (3002, "common"),
    }

    check(set(known_sources()) >= set(expected), f"registry missing sources: {known_sources()}")

    for s in samples:
        st = s["source_type"]
        parser = get_parser(st)
        check(parser is not None, f"no parser for {st}")
        if parser is None:
            continue
        event = parser.parse(s)
        check(event is not None, f"{st}: parser returned None")
        if event is None:
            continue
        errs = validate(event)
        check(errs == [], f"{st}: invalid OCSF -> {errs}")
        cls, sector = expected[st]
        check(event["class_uid"] == cls, f"{st}: class_uid {event['class_uid']} != {cls}")
        check(event["siem"]["sector"] == sector, f"{st}: sector {event['siem']['sector']} != {sector}")
        check(event["type_uid"] == event["class_uid"] * 100 + event["activity_id"],
              f"{st}: type_uid invariant violated")

    # full loop through the bus
    bus = Bus()
    for s in samples:
        bus.produce("raw.events", key=s["meta"].get("ip", "0.0.0.0"), payload=s)
    stats = ws2.run(bus)
    check(stats["normalized"] == len(samples), f"normalized {stats['normalized']} != {len(samples)}")
    check(stats["dropped"] == 0, f"unexpected drops: {stats['dropped']}")
    out = bus.drain("normalized.events")
    check(len(out) == len(samples), "normalized.events count mismatch")
    for m in out:
        check(m.key, "normalized event missing partition key (src ip)")

    # ---- gap-hunt regression checks (2026-08-26) ---------------------------
    # (1)+(2): the daemon handler (make_handler, what serve() calls) and the
    # batch run() must produce IDENTICAL output on the same input -- the
    # pre-fix divergence (handler dead-lettered with key=None while run() used
    # msg.key; drops only counted in run(), recorded as 'acked' in the
    # daemon's metrics) is structurally impossible now because both funnel
    # through _process. Drive both entry points over the same good+bad mix.
    bad = {"source_type": "active_directory", "raw": {"EventID": 9999},
           "meta": {"ip": "10.9.9.9", "ingest_id": "gap-1"}}
    inputs = [(s["meta"].get("ip", "0.0.0.0"), s) for s in samples] + [("10.9.9.9", bad)]
    bus_r, bus_h = Bus(), Bus()
    for key, p in inputs:
        bus_r.produce("raw.events", key=key, payload=copy.deepcopy(p))
        bus_h.produce("raw.events", key=key, payload=copy.deepcopy(p))
    stats_r = ws2.run(bus_r)
    stats_h = {"normalized": 0, "dropped": 0}
    handler = ws2.make_handler(bus_h, stats=stats_h)
    for m in bus_h.drain("raw.events"):   # same drain a worker consume() loop sees
        handler(m.payload)
    check(stats_r == stats_h, f"handler/run stats diverged: {stats_r} != {stats_h}")

    dlq_r = {m.key: m.payload for m in bus_r.drain("raw.events.deadletter")}
    dlq_h = {m.key: m.payload for m in bus_h.drain("raw.events.deadletter")}
    check(dlq_r.keys() == dlq_h.keys(),
          f"handler/run deadletter keys diverged: {sorted(dlq_r)} != {sorted(dlq_h)}")
    # deadlettered_at is wall-clock metadata (legitimately differs run to run);
    # everything else -- keys, original payload verbatim, errors, deadletter
    # field -- must be byte-identical, or the paths have diverged again.
    def _canonical(payload):
        p = copy.deepcopy(payload)
        if isinstance(p.get("deadletter"), dict):
            p["deadletter"].pop("deadlettered_at", None)
        return p

    check({k: _canonical(v) for k, v in dlq_r.items()}
          == {k: _canonical(v) for k, v in dlq_h.items()},
          "handler/run deadletter payloads diverged")
    check(dlq_r.get("10.9.9.9"), f"deadletter lost the partition key 10.9.9.9: {sorted(dlq_r)}")

    norm_r = bus_r.drain("normalized.events")
    norm_h = bus_h.drain("normalized.events")
    check(len(norm_r) == len(norm_h) == len(samples),
          f"handler/run normalized counts diverged: {len(norm_r)} != {len(norm_h)}")
    # siem.ingest_id/siem.trace_id are FRESH UUIDs minted per parse when the
    # fixture meta doesn't stamp them (base_event: `ingest_id or
    # str(uuid.uuid4())`; WS-1 stamps them in production via envelope).
    # Everything else -- keys, class, endpoints, enrichment -- must be
    # identical across the two entry points.
    def _canon_norm(m):
        p = copy.deepcopy(m.payload)
        siem = p.get("siem")
        if isinstance(siem, dict):
            siem.pop("ingest_id", None)
            siem.pop("trace_id", None)
        return (m.key, p)

    check([_canon_norm(m) for m in norm_r] == [_canon_norm(m) for m in norm_h],
          "handler/run normalized output diverged")

    # (3): the dead-letter payload must be REQUeue-able. dlq_peek --requeue
    # re-produces a DLQ entry's fields verbatim back to raw.events; the old
    # shape {"raw": msg, "errors": [...]} had no top-level source_type, so the
    # requeued message hit "no parser for source_type" and re-dead-lettered
    # even after the real root cause was fixed. Now the payload carries the
    # ORIGINAL raw.events payload verbatim + metadata, so a requeued message
    # re-enters the SAME parser path and only re-dead-letters on the genuine
    # failure reason.
    dlq_msg = list(dlq_r.values())[0]
    dp = dlq_msg
    check(dp.get("source_type") == "active_directory", f"DLQ payload lost source_type: {list(dp)}")
    check(dp.get("raw") == bad["raw"], "DLQ payload lost original raw")
    check(dp.get("meta") == bad["meta"], "DLQ payload lost original meta")
    check(dp.get("errors") == ["parser returned None"],
          f"DLQ errors {dp.get('errors')} != ['parser returned None']")
    check(dp.get("deadletter", {}).get("stage") == "ws2-normalization",
          "DLQ payload lost deadletter metadata")

    # simulate tools/dlq_peek.py --requeue on the SAME bus: re-produce the DLQ
    # entry's payload+key verbatim to raw.events, then re-run.
    bus_r.produce("raw.events", key=next(iter(dlq_r)), payload=copy.deepcopy(dp))
    stats_req = ws2.run(bus_r)
    check(stats_req == {"normalized": 0, "dropped": 1},
          f"requeued bad payload should dead-letter exactly once: {stats_req}")
    requeued = bus_r.drain("raw.events.deadletter")
    check(len(requeued) == 2, f"requeue produced {len(requeued) - 1} new DLQ entries, want 1")
    # The requeued message must have reached the SAME parser/failure reason
    # (proving it was NOT mis-directed by a missing source_type -- the old bug).
    if requeued:
        check(requeued[-1].payload.get("errors") == ["parser returned None"],
              f"requeued DLQ errors {requeued[-1].payload.get('errors')} != "
              f"['parser returned None'] (old shape mis-dead-lettered here)")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-2: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-2 contract test PASS")


if __name__ == "__main__":
    main()
