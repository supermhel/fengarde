"""WS-5 gap-hunt fixes (2026-08-27): siem:null poison-pill + id-less collapse.

NEW-hunt #2: classifier.py / main.py / llm_adapter.py read
``event.get("siem", {}).get(...)`` -- a ``siem: null`` payload raises
AttributeError (None.get), a NULL pointer poisoned a whole request. Every
siem read in ws5-ai now goes through ``(event.get("siem") or {})`` so a null
siem block is treated as absent, never a crash.

NEW-hunt #8: id-less events (no request event_id, no siem.ingest_id) used to
fall back to the literal 'unknown' for alert_id and bus keys -- every id-less
alert collapsed onto the same doc (alert_id='ai-unknown') and bus key
'unknown'. They now get a deterministic per-event id (a hash of the event
payload), so distinct events no longer collapse while an identical redelivery
of the SAME event still maps to the SAME id (alert indexing stays idempotent
under at-least-once delivery).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"
os.environ.pop("OLLAMA_URL", None)  # force StubLLM

from shared.bus import Bus  # noqa: E402
from classifier import LightClassifier  # noqa: E402
from llm_adapter import StubLLM  # noqa: E402
import main as ws5  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    # ---------------- NEW-hunt #2: siem:null must be handled, never raise ----
    clf = LightClassifier()
    out = clf.predict({"class_uid": 3002, "severity_id": 4, "siem": None})
    check(out["priority"] in ("low", "medium", "high"),
          f"classifier.predict(siem=None) must not raise; got {out}")
    check(out["category"] == "authentication", f"category {out['category']}")

    alert = ws5._alert_payload(
        {"event_id": "e1", "tier": "llm", "verdict": "v", "summary": "s",
         "level": "high",
         "classification": {"category": "x", "priority": "high",
                            "confidence": 0.5},
         "engine": "stub", "model": None},
        {"time": 1, "siem": None})
    check(alert["sector"] is None,
          f"_alert_payload with siem:null must not raise; sector={alert['sector']!r}")

    check(ws5.AiWorker._dedup_key({"event": {"siem": None}, "event_id": "e2"}) == "e2",
          "_dedup_key with siem:null must fall back to the request-level event_id")

    stub_out = StubLLM().analyze({"class_uid": 3002, "siem": None}, ["r"])
    check(stub_out["verdict"] in ("benign", "suspicious", "malicious"),
          f"StubLLM.analyze(siem=None) must not raise; got {stub_out}")

    # ------- NEW-hunt #8: id-less events get a deterministic per-event id -----
    e1 = {"class_uid": 6005, "time": 1750000000000,
          "siem": {"score": 85, "sector": "bank"}}
    e2 = {"class_uid": 6005, "time": 1750000000000,
          "siem": {"score": 85, "sector": "retail"}}
    r1 = {"event_id": None, "tier": "llm", "verdict": "v", "summary": "s",
          "level": "high",
          "classification": {"category": "x", "priority": "high",
                             "confidence": 0.5},
          "engine": "stub", "model": None}
    r2 = dict(r1)
    id1 = ws5._stable_event_id(r1, e1)
    id2 = ws5._stable_event_id(r2, e2)
    check(id1 != "unknown" and id2 != "unknown",
          f"id-less events must not fall back to the literal 'unknown' ({id1}, {id2})")
    check(id1 != id2,
          f"distinct id-less events must get distinct ids, got {id1} == {id2}")
    check(ws5._stable_event_id(r1, e1) == id1,
          "an id-less event's id must be deterministic per event (redelivery-stable)")

    a1 = ws5._alert_payload(r1, e1)
    a2 = ws5._alert_payload(r2, e2)
    check(a1["alert_id"] != a2["alert_id"],
          f"id-less alerts must not collapse onto one alert_id ({a1['alert_id']})")
    check(a1["alert_id"] == f"ai-{id1}",
          f"alert_id must embed the stable per-event id, got {a1['alert_id']!r}")
    check(not a1["alert_id"].endswith("unknown"),
          "id-less alert_id must not use the 'ai-unknown' fallback")
    check(a1["event_ids"] == [id1],
          f"id-less alert event_ids must carry the stable id, got {a1['event_ids']}")

    # End-to-end through run(): two id-less requests must land on the bus under
    # DIFFERENT keys (previously both 'unknown').
    bus = Bus()
    worker = ws5.AiWorker()
    bus.produce("ai.requests", key="noid-1", payload={"reason": [], "event": e1})
    bus.produce("ai.requests", key="noid-2", payload={"reason": [], "event": e2})
    ws5.run(bus, worker)
    results = bus.drain("ai.results")
    alerts = bus.drain("alerts")
    check(len(results) == 2 and len(alerts) == 2,
          f"expected 2 ai.results + 2 alerts, got {len(results)}/{len(alerts)}")
    result_keys = {m.key for m in results}
    alert_keys = {m.key for m in alerts}
    check(len(result_keys) == 2,
          f"id-less ai.results must not share one bus key, got {result_keys}")
    check(len(alert_keys) == 2,
          f"id-less alerts must not share one bus key, got {alert_keys}")
    check("unknown" not in result_keys and "unknown" not in alert_keys,
          f"id-less bus keys must not be the literal 'unknown' ({result_keys})")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-5 gap-hunt: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-5 gap-hunt fixes (siem:null + id-less event ids) PASS")


if __name__ == "__main__":
    main()