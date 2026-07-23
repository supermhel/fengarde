"""WS-5 contract test — zero infrastructure (StubLLM, memory bus).

Asserts:
  * the worker turns an ai.requests message into an ai.results message + an alert,
  * verdict/level scale with score (critical->malicious),
  * the light classifier returns category+priority+confidence,
  * the funnel is decoupled: consuming ai.requests never blocks on the producer.
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
import main as ws5  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


def ai_request(score, ingest_id):
    return {
        "event_id": ingest_id,
        "reason": ["Privileged database operation outside maintenance window"],
        "event": {
            "class_uid": 6005, "activity_id": 5, "severity_id": 4, "time": 1750000000000,
            "siem": {"sector": "bank", "ingest_id": ingest_id, "score": score},
        },
    }


def run():
    clf = LightClassifier()
    pred = clf.predict(ai_request(85, "x")["event"])
    for k in ("category", "priority", "confidence"):
        check(k in pred, f"classifier missing {k}")
    check(pred["category"] == "datastore", f"classifier category {pred['category']}")
    check(pred["priority"] == "high", f"classifier priority {pred['priority']}")

    bus = Bus()
    bus.produce("ai.requests", key="b-1", payload=ai_request(85, "b-1"))
    bus.produce("ai.requests", key="b-2", payload=ai_request(65, "b-2"))
    worker = ws5.AiWorker()
    stats = ws5.run(bus, worker)
    check(stats["analyzed"] == 2, f"analyzed {stats['analyzed']} != 2")

    results = bus.drain("ai.results")
    alerts = bus.drain("alerts")
    check(len(results) == 2, "expected 2 ai.results")
    check(len(alerts) == 2, "expected 2 enriched alerts")

    by_id = {r.payload["event_id"]: r.payload for r in results}
    check(by_id["b-1"]["verdict"] == "malicious", f"b-1 verdict {by_id['b-1']['verdict']}")
    check(by_id["b-1"]["level"] == "critical", f"b-1 level {by_id['b-1']['level']}")
    check(by_id["b-2"]["verdict"] == "suspicious", f"b-2 verdict {by_id['b-2']['verdict']}")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-5: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-5 contract test PASS")


if __name__ == "__main__":
    main()
