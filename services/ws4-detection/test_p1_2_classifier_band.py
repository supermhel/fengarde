"""P1-2 (2026-07-21 audit) -- the 20-59 "light classifier" band must actually
route somewhere.

Before this fix, contracts/scoring.yaml / sigma-convention.md promised
"20-59 -> light classifier (WS-5 layer 2)", Scorer.route() correctly computed
action=="classifier" for that band, but ws4-detection/main.py only ever
checked action=="llm" -- 20-59-scored events were indexed and NEVER routed to
WS-5 at all. This proves: (1) a real rule scoring in that band produces
action=="classifier", (2) main.py now enqueues it to ai.requests with
tier="classifier", and (3) WS-5's AiWorker runs ONLY the light classifier for
that tier (never calls the LLM -- the whole point of a cheap second tier).

Run: python services/ws4-detection/test_p1_2_classifier_band.py
"""
from __future__ import annotations

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
import main as ws4  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def prompt_injection_event(t=1750000000000):
    """Fires agent_prompt_injection_indicator.yml alone: level=medium
    (floor 40), score_weight=50 -> score=max(50,40)=50, squarely in the
    20-59 band (classifier_min=20, llm_min=60, contracts/scoring.yaml)."""
    return {
        "class_uid": 6003, "category_uid": 6, "activity_id": 1, "type_uid": 600301,
        "severity_id": 2, "time": t, "status": "Success",
        "actor": {"user": {"name": "agent-01"}},
        "api": {"operation": "tool_call"},
        "unmapped": {"mcp": {"injection_indicator": True, "session_id": "s-1"}},
        "siem": {"sector": "common", "source_type": "mcp_agent", "ingest_id": f"pi-{t}"},
    }


def run():
    det = ws4.Detector()
    ev, matched, action = det.process(prompt_injection_event())
    titles = [r.title for r in matched]
    check(any("prompt-injection" in t for t in titles), f"injection rule did not fire: {titles}")
    check(20 <= ev["siem"]["score"] < 60, f"expected score in [20,60), got {ev['siem']['score']}")
    check(action == "classifier", f"action {action} != classifier")

    # full bus loop: main.py must enqueue this to ai.requests with tier=classifier
    bus = Bus()
    bus.produce("normalized.events", key="pi", payload=prompt_injection_event())
    det2 = ws4.Detector()
    stats = ws4.run(bus, det2)
    check(stats.get("classifier_enqueued") == 1,
          f"expected 1 classifier_enqueued, got {stats.get('classifier_enqueued')}")
    requests = bus.drain("ai.requests")
    check(len(requests) == 1, f"expected 1 ai.requests message, got {len(requests)}")
    check(requests[0].payload.get("tier") == "classifier",
          f"ai.requests payload missing tier=classifier: {requests[0].payload.get('tier')!r}")

    # WS-5 side: the classifier tier must run ONLY the light classifier, never the LLM.
    ws5_dir = str(SERVICES / "ws5-ai")
    if ws5_dir not in sys.path:
        sys.path.insert(0, ws5_dir)
    os.environ.pop("OLLAMA_URL", None)  # force StubLLM if the llm path were (wrongly) taken
    import importlib
    for m in ("main", "classifier", "llm_adapter"):
        sys.modules.pop(m, None)
    ws5 = importlib.import_module("main")

    worker = ws5.AiWorker()

    class _ExplodingLLM:
        def analyze(self, *a, **kw):
            raise AssertionError("classifier tier must never call the LLM")

    worker.llm = _ExplodingLLM()  # any call blows up the test loudly, not silently
    result = worker.handle(requests[0].payload)
    check(result["verdict"] is None, f"classifier tier must not fabricate a verdict, got {result['verdict']!r}")
    check(result["classification"]["priority"] in ("low", "medium", "high"),
          f"classifier tier must still run the real classifier, got {result['classification']!r}")

    alert = ws5._alert_payload(result, requests[0].payload.get("event", {}))
    check("ai" not in alert, "classifier-tier alert must not carry an 'ai' (LLM verdict) block")
    check("classification" in alert, "classifier-tier alert must carry its classification")


def main():
    run()
    if FAILS:
        print(f"[FAIL] P1-2 classifier band: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] P1-2: 20-59 score band routes to WS-5 with tier=classifier and runs "
          "ONLY the light classifier (never the LLM); the alert it produces carries "
          "no fabricated 'ai' verdict block")


if __name__ == "__main__":
    main()
