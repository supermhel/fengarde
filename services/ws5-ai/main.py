"""WS-5 AI worker entrypoint.

Decoupled funnel consumer (Contract B): reads the buffered `ai.requests` topic at
its own pace and runs one of two tiers per request's `tier` field (set by WS-4's
Scorer.route(), contracts/scoring.yaml):
  - "llm" (score >= llm_min): full LLM triage (local Ollama, StubLLM fallback) +
    the light classifier, same as before this fix.
  - "classifier" (classifier_min <= score < llm_min): ONLY the light classifier
    (classifier.py) runs -- no LLM call. This is the whole point of a cheap
    second tier (P1-2, 2026-07-21 audit): calling the LLM on every 20-59-score
    event would just reintroduce the cost the tier exists to avoid. A request
    with no `tier` field defaults to "llm" (back-compat with any producer that
    predates this).
Both tiers publish `ai.results` and an enriched `alerts` entry; the classifier
tier's alert carries no `ai` (LLM verdict) block, only `classification`, and its
`level` is the classifier's own priority (low/medium/high), not an LLM verdict.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from classifier import LightClassifier  # noqa: E402
from llm_adapter import make_llm  # noqa: E402


class AiWorker:
    def __init__(self):
        self.llm = make_llm()
        self.classifier = LightClassifier()

    def handle(self, request: dict) -> dict:
        event = request.get("event", {})
        tier = request.get("tier", "llm")
        classification = self.classifier.predict(event)
        if tier == "classifier":
            return {
                "event_id": request.get("event_id"),
                "tier": tier,
                "verdict": None,
                "summary": None,
                "level": classification["priority"],
                "classification": classification,
            }
        reasons = request.get("reason", [])
        verdict = self.llm.analyze(event, reasons)
        return {
            "event_id": request.get("event_id"),
            "tier": tier,
            "verdict": verdict.get("verdict"),
            "summary": verdict.get("summary"),
            "level": verdict.get("level"),
            "classification": classification,
        }


def _alert_payload(result: dict, event: dict) -> dict:
    """Build the enriched-alert doc for one ai.results record. The
    classifier tier never called an LLM, so its alert carries no `ai`
    (verdict/summary) block -- only `classification` -- rather than
    fabricating a verdict that was never actually computed."""
    alert = {
        "alert_id": f"ai-{result['event_id']}",
        "time": event.get("time"),
        "level": result["level"],
        "classification": result["classification"],
        "sector": event.get("siem", {}).get("sector"),
        "event_ids": [result["event_id"]],
    }
    if result["tier"] != "classifier":
        alert["ai"] = {"verdict": result["verdict"], "summary": result["summary"],
                       "level": result["level"]}
    return alert


def run(bus, worker: "AiWorker") -> dict:
    stats = {"analyzed": 0}
    for msg in bus.consume("ai.requests", group="cg-ai"):
        result = worker.handle(msg.payload)
        bus.produce("ai.results", key=result["event_id"] or "unknown", payload=result)
        bus.produce("alerts", key=result["event_id"] or "unknown",
                    payload=_alert_payload(result, msg.payload.get("event", {})))
        stats["analyzed"] += 1
    return stats


def _make_handler(bus, worker: "AiWorker"):
    """Build the per-message daemon handler bound to ONE shared `bus`.

    H1 (2026-07-29 audit): ONE Bus() per worker, not one per message. Same
    fix as WS-2/WS-4's P1-3 -- runner.py's `_topic_worker` owns exactly one
    topic (WS-5 consumes only ai.requests) per thread and calls this handler
    serially on that single thread, so there is no cross-thread sharing to
    guard against. A fresh Bus() per message was worse than the P1-3
    per-event-connect cost it left unfixed here: on BUS_BACKEND=memory (the
    project's documented zero-infra dev mode) `Bus()` returns a brand new,
    isolated in-memory bus every call, so every produce() below wrote into a
    bus nothing else ever reads -- ai.results/alerts silently stayed empty
    forever. `bus` is taken as a parameter (rather than constructed inside)
    so this closure is unit-testable without a live daemon loop.
    """
    def handler(payload: dict) -> None:
        result = worker.handle(payload)
        bus.produce("ai.results", key=result["event_id"] or "unknown", payload=result)
        bus.produce("alerts", key=result["event_id"] or "unknown",
                    payload=_alert_payload(result, payload.get("event", {})))
    return handler


def main():
    # Daemon (T0): consume ai.requests via the shared runner. run() above stays the
    # batch path used by tests / the e2e harness. Real local-Ollama triage runs when
    # OLLAMA_URL is set and reachable; otherwise the deterministic StubLLM is used.
    from shared.runner import serve  # noqa: E402
    from shared.log import get_logger  # noqa: E402

    worker = AiWorker()
    mode = type(worker.llm).__name__
    get_logger("ws5-ai").info("ai triage mode", mode=mode)

    handler_bus = Bus()
    handler = _make_handler(handler_bus, worker)

    serve({"ai.requests": ("cg-ai", handler)},
          health_port=int(os.getenv("PORT", "8005")), service_name="ws5-ai")


if __name__ == "__main__":
    main()
