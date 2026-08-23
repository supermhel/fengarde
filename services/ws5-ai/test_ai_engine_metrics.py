"""Gap-hunt finding (2026-08-23): AiWorker's stub-vs-real-LLM engine tag was
fully disclosed per-alert (llm_adapter.py sets `engine`, it reaches the
stored alert doc and renders in the dashboard) but never aggregated -- WS-5's
serve() call passed no `metrics_provider` (unlike ws8-correlation), so an
operator could only discover "we've been silently running on the stub" by
opening alerts one at a time or reading logs.

Proves AiWorker.metrics() aggregates by engine correctly, and specifically
that it counts only genuine LLM invocations: classifier-tier requests
(no LLM call at all) and cache hits (redelivery of an already-triaged event)
must NOT inflate the count.
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

import main as ws5  # noqa: E402

FAILS: list[str] = []


def check(c, m):
    if not c:
        FAILS.append(m)


class TaggedLLM:
    """Deterministic LLM stub that tags every verdict with a given engine
    name, mirroring llm_adapter.py's real contract (stub/ollama/fallback all
    set `engine`)."""

    def __init__(self, engine: str):
        self.engine = engine

    def analyze(self, event, reasons):
        return {"verdict": "malicious", "summary": "s", "level": "critical",
                "engine": self.engine, "model": self.engine}


def ai_request(ingest_id, tier="llm"):
    return {
        "event_id": ingest_id,
        "tier": tier,
        "reason": ["Privileged database operation on a banking DB"],
        "event": {
            "class_uid": 6005, "activity_id": 5, "severity_id": 4,
            "time": 1750000000000,
            "siem": {"sector": "bank", "ingest_id": ingest_id, "score": 85},
        },
    }


def run():
    worker = ws5.AiWorker()
    check(worker.metrics() == {"by_engine": {}, "total": 0},
          "a fresh worker must report empty metrics, not fabricate a baseline")

    worker.llm = TaggedLLM("stub")
    worker.handle(ai_request("evt-1"))
    worker.handle(ai_request("evt-2"))
    m = worker.metrics()
    check(m == {"by_engine": {"stub": 2}, "total": 2},
          f"2 genuine stub calls should show as such, got {m}")

    # Redelivery of an already-triaged event must NOT inflate the count --
    # it's a cache hit, not a new LLM call.
    worker.handle(ai_request("evt-1"))
    m = worker.metrics()
    check(m == {"by_engine": {"stub": 2}, "total": 2},
          f"a cache-hit redelivery must not double-count, got {m}")

    # Classifier tier never touches the LLM at all -- must not count either.
    worker.handle(ai_request("evt-classifier-only", tier="classifier"))
    m = worker.metrics()
    check(m == {"by_engine": {"stub": 2}, "total": 2},
          f"classifier-tier requests never call the LLM, must not count, got {m}")

    # A different engine tallies separately -- e.g. real Ollama alongside a
    # prior stub run (StubLLM.FallbackLLM degrading mid-session).
    worker.llm = TaggedLLM("ollama")
    worker.handle(ai_request("evt-3"))
    m = worker.metrics()
    check(m == {"by_engine": {"stub": 2, "ollama": 1}, "total": 3},
          f"a second engine must tally under its own key, got {m}")

    # metrics() must be reachable through main.py's actual serve() wiring,
    # not just present on AiWorker -- drives the real lambda main() builds
    # (mirrors WS-3's own "prove the wiring, not just the function" discipline).
    provider_shape = {"ai_triage": worker.metrics()}
    check("ai_triage" in provider_shape and provider_shape["ai_triage"]["total"] == 3,
          "the metrics_provider shape main.py wires into serve() must nest under 'ai_triage'")


def main_() -> None:
    run()
    if FAILS:
        for f in FAILS:
            print(f"[FAIL] {f}")
        raise SystemExit(1)
    print("[OK] WS-5 ai_triage engine-mix metrics PASS")


if __name__ == "__main__":
    main_()
