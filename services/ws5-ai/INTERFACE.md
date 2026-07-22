# WS-5 AI Pipeline — Interface Declaration

## Consumes
- Topic `ai.requests` (group `cg-ai`) — buffered funnel input from WS-4.
- Contracts: B (bus), D (funnel thresholds).

## Produces
- Topic `ai.results` — `{event_id, verdict, summary, level, classification}`.
- Topic `alerts` — enriched AI alert.

## Triage
- LLM triage via `make_llm()` → `OllamaLLM` (local, confidential, when `OLLAMA_URL`
  set) or the offline `StubLLM` fallback (score-band heuristic). Output is coerced
  to a fixed `verdict`/`level` enum with a safe default; the verdict is **advisory**
  (annotates an alert detection already raised — see SECURITY.md §6).
- `classifier.py`'s `LightClassifier` (deterministic heuristic skeleton — real
  sklearn TF-IDF/logistic-regression model deferred, same `predict()` interface so
  swapping it in later needs no worker change) IS implemented and wired: `main.py`
  runs it per event ALONGSIDE the LLM verdict, not as a separate lighter-weight
  funnel stage. Per `contracts/scoring.yaml`'s 20-59 "light classifier" band and
  `sigma-convention.md`'s funnel description, the intent was a genuinely separate,
  cheaper path for that score range — but WS-4 (`main.py`) only ever enqueues
  `ai.requests` when the score crosses the `llm` threshold (≥60), so the 20-59 band
  never actually reaches WS-5 today (tracked as P1-2 in the 2026-07-21 audit fix
  plan). `classification` in the `ai.results` payload below is real output, just
  currently only produced on events that also got a full LLM verdict.
- **Decoupled**: the worker consumes the queue at its own pace; scale by adding workers.

## Contract tests
- `python test_contract.py`  (StubLLM + memory bus; no GPU/Ollama needed)

## Run locally
- `python main.py`  (StubLLM unless OLLAMA_URL is set)
