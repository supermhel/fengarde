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
- A single-layer worker in code today (StubLLM/OllamaLLM). The earlier multi-layer
  "LightClassifier" design (a separate CPU pre-classifier) is NOT implemented.
- **Decoupled**: the worker consumes the queue at its own pace; scale by adding workers.

## Contract tests
- `python test_contract.py`  (StubLLM + memory bus; no GPU/Ollama needed)

## Run locally
- `python main.py`  (StubLLM unless OLLAMA_URL is set)
