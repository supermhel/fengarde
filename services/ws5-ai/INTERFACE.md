# WS-5 AI Pipeline — Interface Declaration

## Consumes
- Topic `ai.requests` (group `cg-ai`) — buffered funnel input from WS-4, carrying
  `{event, tier, reason, event_id}`. `tier` is `"llm"` (score ≥ `llm_min`, full LLM
  triage) or `"classifier"` (`classifier_min` ≤ score < `llm_min`, light-classifier
  only, no LLM call) per `contracts/scoring.yaml`. A request with no `tier` field
  defaults to `"llm"` (back-compat with any producer predating this split).
- Contracts: B (bus), D (funnel thresholds).
- Consume ordering is per-tenant fair, not raw FIFO: `main.py` wraps the bus in
  `FairConsumeBus` (`services/shared/fairness.py`) by default — one tenant
  flooding `ai.requests` can no longer occupy every consecutive processing turn
  ahead of another tenant's triage requests. Default on; opt out with
  `FENGARDE_TENANT_FAIR_CONSUME=0`. Bounded within one raw consume batch, see the
  module's own docstring for the honest scope.

## Produces
- Topic `ai.results` — `{event_id, tier, verdict, summary, level, classification}`.
  On the `"classifier"` tier, `verdict`/`summary` are `null` — the LLM was never
  called, so nothing is fabricated in those fields.
- Topic `alerts` — enriched AI alert. The classifier tier's alert carries no `ai`
  (LLM verdict/summary) block, only `classification`; its `level` is the
  classifier's own priority (low/medium/high), not an LLM verdict.

## Triage
- LLM triage via `make_llm()` → `OllamaLLM` (local, confidential, when `OLLAMA_URL`
  set) or the offline `StubLLM` fallback (score-band heuristic). Output is coerced
  to a fixed `verdict`/`level` enum with a safe default; the verdict is **advisory**
  (annotates an alert detection already raised — see SECURITY.md §6).
- `classifier.py`'s `LightClassifier` (deterministic heuristic skeleton — real
  sklearn TF-IDF/logistic-regression model deferred, same `predict()` interface so
  swapping it in later needs no worker change) runs on EVERY request regardless of
  tier. On the `"llm"` tier it runs alongside the LLM verdict; on the `"classifier"`
  tier it runs alone — this is the real, working second funnel path
  `contracts/scoring.yaml`'s 20-59 band and `sigma-convention.md` describe (closed
  as P1-2 in the 2026-07-21 audit fix plan; WS-4's `main.py` does enqueue the
  classifier tier for that band today).
- **LLM triage dedup on redelivery**: a bounded per-event-id cache (`_TriageCache`,
  keyed on `event`'s `siem.ingest_id` falling back to `event_id`) returns the prior
  verdict on a redelivered event instead of re-calling the LLM — at-least-once bus
  delivery no longer means paying for (or re-running) triage twice on the same
  content. Oldest entries evict first once the cache is full; events with no
  ingest_id/event_id are still triaged on every delivery (nothing stable to dedup
  on). Classifier-tier requests never touch this cache (they never call the LLM).
- **Decoupled**: the worker consumes the queue at its own pace; scale by adding workers.

## Contract tests
- `python test_contract.py`  (StubLLM + memory bus; no GPU/Ollama needed)
- `python test_fix_llm_dedup.py`  (dedup cache: redelivery, bounded eviction, back-compat)

## Environment (read by `main.py` / `llm_adapter.py`)
- `PORT` (default `8005`) — health/metrics listener port.
- `OLLAMA_URL` (default `http://localhost:11434`) — Ollama endpoint; unset/unreachable
  degrades to the documented passthrough `StubLLM` (zero infra).
- `OLLAMA_MODEL` — model name to request from Ollama.
- `FENGARDE_TENANT_FAIR_CONSUME` — per-tenant fair consume. **Default on**;
  opt out with `=0`/`=false` (this said "opt-in" until 2026-08-13, contradicting
  this file's own Consumes section above, which correctly says default on).

## Run locally
- `python main.py`  (StubLLM unless OLLAMA_URL is set)
