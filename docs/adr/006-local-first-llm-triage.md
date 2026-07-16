# ADR 006: Local-first LLM triage (Ollama, optional)

**Status:** Accepted, live. **Date:** v0.2 (2026-07); backfilled 2026-07-16.

## Context

WS-5 annotates alerts with an AI-generated verdict/summary. Every SIEM vendor
now has an "AI analyst" feature, and almost all of them mean: the alert — rule
name, source IP, username, whatever raw log text triggered it — gets
serialized into a prompt and sent to a cloud LLM API. For an observability
tool that trade-off is defensible; for a *security* tool it is a harder sell:
that's the exact data an attacker would want (who got compromised, from
where, doing what), leaving the network through a third-party API during the
incident the operator is trying to keep quiet about. It's also untenable for
FENGARDE's targeted deployment context (air-gapped/regulated industrial and
Mittelstand environments) where "alert data left the network" may itself be
a compliance violation.

Normalized event content — including attacker-controlled log fields — also
flows into whatever triage prompt gets built, so a crafted log line can
attempt prompt injection against the model regardless of where it runs.

## Decision

WS-5's LLM backend selection (`make_llm()`, `services/ws5-ai/llm_adapter.py`)
defaults to **local**: set `OLLAMA_URL` to a model running on the operator's
own hardware/VPC and every triage verdict is generated without a byte leaving
the network. **No `OLLAMA_URL` set → the service degrades to a documented
passthrough stub** (`StubLLM`) — the pipeline still produces real alerts with
zero AI dependency at all. A reachable-at-startup-but-later-down Ollama
degrades per-call via `FallbackLLM(OllamaLLM, StubLLM)`, not per-boot.

Prompt-injection blast radius is bounded structurally, not just by policy:
**the verdict is advisory.** WS-5's output annotates an alert that detection
(WS-4) already raised independently — it never gates or suppresses an alert.
A compromised model can produce a bad summary; it cannot make a real
detection disappear, because WS-4's rule engine (ADR 005) has no dependency
on WS-5's output to decide whether to fire.

## Consequences

- **Positive:** "no AI required" is a literal, checkable claim (README) — the
  v0.1 acceptance test (`make e2e`) proves a real alert reaches the index with
  zero LLM involvement, stub-only. This is also why v0.4's incident-report
  hook (`contracts/reporting.md`) follows the same pattern: a builtin
  zero-AI-dependency template backend, with an LLM enhancement layer as a
  strictly optional, swappable seam (`REPORT_BACKEND=http`) — the local-first
  triage decision set the precedent the reporting feature reused rather than
  re-litigating.
- **Positive:** the open-core split (this repo free forever, `fengarde-sec`
  paid) is compatible with this decision by construction — the free repo's
  AI story was never "call our hosted model," so there was no monetization
  pressure to walk back local-first triage later.
- **Trade-off:** local-model quality/latency is whatever the operator's own
  hardware supports — no vendor-hosted frontier-model fallback exists in this
  repo. Documented as a deliberate scope boundary (`docs/posts/local-ai-triage.md`),
  not a gap to silently fix by adding a cloud API key path.
- **Trade-off:** prompt-injection *content* still reaches the model (bounding
  its blast radius doesn't prevent the attempt) — WS-4's independent,
  advisory-only relationship to WS-5 is the actual mitigation, not input
  sanitization on the prompt itself. If the model's summary field is ever
  rendered anywhere without escaping, that becomes a second problem (XSS)
  layered on top of prompt injection — the dashboard's `esc()` discipline
  (log-injection ADR context, `services/shared/sanitize.py`) is what actually
  closes that, not this ADR's decision.
- See `docs/posts/local-ai-triage.md` for the full public-facing rationale
  this ADR summarizes.
