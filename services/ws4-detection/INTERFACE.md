# WS-4 Detection — Interface Declaration

## Consumes
- Topic `normalized.events` (group `cg-detect`).
- Contracts: A (events), D (Sigma rules + scoring), B (bus).
- Files: `contracts/rules/*.yml`, `contracts/scoring.yaml`.

## Produces
- Topic `scored.events` — event + `siem.score`, partition key = src ip.
- Topic `alerts` — one per rule match, partition key = alert_id.
- Topic `ai.requests` — buffered AI funnel input when score >= `llm_min` (60).

## Engine
- Sigma-style rules over OCSF dotted paths; stateful rules use `window_seconds` +
  `threshold` + `group_by` (sliding window, plus `distinct_field` for distinct-count).
  Score = capped sum of weights, with a severity floor; funnel route =
  store / classifier / llm per `scoring.yaml`.
- Operators (v0.3): equality, comparison (`gt/gte/lt/lte/ne`), allowlist suppression
  (`not_in`), time-of-day (`outside_hours`) — non-eval, fail-closed. Grammar in
  `contracts/sigma-convention.md`.
- `class_uid` prefilter: rules bucketed by a *necessary* equality class_uid so an
  event only evaluates candidate rules; multi-class/negation rules fall back to a
  catch-all bucket (always evaluated).
- Deterministic `alert_id` → idempotent alerts under at-least-once redelivery.
- Rule gates (CI): `tools/validate_rules.py` (schema/condition/operator/reference)
  and `tools/check_rule_producers.py` (anti-dormancy).

## Contract tests
- `python test_contract.py`  (memory bus; rule firing + stateful thresholds + funnel)

## Run locally
- `python main.py`
