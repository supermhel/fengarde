# ADR 008: Decline a shared pydantic schema package

**Status:** Accepted (declined), live. **Date:** 2026-08-18.

## Context

The v0.5 combined-plan doc's §B.4 deferred "shared pydantic schema package"
to "the M2 PR that would introduce it," but no PR ever made that decision
either way — `SSOT.md` §4 has carried it as a genuinely dangling item since
2026-07-23 (confirmed by a repo-wide grep that day: zero pydantic usage
anywhere). This ADR closes it.

Every bus payload, OCSF event, alert, and now WS-8 incident shape in this
repo is validated today by a combination of: `contracts/ocsf-event.schema.json`
(JSON Schema, Contract A), `tools/validate_contract.py` (the Phase-0
validator), `tools/validate_rules.py` (Contract D), and hand-written
tolerant-reader `dict.get(...)` access throughout every workstream. None of
the 8 services import pydantic; none declare it in a `requirements.txt`.

## Decision

**Decline.** Contracts stay JSON Schema + hand-rolled dict validation, the
way they are today. No shared pydantic models package is introduced.

Reasoning:

- **A new runtime dependency in every service, for no proven gain.** Bus-only
  coupling (ADR 004) means each of the 8 workstreams builds and ships its
  own container; a shared pydantic package would need to land in every one
  of their `requirements.txt` files, in a codebase whose own M2 quality pass
  went out of its way to keep runtime dependencies minimal (the M7
  observability pass, for example, explicitly avoided the `prometheus_client`
  dependency for the same reason — see `infra/prometheus.yml`'s design note).
- **The existing validation already works and is exercised.** `tools/
  validate_contract.py` gates every OCSF fixture in CI; `check_rule_producers.py`
  and `fire_check.py` prove producer/consumer satisfiability end-to-end. A
  pydantic layer would duplicate that coverage, not add new coverage, unless
  paired with a real migration of every parser/rule/handler — a large,
  cross-cutting change with no concrete bug it would have caught.
- **Tolerant-reader discipline is a deliberate project convention, not an
  oversight.** Additive fields (envelope v1's `trace_id`, WS-8's `incidents`
  shape, A5 enrichment's `src_endpoint.reputation`) are designed to be safely
  absent from an old producer or an old consumer. A pydantic model with
  strict field validation would need to relax to the same permissiveness to
  preserve this property, at which point it adds ceremony without adding
  safety.

## Consequences

- **Positive:** no new dependency surfaces in any service's supply-chain
  scan (`pip-audit`, SBOM) for zero behavior change.
- **Positive:** closes a 2+ month dangling doc-debt item (`SSOT.md` §4)
  cleanly, with a real decision on record instead of an indefinite "someone
  will decide in a future PR" placeholder.
- **Trade-off, accepted:** contract violations are still caught at
  validation-gate time (CI) or at parse time (a malformed field silently
  dropped by a tolerant `dict.get`), not at the type-checker level a
  pydantic model would give mypy. This repo already runs `mypy` as a
  blocking CI gate (M2) on the *code*, just not on the wire-format
  boundary — an accepted scope line, not a gap discovered by this ADR.
- **Reversible:** nothing here is irreversible. If a future service
  genuinely needs typed validated payload objects (e.g. a new
  externally-facing API with many third-party integrators), that can be
  scoped and decided for that one case without reopening this ADR for the
  whole repo.
