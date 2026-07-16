# Architecture Decision Records

Backfilled 2026-07-16 (M2, PLAN_C Tier 2.3) for the six standing decisions
already made and shipped — these record reasoning that previously lived only
in commit messages, `docs/superpowers/specs/`, and `docs/posts/`, not a
retroactive justification invented after the fact. Each ADR cites the code/doc
that proves the decision is real, not aspirational.

New architecturally-significant decisions going forward get a new ADR here
(per `CLAUDE.md`'s standing guardrail: ask the human before changing the bus
message schema, adding heavyweight dependencies, or anything with this kind
of blast radius — the ADR is where that conversation gets recorded once made).

| # | Decision | Status |
|---|---|---|
| [001](001-redis-streams-as-the-bus.md) | Redis Streams as the message bus | Accepted, live |
| [002](002-ocsf-as-the-only-normalized-shape.md) | OCSF as the only normalized event shape | Accepted, live |
| [003](003-opensearch-not-elasticsearch.md) | OpenSearch, not Elasticsearch | Accepted, live |
| [004](004-microservice-split-bus-only-coupling.md) | Seven-workstream split, bus-only coupling | Accepted, live |
| [005](005-fail-closed-rule-evaluation.md) | Fail-closed detection-rule evaluation | Accepted, live |
| [006](006-local-first-llm-triage.md) | Local-first LLM triage (Ollama, optional) | Accepted, live |

Format: lightweight [Michael Nygard-style](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions) ADRs — Context / Decision / Consequences.
