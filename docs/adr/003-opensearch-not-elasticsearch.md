# ADR 003: OpenSearch, not Elasticsearch

**Status:** Accepted, live. **Date:** v0.1 (2026-06); backfilled 2026-07-16.

## Context

FENGARDE needs a search/analytics store for indexed events and alerts:
full-text + structured query, reasonable ingest throughput, and an index
lifecycle story. The default choice for most SIEM projects is the
Elastic stack, but Elasticsearch/Kibana moved off an OSI-approved license
to the SSPL in 2021 (Elastic-licensed features require a subscription past a
certain point) — an asterisk that most "open-source SIEM" write-ups eventually
get to in a footnote. Wazuh, probably the most-cited open SIEM, inherits that
asterisk because its storage layer is Elastic.

## Decision

FENGARDE's storage layer is **OpenSearch** — the Apache-2.0 fork Amazon and a
community of maintainers took over when Elastic changed its license.
`infra/docker-compose.yml`'s `opensearch` service pulls
`opensearchproject/opensearch:2.13.0`, full stop — no Elastic dependency
anywhere in the stack. Storage is a thin adapter
(`services/ws3-indexer/storage/`) with two backends: an in-memory store for
the entire zero-infra test suite (`STORAGE_BACKEND=memory`, the default for
`make test`), and the real `OpenSearchStore` for the live stack
(`STORAGE_BACKEND=opensearch`).

## Consequences

- **Positive:** no license asterisk to defend or explain — a real property of
  the dependency graph anyone can check, not a marketing claim. Also a real
  operational property for a security tool: OpenSearch's roadmap and plugin
  ecosystem move independent of a single vendor's commercial incentives,
  relevant when "will this feature still be free/open in two years" isn't
  hypothetical for a project that expects to run in regulated environments.
- **Trade-off, documented (SECURITY.md §2, not an oversight):** the
  OpenSearch security plugin ships **disabled** by default
  (`DISABLE_SECURITY_PLUGIN=true`) — a deliberate scope cut for the
  local/air-gapped deployment tier this repo currently targets, layered with
  FENGARDE's own opt-in auth (`FENGARDE_API_KEY`, v0.4 Track S) and
  loopback-only port binding rather than OpenSearch's own RBAC. Re-evaluate
  when the multi-tenant tier (ADR 001's Kafka trigger, M4's RBAC work) is
  built — that tier likely needs OpenSearch's security plugin enabled for
  real per-tenant index isolation.
- **Trade-off:** single-instance OpenSearch in the current tier, same HA
  caveat as ADR 001's Redis decision — no replica/cluster design yet,
  conscious Phase-3 scope cut per the 2026-07-02 architecture review.
- See `docs/posts/opensearch-not-elastic.md` for the full public-facing
  rationale this ADR summarizes.
