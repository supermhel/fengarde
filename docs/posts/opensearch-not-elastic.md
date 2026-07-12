# OpenSearch, not Elastic: an open-source SIEM without the license asterisk

*Draft technical write-up — v0.4.*

Almost every "open-source SIEM" comparison article eventually gets to a
footnote: *"Elasticsearch/Kibana are source-available under the SSPL, not
OSI-approved open source; Elastic-licensed features require a subscription
past a certain point."* Wazuh — probably the most-cited open SIEM — inherits
that asterisk, because its storage layer is Elastic.

ARGIEM's storage layer is [OpenSearch](https://opensearch.org/) — the
Apache-2.0 fork that Amazon and a community of maintainers took over when
Elastic changed its license in 2021. There's no fine print. The "no asterisks"
claim is not marketing; it's a property of the dependency graph you can check
yourself: `infra/docker-compose.yml`'s `opensearch` service pulls
`opensearchproject/opensearch:2.13.0`, full stop.

## Why this is a real (not just legal) differentiator

It's not only about licensing purity. OpenSearch's roadmap and plugin
ecosystem move independent of a single vendor's commercial incentives —
relevant for a security tool, where "will this feature still be free/open in
two years" is a real operational question, not a hypothetical one.

## What ARGIEM does and doesn't turn on

Storage is a thin adapter (`services/ws3-indexer/storage/`) with two
backends: an in-memory store for the entire zero-infra test suite, and the
real `OpenSearchStore` for the live stack. The OpenSearch security plugin
ships **disabled** by default (`DISABLE_SECURITY_PLUGIN=true`) — a deliberate
v0.1-era trade-off for zero-friction local development, not an oversight.
v0.4 tightens the actual mitigation instead of pretending the plugin is
enough: OpenSearch's port is bound to `127.0.0.1` by default (never published
beyond localhost), and a separate opt-in shared-secret layer
(`ARGIEM_API_KEY`) protects the two HTTP write surfaces (triage and inventory
APIs) that sit in front of it. `SECURITY.md` states exactly what this does
and doesn't cover — no TLS anywhere, no per-user identity, a deterrent, not
an access-control system.

## The honest trade-off

OpenSearch, like Elasticsearch, is a real distributed search engine — running
it well at scale is genuine operational work (JVM heap tuning, shard
management, `vm.max_map_count` on Linux, all covered by `make preflight`'s
doctor script). ARGIEM doesn't pretend that complexity vanishes; it just
refuses to add a licensing question on top of it.

*Read the storage adapter at
[`services/ws3-indexer/storage/`](../../services/ws3-indexer/storage/) and the
threat-boundary details in [`SECURITY.md`](../../SECURITY.md).*
