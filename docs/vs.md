# FENGARDE vs. Wazuh vs. Elastic Security vs. Security Onion

An honest comparison, not a sales pitch. FENGARDE is younger and smaller in
scope than every project below — say so plainly, because credibility is the
actual product here (`SSOT.md` §2's proven-vs-claim discipline applies to
this doc as much as anywhere else). If something below is wrong or has
changed, that's a bug in this doc — open an issue.

This page compares detection-pipeline products. It does not cover managed
services or SME-focused platforms sold on sovereignty positioning rather
than as a self-hostable SIEM — see "German-native sovereignty players"
below for that adjacent category.

**Read the whole table before picking anything.** The honest summary: Wazuh
and Elastic Security are mature, broadly-adopted platforms with far more
integrations, community rule content, and battle-testing than FENGARDE has
today. FENGARDE's case is narrower — OCSF-native normalization, a
genuinely open-source (no SSPL) storage layer, local-first AI triage, and
detection content for a source class (AI-agent/MCP telemetry) no other
open-source, OCSF-integrated SIEM covers yet — not "does everything those
do, plus more." (Commercial AI-agent-security products exist — Palo Alto
Prisma AIRS, Nightfall AI, Cyera, Lasso Security, CrowdStrike Falcon among
them — just not as an OCSF-normalized SIEM parser/rule-pack.)

| | **FENGARDE** | **Wazuh** | **Elastic Security** | **Security Onion** |
|---|---|---|---|---|
| License | Apache-2.0, fully open | Apache-2.0 (agent/manager); storage layer is Elasticsearch (SSPL, see below) | Elastic License / SSPL past a feature tier — not OSI-approved open source | Apache-2.0 (the distro); bundles Elasticsearch (SSPL) |
| Storage layer | OpenSearch (Apache-2.0 fork, no license asterisk) | Elasticsearch (SSPL since 2021) | Elasticsearch (SSPL since 2021) | Elasticsearch (SSPL since 2021) |
| Event schema | OCSF-native from the first parser (`docs/adr/002-ocsf-as-the-only-normalized-shape.md`) | Its own field set, ECS-influenced | Elastic Common Schema (ECS) | ECS (via the Elastic components it bundles) |
| Maturity / adoption | Early — pre-launch as of this doc, 15 parsers, 26 rules, no production deployments cited | Mature, large deployed base, active community rule ecosystem | Mature, large enterprise deployed base | Mature, widely used in SOC/training contexts |
| Detection content volume | 26 rules, hand-written, each with an anti-dormancy proof it's reachable by a real parser | Large ruleset (Wazuh's own + Elastic/Sigma-derived), years of community contribution | Large, Elastic's own detection-rules repo + Sigma support | Large — ships Suricata/Zeek/Elastic detection content together |
| AI-agent/MCP telemetry detection | Yes — the only one of these four with dedicated parser + rule pack for AI-agent tool-call activity (`docs/agent-monitoring.md`) | No | No | No |
| Local-first AI triage | Yes, Ollama-based, degrades to a documented stub with zero AI dependency (`docs/adr/006-local-first-llm-triage.md`) | No built-in LLM triage layer | Elastic AI Assistant exists but is a hosted/cloud-oriented feature, not a local-model-first design | No |
| Agent/collector model | Bus-only microservices (Redis Streams), no host agent required for the sources it supports | Lightweight host agent (Wazuh agent) + manager, well-established | Elastic Agent / Beats, well-established | Suricata/Zeek sensors + Elastic stack, well-established |
| Multi-tenancy | Yes — tenant-scoped storage, per-tenant rule enablement, RBAC (see SSOT.md §1's MSP-grade row) | Supported (indexer clustering, per-agent grouping) | Supported (Elastic's space/tenant model) | Not really its design center (typically one org's network) |
| Compliance/reporting templates | An open, zero-AI-dependency incident-report draft generator ships, plus a NIS2/German-market template layer (see SSOT.md §1's M5 row) | Compliance dashboards exist (PCI-DSS, GDPR, etc.) | Elastic Security has compliance-oriented content/integrations | Not a primary focus |
| Deployment footprint | Docker Compose, ~7 services + Redis + OpenSearch; `make chaos` crash-recovery gate is live-verified (see SSOT.md §1's chaos-gate row) | Agent + manager + (Elastic) indexer; well-documented at scale | Elastic stack, scales to very large deployments, more operational surface | ISO/appliance-style install, purpose-built for a SOC |
| Best fit today | Teams that want OCSF-native normalization, no SSPL anywhere, AI-agent telemetry coverage, and are comfortable running something pre-1.0 | Teams that want a mature, widely-deployed agent-based SIEM with a large existing rule ecosystem | Teams already invested in the Elastic stack, or that need its scale/ecosystem and accept the SSPL boundary | SOC/training environments that want a purpose-built, appliance-like distro |

## Why this table exists

Every "open-source SIEM" comparison eventually has to address the
Elasticsearch/SSPL question (`docs/posts/opensearch-not-elastic.md` covers
this in more depth) — Wazuh and Security Onion are both genuinely valuable,
widely-deployed projects that happen to depend on a storage layer that
isn't OSI-approved open source past a certain feature tier. That's a real,
checkable fact about their dependency graph, not a knock on their quality.
FENGARDE's answer is OpenSearch; the trade-off is that FENGARDE hasn't
earned the years of production hardening and community content those
projects have.

## German-native sovereignty players

The comparisons above are all self-hostable SIEM/detection products. FENGARDE's
"sovereignty by construction" positioning (local-first, no data leaves the
network) also runs directly into two German-native players who compete on the
same claim in the same market, and belong in this doc for the same reason
Wazuh/Elastic/Security Onion do — a skeptical reader should be able to check
the honest comparison here rather than find it themselves:

- **[DCSO](https://dcso.de/en/service/managed-detection-response/)** — "Managed
  Detection & Response, made in Germany," data stored exclusively on-site, sold
  explicitly on full digital sovereignty. It's a managed service, not a
  self-hostable open-source SIEM — the overlap is the sovereignty claim, not
  the deployment model.
- **[Enginsight](https://sitsi.pacanalyst.com/enginsight-a-german-cybersecurity-platform-focused-on-the-sme-segment/)**
  — Jena-founded, German-developed, SME-focused, GDPR/BSI/KRITIS-native, with
  explicit "independence from non-European technology stacks" positioning —
  the closest existing competitor to FENGARDE's Mittelstand target segment.

Neither is Apache-2.0/open-source, so FENGARDE's openness + no-SSPL-storage
argument still holds against both. But "sovereignty" alone is not an empty
category either of them has left uncontested — FENGARDE's honest differentiator
in this specific comparison is open-source + self-hostable + free, not being
first or alone on data residency.

## What would change this table

Real production deployments, a larger rule catalog (the roadmap's Sigma
import layer, M7, is aimed at this directly), and the M1 correctness gates
(`make chaos`, published benchmark numbers) actually passing in CI, not
just existing as scripts. This doc gets updated as those land — see
`SSOT.md` §2 for the current proven-vs-claim status of each.
