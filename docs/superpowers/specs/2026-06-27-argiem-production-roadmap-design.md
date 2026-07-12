# ARGIEM SIEM — Production-Readiness Audit & Implementation Roadmap

**Date:** 2026-06-27
**Status:** Design / plan (no implementation code in this round)
**Author:** Brainstorming session (Claude Code)

---

## 1. Locked decisions (scope)

These were confirmed interactively and drive every trade-off below.

| Decision | Choice | Consequence |
|---|---|---|
| Target maturity | **Production-grade** | Real Redis/Kafka, real OpenSearch, real Ollama, security, observability, HA. |
| This round's deliverable | **Audit + plan only** | No implementation code is written now; this document + the plan file are the output. |
| Deployment topology | **3 tiers: edge + local + central** | Adds a packaging/placement/transport track on top of pipeline work. |
| Edge tier capability | **Buffered forwarders** | Edge = collectors with a durable local store-and-forward queue; drains to central on reconnect. No event loss across outages. *(R-1 mitigated.)* |
| Endpoint agents | **Yes — agent-based collection tier (WS-8)** | Agents on real devices for host-level telemetry (processes, FIM, EDR-style); buffer locally. Deep device monitoring. |
| AI-agent observability | **Yes** | Observe the WS-5 triage LLM: prompt/verdict audit, precision tracking, drift, prompt-injection guardrails. |
| Fleet/agent observability | **Yes** | Health of collectors + agents: alive, version, drift, dropped events, buffer depth. |
| Analyst console form | **Web + Tauri desktop shell** | One web frontend; Tauri shell for analyst workstations + the air-gapped box. "Cloud app" = central web deployment. |
| Local tier | **Real air-gapped single-node product** | Full pipeline on one host, runs disconnected (data residency). First-class target, not just dev. |
| Central tier | **Scaled Kubernetes** | Helm, HPA on consumer lag, GPU pool for AI, ILM/retention. |
| Sequencing strategy | **A — Harden-then-lift** | Stabilize on dev stack → externalize state → validate real infra → package for 3 footprints. Risk-first, every step verifiable. |

---

## 2. Current-state audit (evidence-based)

Reviewed the repository on disk and ran the existing test suite with the real interpreter
(`C:\Python313\python.exe`; the Bash PATH only had the Windows Store stub).

### 2.1 What is genuinely done and solid

- **Phase 0 contracts complete & validated.** All five contracts present under `contracts/`.
  `tools/validate_contract.py` passes: 3 valid fixtures accepted, the invalid one correctly
  rejected on both a bad MAC pattern and the `type_uid = class_uid×100 + activity_id`
  invariant. The OCSF pivot schema is real and enforced.
- **Phase 1: all 7 workstreams implemented in isolation, all contract tests green.**
  ~2,500 LOC. Each `services/wsN-*/` carries an `INTERFACE.md`, mocks/stubs, and a
  `test_contract.py` that passes with **zero infrastructure** (memory bus, in-memory store,
  StubLLM, SQLite).
- **Clean coupling layer.** `services/shared/bus.py` abstracts memory ↔ Redis Streams behind
  one `Bus()` API (env `BUS_BACKEND`), and `services/shared/ocsf.py` reuses the single
  source-of-truth validator. This is the architectural keystone and it is well done.
- **An e2e composition tool already exists** (`tools/integration_e2e.py`) and the
  WS-1→2→4→3 pipeline *does* compose on the memory bus.

### 2.2 Gap register (what blocks "ground work done")

Severity: **P0** = blocks local dev / correctness; **P1** = blocks production target; **P2** = completeness.

| ID | Gap | Evidence | Sev | Phase |
|----|-----|----------|-----|-------|
| G-01 | **Windows/Unicode portability** — `integration_e2e.py` crashes on its final `print` (`cp1252` can't encode `→`); stdout assumes UTF-8. Breaks on the dev machine itself. | Ran the tool: `UnicodeEncodeError: '→'`. | P0 | 1.5 |
| G-02 | **Thin parser coverage** — WS-1 emitted 9 raw events; WS-2 normalized only **1**, dropped **8**. No SNMP-trap or NetFlow parser; mocks ↔ parsers misaligned. | e2e: `WS-2 normalized=1 dropped=8`. WS-2 has only AD/Cisco-ASA/SSH/vSphere parsers. | P0 | 1.5 |
| G-03 | **Happy path never produces an alert** — the one event that flows through triggers 0 rules / 0 AI. | e2e: `WS-4 scored=1 alerts=0 ai=0`. | P1 | 1.5 |
| G-04 | **e2e covers only 4 of 7 WS** — WS-5 (AI), WS-6 (inventory enrichment), WS-7 (dashboard contract) absent from integration. | `tools/integration_e2e.py` imports ws1/2/4/3 only. | P1 | 1.5 |
| G-05 | **WS-4 correlation state is in-process** — sliding windows live in `self._windows: defaultdict(deque)` inside each `Rule`. Scaling to N replicas splits the stream and loses state on restart/rebalance. Brief mandates Redis-backed windows w/ TTL. | `services/ws4-detection/engine.py:57`. | P1 | 2 |
| G-06 | **No structured logging / `trace_id`** — services use `print()`. Brief mandates JSON logs + cross-service `trace_id`; k8s log aggregation requires it. | `services/ws2-normalization/main.py:52` = `print(...)`. | P1 | 1.5 |
| G-07 | **No `/health` endpoints** anywhere. Brief mandates them; k8s liveness/readiness probes require them. | Grep for `health` across `services/**.py` → none. | P1 | 1.5 |
| G-08 | **No retry / idempotency / poison-pill (DLQ)** on bus consumers. Brief mandates idempotence + retry + poison queues. | No `retry`/`poison`/`backoff` in service code. | P1 | 2 |
| G-09 | **Real infra never exercised** — only the memory bus has run. Redis Streams, OpenSearch bulk indexing + ILM, and Ollama are untested end-to-end. | compose never brought up; e2e forces `BUS_BACKEND=memory`. | P1 | 2 |
| G-10 | **Security disabled / absent** — OpenSearch `DISABLE_SECURITY_PLUGIN=true`; no TLS for syslog; WS-7 auth is a mock; no secrets management. | `infra/docker-compose.yml`. | P1 | 3 |
| G-11 | **No observability** — no metrics (consumer lag, throughput, queue depth), no dashboards, no pipeline-health alerting. | absent. | P1 | 3 |
| G-12 | **No k8s / Helm / CI** — no `k8s/`, `helm/`, or `.github/`. No multi-arch images, image scanning, or signing. | dir scan. | P1 | 4 |
| G-13 | **No deployment-topology packaging** — no edge image + secure transport, no air-gapped single-node bundle. | new requirement. | P1 | 4 |
| G-14 | **Functional completeness vs brief** — missing parsers (CEF/LEEF, DB-audit, k8s, vSphere depth), rule modules (bank cards/HSM/DDL, DC mass-VM-delete/privileged-container), most WS-7 pages, WS-6 discovery job, real ML classifier. | per-WS read vs brief §WS-1..7. | P2 | 5 |
| G-15 | **No backup/DR or compliance proof** — no snapshot/restore test; PCI 400-day retention + raw_data audit not validated under real storage. | absent. | P2 | 5 |
| G-16 | **No endpoint agent tier** — collection is agentless only; no host-level telemetry, no agent enrollment/heartbeat. | new scope. | P2 | 5 |
| G-17 | **No AI-agent observability / guardrails** — WS-5 LLM verdicts are unaudited and unmeasured; no prompt-injection defense on attacker-controlled log text. | new scope. | P1 | 3 |
| G-18 | **No fleet/agent health observability** — collector/agent liveness, version, drift, buffer depth not tracked. | new scope. | P1 | 3 |
| G-19 | **No desktop console packaging** — WS-7 is web only; no Tauri shell for workstations / air-gapped box. | new scope. | P2 | 4 |

---

## 3. Target architecture (3-tier topology)

The **workstream architecture is unchanged**. Tiering is a *placement + packaging + transport*
concern — not a rewrite — because every service is decoupled through frozen contracts and the
bus abstraction.

### 3.1 What runs where

| Component | Edge (remote site / appliance) | Local (on-prem single node) | Central (cloud / k8s) |
|---|:--:|:--:|:--:|
| WS-1 Collectors | ✅ primary | ✅ | optional |
| WS-8 Endpoint agents | ✅ on devices | ✅ on devices | ✅ on devices |
| Store-and-forward buffer | ✅ durable | n/a | n/a |
| WS-2 Normalization | — | ✅ | ✅ scaled |
| WS-3 Indexer + OpenSearch | — | ✅ single-node | ✅ scaled + ILM |
| WS-4 Detection (Redis state) | — | ✅ | ✅ scaled |
| WS-5 AI (classifier + LLM) | — | small CPU model | ✅ GPU pool |
| WS-6 Inventory | — | ✅ | ✅ |
| WS-7 Dashboard | — | ✅ | ✅ |
| Bus backend | local durable queue → relay | Redis Streams | Kafka |

### 3.2 Cross-tier data flow

```
EDGE site(s) / monitored devices     CENTRAL (k8s)  or  LOCAL (single node, self-contained)
┌──────────────────────┐  mTLS/TLS    ┌───────────────────────────────────────────────┐
│ WS-1 collectors +    │ ─raw.events─▶ │ bus → WS-2 → WS-4 ──▶ WS-3 → OpenSearch        │
│ WS-8 device agents   │  (over WAN)   │              │  └─ai.requests─▶ WS-5 ─▶ alerts │
│  └ durable buffer    │  drain on     │              └─ WS-6 inventory ◀── WS-2 enrich │
│    (store-&-forward) │  reconnect    │ WS-7 console (web + Tauri) ◀ alerts + WS-6 API │
└──────────────────────┘              └───────────────────────────────────────────────┘
```

- **Edge → Central transport** is the one WAN-crossing link: mutual TLS, authenticated,
  compressed. Each edge node has a stable `site_id`, `sector`, and an allocated `source_id`
  range. A **durable local store-and-forward buffer** holds events across WAN outages and drains
  oldest-first on reconnect (idempotent keys → central dedupes replays). *(R-1 mitigated.)*
- **Local** collapses the whole right-hand box onto one host (k3s or compose), with a
  single-node OpenSearch, a small CPU LLM (or StubLLM), and **no external dependency** so it
  runs air-gapped.
- **Central** is the same box scaled horizontally on k8s with Kafka, an OpenSearch
  StatefulSet/operator, and a GPU node pool for Ollama.

### 3.3 Invariants preserved across all tiers

- OCSF is the only internal schema; all heterogeneity absorbed in WS-2 parsers (Contract A).
- The bus is the only coupling (Contract B); backend swaps by env, never by code change.
- Workers are stateless; all state lives in Redis (cache/windows) or OpenSearch (durable).
- `validate_event` runs in CI on every producer's output.

### 3.4 Endpoint agent tier (WS-8) — agent-based collection

A lightweight, signed agent installed on real devices, complementing agentless collection:

- **Telemetry:** host-level signal agentless sources can't provide — process/exec events,
  file-integrity (FIM), logged-on users, listening ports, package/patch state, optional EDR-style
  detections. Normalizes to OCSF (reuses WS-2 classes) and produces `raw.events` like any collector.
- **Resilience:** the agent buffers locally (it *is* a buffered forwarder), so device/WAN outages
  never drop events — the same mechanism that mitigates R-1.
- **Enrollment & identity:** mTLS certificate enrollment; each agent has a stable `device.uid`
  registered in WS-6 inventory; heartbeats feed fleet observability (§3.5).
- **Security posture (R-6):** an agent is a privileged foothold — signed binaries, least privilege,
  pinned server cert, tamper-evident config, controlled auto-update.

### 3.5 Observability of agents (fleet) and of the AI agent (LLM)

- **Fleet observability (G-18):** per-agent/collector liveness, version, config drift, dropped-event
  count, and buffer depth / oldest-unsent age → metrics + a **Sources/Fleet** view in WS-7, with
  alerting when a site goes dark or a buffer fills.
- **AI-agent observability (G-17):** the WS-5 triage LLM is an auditable component, not an oracle —
  immutable prompt+response audit log, verdict **precision tracking** against analyst overrides,
  latency/cost, and drift detection. **Prompt-injection guardrails are mandatory:** log content is
  attacker-controlled input flowing into the model (R-7), so inputs are delimited/escaped, the
  system prompt is hardened, and outputs are schema-validated before they can drive any action.

---

## 4. Phased roadmap (Strategy A — harden-then-lift)

Phase 0 (contracts) and Phase 1 (isolated implementations) are **done**. The work begins at 1.5.
Each phase has an explicit **exit gate** — the objective evidence that its groundwork is done
before the next phase starts.

### Phase 1.5 — Stabilize the dev stack *(close the seams on the memory bus)*
**Goal:** the full 7-WS pipeline composes and produces a real alert, cross-platform, with
production-shaped logging/health primitives in the shared layer.

Tasks:
1. **Portability fix (G-01):** force UTF-8 stdout in shared tooling; remove non-encodable glyph
   assumptions; verify on Windows + Linux.
2. **Structured logging (G-06):** `shared/log.py` — JSON logs with level + `trace_id`; propagate
   `trace_id` across bus messages; replace `print()` in every service.
3. **Health primitive (G-07):** `shared/health.py` — a `/health` endpoint helper every
   long-running worker mounts (readiness = bus reachable; liveness = loop alive).
4. **Parser coverage (G-02):** add SNMP-trap and NetFlow parsers; align WS-1 mocks with WS-2
   parser inputs so drop-rate → ~0 on the mock corpus.
5. **Real alert path (G-03):** ensure the mock corpus contains at least one event that fires a
   rule → emits an alert → enqueues to `ai.requests`.
6. **Full e2e (G-04):** extend `integration_e2e.py` to WS-1→2→4→{3,5,6} and assert the WS-7 data
   contract; assert **≥1 alert** and **≥1 AI verdict** end-to-end.

**Exit gate:** `run_all_tests.sh` + extended e2e are green on Windows *and* Linux; e2e emits
≥1 alert and ≥1 AI result; zero `print()` left in service hot paths.

### Phase 2 — Externalize state & validate real infra *(single shared backplane)*
**Goal:** the pipeline runs on **real Redis + OpenSearch + Ollama**, and WS-4 scales without
losing correlation.

Tasks:
1. **WS-4 state to Redis (G-05):** move sliding windows/counters to Redis (sorted sets + TTL);
   key by partition (`src_endpoint.ip`); make the worker fully stateless; prove correlation
   survives restart and 2+ replicas.
2. **WS-5 real queue + LLM:** Redis-backed `ai.requests`; Ollama worker with timeout + retry;
   real CPU classifier (replace stub) per the funnel thresholds (<20 archive / 20–59 ML / ≥60 LLM).
3. **WS-3 real storage:** validated bulk indexing + partial score-update; provision index
   templates + ILM (incl. PCI 400-day) against a live OpenSearch.
4. **Reliability primitives (G-08):** idempotent consumers, retry/backoff, dead-letter (poison)
   queues on the bus abstraction.
5. **Real-infra e2e (G-09):** bring up `infra/docker-compose.yml`; run the extended e2e against
   real backends, not memory.

**Exit gate:** extended e2e green against real Redis+OpenSearch+Ollama; WS-4 at 2 replicas keeps
correlation correct across a forced restart; poison messages land in a DLQ, never wedge the loop.

### Phase 3 — Production hardening *(security, observability, resilience)*
**Goal:** the central stack is safe, observable, and survives failure.

Tasks:
1. **Security (G-10):** enable OpenSearch security (TLS + RBAC); syslog over TLS; secrets via
   k8s Secrets / sealed-secrets; replace WS-7 mock auth with real auth + RBAC roles (analyst,
   admin, auditor).
2. **Observability (G-11):** Prometheus metrics (consumer lag, throughput, queue depth, LLM
   latency); Grafana/OpenSearch dashboards; log aggregation; alerting on pipeline-health SLOs.
3. **Resilience:** graceful shutdown (drain in-flight, ack, exit); lag-based autoscale signal;
   backpressure when downstream is slow; restart/kill chaos tests.
4. **Kafka backend:** introduce Kafka behind the existing `Bus()` abstraction for the central
   tier; a swap test proves identical behavior vs Redis Streams.
5. **AI-agent observability + guardrails (G-17):** immutable prompt/verdict audit log; verdict
   precision tracking vs analyst overrides; drift detection; prompt-injection guardrails on
   ingested log text (input delimiting, hardened system prompt, schema-validated output).
6. **Fleet observability (G-18):** collector/agent liveness, version, drift, dropped events, and
   buffer depth as metrics; alert on a dark site or a filling buffer.

**Exit gate:** kill-a-worker and restart tests pass with zero data loss; security scan clean;
SLOs (ingest lag, alert latency) defined and dashboarded; LLM verdicts audited with a measured
precision number; the fleet view shows every collector/agent's health.

### Phase 4 — Deployment topology *(edge / local / central packaging)*
**Goal:** one artifact set deploys to all three footprints.

Tasks:
1. **Images & CI/CD (G-12):** multi-arch (amd64+arm64) minimal images; CI = contract tests gate
   → build → scan → sign → push; Helm lint; per-tier artifacts.
2. **Central (k8s):** Helm chart — Deployments, HPA on consumer lag, OpenSearch StatefulSet/
   operator, Ollama GPU node pool, NetworkPolicies, probes, resource limits.
3. **Local (air-gapped, G-13):** k3s or compose bundle — full stack on one host; **offline image
   bundle**; single-node OpenSearch; small CPU LLM; seed/restore; proven to install and run with
   no internet.
4. **Edge (buffered forwarders, G-13):** minimal WS-1/WS-8 image + **durable local store-and-forward
   queue** (rsyslog disk-queue / file spool / local Redis-AOF) + mTLS transport to central bus;
   `site_id`/`sector`/`source_id` config; GitOps fleet config.
5. **Desktop console shell (G-19):** package WS-7 as a Tauri app (signed, auto-update) for analyst
   workstations and the air-gapped local box; same web frontend underneath.

**Exit gate:** each footprint deploys and passes a smoke test; air-gapped install proven with no
network; an edge node ships events to central over mTLS; a forced WAN outage loses zero events
(buffer drains on reconnect); the Tauri shell launches against local + central backends.

### Phase 5 — Functional completeness & end-to-end validation
**Goal:** deliver the brief's full feature set and prove the core promise at scale.

Tasks:
1. **Parsers (G-14):** CEF/LEEF, Oracle/SQL-Server DB-audit (bank), Kubernetes + vSphere (DC).
2. **Rule modules (G-14):** bank (mass-card-access, DDL, HSM ops), DC (serial VM delete,
   privileged container, hypervisor access); stateful correlation rules.
3. **Dashboard (G-14):** triage hi-fi (per wireframe), inventory, detection tuning, sources
   health, PCI compliance + export, infra, free OCSF search; mobile-responsive; keyboard nav.
4. **WS-6 discovery (G-14):** periodic SNMP-ARP / DHCP / ARP ingestion → `assets.updates`.
5. **WS-8 endpoint agent (G-16):** the agent itself — host telemetry (process/exec, FIM, ports,
   users, patch state) → OCSF `raw.events`; mTLS enrollment; `device.uid` registration in WS-6;
   heartbeats into fleet observability. Multi-arch, signed, controlled auto-update.
6. **Scale & compliance (G-15):** load test (millions in → handful of alerts out); PCI 400-day
   retention + `raw_data` audit proven; snapshot/restore + DR runbooks; SOC analyst runbooks.

**Exit gate:** documented load test meets throughput target; compliance + DR runbooks validated;
agents enroll and stream host telemetry end-to-end; the "millions of signals → handful of
decisions" promise demonstrated end-to-end.

---

## 5. Cross-cutting tracks (run alongside all phases)

- **Testing ladder:** contract tests (have) → integration e2e on real infra (Phase 2) → resilience/
  chaos (Phase 3) → deployment smoke per tier (Phase 4) → load/compliance (Phase 5).
- **Shared libraries first:** `shared/log.py`, `shared/health.py`, bus reliability helpers — built
  once in Phase 1.5/2, adopted everywhere. Avoids per-service drift.
- **Docs as you go:** keep each `INTERFACE.md` current; add a deployment guide per tier; SOC runbooks.
- **Security posture:** least privilege, secrets never in images, image signing, network policies,
  **signed agents with mTLS enrollment**, and **LLM prompt-injection guardrails** — introduced in
  Phase 3, enforced in Phase 4 CI.

---

## 6. Risks & accepted trade-offs

| ID | Risk | Disposition |
|----|------|-------------|
| **R-1** | Edge WAN outage could lose events (audit-completeness gap for a bank). | **Mitigated** — edge adopts a **buffered forwarder** (durable local store-and-forward queue); endpoint agents buffer too. A forced-outage test in the Phase 4 exit gate proves zero loss. |
| R-2 | Ollama needs GPU for acceptable latency; CPU is slow. | Central uses a GPU node pool; local/air-gapped uses a small CPU model or StubLLM, accepting reduced AI throughput. |
| R-3 | Stateful WS-4 migration (in-proc → Redis) could change detection results. | Golden-fixture regression tests around correlation rules before/after the move (Phase 2). |
| R-4 | OpenSearch/Kafka operational complexity on a single air-gapped node. | Single-node OpenSearch + Redis Streams (not Kafka) for the local tier; Kafka only central. |
| R-5 | Scope is large; "production-grade × 3 tiers" is months of work. | Phases are independently shippable; each exit gate is a usable milestone. Local single-node can ship before central k8s. |
| R-6 | Endpoint agents are privileged footholds — a compromised agent is a serious foothold. | Signed binaries, least privilege, pinned server cert (mTLS), tamper-evident config, controlled auto-update; agent build scanned + signed in CI (Phase 3–4). |
| R-7 | **Prompt injection via ingested logs** — attacker-controlled log text flows into the triage LLM. | Mandatory guardrails: input delimiting/escaping, hardened system prompt, schema-validated output that cannot drive actions on its own; verdicts audited (Phase 3, G-17). |
| R-8 | Agent fleet update/management burden across many devices/sites. | GitOps + a controlled auto-update channel; fleet observability flags drift/stragglers (G-18). |

---

## 7. Verification philosophy ("ground work done" = evidence, not assertion)

Each phase closes only on its **exit gate**, demonstrated by a command and its output — never by
claim. The progression is deliberately *seams-first*: portability and the full e2e (1.5), then
real infra and statefulness (2), then failure behavior (3), then packaging (4), then scale (5).
This front-loads the riskiest production concerns, matching the stated goal of finishing the
ground work before moving on.

---

## 8. Open questions (to resolve during planning, not blocking)

1. **Central bus:** commit to Kafka in Phase 3, or stay on Redis Streams until scale forces Kafka?
   (Abstraction makes this deferrable.)
2. **CI platform:** GitHub Actions vs GitLab CI vs other? (`.github/` assumed but unconfirmed.)
3. **Local orchestration:** k3s vs plain docker-compose for the air-gapped single-node product?
4. **Inventory store at scale:** keep SQLite for local, Postgres for central — or Postgres everywhere?
5. **AI model:** confirm default (brief says Qwen 2.5 14B Q4) and the CPU fallback model for local.
6. **Agent technology:** build a custom lightweight agent, or wrap osquery / OpenTelemetry Collector?
   (Trade-off: control + footprint vs. maturity + ecosystem.)
7. **Agent PKI/enrollment:** how agent certificates are issued and rotated (own CA vs. SPIFFE/SPIRE)?
8. **Tauri distribution:** per-OS code-signing + auto-update channel, and the air-gapped update path.

---

## 9. Parallel strategic track — ARGIEM-Sec & commercial positioning v2.0

**Status: design only, nothing executed.** Consolidated from three hands-off docs delivered
2026-07-01 (`ARGIEM_hands_off_docs_ARGIEM-Sec_positionnement.md`,
`ARGIEM-Sec_architecture_et_plan.md`, `ARGIEM-Sec_plan_execution_pas_a_pas.md`). This section is a
**parallel commercial track**, distinct from the open-source v0.1/v0.2 line already shipped to
[github.com/supermhel/argiem](https://github.com/supermhel/argiem) — see the flag below before
treating the two as one narrative.

### 9.0 Tension — RESOLVED via `/plan-ceo-review` 2026-07-01: open-core

Mid-project the goal was explicitly changed to **"research and open-source"** (Apache-2.0, public
repo, community parsers/rules). This section described the opposite: a **proprietary** trained
model (ARGIEM-Sec) and a **commercial sovereign-SIEM** positioning. Reviewed with the CEO-review
lens (Premise Challenge + Dream State Mapping): the real question wasn't "open-source OR
commercial" — that's a false binary that risks credibility on both sides (a bank evaluating "the
sovereign SIEM" doesn't want to find "community project" on GitHub; a contributor writing a parser
doesn't want to discover their PR quietly fuels an undisclosed commercial pitch). The direct path
is an explicit **open-core** boundary, confirmed by the user 2026-07-01. See §9.7 for the full
resolution — do not read §9.1–9.6 below as still-unreconciled; they now operate inside that
boundary.

### 9.1 Positioning v2.0 (commercial/strategic)

- **Pitch (unchanged core):** "From millions of signals to a handful of decisions. Without ever
  leaving your walls." **New international variant:** "The sovereign SOC that speaks your
  language and knows your regulator."
- **5 differentiation pillars** (4 existing + 1 new):
  1. Sovereignty by construction (local-first, no data leaves the walls)
  2. Compliance as a pipeline *output* — now backed by a proprietary model, not just intent
  3. Dual sector specialization (banking + data center)
  4. Structural economics (local LLM vs. per-seat/per-GB SaaS pricing)
  5. **[NEW] Proprietary multilingual, multi-regulatory model** — assessed as the most durable
     moat identified so far
- **Segmentation:** Germany first → Austria/Switzerland (Wave 2) → English-speaking EU (Wave 3) →
  GCC/Gulf (international horizon). Each new market = a regulatory *module*, not a new product.
- **Competitive read:** no incumbent (Datadog, Splunk, Wazuh, LogPoint, Aleph Alpha) currently
  occupies "native AI triage + sovereignty + multi-regulatory" simultaneously.
- **Locked decisions (don't reopen without cause):** positioning is "Germany-first, international
  by design" (not Germany-only); ARGIEM-Sec is now an official differentiation pillar, not a
  research note; the regulatory mapping pillar must **never** be marketed before it is legally
  validated.

### 9.2 ARGIEM-Sec architecture (the proprietary model)

**State: a design specification. Not trained. No corpus assembled at scale. No run started.**
Never present it otherwise externally.

Four stacked layers, each trained once and composed at inference — the same sector-gating
principle already used in ARGIEM's detection rules, applied to language/regulation instead:

| Layer | Purpose | Candidate / method |
|---|---|---|
| 0 — Base | Multilingual European foundation | Teuken-7B / OpenGPT-X (Apache-2.0, 24 EU languages) — candidate, not final |
| 1 — Universal security | Domain grounding, language-independent | Continued pretraining (CPT) on Sigma, OCSF, MITRE ATT&CK, CVE/NVD |
| 2 — Regulatory modules | Per-market compliance | LoRA adapters, hot-swappable at inference — DE first, then EN, then AR |
| 3 — Behavior/output | Analyst-facing format | SFT: summary + verdict + actions, in the analyst's language |

Principle: retrain the core (layers 0+1) once; every new market is a new adapter (layer 2), never
a full retrain.

**Locked decisions:** base model is not German-only (corrected from v1 — the need is
European/international); CPT for knowledge (layers 1–2), SFT for behavior (layer 3) — do not
conflate the two objectives; a security evaluation gate (CyberSecEval / Purple Llama) is
**blocking** before any deployment, non-negotiable; DeepSeek and other PRC-origin models are
excluded from the entire ARGIEM-Sec stack (documented security degradation).

**Open questions (§9 of the architecture doc):** final base (Teuken-7B vs. Foundation-Sec-8B, to
be benchmarked); CPT vs. RAG for regulatory content (likely both, ratio TBD); build vs. outsource
the CPT phase; sequencing against the rest of ARGIEM; a dedicated WS-8 vs. extending WS-5.

### 9.3 Execution plan — 5 waves

The real bottleneck is **GPU access** and an **experienced ML/NLP profile**, not code or method —
so Wave 0 and Wave 1 run in parallel now, and nothing waits on a resource it doesn't yet need.

| Wave | Who | Can start | Blocks on |
|---|---|---|---|
| 0 — Prep (data, code, corpus) | Claude, now | Immediately | Nothing |
| 1 — Structuring decisions | Human | Immediately | Nothing |
| 2 — Real execution (CPT/LoRA/eval) | Human + GPU | Waves 0 & 1 done | GPU access, ML profile |
| 3 — Integration into ARGIEM (WS-5/Contract D) | Both | Wave 2 done (model passed eval) | Blocking evaluation |
| 4 — International extension (EN, AR...) | Both | Wave 3 stable in production | Per-market design partner |

**Wave 0 (Claude, no GPU/decision needed) — 6 actions, ~1 session each unless noted:**

| # | Action | Deliverable |
|---|---|---|
| 0.1 | Synthetic SFT data from Phase 0 OCSF fixtures (alert → summary + verdict + actions) | `corpus/sft-synthetic-v0/` |
| 0.2 | Structure German regulatory text (DORA, NIS2, BSI, BaFin) from open sources | `corpus/regulatory-de-v0/` (1–2 sessions) |
| 0.3 | Training scripts (CPT + LoRA/QLoRA), `transformers`/`peft`/`trl`-based, parameterized | `scripts/cpt_train.py`, `scripts/lora_finetune.py` |
| 0.4 | Evaluation harness: CyberSecEval integration, an OCSF-fixture benchmark, domain-vs-general perplexity | `eval/run_cybersecval.py`, `eval/benchmark_ocsf.py` |
| 0.5 | Technical model card (capabilities, limits, training data, eval axes) | `ARGIEM-Sec_model_card_v0.md` |
| 0.6 | Regulatory mapping test set (alert → expected DORA/NIS2 article), draft only — needs legal sign-off before real use | `eval/regulatory_mapping_testset_de.jsonl` |
| 0.7 *(gap noted in the source plan, not yet scheduled)* | Universal security corpus: SigmaHQ, MITRE ATT&CK, CVE/NVD — required by Wave 2 action 2.2 but missing from the original Wave 0 list | `corpus/security-universal-v0/` |

Claude explicitly **cannot**, in this wave: actually download a base model or run training (no
GPU/network access in the execution environment). Wave 0's output is code and data ready to use,
not a trained model.

**Wave 1 — 5 human decisions (parallel, no prerequisite):**

| # | Decision | Options | Plan's recommendation |
|---|---|---|---|
| 1.1 | ML/NLP profile: hire, contract, or partner? | Internal hire / specialized freelance / lab partnership (Fraunhofer, DFKI) | The real critical dependency — decide on budget/timeline |
| 1.2 | GPU budget: buy or rent? | Own hardware (RTX 5090/PRO 6000, ~€2–9k) vs. hourly cloud GPU | Rent for the one-off CPT/SFT phase; buy only if usage becomes regular |
| 1.3 | Sequencing vs. the rest of ARGIEM | Parallel to the 7-workstream build, or after the core product proves value | Open — resource trade-off |
| 1.4 | Org structure | New dedicated WS-8, or extend WS-5 | Open |
| 1.5 | Fallback if ARGIEM-Sec slips | Foundation-Sec-8B (Cisco) as an interim | Recommended as a safety net |

**Waves 2–4 (summary):** Wave 2 benchmarks candidate bases, runs the security-layer CPT, the
behavior SFT, the DE regulatory adapter, and the blocking evaluation (2–4 weeks each, needs
Wave 0's corpus + Wave 1's resourcing decision). Wave 3 serves the model via Ollama/vLLM inside
WS-5, adds a jurisdiction/market field to alert context to route the right regulatory adapter, and
starts collecting anonymized analyst feedback for the first real-data retrain. Wave 4 (not urgent)
adds EN/AR/other-EU adapters, gated on a design partner per market.

**Critical dependencies:** nothing blocks starting Wave 0 today. Wave 2 cannot be planned
seriously without Decision 1.1 (who runs CPT/SFT). **Action 2.4 (the regulatory adapter) must not
reach production without legal validation** of test set 0.6 — regulatory hallucination in an audit
context is a named risk. Wave 4 must not start before Wave 3 is stable in production.

### 9.4 What an AI assistant can and cannot do on this track

Stated explicitly so no future session overestimates it:

- **Can:** write training code (CPT, LoRA/QLoRA), generate synthetic SFT data by distillation,
  structure regulatory corpora, write evaluation harnesses, document (model cards, plans).
- **Cannot:** actually run training (no GPU/network access in this execution environment); replace
  the iterative judgment of an experienced ML profile; legally validate a regulatory mapping;
  supply real triage data (only a design partner can); sustain operational continuity across
  weeks of training runs.

### 9.5 New risks this track adds to §6

| ID | Risk | Disposition |
|----|------|-------------|
| R-9 | ARGIEM-Sec build stalls or slips, undercutting Pillar 5 of the positioning | Foundation-Sec-8B named as an explicit fallback (Decision 1.5); positioning must not promise Pillar 5 ahead of what the architecture/execution plan can actually support |
| R-10 | Aleph Alpha (or another sovereign-EU-LLM player) competes directly on German soil | Monitor; differentiate on the security-specific CPT + regulatory adapters, not the base model alone |
| R-11 | Regulatory hallucination in an audit context | Test set 0.6 requires legal/compliance sign-off before any production use; never marketed before validated (locked decision, §9.1) |

### 9.6 Immediate next action (if this track is picked up)

Two non-exclusive options: **(a)** start Wave 0 now — actions 0.1 (synthetic SFT data) and 0.7
(universal security corpus) need no prior decision and can run in the same Claude session; **(b)**
rule on Wave 1's five decisions first, especially 1.1 (who executes) and 1.3 (sequencing against
the open-source v0.1/v0.2 line that has already shipped).

### 9.7 Merged strategy — open-core, confirmed 2026-07-01

**The line, drawn explicitly:**

| Layer | License | What it is |
|---|---|---|
| **Free forever** | Apache-2.0, public, as-shipped | The 7-workstream pipeline (WS-1..7), OCSF normalization, the bus abstraction, **all parsers and detection rules** (community-contributed, unlimited, no cap), the dashboard, and WS-5 with `StubLLM`/self-hosted-`Ollama` triage — exactly what's live today at [github.com/supermhel/argiem](https://github.com/supermhel/argiem) at v0.2.0. Nothing here changes. No relicensing, no feature walk-back, no bait-and-switch risk for existing contributors or users. |
| **Proprietary, paid** | Closed, separate repo | **ARGIEM-Sec** (the trained multilingual security model — layers 0-3 from §9.2) and the **regulatory compliance layer** (the DE/EN/AR LoRA adapters, the legally-validated regulatory mapping test sets, Pillar 2's "compliance as pipeline output" promise). This is Pillar 5 of the positioning doc, sold as an add-on or hosted product. |

**Why this line and not another:** the free tier's value (parser/rule coverage) grows *from
community contribution* — the flywheel that makes open-source worth doing at all. The paid tier's
value (a trained model + legally-defensible compliance mapping) requires capital, GPU time, and
legal sign-off that a community PR cannot supply — that's the actual scarce, defensible thing, not
the pipeline plumbing around it. Gating the pipeline itself would kill the flywheel for no
moat benefit; keeping the model open would give away the one thing competitors can't fork.

**No architecture change required.** The seam already exists:
`services/ws5-ai/llm_adapter.py::make_llm()` today chooses `StubLLM` vs `OllamaLLM` off
`OLLAMA_URL`. ARGIEM-Sec becomes a third branch in that same function (e.g. `ARGIEM_SEC_URL` or a
served-model endpoint) — the open-source WS-5 code calls out to it exactly like it calls Ollama
today. The proprietary weights/adapters never need to enter the public repo; only the *client*
code (which model to call) does, and that's already open.

**Concrete recommendation for Wave 0 execution:** do ARGIEM-Sec work (corpus, training scripts,
eval harness, model card, regulatory test sets) in a **separate private repository from day one**,
not a branch or subdirectory of `supermhel/argiem`. Reasons: (1) the regulatory corpus and
eval/compliance test sets are exactly the proprietary asset being protected — one accidental
public commit undoes the whole boundary; (2) it keeps the OSS repo's contributor experience clean
— nobody cloning `argiem` for a parser PR needs to see commercial-track scaffolding; (3) it makes
the license boundary a filesystem boundary, not a discipline problem.

**Sequencing vs. the shipped OSS line (resolves Wave 1 decision 1.3):** no conflict — they're
different repos, different work. Wave 0's 6 actions (§9.2) need zero GPU/decision and can start
immediately in the new private repo without touching or pausing the public repo's v0.2/v0.3 work.

**Positioning consistency check:** the locked decision in §9.1 — "the regulatory mapping pillar
must never be marketed before it is legally validated" — now has teeth: it literally cannot ship
because it lives in the closed repo, gated on Wave 2 action 2.5's blocking evaluation and legal
sign-off on test set 0.6. The open-core split enforces that discipline structurally, not just by
promise.

---

## 10. Next step

On approval of this design, invoke the **writing-plans** skill to convert Phases 1.5–5 into an
executable, checkbox-level plan file (one section per phase, tasks with verification commands and
exit-gate checks). No implementation code is written until that plan is reviewed and approved.

Separately, §9 (ARGIEM-Sec + commercial positioning): the open-core reconciliation is decided
(§9.7). Still open before Wave 0 execution starts: create the private ARGIEM-Sec repo, then decide
whether to invoke **writing-plans** for a Wave-0 execution plan (actions 0.1–0.7, §9.2) in that
new repo. It is not part of the Phases 1.5–5 checklist above and should not be silently folded
into it — different repo, different plan file, same product.
