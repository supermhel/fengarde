# FENGARDE

[![CI](https://github.com/supermhel/fengarde/actions/workflows/ci.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/ci.yml)
[![CodeQL](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/supermhel/fengarde/badge)](https://securityscorecards.dev/viewer/?uri=github.com/supermhel/fengarde)

> Badges reflect the latest real run on `main`, not a promise. Scorecard's
> remaining findings are accepted, documented trade-offs, not gaps — see
> [SSOT.md](SSOT.md) §1.

**FENGARDE connects security telemetry across IT, AI and OT to show what
happened, who or what acted, what was affected, how the events relate, and
what evidence supports the conclusion.**

Built for the European industrial Mittelstand — open-source, self-hosted,
Apache-2.0, with a draft NIS2 incident-notification path, a deterministic
German/English report generator, opt-in RBAC/MFA/audit-log/multi-tenancy for
MSP-style deployments, an opt-in HA profile (live-kill-tested, not just
wired), and AI triage that never leaves your network.

FENGARDE ingests logs from multiple sources, normalizes them to a single schema
([OCSF](https://schema.ocsf.io/)), runs correlation rules over a sliding window,
and surfaces alerts in a dashboard. Storage is OpenSearch. Every service is
independent and talks to the rest of the system only through a message bus, so
you can scale or replace any piece without rewriting the others.

Three things make it different from a generic self-hosted SIEM:

- **OCSF-native, not retrofitted.** Every source normalizes to the same open
  schema from day one, so one rule covers every source that emits the event —
  an SSH login, a Windows login and an Active Directory login are one
  brute-force detection, not three. Instrument once, stay portable, no vendor
  log-format lock-in.
- **OT and IT in one pipeline.** OPC UA and Modbus/TCP normalize into the same
  OCSF schema as Active Directory, Windows and your firewall, so the plant floor
  runs through the same detection engine, dashboard and report path as the
  office network — not a second toolchain.
- **AI triage that never leaves your network.** Local Ollama by default, with a
  documented stub fallback — your alert data is never piped through a
  third-party LLM API.

> **OpenSearch, not Elastic:** no license asterisk on the storage engine
> ([ADR 003](docs/adr/003-opensearch-not-elasticsearch.md)) — worth knowing,
> but not a differentiator against Wazuh (its indexer is an OpenSearch fork
> too). Only relevant against Elastic-based stacks.

---

## Quickstart

```sh
git clone https://github.com/supermhel/fengarde.git && cd fengarde
make preflight   # doctor: checks vm.max_map_count, Docker RAM, free ports
make demo        # docker compose up -- a real SSH brute-force alert appears
                 # in the dashboard within ~30-60s, no manual step
# open http://localhost:8080
```

No Docker on hand? The whole detection pipeline runs zero-infra:

```sh
make e2e         # SSH brute-force -> real alert -> idempotent replay, no Docker/Redis/OpenSearch
bash tools/demo.sh   # same test, narrated (Windows: powershell -File tools\demo.ps1)
```

**What you're seeing:** 10 failed logins from one IP within 60 seconds (SSH
`Failed password` or Windows `EventID 4625` — both normalize to the same OCSF
Authentication event) trip
[`common_bruteforce.yml`](contracts/rules/common_bruteforce.yml)
(`threshold: 10`, `window_seconds: 60`, grouped by source IP), and the alert
lands in the dashboard's alert list, idempotent under redelivery.

**Prerequisites:** Docker Desktop or Docker Engine + Compose v2, ≥4 GB RAM
allocated to Docker; Linux, macOS, or Windows via WSL2 (Linux containers,
POSIX `sh` scripts). Python 3 only if you're contributing a parser — no
Docker needed for that (see [Contributing](#contributing)).

<details>
<summary>Linux/WSL2: OpenSearch needs <code>vm.max_map_count</code> raised first</summary>

```sh
sudo sysctl -w vm.max_map_count=262144
# persist across reboots:
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-fengarde.conf
```

Without it, OpenSearch fails with a JVM crash, not a helpful error. Not
needed on macOS Docker Desktop (handled inside its VM). `make preflight`
checks this for you and prints the exact fix if anything's missing.

</details>

Other targets:

```sh
make test     # full zero-infra contract test suite, no Docker needed
make up       # start the stack detached
make down     # stop the stack, remove volumes
make ha-up    # opt-in: Redis Sentinel + 3-node OpenSearch HA (needs REDIS_PASSWORD)
make ha-down  # stop the HA profile, remove its volumes
```

| Port | Service | What it is |
|------|---------|------------|
| 6379 | `redis` (`siem-bus`) | Message bus between services |
| 9200 | `opensearch` (`siem-store`) | Event/alert storage + query API |
| 5601 | `dashboards` (`siem-dashboards`) | OpenSearch Dashboards |
| 8000 | `ws6-inventory` | Inventory API (IP/MAC history) |
| 8080 | `ws7-dashboard` | FENGARDE alert console |
| 5514/udp | `ws1-collectors` | Live syslog ingestion (unauthenticated — trusted segment only) |
| 8013 | `ws3-indexer` | Triage API — internal only, not published to the host |
| 9090 | `prometheus` | Metrics — opt-in, `observability` compose profile |
| 3000 | `grafana` | Dashboards over Prometheus — opt-in, same profile; default `admin`/`admin`, see `SECURITY.md` §1 |

`make preflight` checks the published ports are free before you start.

---

## What's real

Working end-to-end pipeline. This table is a snapshot of `main` (last tagged
release: `v0.10.0`) — for the itemized history see [CHANGELOG.md](CHANGELOG.md),
for the continuously-updated authoritative status see [SSOT.md](SSOT.md); this
table is a summary, that file is the source of truth. Product tour with real
screenshots: [supermhel.github.io/fengarde](https://supermhel.github.io/fengarde/).

**Phase 5 (analyst read path) is code-complete on
[PR #92](https://github.com/supermhel/fengarde/pull/92), not yet merged** —
rows marked **(PR #92)** describe that branch, not `main`.

| Capability | Status | Notes |
|---|---|---|
| **Detection pipeline** (collect → normalize → detect → index → dashboard) | ✅ Works | End-to-end since v0.1 |
| **Parsers (17)** | ✅ Works | Cisco ASA, Active Directory, VMware vSphere, Linux SSH, generic syslog, Windows Event Log, DB audit, MCP/AI-agent tool-call audit, OPC UA/OT audit, n8n automation-platform audit, DNS query log, Kubernetes audit, CEF, AWS CloudTrail, Sysmon, Modbus/TCP protocol-anomaly detector, inventory-diff OT device detector — all → OCSF |
| **Detection rules (29)** | ✅ Works | Brute-force (per-IP and sourceless), port-scan, lateral-movement, password-spray, privileged-group grant, after-hours admin, impossible-travel, bank DB priv-esc, DC mass-VM-delete, agent credential-file access / tool-call burst / prompt-injection / destructive-command / egress-non-allowlisted, OT write-outside-maintenance / new-engineering-connection / config-change / Modbus unauthorized-write (+ ticketed downgrade) / new device on segment, n8n new-webhook-exposed / after-hours workflow-modified, DNS exfil, privileged-container-create, cloud root console login, mass DB-object read, rapid account create/delete, beaconing |
| **Rule grammar** | ✅ Works | Boolean logic, comparison operators, allowlist suppression (CIDR + exact), time-of-day — fail closed on malformed input |
| **Rule prefilter** | ✅ Works | Rules bucketed by `class_uid`; events only evaluated against candidate rules |
| **Anti-dormancy + rule-boundary guardrails** | ✅ Works | CI proves every rule is satisfiable by a real parser's output, and that declared thresholds/predicates are actually enforced (12/12 stateful, 16/16 stateless) — engine-vs-declaration agreement, not a claim that thresholds are well-chosen. See `SSOT.md` |
| **AI triage** (local Ollama) | ✅ Works, opt-in | Via `OLLAMA_URL` (default `qwen2.5`); unset or unreachable degrades to a deterministic offline stub — zero infra, zero network calls. Per-rule `llm_gate: false` opt-out. Verdict and which engine actually ran (Ollama vs. stub) shown in the dashboard's "Why" panel |
| **Triage workflow** | ✅ Works | Status + analyst note per alert, editable in the dashboard; concurrent writes protected (lock + OpenSearch optimistic concurrency) |
| **Incident-report draft hook** | ✅ Works | `POST /alerts/{id}/report` — generic markdown report, always `status: draft` with a disclaimer; regulated-content backend is a paid, optional add-on |
| **NIS2 (DE) report template** | ✅ Works | Deterministic German/English NIS2 Art. 23 / §32 BSIG draft (`?template=nis2`); 3 stages × 2 languages, picker in the dashboard; every entity-specific fact is an explicit `[ANALYST MUST PROVIDE]` placeholder, never fabricated |
| **Opt-in auth** | ✅ Works | Shared-secret `FENGARDE_API_KEY`, dashboard basic-auth, Redis `AUTH` — unset stays fully open |
| **RBAC** | ✅ Works, opt-in | Per-user accounts/roles/tenant scoping, session cookies, CSRF protection, login UI; unset = pre-RBAC API-key-only behavior |
| **MFA/TOTP** | ✅ Works, opt-in | Per-user, stdlib RFC 6238; provision→confirm activation, login gates once active, re-entering your password required for config changes. Enrollment UI in the dashboard's Security panel |
| **Admin audit log** | ✅ Works, opt-in | Append-only, capacity-capped, fail-open; `GET /audit` and a dashboard Audit tab |
| **Redis-backed sessions** (multi-replica RBAC) | ✅ Works, opt-in | Every session row HMAC-signed; `FENGARDE_SESSION_SECRET` required to start |
| **Multi-tenancy** | ✅ Works | `tenant_id` threaded end-to-end; per-tenant indices + rule enablement + fair consume ordering (one flooding tenant can't starve another); reflected throughout the dashboard |
| **Versioned REST API** | ✅ Works | OpenAPI 3.1 spec (`contracts/triage-api.yaml`), bare or `/api/v1/...`; spec-vs-code drift CI-tested |
| **Outbound alert webhooks** | ✅ Works, opt-in | HMAC-SHA256-signed deliveries; see `docs/webhooks.md` |
| **Parser/rule plugin interface** | ✅ Works | External pip package can ship a parser or rule pack via entry points, no fork needed; see `docs/plugin-development.md` |
| **Cross-alert correlation** (WS-8) | ✅ Works | A second consumer tracks actor/IP/device activity over a rolling window and promotes an incident once ≥2 distinct MITRE tactics appear — catches a low-and-slow attacker no single rule's own threshold would catch. Deterministic `incident_id`; bounded, swept memory |
| **Chaos-tested delivery** | ✅ Works | `make chaos`: 40 scenarios, every pipeline service SIGKILLed mid-replay — zero lost, zero duplicate alerts. Consumer-failure durability; Redis-primary failover is a separate proven scenario, see `SSOT.md` |
| **HA profile** (Redis Sentinel + 3-node OpenSearch) | ✅ Works, opt-in | `make ha-up`. Both sides live-kill-tested: Sentinel failover (~1s promotion, zero lost messages), OpenSearch write round-robin to a surviving node |
| **Dashboard** | ✅ Works | Alert feed with MITRE tags + severity, raw event browser, time-range picker, saved searches, dark mode, per-alert playbooks, Ops/Audit/API-keys panels, inventory with live asset drill-in |
| **Product tour** | ✅ Works, live | Real screenshots off a live stack — [supermhel.github.io/fengarde](https://supermhel.github.io/fengarde/) |
| **Entity resolution** (WS-9) | ✅ Works | Deterministic entity ids off `entity.updates`; bounded, idempotent under redelivery |
| **Causal incident graph** (`incident.graph`) | ✅ Works | WS-8 emits a typed causal DAG per incident (`caused_by`/`invoked`/`authenticated_as`/`wrote_to`/`changed`), each edge grounded in one alert's own evidence, never a transitive inference |
| **Evidence package** (WS-3) | ✅ Works | Immutable Merkle hash-chain over an incident's alerts/events/graph, tamper-evident verification, deterministic `package_id` |
| **Bounded AI-triage concurrency** (WS-5) | ✅ Works | Thread pool + admission semaphore; per-event-id dedup under concurrent redelivery |
| **OT business context** (`contracts/ot-points/`) | ✅ Works, opt-in | Additive per-device plant/line/owner/safety fields — schema-only, config not inference |
| **AI-to-OT digital twin** (`eval/twin/`) | ✅ Works | Deterministic offline validation harness (PLC sim, attack scenario, oracle, negative controls, telemetry degradation) measuring operational outcome metrics — every number harness-measured, honest `null` where nothing exists to measure (e.g. MTTR) |
| **Adversarial mutation validation** (`eval/adversarial/`) | ✅ Works | Three layers: deterministic + blocking mutation matrix (8 axes, must keep detection **and** chain fidelity **and** false-correlation rate to pass), a curated corpus, and a nightly LLM-composed adversary that's advisory-only and never blocks CI |
| **Entity / incident-graph / evidence read routes** (WS-3) | ✅ Works (PR #92) | `GET /entities/{id}`, `GET /incidents/{id}/graph`, `GET /incidents/{id}/evidence` — evidence route verifies the hash chain before ever serving it (409 on failure, never a silent unverified 200) |
| **Dashboard: incident causal graph + evidence panel** | ✅ Works (PR #92) | Incident detail renders the causal DAG as an SVG plus a build-on-click evidence panel, alongside the member-alert list |
| **Dashboard: live asset drill-in** | ✅ Works (PR #92) | Inventory now reads the live single-device record, not just the list snapshot |
| **OT-criticality exposure scoring** | ✅ Works (PR #92) | `contracts/ot-points/*.yml` criticality now adds real points to an OT alert's score |
| **Incident-level NIS2 draft** | ✅ Works (PR #92) | `POST /incidents/{id}/report` — a separate seam from the alert-scoped report, causal-ordered narrative |
| **`eval/trend.jsonl` viewer** | ✅ Works (PR #92) | Static HTML render of the real nightly detection-quality + twin scorecard history |
| SNMP / NetFlow / custom-JSON / proxy parsers | 🚧 Planned | Deferred — [good first issue](CONTRIBUTING.md) |
| S7/PROFINET parser | 🚧 Deferred | Needed vocabulary sits behind a Siemens support login this project doesn't have access to |

> **No AI required.** The pipeline produces real alerts with zero infra and no LLM;
> Ollama triage is an optional layer that degrades gracefully to a stub.

---

## Architecture

```
WS-1 Collectors ─raw.events─▶ WS-2 Normalization ─normalized.events─┬─▶ WS-3 Indexer ─▶ OpenSearch
   (Cisco ASA / AD /          (parsers → OCSF)                      └─▶ WS-4 Detection ─scored.events─▶ WS-3
    VMware / Linux SSH)                                                  │  alerts ─▶ WS-3, WS-8, WS-9
   ─assets.updates─▶ WS-6 Inventory (IP/MAC) ─raw.events─▶ (new device -> WS-2, feedback loop)
                                                                          └─ai.requests─▶ WS-5 AI (real local
                                                                                Ollama triage, stub fallback)
                                                                                ─ai.results/alerts─▶ WS-3
WS-8 Correlation ◀─alerts (2nd consumer group)── multi-tactic entity tracks ─incidents─▶ WS-3
                    └─ incident.graph (typed causal DAG, v2) ─▶ WS-3 (persists + serves; dashboard renders it)
WS-9 Resolver ◀─alerts (3rd consumer group, entity extraction)── entity.updates ─▶ WS-3 (persists + serves `GET /entities/{id}`)
WS-7 Dashboard ◀── HTTP only (nginx → WS-3's triage/report/rules/incidents/entities/evidence API + WS-6's inventory API), never the bus
```

The **only** coupling between backend services is the message bus — no
service calls another's code or API directly. Everything else is a frozen
contract under [`contracts/`](contracts/). All source-format heterogeneity is
absorbed at the edge (one parser per source in WS-2); the interior of the
system handles a single schema (OCSF). WS-7 is the one exception by
necessity: a browser UI, so it reaches WS-3/WS-6 over HTTP via nginx — it
never touches the bus, and no backend service depends on it.

| WS | Service | Role |
|----|---------|------|
| 1 | `services/ws1-collectors` | Collect logs → `raw.events` |
| 2 | `services/ws2-normalization` | Parsers → validated OCSF events (17 parsers) |
| 3 | `services/ws3-indexer` | Routing + OpenSearch indexing; entity/incident-graph/evidence read routes (PR #92) |
| 4 | `services/ws4-detection` | Correlation rules + scoring + windowing (29 rules) |
| 5 | `services/ws5-ai` | Triage — real local-LLM (Ollama), stub fallback, bounded concurrency |
| 6 | `services/ws6-inventory` | IP/MAC inventory API (SQLite) |
| 7 | `services/ws7-dashboard` | Alert console |
| 8 | `services/ws8-correlation` | Cross-alert correlation + causal incident graph |
| 9 | `services/ws9-resolver` | Deterministic entity resolution (`entity.updates`) |

For current status and the forward roadmap, see **[SSOT.md](SSOT.md)** (read that first).
For historical design context: [`docs/PHASE0_README.md`](docs/PHASE0_README.md).

---

## Performance

```sh
python tools/fengarde_bench.py --events 20000 --mixed
```

One-command, reproducible by anyone with a clone — no Docker required.

| Metric | Value |
|---|---|
| Sustained EPS (5,000 events, `linux_ssh` only) | ~985 events/sec |
| Sustained EPS (20,000 events, mixed sources) | ~2,500-2,650 events/sec |
| Peak resident memory (20,000-event run) | ~114 MB |
| Rule prefilter vs. forced linear scan (29 rules, 20,000 events) | 1.12x faster |

This is a **zero-infra CPU-bound baseline** (one process, in-memory bus) — it
measures how fast the Python code processes a batch, excluding real Redis
network I/O and OpenSearch indexing latency. Not a "handles N events/sec in
production" claim on its own — see the live-stack numbers below for that.

```sh
python tools/fengarde_bench_live.py   # needs `make up` / Docker running
```

| Metric | Value |
|---|---|
| Live sustained EPS (5,000 mixed events, real Redis + real OpenSearch) | ~43.9 events/sec |
| Ingest→alert latency, p50 / p99 (10 brute-force bursts) | ~2,045 ms / ~2,063 ms |

An order of magnitude below the zero-infra number, as expected once real
network I/O and indexing latency (including OpenSearch's 1s default
`refresh_interval`) are in the loop — this is the "closer to production"
number, the batch number above is the CPU-bound ceiling. Neither ran on a
fixed reference box; both ran on whatever machine invoked them.

---

## Evaluation & detection quality

"A rule passes CI" and "a rule actually fires on real attack traffic" are
different claims — this repo keeps them separate across three eval lanes
under `eval/`:

| Command | What it proves | Needs |
|---|---|---|
| `make attack-scorecard` | Declared MITRE ATT&CK/ATT&CK-ICS/ATLAS coverage, an empirical check that every tagged rule fires on its own real producer fixture, and a boundary check that stateful rules stay silent under-threshold/past-window — three distinct claims | Zero infra |
| `make eval-detection` | Independent-oracle replay: real Windows Security/Sysmon attack corpora (EVTX-ATTACK-SAMPLES, splunk/attack_data) through the live pipeline, checked against a ground truth computed separately from the engine's own logic. See [`eval/detection_accuracy/README.md`](eval/detection_accuracy/README.md) for licensing/setup (both corpora are third-party, not vendored) | Real datasets fetched separately |
| `make nis2-demo` | A real alert becomes a structurally-compliant NIS2 draft, across 12 synthetic scenarios × 3 stages × 2 languages | Zero infra |
| `python tools/detection_quality_eval.py` | Precision/recall/F1 regression trip-wire against a small hand-labeled corpus, including adversarial labels that keep it honest — engine-vs-labels agreement, not a real-world quality bar | Zero infra |

`attack-scorecard`, the report-generator eval, and the detection-quality
canary all run in `run_all_tests.sh`; `eval-detection` is dataset-gated so
it's excluded from the zero-infra gate, but it's the harness that has
actually caught real false negatives in shipped rules.

---

## Contributing

The fastest way to contribute is to **add a parser** — no Docker or OpenSearch needed:

```sh
cd services/ws2-normalization && python test_contract.py
```

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the contribution workflow and
**[docs/adding-a-parser.md](docs/adding-a-parser.md)** for a step-by-step walkthrough
(copy `linux_ssh.py`, make three small edits, verify). The parsers marked
🚧 Planned above are the obvious first PRs — or propose a new detection rule via the
[rule request template](.github/ISSUE_TEMPLATE/rule_request.md).

Monitoring AI agents/MCP servers? See **[docs/agent-monitoring.md](docs/agent-monitoring.md)**.

Running FENGARDE for multiple customers as an MSSP? See
**[docs/mssp-quickstart.md](docs/mssp-quickstart.md)** — and the
**[partner registration](https://github.com/supermhel/fengarde/issues/new?template=mssp_partner_registration.md)**
if you'd like to be listed.

---

## Security

FENGARDE services are designed for a **localhost / Docker-Compose network only**
and are **not** hardened for internet exposure. Authentication is **opt-in**
(`FENGARDE_API_KEY`, dashboard basic-auth, Redis `AUTH` — all off by default).
A real identity/RBAC layer (`FENGARDE_RBAC_DB`) exists, also opt-in and off
by default (single-process session store, not yet HA — see `SSOT.md` §2). The
detection engine executes rule files — only run rules you trust. Need to
reach the dashboard from outside the host? See
**[docs/deployment.md](docs/deployment.md)** for a reverse-proxy TLS example.
See **[SECURITY.md](SECURITY.md)** for the full threat boundary and how to
report a vulnerability.

---

## Open core — what's free, what's paid

**This repository is free and open source forever, under Apache-2.0.**
Everything in it — the pipeline, every parser, every detection rule, the
dashboard, the triage API, the generic and NIS2 report templates — is the
complete product, not a crippled trial.

There is a separate, closed companion product, **FENGARDE-Sec**: a paid
layer for regulated deployments (legally-validated report content and
model-assisted compliance tooling). It plugs in only through one frozen,
documented seam — the report-backend contract in
[`contracts/reporting.md`](contracts/reporting.md) (`REPORT_BACKEND=http`).
Nothing in this repo requires it, phones home to it, or degrades without it.
New capability that fits the seam ships here, open; only the regulated/legal
content layer is paid.

---

## License

FENGARDE is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).
