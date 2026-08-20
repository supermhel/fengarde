# FENGARDE

[![CI](https://github.com/supermhel/fengarde/actions/workflows/ci.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/ci.yml)
[![CodeQL](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/supermhel/fengarde/badge)](https://securityscorecards.dev/viewer/?uri=github.com/supermhel/fengarde)

> Badges above reflect the most recent real run on `main`, not a promise —
> CI/CodeQL/Scorecard have all run at least once as of 2026-07-19 (post-merge
> of PR#2); Scorecard's own findings drove a supply-chain pinning pass
> (workflow SHAs, Docker base image digests) that took its score from an
> initial ~54 open alerts down to 19, all of which are accepted policy-level
> trade-offs (see `SSOT.md` §1), not unaddressed gaps.

**The open-source SIEM for the European industrial Mittelstand — turns your
factory and IT logs into draft NIS2 incident notifications, with AI triage that
never leaves your network.**

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

> **On OpenSearch vs. Elastic:** storing in OpenSearch means there is no license
> asterisk on the storage engine ([ADR 003](docs/adr/003-opensearch-not-elasticsearch.md)),
> which is worth knowing but is *not* a differentiator against the comparison
> people actually make — Wazuh's indexer is an OpenSearch fork too. It only
> distinguishes FENGARDE from Elastic-based stacks, so it is not listed above.

New since v0.4: a deterministic German/English NIS2 draft-report generator
(additive on the same incident-report hook, `?template=nis2`; see
[`contracts/reporting.md`](contracts/reporting.md)), opt-in RBAC/MFA/audit-log/
webhooks/multi-tenancy for MSP-style deployments, and an opt-in HA profile
(Redis Sentinel + 3-node OpenSearch) with **live-kill-tested failover on both
sides** — not just wired, actually proven by killing a real node and watching
the write path survive.

---

## Quickstart (10 minutes)

```sh
git clone https://github.com/supermhel/fengarde.git && cd fengarde
make preflight   # doctor: checks vm.max_map_count, Docker RAM, free ports
make demo        # docker compose up -- a real SSH brute-force alert appears
                 # in the dashboard within ~30-60s, no manual step
# open http://localhost:8080
```

No Docker on hand? The whole detection pipeline runs zero-infra:
`make e2e` proves the same SSH brute-force → real alert → idempotent-replay
path with no Redis/OpenSearch/Docker at all.

---

## Demo

See FENGARDE turn a real SSH brute-force burst into a real alert — **with zero
infrastructure** (no Docker, no Redis, no OpenSearch):

```sh
bash tools/demo.sh
```

This feeds 10 failed SSH logins from one IP through the whole pipeline
(normalize → detect → triage → index), shows the brute-force **alert** come
out, and replays the event to prove the alert is **idempotent** (deduped, not
duplicated).

### Try it yourself

```sh
# Zero-infra: SSH brute-force -> real alert, idempotent under replay (no Docker).
make e2e                                  # runs demo_e2e.py (fast, no narration)
bash tools/demo.sh                        # same test with banner + story narration
#                                         #  Windows: powershell -File tools\demo.ps1

# Full live stack (collect -> normalize -> detect -> index -> dashboard):
make up                                   # docker compose up -d
# ...then open the FENGARDE alert console at:
#   http://localhost:8080
make down                                 # stop the stack and remove volumes
```

> First time on the live stack? Run `make preflight` first — it checks
> `vm.max_map_count`, Docker RAM, and free ports, and prints the exact fix for
> anything missing. See [Pre-flight](#️-pre-flight--read-this-before-you-start-the-stack).

---

## What's real (on `main` today — last tagged release is v0.5.0)

FENGARDE ships a **working detection pipeline**. We are deliberate about what is
real versus what is planned — this is a security tool, so accuracy matters more than
a long feature list. This table describes the current tip of `main`, not just the
last tag: v0.5.0 (`v0.4.0`/`v0.5.0` tags both live) shipped 2026-07-23, and real,
tested work has landed on `main` since without a new tag of its own (most recently
WS-8 cross-alert correlation and a dashboard visual redesign, PR #64, merged
2026-08-19) — if you need a pinned, tagged release rather than the moving tip, use
`v0.5.0` and expect it to be missing anything below dated after 2026-07-23. See
[SSOT.md](SSOT.md) for the authoritative, continuously updated status — this table
is a snapshot, that file is the source of truth.

> **This table is `main`-only, on principle.** Two PRs are open with real, tested
> work not reflected below until they merge: [#69](https://github.com/supermhel/fengarde/pull/69)
> (dashboard: raw event browser, Ops/Audit tabs, AI engine/model tagging, MFA
> enrollment UI, a screenshot product tour) and
> [#70](https://github.com/supermhel/fengarde/pull/70) (fixes unbounded in-process
> growth in WS-8's correlator under sustained high-cardinality alert volume). See
> `SSOT.md` §1 if you want the in-flight detail; this table only claims what's
> actually merged, so a fresh clone of `main` never gets a capability this table
> promised and doesn't yet have.

| Capability | Status | Notes |
|---|---|---|
| **Detection pipeline** (collect → normalize → detect → index → dashboard) | ✅ Works | End-to-end since v0.1 |
| **Parsers (17)** | ✅ Works | Cisco ASA, Active Directory, VMware vSphere, Linux SSH, generic syslog, Windows Event Log (incl. account-change 4720/4722/4726/4728/4732), DB audit (GRANT/REVOKE/ALTER), MCP/AI-agent tool-call audit, OPC UA/OT audit, n8n automation-platform audit, DNS query log, Kubernetes audit, CEF (generic appliance), AWS CloudTrail, Sysmon (process/network/file), Modbus/TCP protocol-anomaly detector, inventory-diff OT device detector — all → OCSF |
| **Detection rules (28)** | ✅ Works | Brute-force (per-IP and sourceless/per-target-host), port-scan, lateral-movement, password-spray, privileged-group grant, after-hours admin, impossible-travel, bank DB priv-esc, DC mass-VM-delete, agent credential-file access / tool-call burst / prompt-injection indicator / destructive-command / egress-non-allowlisted-domain, OT write-outside-maintenance / new-engineering-connection / config-change / Modbus unauthorized-write / new device on segment, n8n new-webhook-exposed / workflow-modified-after-hours, DNS exfil, privileged-container-create, cloud root console login, mass DB-object read, rapid account create/delete, beaconing (periodicity primitive) |
| **Rule grammar** | ✅ Works | Boolean logic, comparison operators (`gt/gte/lt/lte/ne`), allowlist suppression (`not_in`, CIDR + exact), time-of-day (`outside_hours`) — all fail closed on malformed input |
| **Rule prefilter** | ✅ Works | Rules bucketed by `class_uid` equality selection; events only evaluated against candidate rules (fixes the O(rules×events) scan) |
| **Anti-dormancy guardrail** | ✅ Works | `tools/check_rule_producers.py` in the CI gate proves every rule's selections are satisfiable by values a real parser actually emits |
| **Rule boundary guardrail** | ✅ Works | Satisfiable ≠ fires, and firing ≠ firing *only when it should*. `eval/attack/fire_check.py` proves all 27 MITRE-tagged rules fire on their own fixture, then probes the negative half — catching a rule that is too **loose**, which shows up as false-positive volume months later rather than as a dead rule. Two constructions, because the two rule kinds fail differently: each **stateful** rule is replayed one under its threshold and spread just past its window and must stay silent (12/12 hold); each **stateless** rule has one declared predicate violated at a time and must stop firing (15/15 hold, 46 predicate near-misses, none skipped). Scope, stated narrowly: engine-vs-declaration agreement — that declared thresholds and predicates are enforced, **not** that they are well chosen. See `SSOT.md` |
| **AI triage** (local Ollama) | ✅ Works | Real local-LLM triage via `OLLAMA_URL`; degrades to a documented passthrough stub with zero infra |
| **Triage workflow** | ✅ Works | Status + analyst note per alert, persisted via the WS-3 triage API, editable in the dashboard; concurrent writes protected at two layers (in-process lock + OpenSearch optimistic concurrency) |
| **Incident-report draft hook** | ✅ Works (v0.4) | `POST /alerts/{id}/report` renders a generic markdown incident report from alert facts, always marked `status: draft` with a disclaimer; the regulated-content backend is a paid, optional add-on (`contracts/reporting.md`) |
| **Opt-in auth** | ✅ Works (v0.4) | Shared-secret `FENGARDE_API_KEY` on the triage/inventory APIs, opt-in dashboard basic-auth, opt-in Redis `AUTH` — unset (default) stays fully open, matching v0.1-v0.3 behavior |
| **Syslog UDP listener** (WS-1) | ✅ Works | Live datagrams → `raw.events` |
| **Multi-tenancy** | ✅ Works | `tenant_id` threaded collector→normalize→detect→index; per-tenant OpenSearch indices, per-tenant rule enablement; isolation proven by `tools/test_multi_tenant_isolation.py`. Detection/AI-triage consume ordering is also per-tenant fair (`services/shared/fairness.py`): one flooding tenant can no longer occupy every consecutive processing turn ahead of another sharing the same deployment — bounded within one consume batch, not full compute isolation, see the module's own honest-scope note |
| **RBAC** | ✅ Works, opt-in | Per-user accounts/roles/tenant scoping via `FENGARDE_RBAC_DB`; session cookies, CSRF protection, dashboard login UI; unset (default) = pre-RBAC API-key-only behavior, byte-for-byte unchanged |
| **MFA/TOTP** | ✅ Works, opt-in | Per-user, stdlib-only RFC 6238 (`services/shared/mfa.py`); provision → confirm two-step activation, login gates once active, config changes require re-entering your own password (a stolen session cookie alone can't touch it). Live-verified end to end 2026-08-11 (`services/ws3-indexer/test_mfa_live_e2e.py`, real HTTP against the deployed handler) — that run caught and fixed a real bug where the module's import path resolved in a source checkout but not in the built container, leaving MFA inert in every deployment while the zero-infra tests stayed green |
| **Admin audit log** | ✅ Works, opt-in | Append-only, capacity-capped JSONL trail of login/triage/report events, fail-open (an audit outage never blocks a request), `GET /audit` (admin-only) |
| **Redis-backed sessions (multi-replica RBAC)** | ✅ Works, opt-in | `FENGARDE_SESSION_BACKEND=redis`; every session row is HMAC-signed and `FENGARDE_SESSION_SECRET` is required to start — a process that can write to Redis directly still can't forge a session |
| **Versioned REST API** | ✅ Works | `contracts/triage-api.yaml` (OpenAPI 3.1); every route reachable bare or under `/api/v1/...`; spec-vs-code drift is CI-tested |
| **Outbound alert webhooks** | ✅ Works, opt-in | HMAC-SHA256-signed deliveries to operator-configured URLs (`contracts/webhooks/*.yml`, ships empty); see `docs/webhooks.md` |
| **Parser/rule plugin interface** | ✅ Works | External pip package can ship a parser or rule pack via Python entry points, no fork needed; see `docs/plugin-development.md` |
| **Cross-alert correlation** (WS-8) | ✅ Works | A second, independent consumer of the `alerts` topic tracks `actor:{name}`/`ip:{addr}` activity over a longer horizon (default 24h) and promotes a track to an `incidents` document once it shows ≥2 distinct MITRE tactics — catches a low-and-slow attacker who paces each technique under any single rule's own threshold. Deterministic `incident_id`, so a growing incident re-emits under the same id instead of duplicating. **Known limitation, fix in review** ([#70](https://github.com/supermhel/fengarde/pull/70), not yet on `main`): the in-process side tables backing this can grow unbounded under sustained high-cardinality alert volume (e.g. an attacker spraying distinct source IPs) — see `SSOT.md` §1 |
| **Chaos-tested delivery** | ✅ Works | `make chaos`: 40 scenarios, each pipeline service SIGKILLed mid-replay — zero lost, zero duplicate alerts (2026-07-18 run). Proves consumer-failure durability; a Redis-primary failover is a separate scenario, see `SSOT.md` |
| **HA profile** (Redis Sentinel + 3-node OpenSearch) | ✅ Works, opt-in | `docker-compose.ha.yml` / `make ha-up`. Both sides live-kill-tested, not just wired: Sentinel failover (~1s promotion, zero lost messages) and 3-node OpenSearch (killed a real node, confirmed a write still succeeds via round-robin to a surviving node, cluster back to `green` after restart) |
| **Per-source syslog metrics** | ✅ Works | Bounded, LRU-evicted, thread-safe per-peer-IP breakdown on WS-1's `/metrics` |
| **Dashboard: saved searches, dark mode, alert lifecycle + playbooks** | ✅ Works | Client-side saved alert-search filters, OS-aware dark/light theme, per-alert playbook rendering |
| **NIS2 (DE) report template** | ✅ Works | Deterministic German/English NIS2 Art. 23 / §32 BSIG draft, additive on the report hook (`?template=nis2`); every entity-specific fact renders as an explicit `[ANALYST MUST PROVIDE]` placeholder, never fabricated |
| SNMP parser | 🚧 Planned | Deferred — [good first issue](CONTRIBUTING.md) |
| NetFlow parser | 🚧 Planned | Deferred (binary format) |
| Custom JSON parser | 🚧 Planned | Deferred |
| Proxy / web-gateway parser | 🚧 Planned | DNS query log already ships (class 4002) — this is its HTTP-proxy sibling |
| S7/PROFINET parser | 🚧 Deferred | Not a scope decision — the concrete vocabulary needed sits behind a Siemens support login this project doesn't have access to; see `docs/superpowers/specs/2026-07-21-s7-profinet-decision-gate.md` |

> **No AI required.** The pipeline produces real alerts with zero infra and no LLM;
> Ollama triage is an optional layer that degrades gracefully to a stub.

---

## Performance (`fengarde-bench`)

```sh
python tools/fengarde_bench.py --events 20000 --mixed
```

One-command, reproducible by anyone with a clone — no Docker required. Measured
2026-08-07 on the same class of sandbox host as the original 2026-07-16 number
(not a fixed reference VPS, see caveat below):

| Metric | Value |
|---|---|
| Sustained EPS (5,000 events, `linux_ssh` only) | ~570 events/sec |
| Sustained EPS (20,000 events, mixed `ssh`/`asa`/`generic_syslog`) | ~1,300-1,600 events/sec |
| Peak resident memory (20,000-event run) | ~100 MB |

**Down from the 2026-07-16 numbers (~13,000 EPS) — two separate causes, not one:**
(1) a real bug in the benchmark script itself: synthetic events were timestamped
marching *forward* from "now" (`base_s + seq`), so past ~300 events every
subsequent event tripped the engine's 5-minute future-event anti-poisoning
guard, flooding stdout with one warning per stateful rule per event during the
timed section — fixed 2026-08-07 (`tools/fengarde_bench.py`, same bug class
already fixed once in `eval/attack/fire_check.py` and once in
`tools/chaos_test.py`, never applied here). (2) even after that fix, real
throughput is genuinely lower than 2026-07-16 — the code now does more work per
event than it did then (a larger rule set, the A5 enrichment stage, the M1
recursive log-injection sanitizer over `unmapped.*`, structured logging
replacing bare `print()`), and nobody has re-profiled where the remaining cost
actually goes. Read this as the current honest number, not a regression that's
been root-caused down to a single line — if raw batch throughput matters for
your deployment, treat ~1,500 EPS as today's real baseline, not ~13,000.

**Read before citing these numbers anywhere:** this is a **zero-infra CPU-bound
baseline** — one process, the in-memory bus, `MemoryStore` — measuring how fast
WS-2/WS-4/WS-3's Python code processes a batch. It excludes real Redis network
I/O, OpenSearch indexing latency, and any real queuing/backpressure behavior a
live stack has. It is **not** a "FENGARDE handles N events/sec in production"
claim, and there is no p50/p99 ingest→alert latency number yet — batch
processing has no realistic queuing delay to measure; that number only means
something against a live bus. The live-stack number on a defined reference box
is still an open TODO (needs Docker, which this repo's current CI/dev
environment doesn't always have).

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose v2) with **≥ 4 GB RAM** allocated to Docker.
- **OS:** Linux, macOS, or **Windows via WSL2**. (The demo stack runs Linux containers; the
  pre-flight and demo scripts are POSIX `sh`.)
- **Python 3** — only if you want to run the contract tests or contribute a parser.
  You do **not** need Docker to add a parser (see [Contributing](#contributing)).

---

## ⚠️ PRE-FLIGHT — read this before you start the stack

OpenSearch (the storage engine) **will not boot** on Linux/WSL2 with default kernel
settings. It needs the `vm.max_map_count` limit raised. Run this **once per machine**
(it resets on reboot):

```sh
sudo sysctl -w vm.max_map_count=262144
```

To make it persist across reboots:

```sh
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-fengarde.conf
```

> On **macOS with Docker Desktop** this is handled inside the Docker VM and you can
> usually skip it. On **Linux/WSL2** it is required — without it you get a JVM crash,
> not a helpful error.

`make preflight` (below) checks this for you and prints the exact fix if anything is
missing.

---

## Quick start

```sh
# 1. Check your machine is ready (vm.max_map_count, Docker RAM, free ports)
make preflight

# 2. Bring up the full stack
make demo
```

`make demo` runs the pre-flight check, then starts every service with Docker Compose.
All services are long-running daemons with a `/health` endpoint and a restart policy.

> **Want to see FENGARDE work without Docker?** Run **`make e2e`** — a zero-infra
> acceptance test that feeds a real SSH brute-force burst through the whole pipeline
> and shows the alert come out the other end (details in
> [How to see the alert](#how-to-see-the-alert)).
>
> **Honest status:** the *in-stack* live feeder and the *live* dashboard (which reads
> alerts straight from OpenSearch) are the remaining DX2/DX4 items — see
> `SSOT.md` for current status (the original build plan is historical and no
> longer kept in this repo). The end-to-end detection logic itself is proven
> today by `make e2e`.

Other handy targets:

```sh
make e2e      # zero-infra ACCEPTANCE test: SSH brute-force -> real alert (no Docker)
make test     # run the full zero-infra contract test suite (no Docker needed)
make up       # start the stack detached (docker compose up -d)
make down     # stop the stack and remove volumes
make ha-up    # OPT-IN: Redis Sentinel (1 primary + 2 replicas + 3 Sentinels) + 3-node OpenSearch HA
              # profile on top of the default stack (needs REDIS_PASSWORD) -- see
              # infra/docker-compose.ha.yml's header comment. Default `make up` is unaffected.
make ha-down  # stop the HA profile and remove its volumes
```

---

## Ports

| Port | Service | What it is |
|------|---------|------------|
| 6379 | `redis` (`siem-bus`) | Message bus between services |
| 9200 | `opensearch` (`siem-store`) | Event/alert storage + query API |
| 5601 | `dashboards` (`siem-dashboards`) | OpenSearch Dashboards |
| 8000 | `ws6-inventory` | Inventory API (IP/MAC history) |
| 8080 | `ws7-dashboard` | FENGARDE alert console |
| 5514/udp | `ws1-collectors` | Live syslog ingestion (unauthenticated — trusted segment only) |
| 8013 | `ws3-indexer` | Triage API — **internal only**, the dashboard proxies to it container-to-container; not published to the host |
| 9090 | `prometheus` | Metrics scrape + query — **opt-in**, `observability` compose profile only (`docker compose --profile observability up`) |
| 3000 | `grafana` | Dashboards over Prometheus — **opt-in**, same profile; ships with a default `admin`/`admin` credential, see `SECURITY.md` §1 |

`make preflight` checks the published ports are free before you start.

---

## How to see the alert

The acceptance test for v0.1 is a real **brute-force alert**, not mock data:

1. **The signal.** 10 failed authentication events from a single source IP within
   60 seconds. FENGARDE produces these from a Linux SSH `Failed password` line or a
   Windows `EventID 4625` — both normalize to the same OCSF Authentication event
   (`class_uid: 3002`, `activity_id: 4`).
2. **The rule.** [`contracts/rules/common_bruteforce.yml`](contracts/rules/common_bruteforce.yml)
   matches those events, grouped by `src_endpoint.ip`, with `threshold: 10` and
   `window_seconds: 60`. It is source-agnostic, so it fires identically on SSH or AD.
3. **The alert.** When the 10th failure from one IP lands inside the window, the
   detection service emits an alert that flows to the indexer and into the dashboard
   alert list.

See the **whole pipeline** produce the alert with **no infrastructure** — the
acceptance test injects 10 failed SSH logins and asserts a real brute-force alert
reaches the index, and that replaying the same event reuses the same alert id
(idempotent, so at-least-once delivery never double-alerts):

```sh
make e2e        # or: python tools/demo_e2e.py
```

Expected tail:

```
  ALERT: Authentication brute-force from single source src=203.0.113.5 score=70 id=...
  T7 OK: new window-overlapping event deduped via deterministic alert_id ... (alerts count stayed 2)
  T7 OK: true identical-event replay reused alert_id ... -> deduped (alerts count stayed 2)
[OK] FENGARDE v0.1 acceptance: SSH brute-force -> real alert in the index, idempotent under replay. Zero infra.
```

Prefer a unit-level check? The WS-4 detection contract test asserts the rule fires on
the 10th attempt: `cd services/ws4-detection && python test_contract.py`.

For the full Dockerized stack (collect → normalize → detect → index → dashboard), run
`make demo` and open the dashboard at <http://localhost:8080>.

---

## Architecture

```
WS-1 Collectors ─raw.events─▶ WS-2 Normalization ─normalized.events─┬─▶ WS-3 Indexer ─▶ OpenSearch
   (Cisco ASA / AD /          (parsers → OCSF)                      └─▶ WS-4 Detection ─scored.events─▶ WS-3
    VMware / Linux SSH)                                                  │  alerts ─▶ WS-3, WS-8
   ─assets.updates─▶ WS-6 Inventory (IP/MAC) ─raw.events─▶ (new device -> WS-2, feedback loop)
                                                                          └─ai.requests─▶ WS-5 AI (real local
                                                                                Ollama triage, stub fallback)
                                                                                ─ai.results/alerts─▶ WS-3
WS-8 Correlation ◀─alerts (2nd consumer group)── multi-tactic entity tracks ─incidents─▶ WS-3
WS-7 Dashboard ◀── HTTP only (nginx → WS-3's triage/report/rules/incidents API + WS-6's inventory API), never the bus
```

The **only** coupling between backend services (WS-1 through WS-6, WS-8) is the message
bus — no service calls another's code or API directly. Everything else is a frozen
contract under [`contracts/`](contracts/). All source-format heterogeneity is absorbed at
the edge (one parser per source in WS-2); the interior of the system handles a single
schema (OCSF). WS-7 is the one exception by necessity: it's a browser UI, so it reaches
WS-3/WS-6 over HTTP (via nginx) — it never touches the bus, and no backend service depends
on it.

| WS | Service | Role | Status |
|----|---------|------|-------------|
| 1 | `services/ws1-collectors` | Collect logs → `raw.events` | ✅ |
| 2 | `services/ws2-normalization` | Parsers → validated OCSF events | ✅ (17 parsers) |
| 3 | `services/ws3-indexer` | Routing + OpenSearch indexing (idempotent) | ✅ |
| 4 | `services/ws4-detection` | Correlation rules + scoring + windowing | ✅ (28 rules) |
| 5 | `services/ws5-ai` | Triage | ✅ real local-LLM (Ollama) since v0.2, stub fallback |
| 6 | `services/ws6-inventory` | IP/MAC inventory API (SQLite) | ✅ |
| 7 | `services/ws7-dashboard` | Alert console | ✅ |
| 8 | `services/ws8-correlation` | Cross-alert correlation (multi-stage incident detection) | ✅ (2026-08-18, live-verified) |

For current status and the forward roadmap, see **[SSOT.md](SSOT.md)** (read that first).
For historical design context: [`docs/PHASE0_README.md`](docs/PHASE0_README.md).

---

## Evaluation & detection quality

"A rule passes CI" and "a rule actually fires on real attack traffic" are
different claims — this repo keeps them separate rather than conflating them,
across three eval lanes under `eval/`:

| Command | What it proves | Needs |
|---|---|---|
| `make attack-scorecard` | **Declared** MITRE ATT&CK/ATT&CK-ICS/ATLAS coverage (which techniques a rule's `mitre:` block claims), an **empirical** check that every tagged rule's condition actually fires on its own real producer fixture through the live detection engine, and a **boundary** check that each stateful rule stays silent one event under its threshold and when its events are spread past its window — three distinct claims, never merged into one number | Zero infra |
| `make eval-detection` | Independent-oracle replay: real Windows Security/Sysmon attack corpora (EVTX-ATTACK-SAMPLES, splunk/attack_data) fed through the live pipeline, alerts checked against a ground truth computed separately from the engine's own logic — this is what catches a bug a unit test mirroring the engine's own code cannot. See [`eval/detection_accuracy/README.md`](eval/detection_accuracy/README.md) for dataset licensing and setup (both corpora are third-party, not vendored; the target skips cleanly with no datasets fetched) | Real datasets fetched separately |
| `make nis2-demo` | End-to-end proof that a real alert becomes a structurally-compliant NIS2 draft (disclaimer, draft status, no fabricated entity facts) — the same checklist `eval/report_generator/`'s harness runs across 12 synthetic scenarios × 3 stages × 2 languages in CI | Zero infra |
| `python tools/detection_quality_eval.py` | Precision/recall/F1 canary: the real engine against a small hand-labeled corpus (`docs/detection-quality.md`), including two deliberately adversarial labels that keep the numbers honest instead of a trivial 1.0. This is *engine-versus-labels* agreement, not real-world detection fidelity — a regression trip-wire (floor 0.5), not a quality bar | Zero infra |

None of these are optional add-ons bolted on for show — `attack-scorecard`,
the report-generator eval, and the detection-quality canary all run in
`run_all_tests.sh`; `eval-detection` is deliberately excluded from the
zero-infra gate (a target that always skips would be noise there) but is the
harness that actually caught real false negatives in the brute-force rule
during the 2026-07-21 audit pass.

---

## Contributing

The fastest way to contribute is to **add a parser** — and you do **not** need Docker
or OpenSearch to do it. The whole inner loop is one command:

```sh
cd services/ws2-normalization && python test_contract.py
```

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the contribution workflow and
**[docs/adding-a-parser.md](docs/adding-a-parser.md)** for a step-by-step walkthrough
(copy `linux_ssh.py`, make three small edits, verify). The three deferred parsers above
are the obvious first PRs — or propose a new detection rule via the
[rule request template](.github/ISSUE_TEMPLATE/rule_request.md).

Monitoring AI agents/MCP servers? See **[docs/agent-monitoring.md](docs/agent-monitoring.md)**.

---

## Security

FENGARDE services are designed for a **localhost / Docker-Compose network only** and
are **not** hardened for internet exposure. Authentication is **opt-in**
(`FENGARDE_API_KEY` shared-secret, dashboard basic-auth, Redis `AUTH` — all default
OFF, matching pre-v0.4 behavior until you opt in). A real identity/RBAC layer
(`FENGARDE_RBAC_DB` — SQLite users, scrypt hashing, sessions, roles, CSRF-protected
writes, tenant isolation) exists as of v0.5/M4, also opt-in and off by default
(single-process session store, not yet HA — see SSOT.md §2). The detection engine
executes rule files — so only run rules you trust. Need to reach the dashboard
from outside the host? See **[docs/deployment.md](docs/deployment.md)** for a reverse-proxy
TLS example. See **[SECURITY.md](SECURITY.md)** for the full threat boundary and how to
report a vulnerability.

---

## Open core — what's free, what's paid

**This repository is free and open source forever, under Apache-2.0.** Everything in it
— the pipeline, every parser, every detection rule, the dashboard, the triage API, the
generic and NIS2 report templates — is the complete product, not a crippled trial.

There is a separate, closed companion product, **FENGARDE-Sec**, developed in a private
repository: a paid layer for regulated deployments (legally-validated report content and
model-assisted compliance tooling). It plugs into this repo only through one frozen,
documented seam — the report-backend contract in
[`contracts/reporting.md`](contracts/reporting.md) (`REPORT_BACKEND=http`). Nothing in
this repo requires it, phones home to it, or degrades without it.

Practically: features never move from this repo to the paid layer. New capability that
fits the seam ships here open; only the regulated/legal content layer is paid.

---

## License

FENGARDE is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).
