# FENGARDE

[![CI](https://github.com/supermhel/fengarde/actions/workflows/ci.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/ci.yml)
[![CodeQL](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml/badge.svg)](https://github.com/supermhel/fengarde/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/supermhel/fengarde/badge)](https://securityscorecards.dev/viewer/?uri=github.com/supermhel/fengarde)

> Scorecard badge reads "unknown" until `.github/workflows/scorecard.yml` runs
> at least once on `main` (M2, PLAN_C Tier 2.2) — a measured score, not a
> claimed one. Same for CI/CodeQL: the badge reflects whatever the most recent
> real run on `main` found, not a promise.

**The open-source SIEM for the European industrial Mittelstand — turns your
factory and IT logs into draft NIS2 incident notifications, with AI triage that
never leaves your network.**

FENGARDE ingests logs from multiple sources, normalizes them to a single schema
([OCSF](https://schema.ocsf.io/)), runs correlation rules over a sliding window,
and surfaces alerts in a dashboard. Every service is independent and talks to the
rest of the system only through a message bus, so you can scale or replace any
piece without rewriting the others.

Three things make it different from a generic self-hosted SIEM:

- **OCSF-native, not retrofitted.** Every source normalizes to the same open
  schema from day one — instrument once, stay portable, no vendor log-format
  lock-in.
- **OpenSearch, not Elastic.** No license asterisk on the storage engine — the
  open-source story has no fine print.
- **AI triage that never leaves your network.** Local Ollama by default, with a
  documented stub fallback — your alert data is never piped through a
  third-party LLM API.

New in v0.4: parser packs for the sources this wedge actually needs — MCP/AI-agent
tool-call audit logs, industrial OPC UA control-system events, and n8n automation-platform
logs — plus an incident-report draft hook (the open half of a NIS2/DORA
regulatory-evidence feature; see [`contracts/reporting.md`](contracts/reporting.md)).

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

## What's real (v0.1-v0.5 shipped)

FENGARDE ships a **working detection pipeline**. We are deliberate about what is
real versus what is planned — this is a security tool, so accuracy matters more than
a long feature list.

| Capability | Status | Notes |
|---|---|---|
| **Detection pipeline** (collect → normalize → detect → index → dashboard) | ✅ Works | End-to-end since v0.1 |
| **Parsers (14)** | ✅ Works | Cisco ASA, Active Directory, VMware vSphere, Linux SSH, generic syslog, Windows Event Log (incl. account-change 4720/4722/4726/4728/4732), DB audit (GRANT/REVOKE/ALTER), MCP/AI-agent tool-call audit, OPC UA/OT audit, n8n automation-platform audit, DNS query log, Kubernetes audit, CEF (generic appliance), AWS CloudTrail — all → OCSF |
| **Detection rules (26)** | ✅ Works | Brute-force (per-IP and sourceless/per-target-host), port-scan, lateral-movement, password-spray, privileged-group grant, after-hours admin, impossible-travel, bank DB priv-esc, DC mass-VM-delete, agent credential-file access / tool-call burst / prompt-injection indicator / destructive-command / egress-non-allowlisted-domain, OT write-outside-maintenance / new-engineering-connection / config-change, n8n new-webhook-exposed / workflow-modified-after-hours, DNS exfil, privileged-container-create, cloud root console login, mass DB-object read, rapid account create/delete, beaconing (periodicity primitive) |
| **Multi-tenancy / RBAC / webhooks / plugins** (v0.5, M4) | ✅ Works, opt-in | Tenant-scoped indices, per-tenant rule enablement; `FENGARDE_RBAC_DB` opt-in identity/RBAC (SQLite, scrypt, sessions, CSRF); outbound HMAC-signed webhooks; entry-points parser/rule plugin interface. All default OFF — zero behavior change unless you opt in |
| **Rule grammar** | ✅ Works | Boolean logic, comparison operators (`gt/gte/lt/lte/ne`), allowlist suppression (`not_in`, CIDR + exact), time-of-day (`outside_hours`) — all fail closed on malformed input |
| **Rule prefilter** | ✅ Works | Rules bucketed by `class_uid` equality selection; events only evaluated against candidate rules (fixes the O(rules×events) scan) |
| **Anti-dormancy guardrail** | ✅ Works | `tools/check_rule_producers.py` in the CI gate proves every rule's selections are satisfiable by values a real parser actually emits |
| **AI triage** (local Ollama) | ✅ Works | Real local-LLM triage via `OLLAMA_URL`; degrades to a documented passthrough stub with zero infra |
| **Triage workflow** | ✅ Works | Status + analyst note per alert, persisted via the WS-3 triage API, editable in the dashboard; concurrent writes protected at two layers (in-process lock + OpenSearch optimistic concurrency) |
| **Incident-report draft hook** | ✅ Works (v0.4) | `POST /alerts/{id}/report` renders a generic markdown incident report from alert facts, always marked `status: draft` with a disclaimer; the regulated-content backend is a paid, optional add-on (`contracts/reporting.md`) |
| **Opt-in auth** | ✅ Works (v0.4) | Shared-secret `FENGARDE_API_KEY` on the triage/inventory APIs, opt-in dashboard basic-auth, opt-in Redis `AUTH` — unset (default) stays fully open, matching v0.1-v0.3 behavior |
| **Syslog UDP listener** (WS-1) | ✅ Works | Live datagrams → `raw.events` |
| **Triage workflow** | ✅ Works (v0.3) | Status + analyst note per alert, persisted via WS-3 triage API, editable in the dashboard. Container-to-container nginx path validated by config review, not yet by a live-stack smoke test |
| SNMP parser | 🚧 Planned | Deferred — [good first issue](CONTRIBUTING.md) |
| NetFlow parser | 🚧 Planned | Deferred (binary format) |
| Custom JSON parser | 🚧 Planned | Deferred |

> **No AI required.** The pipeline produces real alerts with zero infra and no LLM;
> Ollama triage is an optional layer that degrades gracefully to a stub.

---

## Performance (`fengarde-bench`)

```sh
python tools/fengarde_bench.py --events 20000 --mixed
```

One-command, reproducible by anyone with a clone — no Docker required. Measured
2026-07-16 on a 4 vCPU / 15 GB sandbox host (not a fixed reference VPS, see caveat
below):

| Metric | Value |
|---|---|
| Sustained EPS (5,000 events, `linux_ssh` only) | ~12,950 events/sec |
| Sustained EPS (20,000 events, mixed `ssh`/`asa`/`generic_syslog`) | ~13,750 events/sec |
| Peak resident memory (20,000-event run) | ~84 MB |

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
> [the build plan](docs/superpowers/specs/2026-06-27-fengarde-v0.1-build-plan.md). The
> end-to-end detection logic itself is proven today by `make e2e`.

Other handy targets:

```sh
make e2e      # zero-infra ACCEPTANCE test: SSH brute-force -> real alert (no Docker)
make test     # run the full zero-infra contract test suite (no Docker needed)
make up       # start the stack detached (docker compose up -d)
make down     # stop the stack and remove volumes
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
  T7 OK: replay reused alert_id ... -> deduped (alerts count stayed 2)
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
   (Cisco ASA / AD /          (parsers → OCSF)                      ├─▶ WS-6 Inventory (IP/MAC)
    VMware / Linux SSH)                                             └─▶ WS-4 Detection ─scored.events─▶ WS-3
                                                                          │  alerts ─▶ WS-3 / WS-7
                                                                          └─ai.requests─▶ WS-5 AI (stub) ─▶ WS-3/WS-7
WS-7 Dashboard ◀── WS-6 API + alerts
```

The **only** coupling between services is the message bus. Everything else is a frozen
contract under [`contracts/`](contracts/). All source-format heterogeneity is absorbed
at the edge (one parser per source in WS-2); the interior of the system handles a single
schema (OCSF).

| WS | Service | Role | v0.1 status |
|----|---------|------|-------------|
| 1 | `services/ws1-collectors` | Collect logs → `raw.events` | ✅ |
| 2 | `services/ws2-normalization` | Parsers → validated OCSF events | ✅ (15 parsers) |
| 3 | `services/ws3-indexer` | Routing + OpenSearch indexing (idempotent) | ✅ |
| 4 | `services/ws4-detection` | Correlation rules + scoring + windowing | ✅ (26 rules) |
| 5 | `services/ws5-ai` | Triage | ✅ real local-LLM (Ollama) since v0.2, stub fallback |
| 6 | `services/ws6-inventory` | IP/MAC inventory API (SQLite) | ✅ |
| 7 | `services/ws7-dashboard` | Alert console | ✅ |

For current status and the forward roadmap, see **[SSOT.md](SSOT.md)** (read that first).
For historical design context: [the v0.1 build plan](docs/superpowers/specs/2026-06-27-fengarde-v0.1-build-plan.md)
and [`docs/PHASE0_README.md`](docs/PHASE0_README.md).

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
Curious how FENGARDE compares to Wazuh/Elastic Security/Security Onion? See
**[docs/vs.md](docs/vs.md)** — an honest comparison, not a sales pitch.

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
