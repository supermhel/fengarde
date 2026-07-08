# ARGUS

**An open-source SIEM pipeline that turns raw security logs into real alerts — with a decoupled, contract-first architecture you can extend one parser at a time.**

ARGUS ingests logs from multiple sources, normalizes them to a single schema
([OCSF](https://schema.ocsf.io/)), runs correlation rules over a sliding window,
and surfaces alerts in a dashboard. Every service is independent and talks to the
rest of the system only through a message bus, so you can scale or replace any
piece without rewriting the others.

---

## Demo

See ARGUS turn a real SSH brute-force burst into a real alert — **with zero
infrastructure** (no Docker, no Redis, no OpenSearch):

[![asciicast](https://asciinema.org/a/OORTESTMdagRX7HI.svg)](https://asciinema.org/a/OORTESTMdagRX7HI)

The cast above runs [`tools/demo.sh`](tools/demo.sh): it feeds 10 failed SSH logins
from one IP through the whole pipeline (normalize → detect → triage → index),
shows the brute-force **alert** come out, and replays the event to prove the alert
is **idempotent** (deduped, not duplicated).

**Recording the cast** is a manual, one-time step for a maintainer —
[asciinema](https://asciinema.org/) records a real interactive terminal, so it
can't be produced by CI or an automated agent. Run these in a real terminal:

```sh
asciinema rec --command "bash tools/demo.sh" argus-demo.cast
asciinema upload argus-demo.cast   # prints the asciinema.org URL + id
```

Then replace `PLACEHOLDER` above with the id from the upload URL.

### Try it yourself

```sh
# Zero-infra: SSH brute-force -> real alert, idempotent under replay (no Docker).
make e2e                                  # runs demo_e2e.py (fast, no narration)
bash tools/demo.sh                        # same test with banner + story narration
#                                         #  Windows: powershell -File tools\demo.ps1

# Full live stack (collect -> normalize -> detect -> index -> dashboard):
make up                                   # docker compose up -d
# ...then open the ARGUS alert console at:
#   http://localhost:8080
make down                                 # stop the stack and remove volumes
```

> First time on the live stack? Run `make preflight` first — it checks
> `vm.max_map_count`, Docker RAM, and free ports, and prints the exact fix for
> anything missing. See [Pre-flight](#️-pre-flight--read-this-before-you-start-the-stack).

---

## What's real (v0.2 shipped, v0.3 in progress)

ARGUS ships a **working detection pipeline**. We are deliberate about what is
real versus what is planned — this is a security tool, so accuracy matters more than
a long feature list.

| Capability | Status | Notes |
|---|---|---|
| **Detection pipeline** (collect → normalize → detect → index → dashboard) | ✅ Works | End-to-end since v0.1 |
| **Parsers (7)** | ✅ Works | Cisco ASA, Active Directory, VMware vSphere, Linux SSH, generic syslog, Windows Event Log (incl. account-change 4720/4722/4726/4728/4732), DB audit (GRANT/REVOKE/ALTER) — all → OCSF |
| **Detection rules (7)** | ✅ Works | Brute-force, port-scan, lateral-movement, password-spray, privileged-group grant, bank DB priv-esc, DC mass-VM-delete |
| **Rule grammar** | ✅ Works | Boolean logic, comparison operators (`gt/gte/lt/lte/ne`), allowlist suppression (`not_in`, CIDR + exact) — all fail closed on malformed input |
| **Rule prefilter** | ✅ Works | Rules bucketed by `class_uid` equality selection; events only evaluated against candidate rules (fixes the O(rules×events) scan) |
| **Anti-dormancy guardrail** | ✅ Works | `tools/check_rule_producers.py` in the CI gate proves every rule's selections are satisfiable by values a real parser actually emits |
| **AI triage** (local Ollama) | ✅ Works | Real local-LLM triage via `OLLAMA_URL`; degrades to a documented passthrough stub with zero infra |
| **Syslog UDP listener** (WS-1) | ✅ Works | Live datagrams → `raw.events` |
| **Triage workflow** | ✅ Works (v0.3) | Status + analyst note per alert, persisted via WS-3 triage API, editable in the dashboard. Container-to-container nginx path validated by config review, not yet by a live-stack smoke test |
| SNMP parser | 🚧 Planned | Deferred — [good first issue](CONTRIBUTING.md) |
| NetFlow parser | 🚧 Planned | Deferred (binary format) |
| Custom JSON parser | 🚧 Planned | Deferred |

> **No AI required.** The pipeline produces real alerts with zero infra and no LLM;
> Ollama triage is an optional layer that degrades gracefully to a stub.

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
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-argus.conf
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

> **Want to see ARGUS work without Docker?** Run **`make e2e`** — a zero-infra
> acceptance test that feeds a real SSH brute-force burst through the whole pipeline
> and shows the alert come out the other end (details in
> [How to see the alert](#how-to-see-the-alert)).
>
> **Honest status:** the *in-stack* live feeder and the *live* dashboard (which reads
> alerts straight from OpenSearch) are the remaining DX2/DX4 items — see
> [the build plan](docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md). The
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
| 8080 | `ws7-dashboard` | ARGUS alert console |
| 5514/udp | `ws1-collectors` | Live syslog ingestion (unauthenticated — trusted segment only) |
| 8013 | `ws3-indexer` | Triage API — **internal only**, the dashboard proxies to it container-to-container; not published to the host |

`make preflight` checks the published ports are free before you start.

---

## How to see the alert

The acceptance test for v0.1 is a real **brute-force alert**, not mock data:

1. **The signal.** 10 failed authentication events from a single source IP within
   60 seconds. ARGUS produces these from a Linux SSH `Failed password` line or a
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
[OK] ARGUS v0.1 acceptance: SSH brute-force -> real alert in the index, idempotent under replay. Zero infra.
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
| 2 | `services/ws2-normalization` | Parsers → validated OCSF events | ✅ (4 parsers) |
| 3 | `services/ws3-indexer` | Routing + OpenSearch indexing (idempotent) | ✅ |
| 4 | `services/ws4-detection` | Correlation rules + scoring + windowing | ✅ |
| 5 | `services/ws5-ai` | Triage | 🚧 passthrough stub (AI in v0.2) |
| 6 | `services/ws6-inventory` | IP/MAC inventory API (SQLite) | ✅ |
| 7 | `services/ws7-dashboard` | Alert console | ✅ |

For the full design, scope decisions, and roadmap, see
[the v0.1 build plan](docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md) and
[`docs/PHASE0_README.md`](docs/PHASE0_README.md).

---

## Contributing

The fastest way to contribute is to **add a parser** — and you do **not** need Docker
or OpenSearch to do it. The whole inner loop is one command:

```sh
cd services/ws2-normalization && python test_contract.py
```

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the contribution workflow and
**[docs/adding-a-parser.md](docs/adding-a-parser.md)** for a step-by-step walkthrough
(copy `linux_ssh.py`, make three small edits, verify). The five deferred parsers above
are the obvious first PRs.

---

## Security

ARGUS v0.1 services are designed for a **localhost / Docker-Compose network only** and
are **not** hardened for internet exposure. There is **no authentication in v0.1 by
design**, and the detection engine executes rule files — so only run rules you trust.
See **[SECURITY.md](SECURITY.md)** for the full threat boundary and how to report a
vulnerability.

---

## License

ARGUS is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).
