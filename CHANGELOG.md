# Changelog

All notable changes to ARGUS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **DB-audit parser** (`db_audit`) — vendor-agnostic database audit logs → OCSF Datastore Activity (6005), activity_id 5 for GRANT/REVOKE/ALTER. Un-dormants the `bank_db_priv_esc` rule, which matched a class no parser emitted.
- **Windows account-change coverage** — `windows_eventlog` parser extended to EventIDs 4720/4722/4726/4728/4732 (Account Change, class 3003), with acting admin in `actor.user` and target account in `unmapped.target_user`.
- **Password-spray rule** (`common_password_spray.yml`) — one account failing auth from ≥8 distinct source IPs (inverse of brute-force).
- **Privileged-group grant rule** (`common_priv_grant.yml`) — single-shot on Account Change activity 5.
- **Rule grammar: comparison operators + allowlists** — `gt/gte/lt/lte/ne` operators and a `not_in: <allowlist>` suppression clause (`contracts/allowlists/*.yml`, CIDR + exact match) in the boolean evaluator. Operators fail closed on malformed input; a missing/malformed allowlist *file* fails open on the rule (keeps firing) but closed on suppression (never suppresses).
- **Rule prefilter** — the detector buckets rules by their `class_uid` equality selection and only evaluates candidate rules per event, replacing the O(rules×events) linear scan. Alert-firing behavior verified byte-identical before/after.
- **Anti-dormancy guardrail** (`tools/check_rule_producers.py`, in `run_all_tests.sh`) — proves each rule's equality selections/`group_by`/`distinct_field` are satisfiable by an actual (path, value) pair some registered parser emits against a real fixture.
- **Detection coverage map** (`contracts/detection-coverage.md`) — ground truth of OCSF classes emitted by shipped parsers vs. rule coverage.
- **Triage workflow (v0.3 C1)** — status + analyst note per alert: new WS-3 triage HTTP API (`GET/POST /alerts/{id}/triage`, `TRIAGE_PORT` default 8013), `find_alert()` cross-index lookup in both storage backends, dashboard status dropdown + note field wired via a same-origin `/api/triage` nginx path. Triage field is OCSF-additive with tolerant-reader defaults.
- **RedisBus test parity** — `services/shared/test_runner.py` parametrized so the full MemoryBus behavioral suite also runs against RedisBus in CI's redis-integration job.

### Fixed

- Dashboard `renderGlobal()` called async `getAlerts()` without `await`, so live-alert rendering operated on a Promise and threw in the browser — silently broken since live alerts shipped.
- `storage/opensearch.py` used `urllib.parse.quote()` without importing `urllib.parse` — the first real OpenSearch `index()` call would have raised `AttributeError`.

## [0.2.0] - 2026-07-01

### Added

- **Generic syslog parser** (`generic_syslog`) — RFC 3164 syslog lines (with or without `<PRI>`) → OCSF, with PRI-severity mapping. Covers sources that don't match a product-specific parser.
- **Windows Event Log parser** (`windows_eventlog`) — broad coverage of security-relevant EventIDs (4624 logon, 4634/4647 logoff, 4688 process creation, 4672 special privileges) → OCSF. Complements the existing Active Directory 4625 parser without overlap.
- **Port-scan detection rule** — fires when one source IP hits ≥15 distinct DENIED destination ports within 60s (OCSF Network Activity, activity_id 6). Restricted to denies for precision; open-port scans are intentionally out of scope.
- **Lateral-movement detection rule** — fires when one account successfully authenticates to ≥5 distinct destination hosts within 300s.
- **Distinct-count windowing** — new `hit_distinct()` on both the deque (single-replica) and Redis (multi-replica, sorted-set) window counters, so rules can threshold on the number of *distinct* field values in a window, not just the event count. Rules opt in via `siem.distinct_field` in YAML.
- **Real local-LLM triage (Ollama)** — WS-5 now calls a local Ollama model (`OLLAMA_URL`/`OLLAMA_MODEL`) for alert triage, returning a structured verdict, and degrades gracefully to the passthrough stub when Ollama is unset, unreachable, or returns malformed output. The acceptance test still runs stub-only with zero infra.
- **Real syslog UDP listener (WS-1)** — collectors now accept live syslog datagrams (`SYSLOG_UDP_HOST`/`SYSLOG_UDP_PORT`, default `0.0.0.0:5514`, now published in `docker-compose.yml`) and feed them into `raw.events` for the generic syslog parser, alongside the existing mock collection path.

### Fixed

- Windows parser mapped the logon source and destination host to the same field, leaving the lateral-movement rule unable to ever fire on real data; auth events now correctly split `src_endpoint` (logon origin) from `dst_endpoint.hostname` (target host).
- Cisco ASA parser dropped both endpoints on `denied from IP/port to IP/port`-style deny messages (106001/106006/106015), making the port-scan rule blind to that message family; endpoint extraction now covers `src/dst`, `for/to`, and `from/to` syntaxes.

### Security

- Documented the two new v0.2 attack surfaces in `SECURITY.md`: the syslog UDP listener is unauthenticated/spoofable by protocol design (keep it on a trusted network segment), and LLM triage output is advisory and enum-constrained but not immune to prompt injection.
- Capped the Ollama HTTP response read at 1 MiB to bound memory use against a runaway/hostile local response.

### Verified live (2026-07-01)

Full Docker stack (Docker Desktop 4.80.0 / engine 29.6.1): a real UDP syslog packet sent from the host to the newly-published `5514/udp` port was received by the container's live listener and indexed; 15 Cisco ASA denies to distinct ports fired the port-scan rule; 5 Windows 4624 logons to distinct hosts fired the lateral-movement rule; the existing brute-force rule fired unaffected. All three produced a rule alert AND a WS-5 AI triage verdict (`StubLLM`, since no `OLLAMA_URL` was configured for this run — confirming the documented fallback path), and all three rendered live in the dashboard via `GET /api/alerts`.

## [0.1.0] - 2026-06-30

### Added

- **Full detection pipeline** — end-to-end flow: collect → normalize (OCSF) → detect → index → dashboard. Every stage is independently testable and wired together in a single `docker compose up`.

- **4 log source parsers** — Linux SSH (`/var/log/auth.log`), Cisco ASA syslog, Windows Active Directory EventID 4625 (failed logon), and VMware vSphere. Each parser emits a typed OCSF `Authentication` event.

- **Brute-force detection rule** — fires when a single IP accumulates 10 failed authentications within a 60-second window. Threshold and window are YAML-configurable; no code change required to tune sensitivity.

- **Contract-first architecture** — 7 machine-readable contracts (OCSF event schemas, OpenAPI specs for internal HTTP surfaces, Sigma rule schema) committed alongside code. Contracts are the source of truth; implementations are verified against them in CI.

- **Shared message bus abstraction** — a single `Bus` interface with two concrete backends: an in-memory implementation for unit and acceptance tests (zero infrastructure), and a Redis Streams implementation for production. Services never import a backend directly.

- **Shared runner** — common event-loop component used by every service. Provides ack-after-handler semantics, configurable redelivery on failure, a dead-letter queue for poison messages, and a `/health` HTTP endpoint that CI and Docker health checks hit.

- **Deterministic alert IDs (T7)** — alert IDs are derived from a stable hash of the triggering evidence. Re-processing the same log stream produces identical IDs, making the pipeline idempotent under at-least-once delivery.

- **Global window counter (T6)** — sliding-window counts are stored in Redis sorted sets (`ZCOUNT`). All replicas share a single counter, so horizontal scaling does not split detection windows or cause missed alerts.

- **Zero-infrastructure acceptance test (`make e2e`)** — the full pipeline (parse → detect → index) runs in-process with the in-memory bus. No Docker, no Redis, no OpenSearch required locally. The same test is the CI gate.

- **Live dashboard** — a browser-based UI served by nginx, which also acts as a reverse proxy to OpenSearch. No CORS configuration needed; the browser talks only to nginx.

- **Auto-feeder (devkit-feeder)** — a companion container that injects a synthetic brute-force log sequence on `docker compose up`. A real alert appears in the dashboard within seconds of the stack starting, with no manual curl commands.

- **Secret scanning in CI** — gitleaks runs on every push and pull request. Any credential committed by mistake blocks the build before it reaches reviewers.

- **Apache-2.0 license** — permissive license; use in commercial products, fork freely.

[Unreleased]: https://github.com/supermhel/argus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/supermhel/argus/releases/tag/v0.1.0
