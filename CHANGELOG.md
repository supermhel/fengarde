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
- **After-hours privileged-logon rule** (`common_after_hours_admin.yml`) — Windows 4672 special-privilege assignment (class 1002 activity 2) outside a configurable business-hours window.
- **Rule grammar: comparison operators + allowlists + time-of-day** — `gt/gte/lt/lte/ne` operators, a `not_in: <allowlist>` suppression clause (`contracts/allowlists/*.yml`, CIDR + exact match), and an `outside_hours` time-of-day/day-of-week predicate (with `tz_offset_minutes` and midnight-wrapping windows) in the boolean evaluator. Operators fail closed on malformed input; a missing/malformed allowlist *file* fails open on the rule (keeps firing) but closed on suppression (never suppresses). Grammar documented in `contracts/sigma-convention.md`.
- **Rule prefilter** — the detector buckets rules by their `class_uid` equality selection and only evaluates candidate rules per event, replacing the O(rules×events) linear scan. Alert-firing behavior verified byte-identical before/after.
- **Anti-dormancy guardrail** (`tools/check_rule_producers.py`, in `run_all_tests.sh`) — proves each rule's equality selections/`group_by`/`distinct_field` are satisfiable by an actual (path, value) pair some registered parser emits against a real fixture.
- **Detection coverage map** (`contracts/detection-coverage.md`) — ground truth of OCSF classes emitted by shipped parsers vs. rule coverage.
- **Triage workflow (v0.3 C1)** — status + analyst note per alert: new WS-3 triage HTTP API (`GET/POST /alerts/{id}/triage`, `TRIAGE_PORT` default 8013), `find_alert()` cross-index lookup in both storage backends, dashboard status dropdown + note field wired via a same-origin `/api/triage` nginx path. Triage field is OCSF-additive with tolerant-reader defaults.
- **RedisBus test parity** — `services/shared/test_runner.py` parametrized so the full MemoryBus behavioral suite also runs against RedisBus in CI's redis-integration job.

### Fixed

- **Prefilter mis-bucketing of multi-class rules** — the detector bucketed a rule under the *first* selection's `class_uid`, so a rule spanning classes (e.g. `(class 3002) OR (class 4001)`) was never evaluated for the second class's events: a silent missed detection. Bucketing now probes the condition with the real T4 parser and only buckets under X when class X is provably *necessary* for any match (`a and b` with classless `b` stays bucketed; `a or b`, multi-class OR, and negations fall back to the always-evaluated catch-all). All 8 shipped rules keep their exact buckets — no shipped rule was affected; the bug bit only contributor-style multi-class rules.
- **Triage API lost-update race** — concurrent `POST /alerts/{id}/triage` to the same alert could silently drop one update: the read-modify-write over `ThreadingHTTPServer`'s one-thread-per-request model had no lock. Serialized the critical section with a process-wide write lock (triage writes are rare/cheap; GETs and writes to other alerts are unaffected).
- **Triage API note-clearing bug** — a status-only update unconditionally overwrote `note` to `""`, silently wiping an existing analyst note. `note` is now a true partial update: absent from the body → preserved; present as `""` → deliberately cleared (a distinct, intentional action).
- **WS-6 inventory upsert race** — the `SELECT`-then-`INSERT` in `InventoryStore.upsert` was not atomic; two concurrent observations of the same new MAC both saw no row and both inserted, the second hitting the primary key with an `IntegrityError` surfaced as a 500. Serialized the read-modify-write with an in-process lock (concurrency regression test added).
- Dashboard `renderGlobal()` called async `getAlerts()` without `await`, so live-alert rendering operated on a Promise and threw in the browser — silently broken since live alerts shipped.
- `storage/opensearch.py` used `urllib.parse.quote()` without importing `urllib.parse` — the first real OpenSearch `index()` call would have raised `AttributeError`.
- `storage/opensearch.py::find_alert()` returned an empty dict on a hit with missing/empty `_source`; a triage update on such a hit re-indexed only the triage field and wiped the alert's original fields. Now returns `None` (treated as not-found).
- Runner worker called `bus.consume()` with the default 5 s Redis `block_ms`, leaving it deaf to a shutdown set mid-block so `serve()`'s worker join could time out (CI `redis-integration` hang). Now bounded by a `consume_block_ms` (default 1 s) so shutdown latency stays under the join timeout.

### CI

- Added `.gitleaks.toml` allowlisting canonical-UUID values so rule/entity identifiers (`contracts/rules/*.yml` ids and their test constants) don't trip the `generic-api-key` heuristic. Default ruleset otherwise unchanged; real (non-UUID-shaped) secrets are still detected.

### Added (v0.3 A5 — event enrichment)

- **Offline event enrichment** (`services/ws2-normalization/enrichment/`) — a WS-2 post-normalize stage that adds OCSF-additive context to events from local data files only (no external calls; air-gap-safe): `src_endpoint.reputation` (score + categories) from a local IOC list (`contracts/enrichment/ioc.yml`, exact-IP and CIDR, longest-prefix match) and `src_endpoint.location` (country) from a local CIDR→country map (`contracts/enrichment/geoip.yml`, a lightweight stand-in for a full GeoIP DB, with `INTERNAL` tagging for RFC1918). Additive and fail-open: it never overwrites a parser-set field, and a missing/malformed data file, bad IP, or any error leaves the event untouched and flowing — nothing hard-depends on these fields (tolerant readers). Enriched events still validate against Contract A. Wired into `normalize_one` (parse → enrich → validate). Enriched fields added to the OpenSearch event mappings (common/bank/dc) so they're queryable. Unblocks reputation- and geo-keyed detection rules (a follow-up; no rule consumes these fields yet, so alert behavior is unchanged). 12 unit tests.

### Added (v0.3 B4 — rule validation gate)

- **`tools/validate_rules.py`** — a contributor-facing static validator for `contracts/rules/*.yml`, wired into `run_all_tests.sh`/CI. Reuses the real WS-4 engine's tokenizer/parser and operator set (so "valid" means exactly "the runtime will evaluate this") to check: schema (title, canonical-UUID id, level enum, `siem.score_weight` bounds, stateful window/threshold pairing), that the `condition` parses under the T4 evaluator and references only defined selections, that every selection operator is one the engine implements (unknown operators rejected, not silently fail-closed at runtime), that `not_in` allowlists and `outside_hours` windows are well-formed and reference existing files, and that rule ids are unique. Complements the anti-dormancy `check_rule_producers.py`. 20 unit tests (`tools/test_validate_rules.py`) — every check has an adversarial reject case.

### Added (v0.3 B2 — backpressure)

- **Ingest-edge shedding** — `SyslogUDPServer` now sheds excess datagrams via a token bucket (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s) before they ever reach the bus, rather than letting an unbounded flood grow the Redis stream toward OOM. UDP is connectionless, so shedding (not blocking) is the only lever at this edge; the shed-warning log is itself throttled to 1/sec so a flood can't become a logging DoS.
- **Stream-depth monitoring** — `Bus.depth(topic)` on both backends; `services/ws1-collectors/main.py` runs a background watchdog logging a warning when `raw.events` depth crosses `RAW_EVENTS_DEPTH_WARN` (default 100000). Monitoring-only — the hard cap is the ingest-edge shedding above, not this watchdog.
- No mid-pipeline `MAXLEN` trimming was added or is planned — trimming would silently drop unconsumed events, an audit-completeness violation for a bank.
- **Zero-loss-under-flood fallback (opt-in)** — `services/ws1-collectors/collectors/spool.py`'s `BoundedSpool`: a FIFO, byte-capped, disk-backed JSONL queue. A shed or produce-failed datagram is spooled instead of lost when `SYSLOG_SPOOL_PATH` is set (`SYSLOG_SPOOL_MAX_BYTES`, default 64 MiB); a background thread replays it into the bus in order once capacity/connectivity returns. Still bounded — once the spool itself is full, the event is truly lost, but distinctly counted (`events_lost`) rather than silently merged into the plain shed counter. Disabled by default.

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
