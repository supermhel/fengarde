# Security Policy

FENGARDE is a Security Information and Event Management (SIEM) tool. We take the
security of the project — and the safety of anyone running it — seriously. This
document describes the **current threat boundary** (what FENGARDE does and does not
protect against today) and **how to report a vulnerability**.

---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

you may use **Security → Report a vulnerability**.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a proof-of-concept rule, log line, or request is ideal).
- The affected service / file and version or commit.

**What to expect:**

- Acknowledgement of your report within a few business days.
- An initial assessment and, where applicable, a coordinated disclosure timeline.
- Credit in the release notes if you would like it.

---

## Threat boundary

FENGARDE is a **local, single-host development and demonstration stack**. It is
**not** hardened for production or internet exposure. Sections below carry the
milestone that introduced them (v0.1 network boundary → v0.4 opt-in shared-secret
auth → M4 multi-tenancy + RBAC + webhooks + plugins) — each section's own
label is the accurate version marker; don't infer an overall repo version from
this file's title. Understand these boundaries before running it:

### 1. Localhost / Compose-network only — not internet-exposed

All v0.1 services are intended to run on `localhost` or inside the Docker Compose
network on a trusted machine. They are **not** designed to be reachable from the
public internet or an untrusted network.

- Do **not** expose the published ports (`6379`, `9200`, `5601`, `8000`, `8080`)
  to untrusted networks. As of v0.4, all published ports (`6379`, `9200`, `5601`,
  `8000`, `8080` — and `9090`/`3000` where the stack runs Prometheus/grafana)
  are bound to `127.0.0.1` in `infra/docker-compose.yml` by default — rebinding
  them to `0.0.0.0` is a deliberate choice you're making, not an accident.
- The bundled OpenSearch runs with its security plugin **disabled** for
  zero-friction local development (`DISABLE_SECURITY_PLUGIN=true` in
  `infra/docker-compose.yml`). It must not be exposed beyond the local host.
- **Grafana** (opt-in `observability` profile, loopback-bound `127.0.0.1:3000`)
  ships with a default `admin`/`admin` credential
  (`GF_SECURITY_ADMIN_PASSWORD=admin` in `infra/docker-compose.yml`). Change it
  before enabling the profile on any host where port 3000 is reachable beyond
  localhost — it is protected only by the loopback binding, not by any auth
  beyond that default password.

### 2. Authentication is opt-in (v0.4+), layered up to real RBAC in M4.2

v0.1/v0.2/v0.3 shipped with **no authentication at all** — anyone who could
reach a port could call its API. v0.4 added a minimal, honest, **opt-in**
shared-secret layer; M4.2 adds a second, independent opt-in layer
with actual per-user identity and roles:

- **`FENGARDE_API_KEY`** — a shared secret checked via `X-Api-Key` on the WS-3
  triage API and the WS-6 inventory API (`services/shared/authz.py`,
  `services/ws6-inventory/authz.py`). **Unset (default) = every request
  allowed**, with one warning logged at service start
  (`"auth disabled: FENGARDE_API_KEY not set"`). Set it and every write/read on
  those two APIs requires the matching header; the dashboard's nginx proxy
  injects it server-side so the browser never holds the key.
- **`FENGARDE_RBAC_DB`** (M4.2) — a SQLite file path. Unset (default) =
  the WS-3 triage/report endpoints stay exactly the pre-M4.2 API-key-only
  behavior; `/auth/login`, `/auth/logout`, `/auth/me` don't even exist. Set
  it and: real per-user accounts (`services/shared/users.py`, passwords
  hashed with `hashlib.scrypt` — stdlib, no new dependency — salted,
  constant-time verified), a role per user (`read_only` < `analyst` <
  `admin`, `services/shared/rbac.py`), a tenant per user (M4.1's
  `tenant_id` — a non-admin user can only reach their OWN tenant's alerts;
  cross-tenant requests get 404, never 403, so they don't confirm the
  resource exists), session cookies (`HttpOnly`, `SameSite=Strict`, 8h TTL,
  in-memory — a restart logs everyone out, no persistence across replicas
  yet), and per-username login rate limiting (5 failures / 5 min lockout,
  `services/shared/rbac.py::LoginRateLimiter`). First boot with an empty
  user DB creates one `admin` account **only if** the operator supplies
  `FENGARDE_ADMIN_PASSWORD` (read once at first boot; unset it afterwards).
  The service never generates, logs, or stores a plaintext credential —
  only the scrypt hash reaches disk — and there is no `admin/admin` or any
  other default credential, ever. Env var unset + empty store = fail-closed
  (nobody can log in) with a loud startup warning. See
  `services/ws3-indexer/test_rbac_api.py` for the full behavior proven over
  real HTTP.
- **`FENGARDE_SESSION_SECRET`** — required when `FENGARDE_SESSION_BACKEND=redis`
  (multi-replica session sharing, `services/shared/sessions.py`).
  `RedisSessionStore` HMAC-signs every session row it writes and rejects any
  row it reads back without a valid signature — so a process that can write
  to Redis directly (but doesn't hold this secret) cannot forge an
  authenticated session. Unset = `RedisSessionStore` **refuses to start**
  (fail loud, not a silent unsigned fallback); the default `memory` session
  backend does not need it. Generate a high-entropy value and keep it
  identical across every replica sharing the Redis session store — a
  mismatched secret across replicas makes every replica reject every other
  replica's sessions as forged.
- **MFA/TOTP** (`services/shared/mfa.py`, opt-in per user) — stdlib-only
  RFC 6238. `POST /auth/mfa/enable` provisions a secret (pending), `POST
  /auth/mfa/verify` confirms a code to activate it; once active, `/auth/login`
  requires a valid `totp_code`. Both MFA-config routes require the ACTING
  user's own current password in the request body, even though a valid
  session cookie is already presented — a stolen session cookie alone cannot
  disarm or re-provision an account's MFA, since re-provisioning
  unconditionally resets `totp_active` to 0. Rate-limited per username in a
  namespace separate from login lockout, and every attempt (success or
  failure) is written to the audit log below.
- **Admin audit log** (`services/ws3-indexer/audit.py`, always on when RBAC is
  enabled) — append-only JSONL, capacity-capped (oldest entries tail-trimmed,
  never rewritten in place), fail-open (a write failure is swallowed and
  logged, never breaks the request it's auditing). Records login
  success/failure, triage updates, and report generation. `GET /audit`
  requires the `admin` role. Default location is a path inside the
  ws3-indexer container's own tree (`FENGARDE_AUDIT_LOG` to override) — on an
  ephemeral container filesystem this does not survive a restart unless the
  path is mounted to a persistent volume; treat it as operational trail, not
  a durable compliance record, unless you mount it.
- **Dashboard basic-auth** — opt-in via the `infra/docker-compose.auth.yml`
  override (nginx `auth_basic` + htpasswd). The main compose file ships this
  **off by default** so `docker compose up` stays zero-prerequisite.
- **Redis `AUTH`** — opt-in via `REDIS_PASSWORD`; unset = no password,
  matching prior behavior.
- **OpenSearch's security plugin stays disabled** (see §1) — TLS/cert
  management for it is out of scope; the mitigation remains the network
  boundary (`127.0.0.1`-bound ports, never publish beyond localhost).

**What M4.2's RBAC does NOT give you:** TLS anywhere (see
`docs/deployment.md` for a reverse-proxy example), protection for
OpenSearch/Dashboards/the syslog listener (still `FENGARDE_API_KEY`/network-
boundary only), multi-replica session sharing (sessions are in-process —
a real multi-replica RBAC deployment needs a shared session store, tracked
as a follow-up, not built since it needs a live Redis to test against), or
coverage of the WS-6 inventory API (RBAC is wired into WS-3's triage/report
routes only this pass — WS-6 stays `FENGARDE_API_KEY`-only). If you need
TLS or don't yet need real per-user accounts, `FENGARDE_API_KEY` behind a
reverse proxy/VPN you control remains the right minimum for a trusted LAN.

### 3. Rule files are executed by the detection engine — only run trusted rules

The detection engine (WS-4) loads and evaluates **rule files** from
`contracts/rules/`. Rule conditions are part of the engine's evaluation path.
**Treat rule files like code:** only load rules you have written or reviewed and
trust. Do not run rule files from untrusted sources. When accepting a community
rule via a pull request, review its `condition` and fields as carefully as you
would review code.

### 4. Demo credentials must not leak

The local stack is configured for convenience, not secrecy. Never commit a real
`.env`, real credentials, or production secrets to the repository. Default/demo
credentials must never be reachable from outside the Compose network.

### 5. Syslog UDP ingestion is unauthenticated — keep it on a trusted segment

v0.2 adds a real syslog UDP listener in WS-1 (`SYSLOG_UDP_PORT`, default `5514`).
Syslog over UDP is **inherently unauthenticated and spoofable** — there is no
sender verification. Anyone who can reach the port can inject arbitrary log lines,
which become events in the pipeline (event spoofing / detection poisoning / noise).
Bind it only to a trusted network segment or management VLAN; do not expose it to
untrusted networks. This is a property of the syslog protocol, not a bug.

### 6. LLM triage (WS-5) is advisory and prompt-injectable

v0.2 wires WS-5 to a local LLM (Ollama). Normalized event content — which can
include attacker-controlled log fields — is placed into the triage prompt, so a
crafted log line can attempt **prompt injection** to skew the model's verdict.
Two things bound the blast radius: (a) the verdict is **advisory** — it annotates
an alert that detection **already** raised; it does not gate or suppress detection;
and (b) model output is coerced to a fixed enum (`verdict`/`level`) with a safe
default, so malformed/hostile output cannot inject arbitrary data downstream.
Point `OLLAMA_URL` only at a local/trusted model; treat the triage summary as an
untrusted hint, not ground truth.

### 7. Triage API (WS-3) is an unauthenticated write surface

v0.3 adds a triage HTTP API in WS-3 (`TRIAGE_PORT`, default `8013`): `POST
/alerts/{id}/triage` sets a status + analyst note on any alert. Like every other
service it has **no authentication** (see the out-of-scope list) — anyone who can
reach the port can set/clear the triage state of any alert (tamper with an
investigation, clear a note, mark a real alert `false_positive`). Blast radius is
bounded: it touches only the additive `triage` field (never the alert's detection
fields), body size and note length are capped, status is enum-validated, the
handler thread never crashes on malformed input, and concurrent writes to one
alert are serialized against lost updates within a single replica. Keep the port
on the Compose/management network only — the dashboard reaches it
container-to-container; do **not** publish it to untrusted networks. Concurrent
writes are protected at two layers: an in-process lock (single replica) plus
OpenSearch **optimistic concurrency** (`if_seq_no`/`if_primary_term` CAS with
bounded retry, surfacing exhaustion as an honest 409) for writers the lock can't
see — another ws3 replica against a shared cluster. The CAS wire format is
unit-tested against a fake transport, and has been **proven live** (2026-08-11,
`test_opensearch_cas_concurrency_live.py`, 8 real threads racing a real 3-node
cluster, sensitivity-verified: deliberately breaking the CAS lost 7/8 writes,
confirming the test actually measures concurrency control) — wired into CI's
`opensearch-integration` job since 2026-08-21 so this can't go stale again.

### 8. On-disk spool (WS-1 B2) stores raw events in cleartext

The opt-in zero-loss backpressure spool (`SYSLOG_SPOOL_PATH`, off by default)
writes shed/undelivered raw syslog events to a local JSONL file, which can contain
sensitive log content in cleartext. When you enable it, place the spool on a volume
with restrictive filesystem permissions (not world-readable) and a retention
policy; it is a local buffer, not an audit store.

### 9. Outbound alert webhooks (M4.4) send alert content to operator-configured URLs

Opt-in via `contracts/webhooks/*.yml` (ships empty — no files, no outbound
requests, ever); see `docs/webhooks.md` and `contracts/webhooks/README.md`.
Each configured webhook POSTs matching alert documents — which can contain
attacker-influenced fields (source IPs, usernames, rule titles built from log
content) — to a URL an **operator**, not an attacker, configures in a file
that ships to disk, never derived from event content itself. This is a data
egress path you are opting into, same posture as WS-5's outbound LLM calls
(§6): only point a webhook at a destination you trust with your alert data.

- **Authenticity, not confidentiality**: deliveries are HMAC-SHA256 signed
  (`X-Fengarde-Signature-256`, verified with `hmac.compare_digest`) so a
  receiver can confirm a request actually came from this deployment and
  wasn't tampered with in transit — but the body itself is **not**
  encrypted beyond whatever TLS the `url` scheme provides. Use `https://`
  URLs for anything beyond a local trusted network; `http://` is accepted
  (useful for a same-host/Compose-network receiver in dev) but sends alert
  content in cleartext.
- **Secret handling**: `secret_env` in a webhook config names an environment
  variable, never the secret itself — `contracts/webhooks/*.yml` stays safe
  to commit (§4). An unset secret env var fails that one webhook closed
  (never sends an unsigned request); it does not affect other configured
  webhooks.
- **No SSRF surface from event content**: the destination URL comes only
  from the operator-authored config file, never from a field on the alert
  or the triggering event — a malicious log line cannot redirect a webhook
  to an attacker-chosen internal address.
- **At-least-once, not exactly-once**: bounded retries on connection errors
  and 5xx (never on 4xx) mean a rare duplicate delivery is possible;
  receivers should dedup on `X-Fengarde-Delivery-Id`. There is no
  dead-letter queue for exhausted webhook retries yet (unlike the bus's own
  DLQ) — a receiver down for an extended outage silently misses alerts
  fired during that window.

---

### 10. API key pepper defaults empty (defense-in-depth inactive without it)

`FENGARDE_API_KEY_PEPPER` (WS-6 keystore, `services/ws6-inventory/keystore.py`)
defaults to an **empty** byte string. When unset, API keys are HMAC-SHA256-hashed
with an empty key, so a leak of the keys table alone still exposes every key to
an offline brute force — the pepper's entire purpose (protecting against a
DB-only leak *without* also leaking the pepper) is **inactive**. A startup
warning is logged. **Set `FENGARDE_API_KEY_PEPPER` to a high-entropy random
value for production deployments.** Note the trade-off aired in `SSOT.md`:
rotating the pepper invalidates all provisioned keys by design (now detected and
announced via a pepper canary, but re-provisioning remains the recovery path).

**Related defaults worth remembering here, documented in full in their own
sections:**

- **Webhook secrets come from env vars (`contracts/webhooks/*.yml`
  `secret_env`)** — the repo never commits a secret itself; a config names an
  environment variable that must be set at deploy time (`secret_env`), and an
  unset secret makes that one webhook fail closed rather than send an unsigned
  request. See §9.
- **Grafana default credential** — the opt-in `observability` Grafana ships
  `admin`/`admin` until you change `GF_SECURITY_ADMIN_PASSWORD`; loopback-bound,
  but change it before exposing beyond localhost. See §1.
- **TLS / reverse-proxy** — FENGARDE services provide **no TLS of their own**.
  Production deployments are expected to terminate TLS at a reverse proxy (see
  `docs/deployment.md` for a working nginx example) and to keep the backend
  ports on the Compose/management network. Any `http://` (including webhook
  URLs and OLLAMA_URL) sends its content in cleartext once it leaves that
  network boundary.

---

## Out of scope

The following are **known** and **deferred** to later releases:

- Full authentication / authorization is still **opt-in everywhere**, never
  default-on. v0.4 added a shared-secret layer (§2); M4.2 added a second,
  independent opt-in layer with real per-user identity/roles/tenant scoping —
  but nothing forces either on, and the WS-3 triage API (§7) and WS-6 inventory
  API stay open by default like every other service unless an operator sets the
  relevant env var.
- TLS between services and for external endpoints (see `docs/deployment.md` for
  a reverse-proxy TLS example — documented, not built-in).
- Hardened, production-grade OpenSearch security configuration (§1 — the
  security plugin stays disabled; mitigation is the network boundary only).
- Multi-replica / HA is opt-in, not the default deployment. Redis Sentinel
  failover (`make ha-up`) is built and live-kill-tested (automatic promotion,
  app-tier recovery with zero lost messages). 3-node OpenSearch HA ships in
  the same compose profile and is now also live-kill-tested (2026-08-07,
  `services/ws3-indexer/storage/test_opensearch_ha_failover_live.py`: brought
  up the real 3-node cluster, `docker kill`'d `opensearch-1` directly,
  confirmed the write path still succeeded via round-robin failover to a
  surviving node, confirmed the cluster returned to `status: green` after
  restarting the killed node). The triage write path is multi-replica-safe
  via optimistic concurrency (§7) and RBAC sessions are single-process only
  unless `FENGARDE_SESSION_BACKEND=redis` (§2).
  **`services/ws1-collectors`'s UDP syslog listener still has no active/passive
  pair and is a genuine single point of failure with no failover option
  today** — unlike Redis/OpenSearch, this component has no opt-in HA profile;
  a deployment where ingestion availability matters needs its own
  network-level redundancy (e.g. a VIP/keepalived pair — active/active on the
  same UDP port double-ingests, not usable, see the design doc below) until
  this is addressed upstream. **Two related gaps closed 2026-08-21** (steps
  1-2 of a design scoped in `fengarde-sec`'s
  `docs/2026-08-06-ingestion-edge-redundancy.md`, private repo): (1) the
  opt-in zero-loss spool (`SYSLOG_SPOOL_PATH`, §8 above) now mounts on a
  named Docker volume (`ws1-spool`, `infra/docker-compose.yml`) instead of
  the container's writable layer — before this, an operator who enabled the
  spool without also hand-editing the compose file to add a volume mount got
  a spool that silently vanished on every container recreate, defeating the
  entire point of turning it on; verified with a real restart-simulating
  test (a second `BoundedSpool` instance opened against the same path a
  first instance left events in). (2) `/metrics`' `syslog_udp` block now
  reports `seconds_since_last_event`, and a background watchdog
  (`SYSLOG_SILENCE_WARN_S`, default 300s, 0 disables) logs once per outage
  when nothing has arrived — before this, a dead/misdirected/firewalled
  source produced no signal at all: `/health` only ever probed the bus, so a
  silently-starved ingest edge looked identical to a legitimately quiet
  network. Steps 3-4 of that design (an actual VIP active/passive failover
  pair) remain not built, correctly gated behind a demonstrated need per the
  design doc's own recommended stop-point.
- AI-triage prompt-injection guardrails. The AI service calls a local LLM; its
  verdict is advisory and enum-constrained (see threat-boundary §6), but robust
  prompt-injection defenses are still deferred.

**No longer out of scope, moved to §2/§9 above:** multi-tenancy and per-tenant
isolation (M4.1) and per-user RBAC (M4.2) shipped and are documented as opt-in
layers, not absent features — don't cite this section as saying otherwise.

Reports about these documented, out-of-scope limitations are welcome as
**feature requests**, but they are not treated as vulnerabilities against the
current release.

---

## Supported versions

FENGARDE is pre-1.0. Security fixes target the latest `main` and the current
release line only.

| Version | Supported |
|---------|-----------|
| `main` (unreleased work) | ✅ |
| v0.5.0 (latest tag) | ✅ |
| v0.4.0 | ✅ |
| v0.3.0 | ❌ (superseded; upgrade to v0.5.0) |
| < v0.3.0 | ❌ |
