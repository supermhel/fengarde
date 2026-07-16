# Security Policy

FENGARDE is a Security Information and Event Management (SIEM) tool. We take the
security of the project — and the safety of anyone running it — seriously. This
document describes the **current threat boundary (v0.4)** (what FENGARDE does and does not
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

## Threat boundary (v0.4)

FENGARDE is a **local, single-host development and demonstration stack**. It is
**not** hardened for production or internet exposure. Sections below carry the
release that introduced them (v0.1 network boundary → v0.4 opt-in auth);
everything is current as of v0.4. Understand these boundaries before running it:

### 1. Localhost / Compose-network only — not internet-exposed

All v0.1 services are intended to run on `localhost` or inside the Docker Compose
network on a trusted machine. They are **not** designed to be reachable from the
public internet or an untrusted network.

- Do **not** expose the published ports (`6379`, `9200`, `5601`, `8000`, `8080`)
  to untrusted networks. As of v0.4, `6379`/`9200`/`5601` are bound to
  `127.0.0.1` in `infra/docker-compose.yml` by default — rebinding them to
  `0.0.0.0` is a deliberate choice you're making, not an accident.
- The bundled OpenSearch runs with its security plugin **disabled** for
  zero-friction local development (`DISABLE_SECURITY_PLUGIN=true` in
  `infra/docker-compose.yml`). It must not be exposed beyond the local host.

### 2. Authentication is opt-in (v0.4+), layered up to real RBAC in v0.6 (M4.2)

v0.1/v0.2/v0.3 shipped with **no authentication at all** — anyone who could
reach a port could call its API. v0.4 added a minimal, honest, **opt-in**
shared-secret layer; v0.6 (M4.2) adds a second, independent opt-in layer
with actual per-user identity and roles:

- **`FENGARDE_API_KEY`** — a shared secret checked via `X-Api-Key` on the WS-3
  triage API and the WS-6 inventory API (`services/shared/authz.py`,
  `services/ws6-inventory/authz.py`). **Unset (default) = every request
  allowed**, with one warning logged at service start
  (`"auth disabled: FENGARDE_API_KEY not set"`). Set it and every write/read on
  those two APIs requires the matching header; the dashboard's nginx proxy
  injects it server-side so the browser never holds the key.
- **`FENGARDE_RBAC_DB`** (M4.2, v0.6) — a SQLite file path. Unset (default) =
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
  user DB auto-creates one `admin` account with a random password, printed
  **once** to the service log — there is no `admin/admin` or any other
  default credential, ever. See `services/ws3-indexer/test_rbac_api.py` for
  the full behavior proven over real HTTP.
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
unit-tested against a fake transport; like the rest of the OpenSearch adapter it
has not yet been exercised against a live cluster.

### 8. On-disk spool (WS-1 B2) stores raw events in cleartext

The opt-in zero-loss backpressure spool (`SYSLOG_SPOOL_PATH`, off by default)
writes shed/undelivered raw syslog events to a local JSONL file, which can contain
sensitive log content in cleartext. When you enable it, place the spool on a volume
with restrictive filesystem permissions (not world-readable) and a retention
policy; it is a local buffer, not an audit store.

### 9. Outbound alert webhooks (M4.4, v0.6) send alert content to operator-configured URLs

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

## Out of scope (as of v0.4)

The following are **known** and **deferred** to later releases:

- Full authentication / authorization — v0.4 added an opt-in shared-secret
  layer (§2), but per-user identity, roles, and default-on auth remain out of
  scope. The WS-3 triage API (§7) is open by default like every other service.
- TLS between services and for external endpoints.
- Multi-tenancy and per-tenant isolation.
- Hardened, production-grade OpenSearch security configuration.
- Multi-replica / HA deployment overall (Redis/OpenSearch single points of
  failure; HA is design-only). The triage write path is already multi-replica
  safe via optimistic concurrency (§7), but no other multi-replica behavior has
  been designed or tested.
- AI-triage prompt-injection guardrails. As of v0.2 the AI service calls a local
  LLM; its verdict is advisory and enum-constrained (see threat-boundary §6), but
  robust prompt-injection defenses are still deferred.

Reports about these documented, out-of-scope limitations are welcome as
**feature requests**, but they are not treated as vulnerabilities against the
current release.

---

## Supported versions

FENGARDE is pre-1.0. Security fixes target the latest `main` and the current
release line only.

| Version | Supported |
|---------|-----------|
| v0.1 (`main`) | ✅ |
| < v0.1 | ❌ |
