# Security Policy

ARGUS is a Security Information and Event Management (SIEM) tool. We take the
security of the project — and the safety of anyone running it — seriously. This
document describes the **v0.1 threat boundary** (what ARGUS does and does not
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

## v0.1 threat boundary

ARGUS v0.1 is a **local, single-host development and demonstration stack**. It is
**not** hardened for production or internet exposure. Understand these boundaries
before running it:

### 1. Localhost / Compose-network only — not internet-exposed

All v0.1 services are intended to run on `localhost` or inside the Docker Compose
network on a trusted machine. They are **not** designed to be reachable from the
public internet or an untrusted network.

- Do **not** expose the published ports (`6379`, `9200`, `5601`, `8000`, `8080`)
  to untrusted networks.
- The bundled OpenSearch runs with its security plugin **disabled** for
  zero-friction local development (`DISABLE_SECURITY_PLUGIN=true` in
  `infra/docker-compose.yml`). It must not be exposed beyond the local host.

### 2. No authentication in v0.1 — by design

There is **no authentication or authorization** on any ARGUS service in v0.1.
Anyone who can reach a service's port can call its API. This is an accepted,
documented limitation for the local demo stack. Authentication is **out of scope
for v0.1** and is planned for a later release. Until then, the mitigation is the
network boundary above: keep the stack on a trusted, non-exposed host.

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
container-to-container; do **not** publish it to untrusted networks. Known gap: a
**multi-replica lost update** with the OpenSearch backend (two ws3 processes
racing a triage write can lose one; the in-process lock can't span processes) —
needs OpenSearch optimistic concurrency, deferred with the unbuilt HA work.

### 8. On-disk spool (WS-1 B2) stores raw events in cleartext

The opt-in zero-loss backpressure spool (`SYSLOG_SPOOL_PATH`, off by default)
writes shed/undelivered raw syslog events to a local JSONL file, which can contain
sensitive log content in cleartext. When you enable it, place the spool on a volume
with restrictive filesystem permissions (not world-readable) and a retention
policy; it is a local buffer, not an audit store.

---

## Out of scope for v0.1

The following are **known** and **deferred** to later releases (tracked in the
[build plan](docs/superpowers/specs/2026-06-27-argus-v0.1-build-plan.md)):

- Authentication / authorization on services — including the WS-3 triage API
  (§7), which is an unauthenticated write surface like every other service.
- TLS between services and for external endpoints.
- Multi-tenancy and per-tenant isolation.
- Hardened, production-grade OpenSearch security configuration.
- Multi-replica / HA correctness — e.g. the triage lost-update window under a
  multi-process OpenSearch backend (§7). Single-replica deployments are unaffected.
- AI-triage prompt-injection guardrails. As of v0.2 the AI service calls a local
  LLM; its verdict is advisory and enum-constrained (see threat-boundary §6), but
  robust prompt-injection defenses are still deferred.

Reports about these documented, out-of-scope limitations are welcome as
**feature requests**, but they are not treated as vulnerabilities against v0.1.

---

## Supported versions

ARGUS is pre-1.0. Security fixes target the latest `main` and the current
release line only.

| Version | Supported |
|---------|-----------|
| v0.1 (`main`) | ✅ |
| < v0.1 | ❌ |
