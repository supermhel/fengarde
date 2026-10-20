# Adversarial Security Review — FENGARDE

**Reviewer role:** adversarial security reviewer (penetration-tester / SIEM security architect perspective), one member of a multi-agent review swarm.
**Scope:** `services/`, `contracts/`, `infra/`, `tools/`, `.github/workflows/`, static source review only — no live cluster/exploit run.
**Method:** manual code review targeting injection (log/query/command), authn/authz, deserialization, SSRF, path traversal, secrets, crypto, input validation on attacker-controlled log data, privilege escalation, supply chain. Cross-checked every finding against `SECURITY.md`'s documented threat boundary before reporting, to avoid re-flagging accepted/known risk as new.

**Headline:** this codebase has clearly been through prior adversarial passes (see SSOT.md's "F1/F3/P0-P2 adversarial audit" references) — auth, session, CSRF, SQL, OpenSearch query construction, webhook SSRF, and dashboard XSS are all defended carefully and mostly correctly, with the reasoning documented inline. Findings below are the gaps that survived that scrutiny.

---

## Findings (ranked by severity)

### 1. MEDIUM — Attacker-controlled event fields feed unescaped into `alert_id`/window-key construction, enabling deliberate alert collision (SIEM-blinding via ID squatting)

**Where:** `services/ws4-detection/engine.py::alert_key()` (lines ~415-477) and the stateful window-counter key at line ~525.

```python
group = str(get_path(event, self.group_by))
...
return f"{self.id}:{tenant}:{group}:{bucket}"
```

`self.group_by` for several shipped stateful rules points at a field an attacker fully controls:

| Rule | `group_by` |
|---|---|
| `common_password_spray.yml` | `actor.user.name` |
| `common_impossible_travel.yml` | `actor.user.name` |
| `common_lateral_movement.yml` | `actor.user.name` |
| `bank_mass_card_read.yml` | `actor.user.name` |
| `dc_mass_vm_delete.yml` | `actor.user.name` |
| `common_rapid_account_lifecycle.yml` | `unmapped.target_user.name` |

`actor.user.name` is populated verbatim, with **no length cap and no character filtering**, from raw log content — e.g. `services/ws2-normalization/parsers/linux_ssh.py` captures the SSH username with `(?P<user>\S+)` (any non-whitespace, colons included) straight out of a syslog line:

```
Failed password for invalid user evil:99999999 from 1.2.3.4 port 22 ssh2
```

and stores it as `event["actor"]["user"]["name"] = user` unchanged (`linux_ssh.py:126-127`). The OCSF schema (`contracts/ocsf-event.schema.json`) sets no `maxLength` on `actor`, so nothing downstream truncates or rejects it either.

That string is then joined with `:` as a delimiter into the alert identity with **no escaping of the delimiter inside the dynamic components**. `self.id` and `tenant` are safe (rule id is fixed; `tenant` is deployment-stamped, not per-event — confirmed via `services/shared/envelope.py::default_tenant()`), but `group` is attacker-chosen and can itself contain `:`. Because `OpenSearchStore.index()` is an **idempotent upsert keyed on this exact id** (`services/ws3-indexer/router.py` + `storage/opensearch.py::index()`), two different `(rule, tenant, group, bucket)` tuples that happen to format to the identical string collide onto **one stored document** — the later write silently overwrites the earlier one's `rule_title`, `score`, `src_endpoint`, message, etc.

This is a stronger consequence than the already-documented "unauthenticated syslog = spoofable, produces noise" risk (`SECURITY.md` §5): that section accepts *event spoofing / detection poisoning / noise*, but the specific mechanism here lets an attacker who can reach the syslog listener **deliberately overwrite the stored content of a specific existing/predictable alert** rather than merely adding noisy new ones — a targeted "blind the defender on this one alert" primitive, not just background noise. The engineering team was already aware of *accidental* collisions from this same key shape (see the `F1 follow-up` / `P1-1` comments in `alert_key()` about two tenants colliding) and fixed the tenant-scoping gap — but the fix assumed the delimiter itself is safe, which it isn't once a dynamic segment (`group`) can contain the delimiter.

**Exploit sketch:** attacker knows (a) a target rule's fixed `window_seconds` (all rule YAMLs are public/open-source) and (b) either the victim's `group_by` value (e.g. a known username under attack, learned by observing failed-login noise) or simply times their own crafted event to land in the same time bucket as an anticipated legitimate alert. Sending one UDP syslog packet with a crafted username causes WS-4 to compute the same `alert_id` as the targeted alert and re-index over it on the next matching burst.

**Recommendation:** never join attacker-influenced segments with a plain, unescaped delimiter into an identity string. Either (a) hash each dynamic segment (e.g. `hashlib.sha256(group.encode()).hexdigest()`) before joining, or (b) length-prefix each segment (`f"{len(group)}:{group}"`) so the delimiter inside a segment can't be confused with the real one, or (c) reject/replace `:` in `group` before use (cheap but a smaller behavior change). Apply the same fix to the window-counter key at engine.py:525/528/537, which has the identical shape.

---

### 2. LOW-MEDIUM — No container runs as a non-root user

**Where:** every service `Dockerfile` (`services/*/Dockerfile`, `services/devkit-feeder/Dockerfile`).

All eight Dockerfiles pin their base image by digest (good supply-chain hygiene — `FROM python:3.12-slim@sha256:...`) but **none set a `USER` directive**, so every container (including `ws1-collectors`, which parses attacker-controlled network input directly, and `ws7-dashboard`'s nginx, which serves to the browser) runs its main process as root inside the container. This is defense-in-depth, not a standalone exploit: there's no known RCE in this codebase today. But it's exactly the kind of gap that turns a *future* parser memory-safety bug or dependency CVE (stdlib `http.client`, PyYAML, redis-py, etc.) into a root-in-container compromise instead of an unprivileged one, and it's a one-line-per-Dockerfile fix (`RUN useradd -u 10001 -m app && chown -R app /app` + `USER app`) that costs nothing given these services don't bind privileged ports (syslog UDP already uses 5514, not 514, specifically to avoid needing root — `syslog_udp_server.py` docstring — so root isn't even required for the one service that might have wanted it).

**Recommendation:** add a non-root `USER` to each service Dockerfile; verify the syslog UDP bind and any file-write paths (spool, SQLite DBs) still work under the new UID via `make test`/`make up`.

---

### 3. LOW — Unbounded attacker-controlled string fields with no length cap before storage

**Where:** OCSF event fields sourced from raw log content (e.g. `actor.user.name`, `message`, hostnames) — `contracts/ocsf-event.schema.json` sets no `maxLength` on these, and most WS-2 parsers (e.g. `linux_ssh.py`) don't cap the captured groups before writing them into the event.

Contrast this with the code paths that *do* bound attacker-influenced input deliberately and explain why (`services/ws5-ai/llm_adapter.py`'s `_MAX_EVENT_CHARS`/`_MAX_REASONS_CHARS`, `services/ws3-indexer/triage_api.py`'s `_MAX_NOTE_CHARS`/`_MAX_BODY_BYTES`) — the same discipline isn't uniformly applied at parse time for OCSF event fields. A crafted, very long single log line (the raw-line length itself doesn't appear capped in `syslog_udp_server.py` beyond the UDP datagram's own ~65507-byte ceiling) becomes an equally long `actor.user.name`/`message`, inflating OpenSearch document size and the `alert_key`/window-key strings discussed in Finding 1. This is a mild amplifier of Finding 1 and a minor storage/DoS-adjacent nuisance on its own (bounded per-packet by UDP's own datagram limit, so not unbounded in the strict sense, but still uncapped relative to normal field sizes).

**Recommendation:** cap parser-extracted string fields (username, hostname, message) to a sane length (e.g. 256-1024 chars) at parse time, matching the discipline already used in WS-5/WS-3.

---

## Explicitly checked and found sound (noted so the rest of the swarm doesn't re-walk this ground)

- **SQL injection:** every `sqlite3` call site in `services/shared/users.py` and `services/ws6-inventory/store.py` is parameterized (`?` placeholders); the one f-string SQL (`PRAGMA user_version = {version}`) interpolates a fixed internal migration-list integer, never user input.
- **OpenSearch query injection:** `services/ws3-indexer/storage/opensearch.py` builds query DSL as native dicts passed through `json.dumps`, never string-concatenates a value into a query clause — a malicious `tenant_id`/`status`/`family` value becomes a literal term-filter value, not injected query syntax. List-endpoint parameters (`family`, `status`) are additionally enum-validated in `triage_api.py` before reaching the store.
- **Detection rule engine:** explicitly hand-rolled recursive-descent boolean evaluator (`engine.py`, `_eval_condition`) specifically to avoid `eval()` on contributor-supplied rule files — documented in-line as a deliberate choice.
- **Auth/session:** `FENGARDE_API_KEY` compared with `hmac.compare_digest`; passwords hashed with `hashlib.scrypt` (salted, constant-time verified, decoy-hash timing-equalized on unknown username); session tokens are `secrets.token_urlsafe(32)`; CSRF token is a second independent random value checked via `hmac.compare_digest`; cross-tenant/under-privileged requests get 404 not 403 (no existence oracle); login rate limiting is per-username and itself hardened against unbounded-dict-growth DoS.
- **XSS:** `services/ws7-dashboard/index.html` funnels every attacker-influenced field (rule titles, hostnames, IPs, usernames) through a shared `esc()` before any `innerHTML` write, with an explicit in-code comment calling out exactly this threat; report bodies are rendered via `textContent`, never `innerHTML`.
- **SSRF:** outbound webhook URLs (`services/ws3-indexer/webhooks.py`) come only from operator-authored YAML config, never from event/alert content — a crafted log line cannot redirect a webhook. Deliveries are HMAC-SHA256 signed and verified with `hmac.compare_digest`.
- **Deserialization:** no `pickle`/`eval`/`exec`/`yaml.load` (unsafe) anywhere in `services/` or `tools/`; all YAML parsing uses `yaml.safe_load`.
- **Secrets hygiene:** no hardcoded credentials found; `contracts/webhooks/*.yml` stores only an env-var *name* (`secret_env`), never the secret; first-boot admin password is read once from an env var and never logged/stored in plaintext (only the scrypt hash reaches disk).
- **Supply chain:** all `requirements.txt` pin exact versions; all Docker base images are pinned by digest; GitHub Actions workflows use least-privilege `permissions:` blocks and don't interpolate `github.event.*` (PR title/body) into a `run:` shell context, so there's no classic Actions script-injection vector; no `pull_request_target` usage.
- **ReDoS:** parser regexes reviewed are anchored/bounded; `mcp_agent.py`'s heuristic patterns carry an explicit in-line comment confirming no nested quantifiers on attacker-controlled input.

---

## Notes on already-documented, accepted risk (not re-flagged as new)

`SECURITY.md` already transparently documents and accepts: no default authentication on most services, unauthenticated/spoofable syslog UDP ingestion, OpenSearch security plugin disabled, cleartext on-disk spool, advisory/prompt-injectable LLM triage, and no TLS between services. These are honest, scoped, non-production-hardened defaults for a local/dev SIEM stack, not oversights — I did not re-report them as findings. Finding 1 above is reported specifically because its *consequence* (deliberate alert-content overwrite via ID collision) is more targeted than the general "spoofing produces noise" risk the docs describe, and is fixable independently of the broader unauthenticated-ingestion posture.
