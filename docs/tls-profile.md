# TLS profile (WP-3.1)

`infra/docker-compose.tls.yml` puts **Caddy** in front of the console
(`ws7-dashboard`) and the HTTP/JSON ingest endpoint (`ws1-collectors`
`/v1/ingest`), and REMOVES the plaintext publishes of those services — in
this profile they answer **only over TLS (443)**.

Local-CA default: the Caddyfile uses `tls internal`, so Caddy issues
self-signed certs from its own internal CA. No public DNS, no ACME, no cert
files to provision — it works on a bare hostname-less LAN box. (For a public
domain: drop `tls internal` and use your real hostname as the site name —
the ACME HTTP challenge then needs port 80 — exactly the documented Caddy
approach in `docs/deployment.md`.)

## Run

```bash
cd infra
docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls up -d
```

From a host that cannot resolve the internal site names, map them:

```bash
curl -k --resolve siem.internal:443:127.0.0.1 https://siem.internal/
printf '{"EventID": 4624, "Computer": "DC01", "TimeCreated": 1700000000000, "TargetUserName": "jdoe"}\n' \
  | curl -k --resolve ingest.internal:443:127.0.0.1 \
      -X POST 'https://ingest.internal/v1/ingest?source_type=windows_eventlog&format=ndjson' \
      -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' \
      -H 'Content-Type: application/x-ndjson' --data-binary @-
```

Back to the plaintext default:

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls down
docker compose -f docker-compose.yml up -d --remove-orphans
```

## What "only over TLS" means (and how it's enforced)

The override uses the compose-spec merge tag to REPLACE each service's ports
list instead of appending:

```yaml
services:
  ws7-dashboard:    { ports: !override [] }
  ws1-collectors:   { ports: !override [] }
```

`docker compose config` (merged) confirms: `ws7-dashboard`/`ws1-collectors`
have NO published ports (inner ports only), `caddy` publishes `443/tcp` and
is wired with `depends_on` to both. `tools/test_tls_profile.py` (fast tier)
pins the same facts statically, zero-infra.

TLS termination inside ws1/ws7 remains out of scope (the syslog transports
5514/5515 are intentionally NOT in the TLS profile — that is the RFC 5425
follow-up to WP-1.2).

## Verified against the compose stack (2026-11-04, measured)

Profile up (stack otherwise untouched; token from the operator's
`infra/.env`):

```
$ docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls ps caddy ws1-collectors ws7-dashboard
infra-caddy-1          Up        0.0.0.0:443->443/tcp
infra-ws1-collectors-1 Up (healthy)        (no published ports)
infra-ws7-dashboard-1  Up (healthy)        80/tcp   (inner only)

$ curl -sk -o /dev/null -w '%{http_code}\n' --resolve siem.internal:443:127.0.0.1 https://siem.internal/
200

$ curl -sk -w '%{http_code}\n' --resolve ingest.internal:443:127.0.0.1 \
    -X POST 'https://ingest.internal/v1/ingest?source_type=windows_eventlog&format=ndjson' \
    -H 'Authorization: Bearer <token>' -H 'Content-Type: application/x-ndjson' --data-binary @record.ndjson
{"source_type":"windows_eventlog","format":"ndjson","accepted":1,"skipped":0,"errors":[]}
200

$ curl -sk -o /dev/null -w '%{http_code}\n' --resolve ingest.internal:443:127.0.0.1 \
    -X POST 'https://ingest.internal/v1/ingest?source_type=windows_eventlog&format=ndjson' \
    -H 'Content-Type: application/x-ndjson' --data-binary '{"a":1}'     # no token
401

$ curl -s -o /dev/null -m 3 http://127.0.0.1:8080/ ; echo $?      # plaintext console
7 (connection refused)
$ curl -s -o /dev/null -m 3 http://127.0.0.1:8554/ ; echo $?      # plaintext ingest
7 (connection refused)
```

The first ingest attempt right after profile-up returned 502 — Caddy was up
but ws1 had cold-started without `FENGARDE_INGEST_TOKEN` (the worktree's
`infra/` has no `.env`; the operator's does), so its HTTP listener refuses
to start by design. Recreating ws1 with the token present fixed it — not a
proxy defect; included here as the honest footnote (and as the fix for the
next operator).

Trust: analysts `caddy trust` the local CA once, or pin
`curl --cacert <caddy-data-ca>` — the cert name is `siem.internal`,
`ingest.internal`.