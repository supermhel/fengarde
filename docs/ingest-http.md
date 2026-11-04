# HTTP/JSON ingest (`POST /v1/ingest`) — WP-1.1

FENGARDE can take structured JSON directly over HTTP. Point Vector, Fluent Bit,
Filebeat, n8n or an AI-agent gateway at ws1's ingest endpoint with one config
line; each record lands on `raw.events` exactly like the syslog path, with the
`source_type` you declare so WS-2 routes it to the right parser.

```
POST /v1/ingest?source_type=<registered-parser>         body: NDJSON (default)
POST /v1/ingest?source_type=<registered-parser>&format=json-array
Authorization: Bearer <FENGARDE_INGEST_TOKEN>
```

* The endpoint is served by ws1 (`services/ws1-collectors/collectors/
  http_json_collector.py`), bound to `127.0.0.1:8554` by default
  (`INGEST_HTTP_HOST`/`INGEST_HTTP_PORT`), published loopback-only in
  `infra/docker-compose.yml`.
* `source_type` comes from the query parameter **or** the
  `X-Fengarde-Source-Type` header. It MUST be a parser registered in WS-2
  (`generic_syslog`, `windows_eventlog`, `sysmon`, `linux_ssh`, `cef`, ...);
  unknown → `400`.
* Each JSON record is the dict the parser already expects in its own key
  convention (e.g. `EventID`, `TimeCreated`, `Computer` for
  `windows_eventlog`). It is placed in `raw` untouched; `meta` is stamped with
  `received_at`, `ingest_id`, `format`, `trace_id`, `tenant_id`. The bus
  partition key is the request's peer IP (same rule as the syslog path).
* The body is capped at `INGEST_HTTP_MAX_BODY_BYTES` (default 1 MiB) →
  `413`. A malformed line never aborts the batch: it is counted in `skipped`
  with its error in `errors` (first 20).
* Per-source rate limiting `INGEST_HTTP_MAX_EVENTS_PER_SEC` (default 2000/s,
  same token-bucket machinery as the syslog listener, keyed by client IP) →
  `429` when any record was shed.
* When the bus is down: records are spooled with the same
  `collectors/spool.py` machinery as syslog if `INGEST_HTTP_SPOOL_PATH` is set
  → `202` (accepted for later delivery); without a spool → `503` (dropped,
  counted).

## Auth

A bearer token is **required**. set `FENGARDE_INGEST_TOKEN` (compose passes it
through). Without a token the listener refuses to start (ws1 stays up for
`/health`, but `/v1/ingest` is not listening); a missing/wrong token on a
request → `401`. For local development only, an explicit loopback-only switch
(`FENGARDE_INGEST_DEV_LOOPBACK=1`) allows a missing token while bound to
loopback.

TLS is **not** terminated here. Put the endpoint behind the reverse proxy
described in `docs/deployment.md` (Caddy) for transport encryption; the
deployment profile is WP-3.1.

## Idempotent redelivery

Add an `X-Fengarde-Idempotency-Key` header to make redelivery idempotent:
`ingest_id` is derived from the key + line ordinal + record content, so
resending the same batch with the same key produces the same `ingest_id`s
(downstream dedup by member just works). Without the key, every record gets a
fresh uuid4 — identical records are NOT collapsed (see the FIX-21 note in
`syslog_udp_server.py`). Redelivery must preserve line order.

## Response codes (precedence)

| Status | When | Body |
|---|---|---|
| 200 | processed; body carries counts | `{accepted, skipped, errors}` |
| 202 | bus down, all records spooled | + `spooled`, `note` |
| 400 | unknown source_type/format, conflicting query+header, bad body | `error` |
| 401 | missing/wrong bearer token | `error` |
| 403 | dev switch used from a non-loopback peer | `error` |
| 404 | wrong path | `error` |
| 405 | non-POST method | `error` |
| 413 | body over `INGEST_HTTP_MAX_BODY_BYTES` | `error` |
| 429 | per-source rate limit shed records | + `rate_limited` |
| 503 | bus down, no spool (records dropped) or server busy | `error` |

## Verified against the compose stack

The output below was produced by running the real container stack
(redis + ws1-collectors), not a unit test. The bearer token in the curls is
shown as `<FENGARDE_INGEST_TOKEN>` — the literal value used for the run is
redacted from the repo (gitleaks gate).

```
$ docker compose ps ws1-collectors --format '{{.Ports}}'
0.0.0.0:5514->5514/udp, [::]:5514->5514/udp, 127.0.0.1:8554->8554/tcp

# NDJSON batch: 2 valid records + 1 malformed line (counted, batch continues)
$ curl -s -w '\nHTTP=%{http_code}\n' -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog' \
    -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' \
    --data-binary $'{"EventID": 4625, "TimeCreated": "2026-11-04T12:00:00.000Z", "Computer": "WIN-DEV-01"}\nnot-json\n{"EventID": 4634, "TimeCreated": "2026-11-04T12:00:02.000Z"}'
{"source_type":"windows_eventlog","format":"ndjson","accepted":2,"skipped":1,"errors":["line 2: Expecting value"]}
HTTP=200

# JSON array format
$ curl -s -w '\nHTTP=%{http_code}\n' -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=sysmon&format=json-array' \
    -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' -H 'Content-Type: application/json' \
    --data '[{"EventID":1,"Message":"x"},{"EventID":2}]'
{"source_type":"sysmon","format":"json-array","accepted":2,"skipped":0,"errors":[]}
HTTP=200

# Unknown source_type -> 400 (lists the registered parsers)
$ curl -s -w '\nHTTP=%{http_code}\n' -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=bogus' \
    -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' --data '{"a":1}'
{"error":"unknown source_type 'bogus'; registered: ['active_directory', 'cef', 'cisco_asa', 'cloudtrail', 'db_audit', 'dns_query', 'generic_syslog', 'inventory_diff', 'k8s_audit', 'linux_ssh', 'm365_audit', 'mail_gateway', 'mcp_agent', 'modbus_anomaly', 'n8n_audit', 'opcua_audit', 'sysmon', 'vmware_vsphere', 'windows_eventlog']"}
HTTP=400

# No token -> 401; body over the 1 MiB cap -> 413
$ curl -s -o /dev/null -w 'HTTP=%{http_code}\n' -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog' --data '{"a":1}'
HTTP=401
$ python3 -c "print('{\"pad\":\"'+'x'*2000000+'\"}')" | curl -s -w '\nHTTP=%{http_code}\n' -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog' \
    -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' --data-binary @-
{"error":"request body exceeds 1048576 bytes"}
HTTP=413

# Idempotent redelivery: same X-Fengarde-Idempotency-Key -> SAME ingest_id on the bus
$ docker exec siem-bus redis-cli xrange raw.events - + COUNT 100 | grep -o '"ingest_id": *"[^"]*"' | tail -2
"ingest_id": "15fe782b-10b8-cc03-d298-6a940edd8fba"
"ingest_id": "15fe782b-10b8-cc03-d298-6a940edd8fba"

# WS-1 /metrics (inside the container): flat http_* counters
$ curl -s http://127.0.0.1:8001/metrics
{"service": "ws1-collectors", ... "http_events_accepted": 6, "http_events_malformed": 1,
 "http_body_over_cap": 1, "http_requests_ok": 4, "http_requests_4xx": 3, ...}
```

All six steps above ran on 2026-11-04 against `infra-ws1-collectors-1` built from
the WP-1.1 branch (compose project `infra`, redis = `siem-bus`); `XLEN raw.events`
counted exactly the accepted records (2 + 2 + 2 = 6), i.e. every accepted record
reached the bus and the malformed line did not.

## Shipper configs (one line)

Vector:

```toml
[sinks.fengarde]
type = "http"
inputs = ["parsed"]
uri = "http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog"
method = "post"
encoding.codec = "ndjson"
auth.strategy = "bearer"
auth.token = "${FENGARDE_INGEST_TOKEN}"
```

Fluent Bit:

```
[OUTPUT]
    name       http
    match      *
    host       127.0.0.1
    port       8554
    uri        /v1/ingest?source_type=windows_eventlog
    format     ndjson
    header     Authorization Bearer ${FENGARDE_INGEST_TOKEN}
```

Filebeat→curl equivalent (or use `output.elasticsearch`-style custom output
plugins that push HTTP):

```
curl -X POST "http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog" \
  -H "Authorization: Bearer <FENGARDE_INGEST_TOKEN>" \
  --data-binary @events.ndjson
```

What each recipe does and does NOT cover, per source, is tracked in
`docs/shipping/` (WP-1.4, forthcoming).

## Environment

| Var | Default | Meaning |
|---|---|---|
| `FENGARDE_INGEST_TOKEN` | — (required) | bearer token for `/v1/ingest` |
| `FENGARDE_INGEST_DEV_LOOPBACK` | off | allow missing token, loopback-only (dev) |
| `INGEST_HTTP_HOST` | `127.0.0.1` | bind address |
| `INGEST_HTTP_PORT` | `8554` | bind port (checked by `infra/preflight.sh`) |
| `INGEST_HTTP_MAX_BODY_BYTES` | `1048576` | per-request body cap → 413 |
| `INGEST_HTTP_MAX_EVENTS_PER_SEC` | `2000` | per-source token bucket → 429 |
| `INGEST_HTTP_SPOOL_PATH` | unset | on-disk JSONL fallback when the bus is down |
| `INGEST_HTTP_SPOOL_MAX_BYTES` | spool default | spool cap |
