# Input adapters for real shippers (WP-1.3)

Structured sources reach the bus either as dicts in a parser's OWN convention
(EventID/TimeCreated/SubjectUserName, ...) or as whatever a real shipper emits.
The adapters in `services/ws2-normalization/adapters/` sit between the two:
a pure, total rewrite from the shipper's JSON shape to the dict the target
parser already expects. They run in WS-2, before parser `resolve()`, keyed by
`meta.shipper` — the value the sender puts in the `X-Fengarde-Shipper` header
(or `?shipper=` query param) on the HTTP ingest edge — with deterministic
shape-sniffing as fallback for unlabelled records.

```
shipper --NDJSON, X-Fengarde-Shipper: winlogbeat--> ws1 POST /v1/ingest
        --source_type=windows_eventlog&format=ndjson--------------> raw.events
        --> ws2 adapt_record() --> resolve() --> parser --> OCSF
```

## Adapters today

| `shipper` id | source | target parser | what changes |
|---|---|---|---|
| `fluentbit-winevtlog` | Fluent Bit `winevtlog` input, **`event_data_as_map: true`** (Windows) | `sysmon` or `windows_eventlog` | `TimeCreated` string → epoch ms; Sysmon records routed by provider/EventID |
| `winlogbeat` | Winlogbeat 7/8 ECS output (Windows) | `sysmon` or `windows_eventlog` | `winlog.*` nesting flattened to the parser keys; `winlog.time_created` → epoch ms |
| `fluentbit-journald` | Fluent Bit `systemd` input (Linux) | `generic_syslog` → text-sniff routes sshd lines to `linux_ssh` | journald field map → RFC 3164 line built from record fields only |
| `docker-json` | Docker `json-file` driver lines with the Fluent Bit `docker` filter (`docker_id`/`docker_name`) | `generic_syslog` | `{log,stream,time}` → RFC 3164 line; header rebuilt from record fields only |

One sender-side rule: `source_type` must stay a REGISTERED parser
(`windows_eventlog`, `sysmon`, `generic_syslog`, ... — ws1 rejects unknown
values with a 400). The adapter re-labels within its own family by record
content.

## Sending

```bash
# Winlogbeat (or any shipper) -> FENGARDE HTTP ingest
curl -sS -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog&format=ndjson' \
  -H "Authorization: Bearer <FENGARDE_INGEST_TOKEN>" \
  -H 'X-Fengarde-Shipper: winlogbeat' \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @winlogbeat.ndjson
```

`windows_eventlog` covers both parses: a Sysmon record in the same stream is
re-routed to `sysmon` by the adapter (mixed Security+Sysmon channels are the
documented Fluent Bit setup).

## Fixture provenance (honesty ledger)

- `fluentbit-winevtlog` FIXTURE — **REAL capture**: byte-exact output of
  fluent-bit 2.0.6's `winevtlog` input on a Windows host (2023-01-17),
  published by ClickHouse in *"Send Windows Event Logs to ClickHouse with
  Fluent Bit"* (clickhouse.com/blog/...); reproduced with `StringInserts`
  truncated to two entries (the adapter never reads it).
- `fluentbit-winevtlog` SECURITY_FIXTURE — **template-derived**: keys are the
  standard Security-4624 event-data names (Microsoft's event template, echoed
  by Winlogbeat's exported-fields catalog), values in the plugin's flat
  rendering mode.
- `winlogbeat` FIXTURE / SECURITY_LOGON_FIXTURE — **template-derived**: field
  catalog is the official
  `elastic.co/docs/reference/beats/winlogbeat/exported-fields-winlog`;
  values model real 4688 / 4624 records in that shape. (A real pre-ECS
  Winlogbeat 1.x capture from 2016 exists at logz.io/blog/windows-event-log-
  analysis — historical shape only; the adapter targets the current nested
  ECS shape.)
- `fluentbit-journald` FIXTURE — **schema-derived**: field names per systemd
  `journal-fields(5)` (freedesktop.org) + Fluent Bit `systemd` input manual;
  values model a representative sshd auth-failure entry. The RFC 3164 header
  is rebuilt ONLY from fields present in the record.
- `docker-json` FIXTURE — **documented example**: Docker's own canonical
  json-file example (docs.docker.com/engine/logging/drivers/json-file) +
  `docker_id`/`docker_name` per Fluent Bit's `docker` filter manual.

No specimen value was invented in any fixture.

## Honest scope notes

- Fluent Bit `winevtlog` WITHOUT `event_data_as_map: true` renders the event
  text into `Message` and the data into `StringInserts`; the adapter does not
  reverse-engineer that render (too format-fragile). The recipe sets
  `event_data_as_map true`.
- A naked Docker `json-file` line (no `docker_id`/`docker_name`, no
  `--log-opt tag`) has no identifier to build an honest RFC 3164 host/program
  from: the adapter leaves it untouched and it dead-letters with the standard
  "set source_type" hint. Point the recipe at the Fluent Bit `docker` filter.
- Winlogbeat's `winlog.time_created` is ISO-8601 with a UTC `Z`; any offset
  form is accepted; a naive timestamp is assumed UTC. Unparseable
  `TimeCreated` values simply drop the key (the parser falls back to its
  received_at default) — an adapter never fabricates a time.
- `meta.docker_time` is evidence only; nothing override the WS-1 receipt
  clock (`meta.received_at`, Q12 semantics).

## Live verification (compose stack, 2026-11-04)

Rebuilt `ws1-collectors` + `ws2-normalization` from the WP-1.3 branch
(docker compose, redis untouched). One NDJSON record per shipper, each in its
own request with its own `X-Fengarde-Shipper` label — the label is per
request, which is exactly how a real fleet sends (one sender per label):

```
$ curl -sS -X POST 'http://127.0.0.1:8554/v1/ingest?source_type=windows_eventlog&format=ndjson' \
    -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' \
    -H 'X-Fengarde-Shipper: winlogbeat' ...           # -> HTTP 200
  (same for fluentbit-winevtlog -> windows_eventlog,
   fluentbit-journald -> generic_syslog, docker-json -> generic_syslog)

$ docker exec siem-bus redis-cli xlen normalized.events   ->  5 (1 pre-existing + 4 new)
$ docker exec siem-bus redis-cli xrange normalized.events - + | grep -o '"source_type": "[a-z_]*"'
  "source_type": "windows_eventlog"   # winlogbeat 4624 logon  -> class 3002, actor jdoe
  "source_type": "sysmon"             # fluent-bit winevtlog Sysmon capture -> routed by ProviderName
  "source_type": "linux_ssh"          # journald sshd failure    -> RFC 3164 rebuild + text-sniff
  "source_type": "generic_syslog"     # docker json-file line    -> header rebuilt from record fields
```

Lesson captured by the live test's first attempt: labelling a whole mixed
batch `winlogbeat` made the other three shapes no-op (the winlogbeat adapter
correctly declined them) and they dead-lettered with "parser returned None" —
the shipper label must match the record shape within a batch.

## Ships with

- `services/ws2-normalization/test_adapters.py` — per-adapter fixture→parser
  checks through the full WS-2 path (incl. OCSF validation), sniff negative
  controls, shipper-label-vs-sniff precedence, no-op guarantee, and the
  extreme-value totality sweep (2,850 mutations, none raised).
- Recipes for the shipping side are in `docs/shipping/` (WP-1.4).