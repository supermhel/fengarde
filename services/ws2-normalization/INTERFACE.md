# WS-2 Normalization — Interface Declaration

## Consumes
- Topic `raw.events` (group `cg-normalize`) — `{source_type, raw, meta}`.
- Contracts: A (OCSF schema), B (bus).

## Pipeline
- Parse (`source_type` → registered parser) → **sanitize** (M1: strip ANSI
  escapes/C0 control chars from every free-text field a parser may have populated
  from raw content — `message`, `actor.user/process.name`,
  `src_endpoint`/`dst_endpoint.hostname`, all of `unmapped.*` recursively at any
  depth, `api.request.data` — defends the log-injection surface, not browser XSS)
  then **enrich** (A5: additive-only `src_endpoint.reputation` from a local IOC
  list, `src_endpoint.location` from a local CIDR→country map;
  offline/air-gap-safe, fail-open; may ADD optional fields to the already-clean
  event) → validate against Contract A → produce.

## Routing (`parsers/__init__.py::resolve`)
- A registered `source_type` is authoritative: an explicit product label (e.g.
  `tools/agent_log_shipper.py --source-type linux_ssh`) is never overridden by
  content.
- **Exception — `generic_syslog`:** WS-1's UDP listener stamps this label on
  every datagram, so it means "unidentified syslog line", not a product claim.
  For a text line under this label, content-sniff runs first (CEF line start,
  then sshd markers, then a strict `%ASA-N-NNNNNN:` tag, then dnsmasq
  `query[`); the sniffed parser is used only if it actually parses the line.
  Otherwise (no sniff hit, or the specific parser declines, e.g. an sshd
  "Connection closed" line) the line stays on `generic_syslog`, exactly as
  before. A `{`-prefixed (JSON) line under this label is not structured-sniffed.
  A syslog-header-wrapped CEF record (`<134>Oct 11 22:14:15 relay01 CEF:0|...`)
  is unwrapped (`generic_syslog._unwrap_syslog_message`) and parsed by `cef`
  (test_syslog_udp_routing.py test_3b).
- Missing/unknown `source_type`: the same text sniff with `generic_syslog` as the
  catch-all; structured (JSON/dict) payloads go through the field/value sniff,
  and an ambiguous payload returns None → dead-letter.
- WS-1 metadata (`ingest_id`, `trace_id`, `tenant_id`) reaches the event
  unchanged whichever parser wins; the specific parsers also map `received_at`
  → `metadata.logged_time` (`generic_syslog` never did). The sender IP is only
  the bus key — WS-1 does not put it in `meta`, so endpoint IPs come from the line;
  `type_uid` is always derived by `base_event`. Regression test:
  `test_syslog_udp_routing.py` (incl. a UDP-shaped sshd burst → brute-force
  alert through WS-2 → WS-4).

## Produces
- Topic `normalized.events` — OCSF event (Contract A), partition key = `src_endpoint.ip`.
- Topic `raw.events.deadletter` — unparseable/invalid inputs with errors. Payload is
  the ORIGINAL `raw.events` payload verbatim (`source_type`/`raw`/`meta` at top
  level, so `tools/dlq_peek.py --requeue` genuinely re-processes it) plus
  `errors` (top-level, read by `eval/detection_accuracy/evtx_eval.py`) and a
  `deadletter` metadata object (`stage`, `key`, `deadlettered_at`). The entry
  key inherits the original message's partition key (`meta.ip`/`meta.mac`).

## Parsers (one per source type, registry in `parsers/__init__.py`)
- `cisco_asa` → Network Activity (4001), sector common
- `active_directory` → Authentication (3002), sector bank
- `vmware_vsphere` → API Activity (6003), sector datacenter
- `linux_ssh` → Authentication (3002), sector common
- `generic_syslog` → catch-all RFC 3164 syslog → OCSF, sector common
- `windows_eventlog` → Authentication (3002) / Kernel-Process (1002) / Account Change (3003), sector common
- `db_audit` → Datastore Activity (6005), sector bank
- `mcp_agent` → API Activity (6003), sector common (v0.4: MCP/AI-agent tool-call audit logs)
- `opcua_audit` → Authentication (3002) / API Activity (6003), sector datacenter (v0.4: OPC UA industrial audit events)
- `n8n_audit` → API Activity (6003) / Authentication (3002), sector common (v0.4: n8n automation-platform audit logs)
- `dns_query` → DNS/HTTP Activity (4002), sector common (v0.5: dnsmasq/BIND query logs; first class-4002 producer)
- `k8s_audit` → API Activity (6003), sector datacenter (v0.5: Kubernetes audit-webhook events)
- `cef` → Authentication (3002) / Network Activity (4001), sector common (v0.5: generic CEF-emitting appliances; feeds existing common_* rules)
- `cloudtrail` → Authentication (3002) / API Activity (6003), sector common (v0.5: AWS CloudTrail; first cloud-control-plane producer)
- `modbus_anomaly` → Network Activity (4001), sector datacenter (M7, 2026-07-22: Modbus/TCP protocol-anomaly detector -- NOT a vendor audit-log parser, see its module docstring; second OT source after opcua_audit)
- `sysmon` → Kernel/Process Activity (1002) / Network Activity (4001) / File System Activity (1001), sector common (P0-3: Sysmon process/network/file events; first class-1001 producer)
- `inventory_diff` → Network Activity (4001), sector datacenter/ot (M7 Track Y, 2026-08-05: normalizes WS-6's new-device-on-segment notifications; see `services/ws6-inventory/bus_consumer.py` for the producer side)
- `mail_gateway` → Email Activity (4009), sector common (2026-10-14: secure-email-gateway message log; attachment summary incl. macro-capable flag; read by `email_macro_attachment_delivered`)
- `m365_audit` → API Activity (6003) / Authentication (3002), sector common (2026-10-14: Microsoft 365 unified audit log; `UserLoggedIn`/`UserLoginFailed` map to 3002, everything else to 6003; mailbox-rule facts under `unmapped.m365.inbox_rule`, read by `m365_inbox_rule_external_forward`)

19 parsers total, re-synced 2026-10-22 against `parsers/__init__.py`'s `_REGISTRY` (this list had stopped at 17 since the two 2026-10-14 parsers).
`sysmon` also maps EventID 5 (ProcessTerminate) and EventID 10 (ProcessAccess, 2026-10-20) to 1002.

Adding a source = new module + one registry line. `type_uid` always derived.
A parser can also ship as an external, installable Python package via the
`fengarde.parsers` entry-point group (M4.5, `discover_plugin_parsers()`,
`docs/plugin-development.md`) — no fork of this repo required; a plugin whose
`SOURCE_TYPE` collides with a built-in parser is skipped, the built-in wins.

## Contract tests
- `python test_contract.py`  (memory bus; validates every parser's output against the schema)

## Run locally
- `python main.py`
