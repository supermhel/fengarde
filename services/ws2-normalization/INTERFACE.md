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

17 parsers total as of 2026-08-06 (this file previously undercounted at 15 — re-synced against `parsers/__init__.py`'s `_REGISTRY`).

Adding a source = new module + one registry line. `type_uid` always derived.
A parser can also ship as an external, installable Python package via the
`fengarde.parsers` entry-point group (M4.5, `discover_plugin_parsers()`,
`docs/plugin-development.md`) — no fork of this repo required; a plugin whose
`SOURCE_TYPE` collides with a built-in parser is skipped, the built-in wins.

## Contract tests
- `python test_contract.py`  (memory bus; validates every parser's output against the schema)

## Run locally
- `python main.py`
