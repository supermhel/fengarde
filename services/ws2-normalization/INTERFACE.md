# WS-2 Normalization — Interface Declaration

## Consumes
- Topic `raw.events` (group `cg-normalize`) — `{source_type, raw, meta}`.
- Contracts: A (OCSF schema), B (bus).

## Produces
- Topic `normalized.events` — OCSF event (Contract A), partition key = `src_endpoint.ip`.
- Topic `raw.events.deadletter` — unparseable/invalid inputs with errors.

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

Adding a source = new module + one registry line. `type_uid` always derived.

## Contract tests
- `python test_contract.py`  (memory bus; validates every parser's output against the schema)

## Run locally
- `python main.py`
