# WS-1 Collectors — Interface Declaration

## Consumes
- External inputs: **live syslog over UDP** (`SYSLOG_UDP_HOST`/`SYSLOG_UDP_PORT`,
  default `0.0.0.0:5514`; TCP/514 is NOT implemented), plus mock SNMP/NetFlow
  sources (see Mocks) — live SNMP/NetFlow transports are not yet wired.
- Contracts: B (bus topics).

## Produces
- Topic `raw.events` — `{source_type, raw, meta}`, partition key = source IP (`meta.ip`).
- Topic `assets.updates` — `{mac, ip, hostname, seen_at}`, partition key = mac (fallback ip).

## Backpressure (B2)
- Ingest-edge shedding: the UDP listener drops excess datagrams via a token bucket
  (`SYSLOG_MAX_EVENTS_PER_SEC`, default 2000/s) BEFORE the bus; no mid-pipeline
  trim. Depth watchdog (`RAW_EVENTS_DEPTH_WARN`) is monitoring-only.
- Opt-in zero-loss spool (`SYSLOG_SPOOL_PATH`, off by default;
  `SYSLOG_SPOOL_MAX_BYTES`): shed/undelivered events buffered to a bounded on-disk
  JSONL file and replayed. See SECURITY.md §8 (cleartext on disk).

## Mocks provided
- `mocks/sample_syslog.txt`, `mocks/sample_snmp.json`, `mocks/sample_netflow.json`
  let the whole service run offline with no sockets / SNMP agents.

## Contract tests
- `python test_contract.py`  (BUS_BACKEND=memory, no infra)

## Run locally
- `python main.py`  (offline, drains the mocks once)
