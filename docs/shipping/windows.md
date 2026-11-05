# Windows: Sysmon + Security

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What a green test (per author run) covers is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

| Channel | `source_type` sent | Shipper label | Parser that handles it |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | `windows_eventlog` | `fluentbit-winevtlog` | `sysmon` (adapter re-routes by provider/EventID; Sysmon EventIDs 1, 3, 5, 11 on the sniff path) |
| `Security` | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog` |

Send `source_type=windows_eventlog` for both channels: the adapter only rewrites records whose declared type is in the
windows family (`windows_eventlog`/`sysmon`) and moves Sysmon records to `sysmon` itself. See [../input-adapters.md](../input-adapters.md).

## Fluent Bit (winevtlog)

`Event_Data_As_Map true` is **required**: without it the event data is rendered into `Message`/`StringInserts`, which the
adapter does not parse. Option names were taken from the vendor docs
(<https://docs.fluentbit.io/manual/pipeline/inputs/windows-event-log-winevtlog>) but not re-read for this revision: treat them as
unchecked. `Event_Data_As_Map` is vendor-documented but was **not executed**; the `http` output options
(`Format json_lines`, `Header`, `Json_Date_Key`) are from memory of the vendor docs and **unverified**.

```ini fluent-bit-windows.conf
# Fluent Bit (Windows) -> FENGARDE HTTP ingest. Written from vendor docs, NOT executed.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush        5

[INPUT]
    Name                 winevtlog
    Channels             Security,Microsoft-Windows-Sysmon/Operational
    Interval_Sec         1
    Event_Data_As_Map    true

[OUTPUT]
    Name             http
    Match            *
    Host             192.0.2.10
    Port             8554
    URI              /v1/ingest?source_type=windows_eventlog&format=ndjson
    Format           json_lines
    Json_Date_Key    false
    Header           Authorization Bearer ${FENGARDE_INGEST_TOKEN}
    Header           X-Fengarde-Shipper fluentbit-winevtlog
    Header           X-Fengarde-Source ${COMPUTERNAME}
```

Samples checked: [Sysmon 1, hand transcription of a third-party published output, not byte-verified](samples/windows-sysmon.fluentbit.json) (fluent-bit 2.0.6, ClickHouse post, 2023-01-17;
hand-transcribed, no capture file stored) -> `sysmon`; [Security 4624, template-derived](samples/windows-security.fluentbit.json) -> `windows_eventlog`.

## Vector

**No Vector recipe is shipped for Windows.** Vector's Windows event-log source output shape is not covered by any FENGARDE
adapter and no sample of it exists in this repo; writing a config plus a remap to the parser's key names would present an
invented shape as supported. If you need it, remap Vector's output to the `windows_eventlog` key convention (`EventID`,
`TimeCreated`, `Computer`, ...) and send with `source_type=windows_eventlog`; that is untested.

## Winlogbeat (adapter exists, no config shipped)

The `winlogbeat` adapter handles the ECS `winlog.*` shape. Winlogbeat has no HTTP output, so a relay is needed (not provided).
Samples (template-derived from Elastic's exported-fields catalog): [4688](samples/windows-4688.winlogbeat.json) and
[4624](samples/windows-4624.winlogbeat.json), both -> `windows_eventlog`, label `winlogbeat`.

## Not covered

- PowerShell/other channels beyond what `windows_eventlog` and `sysmon` map (unmapped EventIDs dead-letter).
- Sysmon EventID 10 without `source_type=sysmon` (the content sniff omits it).
- Mixing shapes under one `X-Fengarde-Shipper` label in a batch: the label is per request; mismatched shapes dead-letter.
- Vector on Windows (above); remote collection (`remote.*` options); TLS.
