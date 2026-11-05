# Windows: Sysmon + Security

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.
> **Windows, run once on 2026-11-05 (Windows 11, Fluent Bit 4.2.8, normal user, Application and System channels only):** the `winevtlog` input exists in the
> Windows build and this config ran against a real ws1 listener; the real record shape differed from what the adapter assumed (event data is nested under `EventData`) and the
> adapter was fixed. **NOT run:** the `Security` channel (needs an administrator), the Sysmon channel (not installed), Fluent Bit 5.x on Windows (5.1.5 would not start here), TLS.
> See the [Verification log](README.md#verification-log).

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

| Channel | `source_type` sent | Shipper label | Parser that handles it |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | `windows_eventlog` | `fluentbit-winevtlog` | `sysmon` (adapter re-routes by provider/EventID; Sysmon EventIDs 1, 3, 5, 11 on the sniff path) |
| `Security` | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog` (channel itself not run: needs admin) |
| `Application`, `System` (run) | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog`; only EventIDs the parser maps (e.g. System 7045) become events, every other EventID dead-letters as `parser returned None` |

Send `source_type=windows_eventlog` for both channels: the adapter only rewrites records whose declared type is in the
windows family (`windows_eventlog`/`sysmon`) and moves Sysmon records to `sysmon` itself. See [../input-adapters.md](../input-adapters.md).

## Fluent Bit (winevtlog)

`Event_Data_As_Map true` is **required**: without it the event data is rendered into `Message`/`StringInserts`, which the
adapter does not parse. Option names were re-read on 2026-11-05 from the vendor docs
(<https://docs.fluentbit.io/manual/data-pipeline/inputs/windows-event-log-winevtlog>) and confirmed against `fluent-bit -i winevtlog --help` of the 4.2.8 Windows build.

What the 2026-11-05 run (Windows 11, official `fluent-bit-4.2.8-win64.zip`, normal user, `Application,System`, output to a local ws1 `HttpJsonCollector`) showed:

- **The input exists** in the Windows build (`winevtlog`, also `winlog`); 2,640 records were accepted by ws1 (HTTP 200) and went through `adapt_record` -> `resolve` -> `normalize_one` without an exception.
- **`Event_Data_As_Map` behaves as documented:** `event_template_cache_size` defaults to 256; setting it to 0 with the map on stops the input (`event_template_cache_size must be greater than zero when event_data_as_map is enabled`).
- **The record shape is NOT flat.** Every record carries the system fields at the top level (`ProviderName`, `ProviderGuid`, `Qualifiers`, `EventID`, `Version`, `Level`, `Task`, `Opcode`, `Keywords`,
  `TimeCreated`, `EventRecordID`, `ActivityID`, `RelatedActivityID`, `ProcessID`, `ThreadID`, `Channel`, `Computer`, `UserID`, `Message`, `StringInserts`), and 1,544 of 2,640 also carry the named event data
  as a nested `EventData` map (the other 1,096 come from providers whose template could not be resolved, e.g. Service Control Manager 7045 or Security-SPP: `StringInserts` only). The adapter now flattens
  `EventData` into the top level (system keys win on a collision); before the fix the parsers saw none of the event-data fields.
- `TimeCreated` is rendered in the machine's local time with an offset (`2026-08-11 21:21:44 +0100`), which the adapter already converted correctly. `Message` is localized (de-DE here) and some non-ASCII
  characters arrive mangled (`UserID` `NT-AUTORIT<U+E0C4>T\SYSTEM`); the parsers do not read those fields.
- **Result through WS-2:** all 2,640 records route to `windows_eventlog`; 2,638 dead-letter (`parser returned None`, EventIDs the parser does not map) and 2 (System 7045, "service installed") became class 1002 but with
  `Service installed: ? -> ? (by ?)`, because that provider arrives without an `EventData` map and the service name/path exist only in `StringInserts`. The parser now reads System 7045 `StringInserts` positionally (name, path, type, start type, account); a named field still wins. Regression test: `parsers/test_recall_events.py`.
- **A missing channel stops the whole input** (`cannot subscribe 'Microsoft-Windows-Sysmon/Operational' (15007)`, `failed to open and no subscribed channels`) unless `Ignore_Missing_Channels true`, which the config now sets so a host
  without Sysmon still ships the other channels.
- `Read_Existing_Events true` (used only for the test; the recipe tails) produced a first batch over ws1's default 1 MiB body cap: ws1 counted `body_over_cap` and Fluent Bit logged `could not flush records (http_do=-1)`.
  If you backfill, raise `INGEST_HTTP_MAX_BODY_BYTES`.
- **Not run:** the `Security` channel needs an administrator (vendor docs; not tried), so no 4624/4625/4688 record was seen from a real Windows host; no Sysmon record either. Fluent Bit 5.1.5 (win64 zip) exited immediately on this machine
  (`socketpair: No error` / `pipe: No error`, even for `--version`) while 4.2.8 ran; the cause was not determined, so 5.x on Windows is unverified.

The `http` output half (`Format json_lines`, `Header`, `Json_Date_Key false`, bearer header) is the same output block run live in the Docker/journald/n8n recipes: ws1 accepted the records.

```ini fluent-bit-windows.conf
# Fluent Bit (Windows) -> FENGARDE HTTP ingest. Run once on Windows 11 with Fluent Bit 4.2.8 against the Application and System channels (normal user); the Security and Sysmon channels below were NOT run.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush        5

[INPUT]
    Name                 winevtlog
    Channels             Security,Microsoft-Windows-Sysmon/Operational
    Interval_Sec         1
    Event_Data_As_Map    true
    Ignore_Missing_Channels true

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

Samples checked: [real record, Fluent Bit 4.2.8 on Windows 11, Application channel](samples/windows-application.fluentbit.json) (captured on Windows 11 with Fluent Bit 4.2.8 on 2026-11-05, Application channel,
Computer name scrubbed; Windows Error Reporting 1001) -> resolves to `windows_eventlog`, `EventData` flattened, and yields no event because EventID 1001 is not mapped, which is the honest result (it proves the shape and the
adapter flattening, **not** that Security 4624 or Sysmon records parse); [Sysmon 1, hand transcription of a third-party published output, not byte-verified](samples/windows-sysmon.fluentbit.json) (fluent-bit 2.0.6, ClickHouse post, 2023-01-17;
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
- Real `Security` and Sysmon records from Windows (never seen; the 4624 and Sysmon samples remain a template and a hand transcription of a 2023 capture that predates the event-data map).
- Event data of other providers that arrive without an `EventData` map (`StringInserts` only): only System 7045 is read positionally.
