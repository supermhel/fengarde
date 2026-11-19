# Windows: Sysmon + Security

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, except [windows-application.fluentbit.json](samples/windows-application.fluentbit.json), captured from Fluent Bit 4.2.8 on Windows 11 ([sample provenance](README.md#sample-provenance)). `tools/test_shipping_recipes.py` runs them through WS-2.
> **Windows, run once on 2026-11-05 (Windows 11, Fluent Bit 4.2.8, normal user, Application and System channels only):** the `winevtlog` input exists in the
> Windows build and a modified copy of this config (`Channels Application,System`; the committed file lists `Security`, `System` and Sysmon) ran against a real ws1 listener; the shape Fluent Bit actually emits differed from what the adapter assumed (event data is nested under `EventData`) and the
> adapter was fixed. **NOT run in that first pass:** the `Security` channel (needs an administrator), the Sysmon channel (not installed), Fluent Bit 5.x on Windows (5.1.5 would not start here; it did run on 2026-11-13, below), TLS.
> **Second Windows run, 2026-11-13 (Windows 11 de-DE, Fluent Bit 4.2.8, administrator, Sysmon installed):** the `Security` channel did run (4624, 4625, 4688, 4720 seen) and so did Sysmon (EventIDs 1, 3, 5, 11 seen). It found that Security 4625 (failed logon) was dropped; fixed below. **Fluent Bit 5.1.5 on Windows ran the same day** and produced records with the same keys and the same WS-2 results. Security 4798 (~3,100 records, unmapped) is dropped by a Lua filter in the config (tested on Linux only). Security 4648 is not mapped (3 records). Still **NOT run:** a real DST boundary, TLS, a real Winlogbeat, the 4798 filter on the Windows build.
> See the [Verification log](README.md#verification-log).
>
> **The `[INPUT]` of the committed `fluent-bit-windows.conf` (`Security`, `System`, `Microsoft-Windows-Sysmon/Operational`) ran as written on 2026-11-13** (administrator, Sysmon installed, Fluent Bit 4.2.8 and 5.1.5; the lab wrote to a local file instead of the `http` output). The `[OUTPUT]` section and the Lua 4798 filter were not run as written on Windows. `Ignore_Missing_Channels true` is there because a missing channel otherwise stops the whole input.

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

| Channel | `source_type` sent | Shipper label | Parser that handles it |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | `windows_eventlog` | `fluentbit-winevtlog` | `sysmon` (adapter re-routes by provider/EventID; Sysmon EventIDs 1, 3, 5, 11 on the sniff path) |
| `Security` | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog` (4624 -> 3002, 4688 -> 1002, 4720 -> 3003 seen in the 2026-11-13 admin run); EventIDs only the `active_directory` parser maps (4625 failed logon, 4768, 4771) are re-routed by the adapter to `active_directory` (below) |
| `System` (in the recipe; run in a modified copy) | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog`; only EventIDs the parser maps (7045 service installed, 104 log cleared) become events, every other EventID dead-letters as `parser returned None` (2,638 of 2,640 in the run) |
| `Application` (not in the recipe; run in the same copy) | `windows_eventlog` | `fluentbit-winevtlog` | `windows_eventlog`; the events the parser maps come from System, Security or PowerShell channels, so Application records are expected to dead-letter (the committed capture is one) |

Send `source_type=windows_eventlog` for both channels: the adapter only rewrites records whose declared type is in the
windows family (`windows_eventlog`/`sysmon`) and moves Sysmon records to `sysmon` itself. See [../input-adapters.md](../input-adapters.md).

**Security 4625 and the `active_directory` re-route (found 2026-11-13).** The real 4625 arrived as `source_type=windows_eventlog` and dead-lettered (`parser returned None`): `windows_eventlog` does not map it; the `active_directory` parser does, but reads flat `TargetUserName`/`IpAddress`/`WorkstationName`, which only exist after the adapter flattens `EventData`. Both adapters (`fluentbit_winevtlog`, `winlogbeat`) now flatten first, then send EventIDs mapped by `active_directory` and not by `windows_eventlog` (**4625, 4768, 4771**) to `active_directory` (provider `Microsoft-Windows-Security-Auditing` or unnamed). 4624/4634/4647 stay on `windows_eventlog` (both parsers map them). A 4625 is then class 3002 / type 300204, status Failure, with the target user, source IP and workstation, and the common brute-force rules see it. **Security 4798** (user's local group membership enumerated) is the volume source: about 3,100 records in the first read of one lab host, all dead-lettered as unmapped; filter it in the recipe (for example `Event_Query` excluding EventID 4798) rather than shipping noise, unless you add a mapping. That filter is a recommendation: it was not run.

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
- `TimeCreated` is rendered in the machine's local time with an offset (`2026-08-11 21:21:44 +0100`), and **that offset is wrong across DST** (second review, 2026-11-06): the committed capture (EventRecordID 61384) prints `+0100`,
  but the host's own event log has the same event at `2026-08-11T21:21:44+02:00` (W. Europe Standard Time, summer time). Fluent Bit prints the *current* UTC offset, not the one in force at the event time, so the wall clock
  is right and the offset is not. By default the adapter trusts the printed offset, so an event from the other side of a DST switch is dated one hour off (the capture lands at 20:21:44Z; the truth is 19:21:44Z). See
  [Time zone and DST](#time-zone-and-dst) for the opt-in fix. `Message` is localized (de-DE here) and some non-ASCII
  characters arrive mangled (`UserID` `NT-AUTORIT<U+E0C4>T\SYSTEM`); the parsers do not read those fields.
- **Result through WS-2:** all 2,640 records route to `windows_eventlog`; 2,638 dead-letter (`parser returned None`, EventIDs the parser does not map) and 2 (System 7045, "service installed") became class 1002 but with
  `Service installed: ? -> ? (by ?)`, because that provider arrives without an `EventData` map and the service name/path exist only in `StringInserts`. The parser now reads System 7045 `StringInserts` positionally (name, path, type, start type, account); a named field still wins. Regression test: `parsers/test_recall_events.py`.
- **A missing channel stops the whole input** (`cannot subscribe 'Microsoft-Windows-Sysmon/Operational' (15007)`, `failed to open and no subscribed channels`) unless `Ignore_Missing_Channels true`, which the config now sets so a host
  without Sysmon still ships the other channels.
- `Read_Existing_Events true` (used only for the test; the recipe tails) produced a first batch over ws1's default 1 MiB body cap: ws1 counted `body_over_cap` and Fluent Bit logged `could not flush records (http_do=-1)`.
  If you backfill, raise `INGEST_HTTP_MAX_BODY_BYTES`.
- **Not run in this first pass (superseded by the 2026-11-13 run, see the Verification log):** the `Security` channel needs an administrator, so no 4624/4625/4688 record was seen here; no Sysmon record either. Fluent Bit 5.1.5 (win64 zip) exited immediately on this machine
  (`socketpair: No error` / `pipe: No error`, even for `--version`) while 4.2.8 ran; the cause was not determined. The same 5.1.5 zip ran on 2026-11-13, so the failure was not reproducible there.

### Time zone and DST

Set `FENGARDE_WINEVTLOG_TZ` on **ws2** (the normalizer, not the Windows host) to the IANA zone of the Windows host, e.g. `Europe/Berlin`. The `fluentbit-winevtlog` adapter then ignores the printed offset and interprets the printed wall-clock
time in that zone with the correct DST for that date (the capture then yields `2026-08-11T19:21:44Z`; unset it yields `20:21:44Z`; regression-tested). Unset (the default) keeps the old behaviour. The variable is read at call time; an
invalid or unknown zone name is ignored with one warning in the ws2 log (`is tzdata installed?`) and never stops processing. It applies to the `winevtlog` adapter only, never to Winlogbeat.

Trade-offs: it is one zone for **all** `fluentbit-winevtlog` senders reaching that ws2 (hosts in other zones need their own ws2 or Winlogbeat); a wall-clock time in the repeated autumn hour is ambiguous and resolves to its first
occurrence; the zone database must exist in the ws2 image (`zoneinfo` worked in the shipped `python:3.12-slim` image; a slimmer base without `tzdata` would hit the ignore-with-warning path). Where DST accuracy matters, prefer
**Winlogbeat**, which emits UTC timestamps (no recipe config shipped; see below).

The `http` output half (`Format json_lines`, `Header`, `Json_Date_Key false`, bearer header) is the same output block run live in the Docker/journald/n8n recipes: ws1 accepted the records.

```ini fluent-bit-windows.conf
# Fluent Bit (Windows) -> FENGARDE HTTP ingest. The [INPUT] section (Security, System, Sysmon) RAN as written on 2026-11-13 (Windows 11, administrator, Sysmon installed, Fluent Bit 4.2.8 and 5.1.5): real Security 4624/4625/4688/4720 and Sysmon 1/3/5/11 records were read.
# NOT run as written: the [OUTPUT] http section (the lab wrote to a local file instead) and the 4798 [FILTER] below (verified only on a Linux fluent-bit 5.1.5 container with synthetic records; the Windows build's Lua filter was not exercised). System is chatty: expect most of its records to dead-letter as unmapped EventIDs.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush        5

[INPUT]
    Name                 winevtlog
    Channels             Security,System,Microsoft-Windows-Sysmon/Operational
    Interval_Sec         1
    Event_Data_As_Map    true
    # A channel that does not exist (Sysmon not installed) otherwise fails the WHOLE input at start (error 15007), shipping nothing.
    Ignore_Missing_Channels true

# Security 4798 ("local group membership enumerated") is ~3,000 records on an ordinary desktop and no parser maps it. Dropped here so it never reaches ws1.
# The grep filter does NOT work for this: EventID arrives as an integer and `Exclude EventID ^4798$` matched nothing (tested). Lua does.
[FILTER]
    Name    lua
    Match   *
    call    drop_noise
    code    function drop_noise(tag, ts, rec) if tonumber(rec["EventID"]) == 4798 then return -1, ts, rec end return 0, ts, rec end

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
hand-transcribed, no capture file stored) -> `sysmon`, **but with no field mapping**: that 2023 output predates `Event_Data_As_Map`, so there is no `EventData` and the event reads `Process created: ? (by ?)` (the test asserts this limit
explicitly); [Sysmon 1 in the nested-`EventData` shape, **template-derived from Sysmon event 1 field names, not a capture**](samples/windows-sysmon-eventdata.fluentbit.json) (envelope and `EventData` nesting follow the verified Windows 11
Application capture; values invented) -> `sysmon`, with image, command line, user, parent image and pid asserted in `tools/test_shipping_recipes.py` (this proves the adapter and parser handle that shape, **not** that a real Sysmon
install emits it); [Security 4624, template-derived](samples/windows-security.fluentbit.json) -> `windows_eventlog`; [Security 4625, template-derived](samples/windows-4625.fluentbit.json) -> `active_directory`: the EventData key set (TargetUserName, TargetDomainName, Status, SubStatus, FailureReason, LogonType, IpAddress, IpPort, WorkstationName, AuthenticationPackageName) was observed in the 2026-11-13 lab run, but every value here is invented and the record was rebuilt, not stored, so it is not a capture. The test asserts class 3002 / type 300204, actor, source IP, Failure, and the per-IP and per-account brute-force rules tripping on a burst of ten.

## Vector

**No Vector recipe is shipped for Windows.** Vector's Windows event-log source output shape is not covered by any FENGARDE
adapter and no sample of it exists in this repo; writing a config plus a remap to the parser's key names would present an
invented shape as supported. If you need it, remap Vector's output to the `windows_eventlog` key convention (`EventID`,
`TimeCreated`, `Computer`, ...) and send with `source_type=windows_eventlog`; that is untested.

## Winlogbeat (adapter exists, no config shipped)

The `winlogbeat` adapter handles the ECS `winlog.*` shape. Winlogbeat has no HTTP output, so a relay is needed (not provided).
Samples (template-derived from Elastic's exported-fields catalog): [4688](samples/windows-4688.winlogbeat.json) and
[4624](samples/windows-4624.winlogbeat.json), both -> `windows_eventlog`, label `winlogbeat`. The same 4625/4768/4771 -> `active_directory` re-route applies (tested with the 4625 EventData placed in `winlog.event_data`; no Winlogbeat output was ever seen).

## Not covered

- PowerShell/other channels beyond what `windows_eventlog` and `sysmon` map (unmapped EventIDs dead-letter).
- Sysmon EventID 10 without `source_type=sysmon` (the content sniff omits it).
- Mixing shapes under one `X-Fengarde-Shipper` label in a batch: the label is per request; mismatched shapes dead-letter.
- Vector on Windows (above); remote collection (`remote.*` options); TLS.
- Committed samples of Security/Sysmon records from a real host: such records were seen on 2026-11-13 (private host data, not stored), but the committed Security and Sysmon samples remain templates and a hand transcription of a 2023 capture that predates the event-data map. 4798 is unmapped (above).
- Event data of other providers that arrive without an `EventData` map (`StringInserts` only): only System 7045 is read positionally.
