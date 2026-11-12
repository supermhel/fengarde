# Shipping recipes (WP-1.4)

How to get real logs into FENGARDE with Vector, Fluent Bit, rsyslog or syslog-ng. Each recipe names the parser that handles
the data, the ingest path and what is **not** covered. Background: [../input-adapters.md](../input-adapters.md),
[../ingest-http.md](../ingest-http.md), [../syslog-tcp.md](../syslog-tcp.md).

| Source / shipper | Recipe | Ingest path | Parser (`source_type` in the registry) | Sample checked | Sample provenance |
|---|---|---|---|---|---|
| Windows Sysmon (Fluent Bit) | [windows.md](windows.md) | HTTP, `source_type=windows_eventlog`, `fluentbit-winevtlog` | `sysmon` (**no field mapping** for this old shape: message `Process created: ? (by ?)`) | [windows-sysmon.fluentbit.json](samples/windows-sysmon.fluentbit.json) | hand transcription of a third-party 2023 output that predates `Event_Data_As_Map`, not byte-verified |
| Windows Sysmon, real `EventData` shape (Fluent Bit) | [windows.md](windows.md) | same | `sysmon` (image, command line, user, parent image, pid asserted) | [windows-sysmon-eventdata.fluentbit.json](samples/windows-sysmon-eventdata.fluentbit.json) | template-derived from Sysmon event 1 field names in the verified Windows 11 envelope, **not a capture** |
| Windows Application (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` (no event: EventID 1001 unmapped) | [windows-application.fluentbit.json](samples/windows-application.fluentbit.json) | captured on Windows 11 with Fluent Bit 4.2.8 on 2026-11-05 (Application channel), scrubbed |
| Windows Security (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-security.fluentbit.json](samples/windows-security.fluentbit.json) | template-derived |
| Windows 4688 (Winlogbeat) | [windows.md](windows.md) | HTTP via a relay (no config), `winlogbeat` | `windows_eventlog` | [windows-4688.winlogbeat.json](samples/windows-4688.winlogbeat.json) | template-derived |
| Windows 4624 (Winlogbeat) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-4624.winlogbeat.json](samples/windows-4624.winlogbeat.json) | template-derived |
| Linux sshd (Fluent Bit journald) | [linux-auth.md](linux-auth.md) | HTTP, `source_type=generic_syslog`, `fluentbit-journald` | `linux_ssh` | [linux-sshd.fluentbit-journald.json](samples/linux-sshd.fluentbit-journald.json) | schema-derived |
| Linux sshd, OpenSSH 9.8+ `sshd-session` (Fluent Bit journald, Debian 13) | [linux-auth.md](linux-auth.md) | HTTP, `source_type=generic_syslog`, `fluentbit-journald` | `linux_ssh` | [linux-sshd-session.journald.json](samples/linux-sshd-session.journald.json) | captured: a `journalctl -o json` entry from `debian:trixie-slim` (OpenSSH 10.0p2) in a container on 2026-11-07; it carries the field names Fluent Bit's systemd input emits but is journald output, not Fluent Bit output |
| Linux sshd (Vector journald) | [linux-auth.md](linux-auth.md) | syslog TCP 5515 | `linux_ssh` | [linux-sshd.vector.syslog.txt](samples/linux-sshd.vector.syslog.txt) | adapter output shape plus `<38>` PRI (what the remap targets; not a Vector capture) |
| Docker n8n container (Fluent Bit) | [docker.md](docker.md) | HTTP, `generic_syslog`, `docker-json` | `generic_syslog` | [docker-n8n.fluentbit.json](samples/docker-n8n.fluentbit.json) | documented example: adapter fixture shape, NOT this config's literal output (the config's Lua sets `docker_name` to a 12-hex id; `linux_ssh` needs a `sshd[pid]:` prefix in the container's own text, see docker.md) |
| Docker sshd container (Fluent Bit) | [docker.md](docker.md) | same | `linux_ssh` | [docker-sshd.fluentbit.json](samples/docker-sshd.fluentbit.json) | documented example |
| Docker (Vector) | [docker.md](docker.md) | syslog TCP 5515 | `generic_syslog` | [docker-n8n.vector.syslog.txt](samples/docker-n8n.vector.syslog.txt) | adapter output with the container name in the host slot, as the remap emits (not a Vector capture) |
| dnsmasq / Pi-hole (Vector, rsyslog, syslog-ng) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.syslog.txt](samples/dnsmasq.syslog.txt) | documented (parser docstring) |
| dnsmasq / Pi-hole, real log (Vector, Fluent Bit) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [pihole-v6.dnsmasq.txt](samples/pihole-v6.dnsmasq.txt) | captured from `pihole/pihole:2026.10.1` on 2026-11-05, client addresses scrubbed |
| dnsmasq / Pi-hole (Fluent Bit) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.fluentbit-wrapped.syslog.txt](samples/dnsmasq.fluentbit-wrapped.syslog.txt) | template-derived (assumed header) |
| n8n (Vector, Fluent Bit) | [n8n.md](n8n.md) | HTTP, `source_type=n8n_audit` | `n8n_audit` | [n8n-audit.json](samples/n8n-audit.json) | documented (parser docstring); native n8n shape unverified |
| Proxmox sshd (rsyslog, syslog-ng) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [proxmox-sshd.syslog.txt](samples/proxmox-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense sshd (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [opnsense-sshd.syslog.txt](samples/opnsense-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense filterlog (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `generic_syslog` (no firewall parser) | [pfsense-filterlog.syslog.txt](samples/pfsense-filterlog.syslog.txt) | illustrative |

### Sample provenance

One class per sample, from this closed set (enforced by `tools/test_shipping_recipes.py`, which also fails if any doc presents a non-captured sample as a capture):

| Class | Meaning | Samples |
|---|---|---|
| captured | produced by real software and stored (scrubbed where noted) | `windows-application.fluentbit.json` (Fluent Bit 4.2.8, Windows 11, 2026-11-05), `pihole-v6.dnsmasq.txt` (`pihole/pihole:2026.10.1`, 2026-11-05), `linux-sshd-session.journald.json` (`journalctl -o json`, `debian:trixie-slim`, OpenSSH 10.0p2, container, 2026-11-07) |
| hand-transcribed | copied by hand from a third-party published output, not byte-verified | `windows-sysmon.fluentbit.json` |
| template-derived | built from vendor field names inside a verified envelope; values invented | `windows-sysmon-eventdata.fluentbit.json`, `windows-security.fluentbit.json`, `windows-4688.winlogbeat.json`, `windows-4624.winlogbeat.json`, `dnsmasq.fluentbit-wrapped.syslog.txt` |
| schema-derived | field names from the vendor schema, values representative | `linux-sshd.fluentbit-journald.json` |
| adapter-output | the adapter's own output with the transformation a config's remap performs | `linux-sshd.vector.syslog.txt`, `docker-n8n.vector.syslog.txt` |
| documented | the shape a parser docstring or recipe documents | `docker-n8n.fluentbit.json`, `docker-sshd.fluentbit.json`, `dnsmasq.syslog.txt`, `n8n-audit.json` |
| illustrative | hand-written example of a plausible line | `proxmox-sshd.syslog.txt`, `opnsense-sshd.syslog.txt`, `pfsense-filterlog.syslog.txt` |

**Windows config caveat.** `configs/fluent-bit-windows.conf` lists `Security`, `System` and `Sysmon` but that exact file was never run: the run used a copy with `Channels Application,System` (so `System`, the source of 7045 and 104, did run; Security needs an administrator account, Sysmon was not installed); no real
4624/4688/Sysmon record has been seen. **Windows time caveat.** Fluent Bit prints the *current* UTC offset on `TimeCreated`, so events from the other side of a DST switch are dated one hour off unless `FENGARDE_WINEVTLOG_TZ` is set on ws2
or Winlogbeat (UTC) is used; see [windows.md](windows.md#time-zone-and-dst). **sshd time caveat.** `linux_ssh` events are stamped with receipt time, so replayed or backfilled sshd lines (journald, Docker) get "now"; see
[linux-auth.md](linux-auth.md) and [docker.md](docker.md).

## Delivery guarantees (what happens when ws1 is down)

Exercised 2026-11-11 (Docker Desktop, Linux containers; fluent-bit 5.1.5, vector 0.61.0, rsyslog 8.2610 `rsyslog/rsyslog:2026-10`, syslog-ng 4.12.0) against a real ws1 `HttpJsonCollector` / `SyslogTCPServer` that was **stopped for 60 s** (connection refused), then restarted on the same port. Each run: 10 records before, one record every 2 s during the outage, 10 after; records are counted on the bus per sequence number. A "restart" run stops the shipper container halfway through the outage, writes 3 records while it is stopped (file-based shippers only) and starts it again. **What this does not cover:** black-holed networks (packets dropped, no RST), buffer-overflow limits (runs are at most 40 records), the Windows config, and anything on a non-Linux host. No duplicates were seen in any run (the listener was fully down, so no ambiguous responses). Verdicts: **proven** = ran as stated, **contradicted** = ran and the earlier claim was wrong, **unverified** = not run.

ws1 itself answers `202` (spooled, if `INGEST_HTTP_SPOOL_PATH` / `SYSLOG_TCP_SPOOL_PATH` is set) or `503`/`429` and caps a body at `INGEST_HTTP_MAX_BODY_BYTES` (1 MiB, `413`); a retry after `429`/`503` without an idempotency key can duplicate events ([../ingest-http.md](../ingest-http.md)). Delivery is at-least-once everywhere downstream.

| Shipper and config | What ran (60 s outage) | Verdict |
|---|---|---|
| Fluent Bit `http`, **before** this change (no `Retry_Limit`, memory buffer, no `DB` on tail) | 3 of 12 records delivered, **9 lost** (documented default `Retry_Limit` 1); on a restart the in-memory chunks were lost (6 of 6), and the 3 lines written while it was stopped were lost (no tail `DB`) even with filesystem storage | **proven** (the old claim "retried up to `Retry_Limit` then dropped" held; the claim that `DB` files cover the committed tail configs was **contradicted**: they had none) |
| Fluent Bit `http`, `Retry_Limit no_limits` alone | 12 of 12 delivered, 9.7-80 s late; memory buffer only | **proven** |
| Fluent Bit `http`, **committed config now** (`Retry_Limit no_limits`, `storage.type filesystem` + `storage.path`, tail `DB`; n8n config run, docker/dnsmasq/journald changed the same way and not run separately) | no restart: 22 of 22 delivered (9-152 s late). With a restart at 30 s: 10 of 10 outage records written before the restart, **3 of 3 written while stopped**, 5 of 5 written after the restart (still during the outage) and all 10 after restore delivered; 0 lost, 0 duplicated | **proven** for the n8n config; **unverified** for the docker, dnsmasq (`syslog` output) and journald configs, and for `Retry_Limit` on the `syslog` output |
| Fluent Bit Windows config | not changed, not run for outages | **unverified** |
| Vector `socket` sink, TCP (dnsmasq, docker, journald configs) | 21 of 24 delivered, **3 lost** at the moment the connection dropped; reconnect works (first delivery 12.7 s after restore); `buffer.type = "disk"` did **not** prevent the same 3 lost | **contradicted** ("sink retries, buffer pushes back"): in-flight events of a dropped TCP connection are discarded. Prefer the `http` sink, or a syslog-ng / rsyslog relay, if loss matters |
| Vector `http` sink (n8n config), default memory buffer | no restart: 24 of 24 delivered, 19-69 s late. With a restart: the 11 records buffered during the outage were **lost**; 3 written while stopped and the 5 written after the restart (still during the outage) were delivered, so the file checkpoint survived | **proven** (retry); **proven** loss on restart with the default buffer |
| Vector `http` sink with `[sinks.fengarde.buffer] type = "disk"` | no restart: 17 of 17 delivered (25-83 s late). With a restart: 14 of 14 outage records written before the restart, 3 of 3 written while stopped, 6 of 6 written after the restart, and all 10 after restore delivered; 0 lost | **proven**. Not in the committed Vector configs; add it for loss-sensitive hosts |
| Vector `journald` checkpoint / `data_dir` | the `file` source's checkpoint survived a restart (the 3 lines written while stopped arrived); the `journald` source's checkpoint was not exercised | **unverified** for journald |
| rsyslog `omfwd`, **committed config** (no queue) | **0 of 16** messages delivered during the outage, all lost; after the target returned the action stayed suspended and 3 more were lost (first delivery 14 s after restore) | **proven** |
| rsyslog with `action.resumeRetryCount="-1" action.resumeInterval="5" queue.type="LinkedList" queue.filename="fgq" queue.maxDiskSpace="100m" queue.saveOnShutdown="on" queue.size="10000"` and `global(workDirectory=...)` | 16 of 16 delivered (4-64 s late); with a restart 14 of 14 delivered, 0 lost; first delivery 1.4 s after restore | **proven** for exactly these settings; **not in the committed configs** |
| syslog-ng `network()`, **committed config** (in-memory buffer) | 16 of 16 delivered, **61-120 s late** (first one ~57 s after restore: the default reconnect timer). If syslog-ng restarts, everything buffered is **lost** (9 of 9) | **proven**. "Overflow drops" and "UDP never back-pressures" were **not** tested: **unverified** |
| syslog-ng with `disk-buffer(reliable(yes) mem-buf-size(1000000) disk-buf-size(50000000) dir("/tmp/ngdb"))` inside `network()` | 17 of 17 delivered (63-121 s late); with a restart 20 of 20 delivered | **proven**; not in the committed configs |

The Fluent Bit settings are in the committed configs; the Vector, rsyslog and syslog-ng persistence options are not, and a stopped ws1 will lose events on those shippers as the table shows. Checked against vendor sources on 2026-11-06 (read, not run): Fluent Bit `Retry_Limit` default is 1 (fluent-bit-docs `administration/scheduling-and-retries.md`); Vector's default memory buffer is 500 events and `when_full` defaults to `block` (`lib/vector-buffers/src/config.rs` and `lib.rs`). Re-test any persistence setting against a stopped ws1 before relying on it: volumes here were tiny, and the runs used one shipper at a time on the same machine as the listener.

**Other operational notes.** The Fluent Bit journald `DB` directory (`/var/lib/fluent-bit/` in the recipe) must exist and be writable before Fluent Bit starts; it is not created for you. Docker's `partial` (split) lines, from json-file records over 16 KiB, are
not reassembled: each fragment is a separate event ([docker.md](docker.md)).

## What was and was not verified

- **Test green per author run (zero-infra, in the CI gate):** every sample above runs through the real WS-2 path (`adapt_record` -> `parsers.resolve`
  -> parse -> OCSF validation) and resolves to the parser in the table, with the expected OCSF class. Samples that equal an
  adapter fixture are asserted equal to it; Vector-side syslog samples are asserted equal to the adapter output after the transformation the config's remap performs (PRI added / host slot = name);
  config blocks in the recipes are asserted byte-identical to `configs/`, must sit in a labelled fence of their recipe doc, and must carry the
  `source_type` / `X-Fengarde-Shipper` (HTTP) or TCP port 5515 (syslog) the recipe claims. A green run is the author's, not independent proof. Run: `python tools/test_shipping_recipes.py`.
- **Run on 2026-11-05 (see the Verification log):** every config except the Windows one (run in a separate pass, below) was linted with its vendor's official container image and then run live in Linux containers
  (Docker Desktop on Windows 11) against a real ws1 `HttpJsonCollector` / `SyslogTCPServer` on a memory bus, with the received payloads pushed through the real WS-2 path. That found and fixed four real defects
  (n8n Fluent Bit parser, n8n Vector decoding, Vector env-var expansion, journald `Read_From_Tail`).
- **Verified in a second pass (2026-11-05):** a real `pihole/pihole:2026.10.1` log (committed as a sample), the rsyslog `address=` / syslog-ng `ip()` relay bindings, syslog-ng `keep-hostname`, and Vector `include_units` against a journal written by real systemd units (superseded 2026-11-11: `include_units` missed `ssh@...service` and `session-cN.scope` entries; the config now matches on `SYSLOG_IDENTIFIER`).
- **Run 2026-11-11 (verification of PR #153):** socket-activated sshd (`ssh@...service`, `session-cN.scope`) against Fluent Bit and Vector, and 60 s ws1 outages against Fluent Bit, Vector, rsyslog and syslog-ng (see Delivery guarantees and the Verification log). It found and fixed: Vector `include_units` missing per-connection and post-login sshd entries (now `include_matches.SYSLOG_IDENTIFIER`); the Fluent Bit configs losing records in an outage (no `Retry_Limit`) and lines written while stopped (no tail `DB`); and it contradicted the Vector TCP `socket` sink claim and the 'None of this was exercised' sentence.
- **Checked 2026-11-07 (review fixes):** OpenSSH 9.8+ `sshd-session` / `sshd-auth` on Debian 13 in a container (Fluent Bit `Systemd_Filter` lines, adapter mapping, a captured journal entry; see [linux-auth.md](linux-auth.md)); nothing new on Windows.
- **Run on Windows 11, 2026-11-05 (third pass, Application and System channels only):** a modified copy of the Windows Fluent Bit config (`Channels Application,System`) ran as a normal user against a real ws1 listener; the shape Fluent Bit actually emits differs from the earlier assumption
  (nested `EventData`), which found and fixed an adapter defect (see windows.md and the Verification log).
- **Still not verified:** the Windows `Security` channel (needs admin) and Sysmon channel, so no real 4624/Sysmon record has been seen; Fluent Bit 5.x on Windows; any real OPNsense / pfSense / Proxmox / n8n output (inputs were hand-written files, `logger`, `systemd-cat`
  or a real systemd journal in a container); a real Pi-hole other than this container image and version (no hardware, no DHCP, no real LAN clients); TLS paths. The only captured samples are `pihole-v6.dnsmasq.txt`, `windows-application.fluentbit.json` and `linux-sshd-session.journald.json` (see [Sample provenance](#sample-provenance)); every other sample is an adapter fixture, template, transcription or illustration.
- **Optional lint:** `tools/lint_shipping_recipes.sh` runs `vector validate --no-environment`, `fluent-bit --dry-run -c`, `rsyslogd -N1 -f`, `syslog-ng --syntax-only -f` where those tools are installed, and skips cleanly otherwise
  (also the Windows-only and journald configs on a non-matching OS). It is a syntax lint only: `fluent-bit --dry-run` did **not** catch the unregistered `json` parser, and the
  Vector lint cannot see the missing env-var expansion. Not part of the default gate.

## Verification log

Images (tags read from Docker Hub on 2026-11-05): `timberio/vector:0.61.0-alpine` (`0.61.0-debian` for the journald source, which needs `journalctl`), `fluent/fluent-bit:5.1.5`, `rsyslog/rsyslog:2026-10` (rsyslogd 8.2610.0, Ubuntu 24.04),
`balabit/syslog-ng:4.12.0`; helpers `alpine:3.20`, `debian:trixie-slim`. `rsyslog/syslog_appliance_alpine` was skipped (last pushed 2018). Host: Windows 11, Docker Desktop, engine 29.6.1 (Linux containers).
Configs were mounted read-only; the ingest token was generated per run and passed by variable name, never printed.

Lint (all against the committed files):

```
vector validate --no-environment /c/<file>.toml   -> Validated (dnsmasq, docker, journald); n8n FAILED first: "unknown field `decoding`" -> fixed, Validated
fluent-bit --dry-run -c /c/<file>.conf            -> "configuration test is successful" (dnsmasq, docker, journald, n8n); windows: "[error] [config] section 'winevtlog' tried to instance a plugin name that doesn't exist" (Linux build; the Windows build was run, see below)
rsyslogd -N1 -f /c/<file>.conf                    -> clean, one warning: omfwd plain TCP is the "backward-compatible insecure default" (forward, relay)
syslog-ng --syntax-only -f /c/<file>.conf         -> exit 0 (forward, relay)
negative controls (bogus option) -> syslog-ng "syntax error, unexpected LL_IDENTIFIER", fluent-bit "check properties for input plugins is failed", rsyslog "parameter 'Bogus' not known"
```

Live runs (shipper container -> `host.docker.internal` -> ws1 listener on the host -> `adapt_record` -> `resolve` -> `normalize_one`; configs copied with the placeholder address / ports substituted, nothing else changed unless noted):

| Recipe | Image | Result |
|---|---|---|
| Fluent Bit docker (tail + parser + Lua + http) | fluent-bit 5.1.5 | 2 records accepted, `docker-json` / `generic_syslog`, class 1002. `%L` parsed `...00.123456789Z`; Lua set `docker_id` (64 hex) / `docker_name` (12 hex). A bare sshd text line is `generic_syslog`, not `linux_ssh` |
| Fluent Bit n8n | fluent-bit 5.1.5 | before fix: `parser 'json' is not registered`, records shipped as `{"log": ...}` and rejected by the parser; after adding `fluent-bit-n8n-parsers.conf`: `n8n_audit`, classes 6003 and 3002 |
| Vector n8n | vector 0.61.0 | before fix: `unknown field decoding`; then literal `${...}` token -> 401; with `VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true` and the remap: `n8n_audit`, 6003 and 3002 |
| Socket-activated sshd (Debian 13, OpenSSH 1:10.0p1-7+deb13u4, privileged systemd container with `ssh.socket`; stock `Accept=no`, then a custom `Accept=yes` socket with `ssh@.service` and `sshd -i`), 2026-11-11 | own image `fengarde-v-sshsock` (trixie-slim + systemd + openssh-server + sshpass); wrong password, unknown user, accepted login | `SYSLOG_IDENTIFIER` `sshd` (listener) / `sshd-session` (all login lines); `sshd-auth` never appeared. Units: `ssh.service`, `ssh@<n>-...service`, `session-cN.scope`. Fluent Bit committed config: all 33 entries of the first run delivered. Vector with `include_units`: 17 of 33 (first run), 16 of 22 (re-run); Vector with `include_matches.SYSLOG_IDENTIFIER` (committed now): 33 of 33 and 22 of 22 |
| Outage runs, 2026-11-11 (60 s listener stop, refused connections) | fluent-bit 5.1.5, vector 0.61.0, rsyslog `2026-10`, syslog-ng 4.12.0; real ws1 listeners on the host; `logger` on `/dev/log` for rsyslog / syslog-ng, an appended file for Fluent Bit / Vector | see the Delivery guarantees table; 17 runs by the verification session on the pre-change configs, 5 re-runs on the changed Fluent Bit config and Vector restart behaviour. Limits: 40 records at most, one shipper at a time, no black-hole outage, no overflow, no Windows |
| Fluent Bit journald (real journal from a sibling container) | fluent-bit 5.1.5 | `Read_From_Tail On`: 0 of 4 new entries; `Off`: 4 of 4; with `DB` a restart did not replay. Records `linux_ssh`, 3002 |
| Vector journald (real journal from a sibling container without systemd units, `include_units` dropped in the test copy) | vector 0.61.0-debian | `.host`, `._PID`, `.message`, `.timestamp` present; sshd lines `linux_ssh`, 3002; journald's own messages were labelled `sshd[pid]` too |
| Vector docker_logs (Docker socket) | vector 0.61.0 | `.container_name`, `.stream`, `.timestamp`, `.message` present; `<14>` stdout / `<11>` stderr; `generic_syslog`, 1002; LF-terminated |
| Fluent Bit dnsmasq (syslog output) | fluent-bit 5.1.5 | LF-terminated, wrapped `<14>... pihole01 fluent-bit: <line>`; query line `dns_query` 4002, reply line `generic_syslog` 1002 |
| Vector dnsmasq | vector 0.61.0 | LF-terminated; query line `dns_query` 4002; reply line and blank line dead-lettered (`parser returned None`) |
| rsyslog forward / relay | rsyslog 8.2610.0 | `TCP_Framing="traditional"` = LF-terminated; sshd line `linux_ssh` 3002 (plus rsyslog's own startup messages as generic events) |
| syslog-ng forward / relay | syslog-ng 4.12.0 | LF-terminated with no framing option; sshd line `linux_ssh` 3002; relay replaced the host field with the sender's resolved name |

Raw bytes seen by the TCP listener (captured by a proxy in front of it), for example syslog-ng: `b'<38>Nov  5 10:00:01 localhost sshd[77]: Failed password ... (ng-relay)\n'`.
The inputs were my own files and `logger` / `systemd-cat` / `/dev/udp` writes; the driver script lives outside the repo (scratch only). Not covered: real appliances other than the Pi-hole container, TLS, Windows other than the run below.

### Windows run (2026-11-05, Windows 11 Pro de-DE, normal user)

Downloaded `https://packages.fluentbit.io/windows/fluent-bit-4.2.8-win64.zip` (the vendor's download host); SHA256 `1bd0575c2ae6c1803b6288c5cd9efab1546aaa45933e1d5019f8401b409b8eec` equals the published
`.sha256` file. Extracted into a scratch directory, run without elevation, no service, registry, firewall or task changes; the binary and every captured file were deleted afterwards. The same SHA256 check for
`fluent-bit-5.1.5-win64.zip` (`96e9489e...04bcd`) also matched, but that build printed `socketpair: No error` / `pipe: No error` and exited 1 for every command including `--version` (cause undetermined; 4.2.8 ran).

```
fluent-bit -i winevtlog --help          -> input present in 4.2.8; options match the vendor docs (channels, event_data_as_map, event_template_cache_size=256, ignore_missing_channels, read_existing_events, ...)
event_data_as_map=true, cache_size=0    -> [error] event_template_cache_size must be greater than zero when event_data_as_map is enabled; failed initialize input
Channels Application,Microsoft-Windows-Sysmon/Operational (Sysmon not installed) -> [error] cannot subscribe ... (15007); failed to open and no subscribed channels; input init failed; with Ignore_Missing_Channels true: starts
repo config, Channels=Application,System, Host/Port = local ws1 (memory bus, per-run token), Read_Existing_Events + last-hour Event_Query (test only) -> 2 POSTs of 1330 + 1310 records, HTTP 200, 0 skipped
```

Through `adapt_record` -> `resolve` -> `normalize_one`: 2,640 records, no exceptions; all routed to `windows_eventlog`; 2,638 `parser returned None` (EventIDs not mapped); 2 System 7045 -> class 1002, message
`Service installed: ? -> ? (by ?)` when first run; that provider has no `EventData` map (name/path only in `StringInserts`), which the `windows_eventlog` parser now reads (positional order ServiceName, ImagePath, ServiceType, StartType, AccountName, checked on a live 7045 event 2026-11-05; regression test in `parsers/test_recall_events.py`). Not run: Security and Sysmon channels, Fluent Bit 5.x on Windows, TLS.
Run harness (scratch only, not committed): ws1 `HttpJsonCollector` on `127.0.0.1` with a free port, memory bus and a generated token passed to Fluent Bit by environment variable, never printed.

Second pass (2026-11-05, same host and engine; extra images `pihole/pihole:2026.10.1` (tag read from Docker Hub, pushed 2026-10-31), a local `debian:trixie-slim` + `systemd` + `openssh-server` image built for the test, `alpine:3.20` as the UDP sender):

| Item | Setup | Result |
|---|---|---|
| Real Pi-hole log | `pihole/pihole:2026.10.1` (core v6.5, FTL v6.8, dnsmasq `pi-hole-v2.93+30`, Alpine); `nslookup`/`dig` inside and from a sibling; one `pihole deny` domain | 81 log lines committed as `samples/pihole-v6.dnsmasq.txt` (client bridge IPs scrubbed). Vector 0.61.0 tail of the file: 82 bus messages, 25 `query[...]` lines `dns_query` 4002, 56 other lines + 1 blank dead-lettered. Fluent Bit 5.1.5: 81 messages, 25 `dns_query` 4002, 56 `generic_syslog` 1002, each wrapped `<14>Nov  5 09:17:30 pihole01 fluent-bit: <line>`. A blocked query is an ordinary `dns_query`; the `exactly denied` line is a separate generic event or dead-letter |
| rsyslog `address=` | rsyslog 8.2610.0, user-defined Docker network `10.99.0.0/24`, relay `.10`, datagrams to `127.0.0.1` (inside the relay) and to `10.99.0.10` (from a sibling) | no option: both relayed; `address="10.99.0.10"`: only the LAN datagram; `address="127.0.0.1"`: only the loopback datagram |
| syslog-ng `ip()` | syslog-ng 4.12.0, same network | no option: both relayed; `ip("10.99.0.10")`: only LAN; `ip("127.0.0.1")`: only loopback |
| Host field through the relay | same datagrams, host name `FWHOST` | rsyslog: `FWHOST` kept (default). syslog-ng default `keep-hostname(no)`: replaced with the sender's reverse-resolved name (`localhost` / the sender container's name). With `options { keep-hostname(yes); };`: `FWHOST` kept. The committed syslog-ng relay config now sets it; the committed rsyslog and syslog-ng relay configs were re-run (placeholder address substituted) and `FWHOST` arrived, `syslog-ng --syntax-only` exit 0 |
| Vector `include_units` | debian:trixie-slim with systemd as PID 1 (`--privileged --cgroupns=host`, `/sys/fs/cgroup` mounted; Docker Desktop accepted it with no host change), `ssh.service` + a `noise.service`; Vector 0.61.0-debian reading the journal volume | committed config: 9 records, all from `ssh.service`; same journal without `include_units`: 4275 records incl. `noise.service` and kernel messages, all mislabelled `sshd[pid]`; `_PID`-less (kernel) entries fail the remap |

Limits: the datagram senders were `/dev/udp` and `nc`, not an OPNsense/pfSense; the bind test proves the daemon option, not a firewall; a systemd container is a stand-in for a host; the stock `rsyslog/syslog_appliance_alpine` image was not used.

## Prerequisites

### Reaching ws1 from another host

Out of the box nothing here works from a different machine. `infra/docker-compose.yml` publishes ws1's HTTP ingest as
`127.0.0.1:8554` and TCP syslog as `127.0.0.1:5515` (UDP 5514 is already on all interfaces). The recipes use the documentation
placeholder `192.0.2.10` for your ws1 host; for a remote shipper to reach it:

1. Change the host-side mapping in the `ws1-collectors` `ports:` line of `infra/docker-compose.yml`: `"5515:5515/tcp"` and/or
   `"8554:8554"` (or prefix a specific LAN address, e.g. `"<lan-ip>:8554:8554"`). The in-container binds are already `0.0.0.0`
   (`INGEST_HTTP_HOST`, `SYSLOG_TCP_HOST`), so the publish is the only knob; see [../ingest-http.md](../ingest-http.md) and
   [../syslog-tcp.md](../syslog-tcp.md) (Exposure). Then `docker compose up -d ws1-collectors`.
2. Add a firewall rule on the ws1 host allowing only your shippers' addresses to TCP 8554 / 5515. The syslog listener is plaintext
   and unauthenticated, and the HTTP bearer token travels in cleartext over `http://` (every recipe config that sends it carries a
   WARNING comment): use the TLS front from [../deployment.md](../deployment.md) or keep it on a trusted segment.

Shippers on the same host as ws1 can use `127.0.0.1` instead.

### Common settings and framing

`$FENGARDE_INGEST_TOKEN` must be set on the sender (HTTP recipes); replace `192.0.2.10` with your ws1 host.

TCP syslog framing is a **listener-wide** setting (`SYSLOG_TCP_FRAMING`), not per sender. All recipes assume the default
`newline` framing (LF-delimited; rsyslog calls this `TCP_Framing="traditional"`). A sender that uses octet-counted framing (for
rsyslog `TCP_Framing="octet-counted"`) needs a separate listener configured with `SYSLOG_TCP_FRAMING=octet-counting`; do not mix
both on one listener.
