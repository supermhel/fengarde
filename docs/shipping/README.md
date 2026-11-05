# Shipping recipes (WP-1.4)

How to get real logs into FENGARDE with Vector, Fluent Bit, rsyslog or syslog-ng. Each recipe names the parser that handles
the data, the ingest path and what is **not** covered. Background: [../input-adapters.md](../input-adapters.md),
[../ingest-http.md](../ingest-http.md), [../syslog-tcp.md](../syslog-tcp.md).

| Source / shipper | Recipe | Ingest path | Parser (`source_type` in the registry) | Sample checked | Sample provenance |
|---|---|---|---|---|---|
| Windows Sysmon (Fluent Bit) | [windows.md](windows.md) | HTTP, `source_type=windows_eventlog`, `fluentbit-winevtlog` | `sysmon` | [windows-sysmon.fluentbit.json](samples/windows-sysmon.fluentbit.json) | hand transcription of a third-party published output, not byte-verified |
| Windows Application (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` (no event: EventID 1001 unmapped) | [windows-application.fluentbit.json](samples/windows-application.fluentbit.json) | captured on Windows 11 with Fluent Bit 4.2.8 on 2026-11-05 (Application channel), scrubbed |
| Windows Security (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-security.fluentbit.json](samples/windows-security.fluentbit.json) | template-derived |
| Windows 4688 (Winlogbeat) | [windows.md](windows.md) | HTTP via a relay (no config), `winlogbeat` | `windows_eventlog` | [windows-4688.winlogbeat.json](samples/windows-4688.winlogbeat.json) | template-derived |
| Windows 4624 (Winlogbeat) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-4624.winlogbeat.json](samples/windows-4624.winlogbeat.json) | template-derived |
| Linux sshd (Fluent Bit journald) | [linux-auth.md](linux-auth.md) | HTTP, `source_type=generic_syslog`, `fluentbit-journald` | `linux_ssh` | [linux-sshd.fluentbit-journald.json](samples/linux-sshd.fluentbit-journald.json) | schema-derived |
| Linux sshd (Vector journald) | [linux-auth.md](linux-auth.md) | syslog TCP 5515 | `linux_ssh` | [linux-sshd.vector.syslog.txt](samples/linux-sshd.vector.syslog.txt) | adapter output shape plus `<38>` PRI (what the remap targets; not a Vector capture) |
| Docker n8n container (Fluent Bit) | [docker.md](docker.md) | HTTP, `generic_syslog`, `docker-json` | `generic_syslog` | [docker-n8n.fluentbit.json](samples/docker-n8n.fluentbit.json) | documented example: adapter fixture shape, NOT this config's literal output (the config's Lua sets `docker_name` to a 12-hex id; `linux_ssh` needs a `sshd[pid]:` prefix in the container's own text, see docker.md) |
| Docker sshd container (Fluent Bit) | [docker.md](docker.md) | same | `linux_ssh` | [docker-sshd.fluentbit.json](samples/docker-sshd.fluentbit.json) | documented example |
| Docker (Vector) | [docker.md](docker.md) | syslog TCP 5515 | `generic_syslog` | [docker-n8n.vector.syslog.txt](samples/docker-n8n.vector.syslog.txt) | adapter output with the container name in the host slot, as the remap emits (not a Vector capture) |
| dnsmasq / Pi-hole (Vector, rsyslog, syslog-ng) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.syslog.txt](samples/dnsmasq.syslog.txt); real capture [pihole-v6.dnsmasq.txt](samples/pihole-v6.dnsmasq.txt) | documented (parser docstring); capture from `pihole/pihole:2026.10.1` |
| dnsmasq / Pi-hole (Fluent Bit) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.fluentbit-wrapped.syslog.txt](samples/dnsmasq.fluentbit-wrapped.syslog.txt) | template-derived (assumed header) |
| n8n (Vector, Fluent Bit) | [n8n.md](n8n.md) | HTTP, `source_type=n8n_audit` | `n8n_audit` | [n8n-audit.json](samples/n8n-audit.json) | documented (parser docstring); native n8n shape unverified |
| Proxmox sshd (rsyslog, syslog-ng) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [proxmox-sshd.syslog.txt](samples/proxmox-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense sshd (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [opnsense-sshd.syslog.txt](samples/opnsense-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense filterlog (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `generic_syslog` (no firewall parser) | [pfsense-filterlog.syslog.txt](samples/pfsense-filterlog.syslog.txt) | illustrative |

## What was and was not verified

- **Test green per author run (zero-infra, in the CI gate):** every sample above runs through the real WS-2 path (`adapt_record` -> `parsers.resolve`
  -> parse -> OCSF validation) and resolves to the parser in the table, with the expected OCSF class. Samples that equal an
  adapter fixture are asserted equal to it; Vector-side syslog samples are asserted equal to the adapter output after the transformation the config's remap performs (PRI added / host slot = name);
  config blocks in the recipes are asserted byte-identical to `configs/`, must sit in a labelled fence of their recipe doc, and must carry the
  `source_type` / `X-Fengarde-Shipper` (HTTP) or TCP port 5515 (syslog) the recipe claims. A green run is the author's, not independent proof. Run: `python tools/test_shipping_recipes.py`.
- **Run on 2026-11-05 (see the Verification log):** every config except the Windows one (run in a separate pass, below) was linted with its vendor's official container image and then run live in Linux containers
  (Docker Desktop on Windows 11) against a real ws1 `HttpJsonCollector` / `SyslogTCPServer` on a memory bus, with the received payloads pushed through the real WS-2 path. That found and fixed four real defects
  (n8n Fluent Bit parser, n8n Vector decoding, Vector env-var expansion, journald `Read_From_Tail`).
- **Verified in a second pass (2026-11-05):** a real `pihole/pihole:2026.10.1` log (committed as a sample), the rsyslog `address=` / syslog-ng `ip()` relay bindings, syslog-ng `keep-hostname`, and Vector `include_units` against a journal written by real systemd units.
- **Run on Windows 11, 2026-11-05 (third pass, Application and System channels only):** the Windows Fluent Bit config ran as a normal user against a real ws1 listener; the real record shape differs from the earlier assumption
  (nested `EventData`), which found and fixed an adapter defect (see windows.md and the Verification log).
- **Still not verified:** the Windows `Security` channel (needs admin) and Sysmon channel, so no real 4624/Sysmon record has been seen; Fluent Bit 5.x on Windows; any real OPNsense / pfSense / Proxmox / n8n output (inputs were hand-written files, `logger`, `systemd-cat`
  or a real systemd journal in a container); a real Pi-hole other than this container image and version (no hardware, no DHCP, no real LAN clients); TLS paths. Sample files other than `pihole-v6.dnsmasq.txt` are still adapter fixtures / templates, not captures.
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
`Service installed: ? -> ? (by ?)` (no `EventData` map for that provider; service name/path only in `StringInserts`). Not run: Security and Sysmon channels, Fluent Bit 5.x on Windows, TLS.
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
