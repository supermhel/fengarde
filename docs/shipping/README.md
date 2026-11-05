# Shipping recipes (WP-1.4)

How to get real logs into FENGARDE with Vector, Fluent Bit, rsyslog or syslog-ng. Each recipe names the parser that handles
the data, the ingest path and what is **not** covered. Background: [../input-adapters.md](../input-adapters.md),
[../ingest-http.md](../ingest-http.md), [../syslog-tcp.md](../syslog-tcp.md).

| Source / shipper | Recipe | Ingest path | Parser (`source_type` in the registry) | Sample checked | Sample provenance |
|---|---|---|---|---|---|
| Windows Sysmon (Fluent Bit) | [windows.md](windows.md) | HTTP, `source_type=windows_eventlog`, `fluentbit-winevtlog` | `sysmon` | [windows-sysmon.fluentbit.json](samples/windows-sysmon.fluentbit.json) | hand transcription of a third-party published output, not byte-verified |
| Windows Security (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-security.fluentbit.json](samples/windows-security.fluentbit.json) | template-derived |
| Windows 4688 (Winlogbeat) | [windows.md](windows.md) | HTTP via a relay (no config), `winlogbeat` | `windows_eventlog` | [windows-4688.winlogbeat.json](samples/windows-4688.winlogbeat.json) | template-derived |
| Windows 4624 (Winlogbeat) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-4624.winlogbeat.json](samples/windows-4624.winlogbeat.json) | template-derived |
| Linux sshd (Fluent Bit journald) | [linux-auth.md](linux-auth.md) | HTTP, `source_type=generic_syslog`, `fluentbit-journald` | `linux_ssh` | [linux-sshd.fluentbit-journald.json](samples/linux-sshd.fluentbit-journald.json) | schema-derived |
| Linux sshd (Vector journald) | [linux-auth.md](linux-auth.md) | syslog TCP 5515 | `linux_ssh` | [linux-sshd.vector.syslog.txt](samples/linux-sshd.vector.syslog.txt) | adapter output shape plus `<38>` PRI (what the remap targets; not a Vector capture) |
| Docker n8n container (Fluent Bit) | [docker.md](docker.md) | HTTP, `generic_syslog`, `docker-json` | `generic_syslog` | [docker-n8n.fluentbit.json](samples/docker-n8n.fluentbit.json) | documented example: adapter fixture shape, NOT this config's literal output (the config's Lua sets `docker_name` to a 12-hex id) |
| Docker sshd container (Fluent Bit) | [docker.md](docker.md) | same | `linux_ssh` | [docker-sshd.fluentbit.json](samples/docker-sshd.fluentbit.json) | documented example |
| Docker (Vector) | [docker.md](docker.md) | syslog TCP 5515 | `generic_syslog` | [docker-n8n.vector.syslog.txt](samples/docker-n8n.vector.syslog.txt) | adapter output with the container name in the host slot, as the remap emits (not a Vector capture) |
| dnsmasq / Pi-hole (Vector, rsyslog, syslog-ng) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.syslog.txt](samples/dnsmasq.syslog.txt) | documented (parser docstring) |
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
- **Not verified:** the configs themselves. They were written from vendor docs and **not executed or linted** on the machine that
  produced them (Vector, Fluent Bit, rsyslog, syslog-ng are not installed there). Option names that could not be checked are
  marked **unverified** with the vendor URL in the recipe. Whether a real shipper emits exactly the sample shape is not proven;
  only the Fluent Bit Sysmon sample is a hand transcription of a third-party published output, not byte-verified.
- **Optional lint:** `tools/lint_shipping_recipes.sh` extracts the config files and runs `vector validate`, `fluent-bit --dry-run`,
  `rsyslogd -N1`, `syslog-ng --syntax-only` where those tools exist, and skips cleanly otherwise (also the Windows-only and journald configs on a
  non-matching OS); tool output is shown on failure. Not part of the default gate.

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
