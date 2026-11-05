# Shipping recipes (WP-1.4)

How to get real logs into FENGARDE with Vector, Fluent Bit, rsyslog or syslog-ng. Each recipe names the parser that handles
the data, the ingest path and what is **not** covered. Background: [../input-adapters.md](../input-adapters.md),
[../ingest-http.md](../ingest-http.md), [../syslog-tcp.md](../syslog-tcp.md).

| Source / shipper | Recipe | Ingest path | Parser (`source_type` in the registry) | Sample checked | Sample provenance |
|---|---|---|---|---|---|
| Windows Sysmon (Fluent Bit) | [windows.md](windows.md) | HTTP, `source_type=windows_eventlog`, `fluentbit-winevtlog` | `sysmon` | [windows-sysmon.fluentbit.json](samples/windows-sysmon.fluentbit.json) | transcribed real capture |
| Windows Security (Fluent Bit) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-security.fluentbit.json](samples/windows-security.fluentbit.json) | template-derived |
| Windows 4688 (Winlogbeat) | [windows.md](windows.md) | HTTP via a relay (no config), `winlogbeat` | `windows_eventlog` | [windows-4688.winlogbeat.json](samples/windows-4688.winlogbeat.json) | template-derived |
| Windows 4624 (Winlogbeat) | [windows.md](windows.md) | same | `windows_eventlog` | [windows-4624.winlogbeat.json](samples/windows-4624.winlogbeat.json) | template-derived |
| Linux sshd (Fluent Bit journald) | [linux-auth.md](linux-auth.md) | HTTP, `source_type=generic_syslog`, `fluentbit-journald` | `linux_ssh` | [linux-sshd.fluentbit-journald.json](samples/linux-sshd.fluentbit-journald.json) | schema-derived |
| Linux sshd (Vector journald) | [linux-auth.md](linux-auth.md) | syslog TCP 5515 | `linux_ssh` | [linux-sshd.vector.syslog.txt](samples/linux-sshd.vector.syslog.txt) | adapter output (what the remap targets) |
| Docker n8n container (Fluent Bit) | [docker.md](docker.md) | HTTP, `generic_syslog`, `docker-json` | `generic_syslog` | [docker-n8n.fluentbit.json](samples/docker-n8n.fluentbit.json) | documented example |
| Docker sshd container (Fluent Bit) | [docker.md](docker.md) | same | `linux_ssh` | [docker-sshd.fluentbit.json](samples/docker-sshd.fluentbit.json) | documented example |
| Docker (Vector) | [docker.md](docker.md) | syslog TCP 5515 | `generic_syslog` | [docker-n8n.vector.syslog.txt](samples/docker-n8n.vector.syslog.txt) | adapter output (what the remap targets) |
| dnsmasq / Pi-hole (Vector, rsyslog, syslog-ng) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.syslog.txt](samples/dnsmasq.syslog.txt) | documented (parser docstring) |
| dnsmasq / Pi-hole (Fluent Bit) | [dnsmasq-pihole.md](dnsmasq-pihole.md) | syslog TCP 5515 | `dns_query` | [dnsmasq.fluentbit-wrapped.syslog.txt](samples/dnsmasq.fluentbit-wrapped.syslog.txt) | template-derived (assumed header) |
| n8n (Vector, Fluent Bit) | [n8n.md](n8n.md) | HTTP, `source_type=n8n_audit` | `n8n_audit` | [n8n-audit.json](samples/n8n-audit.json) | documented (parser docstring); native n8n shape unverified |
| Proxmox sshd (rsyslog, syslog-ng) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [proxmox-sshd.syslog.txt](samples/proxmox-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense sshd (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `linux_ssh` | [opnsense-sshd.syslog.txt](samples/opnsense-sshd.syslog.txt) | illustrative |
| OPNsense/pfSense filterlog (relay) | [network-gear.md](network-gear.md) | syslog TCP 5515 | `generic_syslog` (no firewall parser) | [pfsense-filterlog.syslog.txt](samples/pfsense-filterlog.syslog.txt) | illustrative |

## What was and was not verified

- **Verified (zero-infra, in the CI gate):** every sample above runs through the real WS-2 path (`adapt_record` -> `parsers.resolve`
  -> parse -> OCSF validation) and resolves to the parser in the table, with the expected OCSF class. Samples that equal an
  adapter fixture are asserted equal to it; Vector-side syslog lines that claim to be adapter output are asserted equal to it;
  config blocks in the recipes are asserted byte-identical to `configs/`. Run: `python tools/test_shipping_recipes.py`.
- **Not verified:** the configs themselves. They were written from vendor docs and **not executed or linted** on the machine that
  produced them (Vector, Fluent Bit, rsyslog, syslog-ng are not installed there). Option names that could not be checked are
  marked **unverified** with the vendor URL in the recipe. Whether a real shipper emits exactly the sample shape is not proven;
  only the Fluent Bit Sysmon sample is a (hand-transcribed) published capture.
- **Optional lint:** `tools/lint_shipping_recipes.sh` extracts the config files and runs `vector validate`, `fluent-bit --dry-run`,
  `rsyslogd -N1`, `syslog-ng --syntax-only` where those tools exist, and skips cleanly otherwise. Not part of the default gate.

Common settings: `$FENGARDE_INGEST_TOKEN` must be set on the sender; replace the placeholder `192.0.2.10` with your ws1 host.
