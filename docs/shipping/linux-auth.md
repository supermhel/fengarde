# Linux auth / sshd

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.

Parser: `linux_ssh` (class 3002 Authentication). Both paths below declare `generic_syslog`; the sshd identifier makes the
WS-2 text sniff hand the line to `linux_ssh`.

## Fluent Bit -> HTTP (journald, adapter `fluentbit-journald`)

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Keep `Strip_Underscores Off`: the adapter reads `MESSAGE`, `_HOSTNAME`, `_PID`, `SYSLOG_IDENTIFIER`.

**Verified live (Fluent Bit 5.1.5 systemd input reading a real journal written by the systemd-journald of a debian:trixie-slim sibling container):** records carry exactly those keys
(`PRIORITY`, `_HOSTNAME`, `_PID`, `SYSLOG_IDENTIFIER`, `MESSAGE`, ...) and resolved to `linux_ssh` (class 3002). **Fixed by this test:** with `Read_From_Tail On` the plugin delivered
0 of 4 entries written after start (same setup, `Off` delivered 4 of 4), so the recipe uses `Read_From_Tail Off` plus `DB /var/lib/fluent-bit/journald.db`; a restart with the DB kept
delivered only the entry written afterwards (no replay). First start therefore ships the existing matching journal history once. `_SOURCE_REALTIME_TIMESTAMP` is absent for
stdout-transport entries (the sample has it; it comes from the syslog transport).

**What `Read_From_Tail` does, as measured.** `Off` starts at the beginning of the (filtered) journal: the first start ships all existing matching history, then follows. `On` should start at the end and ship only new
entries; in the same live test it delivered 0 of the 4 entries written after start (the cause was not determined, so `On` is unverified rather than known broken). The `DB` directory (`/var/lib/fluent-bit/` above) must exist and be
writable by the Fluent Bit user before it starts; Fluent Bit does not create it. Without a working `DB`, a restart re-reads from the beginning (`Off`).

**Event time of sshd events is the receipt time, so backfill and replay are stamped "now".** The `linux_ssh` parser stamps every event with `meta.received_at` (the repo's clock-skew policy: the sender's clock is not
trusted), not with the time inside the line. The journald adapter rebuilds the RFC 3164 date from `_SOURCE_REALTIME_TIMESTAMP`, but that date never reaches an sshd event. Probe: a 2023 journal entry delivered in 2026 became a 2026 event.
Consequences: the first start with `Read_From_Tail Off` (history), a restart without the `DB`, and anything replayed after a ws1 outage all arrive with the time they were received, not the time they happened, which distorts time-window
detections and any forensic timeline. The parser's time policy is deliberately unchanged. To keep history out of the timeline, start with `Read_From_Tail On` (unverified, see above) and accept that earlier entries are not shipped.

**Backfill and the ingest body cap.** ws1 rejects a request body over `INGEST_HTTP_MAX_BODY_BYTES` (default 1 MiB, counted as `body_over_cap`). A large first batch, which `Read_From_Tail Off` on a host with a big journal can produce, may exceed it
and be dropped by ws1 with Fluent Bit logging a flush failure. This was measured only for the Windows recipe; for journald it is a risk, not an observation. Raise the cap before a backfill.

```ini fluent-bit-journald.conf
# Fluent Bit (Linux) systemd/journald -> FENGARDE HTTP ingest. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush        5

[INPUT]
    Name               systemd
    Tag                host.auth
    Systemd_Filter     SYSLOG_IDENTIFIER=sshd
    Read_From_Tail     Off
    DB                 /var/lib/fluent-bit/journald.db
    Strip_Underscores  Off

[OUTPUT]
    Name             http
    Match            host.*
    Host             192.0.2.10
    Port             8554
    URI              /v1/ingest?source_type=generic_syslog&format=ndjson
    Format           json_lines
    Json_Date_Key    false
    Header           Authorization Bearer ${FENGARDE_INGEST_TOKEN}
    Header           X-Fengarde-Shipper fluentbit-journald
    Header           X-Fengarde-Source web01
```

Sample: [journald sshd failure, schema-derived](samples/linux-sshd.fluentbit-journald.json) (field names per `journal-fields(5)`;
values representative) -> `linux_ssh`.

## Vector -> TCP syslog 5515

Vector builds the RFC 3164 line itself and sends it to the syslog TCP listener
([../syslog-tcp.md](../syslog-tcp.md); default newline framing, plaintext and unauthenticated: keep it on a trusted segment).
Vendor docs: <https://vector.dev/docs/reference/configuration/sources/journald/> and
<https://vector.dev/docs/reference/configuration/sinks/socket/>. **Verified live** (Vector 0.61.0 debian image, which ships `journalctl`; the alpine image does not): `.host`, `._PID`, `.message`, `.timestamp` exist; the socket sink with `codec = "text"` sent LF-terminated frames;
`sshd` lines resolved to `linux_ssh`. **`include_units` verified** (Vector 0.61.0-debian reading the journal of a real systemd-as-PID-1 container, debian:trixie-slim, privileged, with `ssh.service` and an extra `noise.service`): the committed config shipped only the 9 `ssh.service` entries (no `noise.service`, kernel or systemd lines); with the line removed the same journal produced 4275 records, all labelled `sshd[pid]` (e.g. `noise-from-other-unit`, kernel network messages), and entries without `_PID` (kernel) fail the remap (`expected string, got null`) and are dropped. Of the 9 shipped lines, `Invalid user ...` resolved to `linux_ssh` (3002); `Server listening ...` and `Connection closed by ...` resolved to `generic_syslog` (1002). On Debian 13 (OpenSSH 10) the journal's own identifier for the per-connection process is `sshd-session`, which the hardcoded `sshd[pid]` label hides.

```toml vector-journald.toml
# Vector (Linux) journald -> FENGARDE TCP syslog 5515. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# Verified on Vector 0.61.0 (debian image, which ships journalctl): .host, ._PID, .message, .timestamp. include_units verified 2026-11-05 on a journal written by real systemd units (README Verification log).
# The sshd[pid] label is hardcoded for every record, so keep include_units: without it other units are mislabelled sshd. Unit names are given without the .service suffix (Debian's is `ssh`).
[sources.journal]
type = "journald"
include_units = ["ssh", "sshd"]

[transforms.to_line]
type = "remap"
inputs = ["journal"]
source = '''
msg = string!(.message)
.message = join(["<38>", format_timestamp!(.timestamp, format: "%b %e %H:%M:%S"), " ", string!(.host), " sshd[", string!(._PID), "]: ", msg], separator: "")
'''

[sinks.fengarde]
type = "socket"
inputs = ["to_line"]
mode = "tcp"
address = "192.0.2.10:5515"
encoding.codec = "text"
```

Sample: [the line this remap is meant to produce](samples/linux-sshd.vector.syslog.txt) -> `linux_ssh`. It is the body the
`fluentbit-journald` adapter produces for the journald fixture with the remap's `<38>` PRI prepended (the adapter emits no PRI; this
remap does; `.host` fills the host slot and the program slot is the hardcoded `sshd`). The test asserts that equality. A real Vector
emission was never captured.

## Not covered

- Non-sshd auth (sudo, PAM-only, `su`, login): lands as `generic_syslog`, not `linux_ssh`.
- The Vector `<38>` priority is hardcoded (auth.info); a failure line is not given a higher severity by the shipper.
- Journald binary export, `auditd`.
