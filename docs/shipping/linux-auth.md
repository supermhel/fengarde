# Linux auth / sshd

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What a green test (per author run) covers is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

Parser: `linux_ssh` (class 3002 Authentication). Both paths below declare `generic_syslog`; the sshd identifier makes the
WS-2 text sniff hand the line to `linux_ssh`.

## Fluent Bit -> HTTP (journald, adapter `fluentbit-journald`)

Ingest path: `POST http://<ws1>:8554/v1/ingest?source_type=<type>&format=ndjson` with
`Authorization: Bearer $FENGARDE_INGEST_TOKEN`, optional `X-Fengarde-Shipper` (adapter label, one per sender) and
`X-Fengarde-Source` (device name). See [../ingest-http.md](../ingest-http.md). TLS is not terminated by ws1; put it behind the proxy in
[../deployment.md](../deployment.md) before leaving a loopback/LAN segment.

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

Keep `Strip_Underscores Off`: the adapter reads `MESSAGE`, `_HOSTNAME`, `_PID`, `SYSLOG_IDENTIFIER`.

```ini fluent-bit-journald.conf
# Fluent Bit (Linux) systemd/journald -> FENGARDE HTTP ingest. Written from vendor docs, NOT executed.
# WARNING: Authorization: Bearer goes over plain http:// -- cleartext on the wire; use the TLS front from docs/deployment.md or keep it on a trusted segment.
[SERVICE]
    Flush        5

[INPUT]
    Name               systemd
    Tag                host.auth
    Systemd_Filter     SYSLOG_IDENTIFIER=sshd
    Read_From_Tail     On
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
<https://vector.dev/docs/reference/configuration/sinks/socket/>. The journald field names and the socket framing default are **unverified**.

```toml vector-journald.toml
# Vector (Linux) journald -> FENGARDE TCP syslog 5515. Written from vendor docs, NOT executed.
# The journald field names used below (.host, ._PID, .message) are UNVERIFIED.
[sources.journal]
type = "journald"
include_units = ["ssh", "sshd"]

[transforms.to_line]
type = "remap"
inputs = ["journal"]
source = '''
msg = string!(.message)
.message = join!(["<38>", format_timestamp!(.timestamp, format: "%b %e %H:%M:%S"), " ", string!(.host), " sshd[", string!(._PID), "]: ", msg], separator: "")
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
