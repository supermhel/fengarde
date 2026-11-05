# dnsmasq / Pi-hole DNS query log

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What a green test (per author run) covers is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

Parser: `dns_query` (class 4002). Path: syslog TCP 5515 (or UDP 5514), declared `generic_syslog`; the `query[...] ... from ...`
shape makes the WS-2 text sniff select `dns_query`. dnsmasq logs queries only with `log-queries`; Pi-hole writes
`/var/log/pihole/pihole.log` (path is the usual default, **verify on your install**).

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

## Vector

```toml vector-dnsmasq.toml
# Vector: dnsmasq/Pi-hole query log -> FENGARDE TCP syslog 5515. Written from vendor docs, NOT executed.
# The file already carries "Mon DD HH:MM:SS dnsmasq[pid]: query[A] name from ip"; only a <PRI> is added.
[sources.dns]
type = "file"
include = ["/var/log/pihole/pihole.log"]

[transforms.to_line]
type = "remap"
inputs = ["dns"]
source = '''
.message = "<30>" + string!(.message)
'''

[sinks.fengarde]
type = "socket"
inputs = ["to_line"]
mode = "tcp"
address = "192.0.2.10:5515"
encoding.codec = "text"
```

Sample: [dnsmasq query line with a PRI added](samples/dnsmasq.syslog.txt). The line itself is the example in the `dns_query`
parser docstring (documented shape, not a capture from a real Pi-hole) -> `dns_query`.

## Fluent Bit

Vendor docs: <https://docs.fluentbit.io/manual/pipeline/outputs/syslog>. Option names and TCP frame terminator **unverified**.
The plugin wraps the original line in its own header.

```ini fluent-bit-dnsmasq.conf
# Fluent Bit: dnsmasq/Pi-hole query log -> FENGARDE TCP syslog 5515. Written from vendor docs, NOT executed.
# Frame terminator of the syslog output over TCP is UNVERIFIED (FENGARDE default expects newline).
[INPUT]
    Name   tail
    Path   /var/log/pihole/pihole.log
    Tag    dns

[OUTPUT]
    Name                    syslog
    Match                   dns
    Host                    192.0.2.10
    Port                    5515
    Mode                    tcp
    Syslog_Format           rfc3164
    Syslog_Message_Key      log
    Syslog_Hostname_Preset  pihole01
    Syslog_Appname_Preset   fluent-bit
```

Sample: [wrapped form](samples/dnsmasq.fluentbit-wrapped.syslog.txt) -- the wrapping header is an assumption about what the
plugin emits (template-derived), not a capture; it shows the parser still matches inside such a line -> `dns_query`.

## Alternative: rsyslog / syslog-ng

dnsmasq already logs to syslog by default; forward it with [network-gear.md](network-gear.md)'s `rsyslog-forward.conf` /
`syslog-ng-forward.conf` instead of tailing a file.

## Not covered

- Pi-hole reply/`forwarded`/`cached`/blocked lines: only `query[...]` lines become DNS events.
- BIND `named` query logs (parser mentions them, not tested here).
- Client attribution behind a forwarding resolver (the `from` address is whatever dnsmasq saw).
