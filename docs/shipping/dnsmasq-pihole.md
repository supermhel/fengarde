# dnsmasq / Pi-hole DNS query log

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.

Parser: `dns_query` (class 4002). Path: syslog TCP 5515 (or UDP 5514), declared `generic_syslog`; the `query[...] ... from ...`
shape makes the WS-2 text sniff select `dns_query`. dnsmasq logs queries only with `log-queries`; Pi-hole writes
`/var/log/pihole/pihole.log` (path is the usual default, **verify on your install**).

The example host `192.0.2.10` is a placeholder: see [Reaching ws1 from another host](README.md#reaching-ws1-from-another-host) (published address change + firewall) before pointing a remote shipper at it.

## Vector

```toml vector-dnsmasq.toml
# Vector: dnsmasq/Pi-hole query log -> FENGARDE TCP syslog 5515. Linted and run live on Linux containers 2026-11-05 (README Verification log).
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

Vendor docs: <https://docs.fluentbit.io/manual/pipeline/outputs/syslog>. **Verified live** (Fluent Bit 5.1.5): the options are accepted, frames are LF-terminated, and the plugin wraps the original line as
`<14>Nov  5 08:34:02 pihole01 fluent-bit: <original dnsmasq line>` (timestamp = send time, `Syslog_Hostname_Preset`/`Syslog_Appname_Preset` honoured). The `query[A]` line resolved to `dns_query` (4002).

```ini fluent-bit-dnsmasq.conf
# Fluent Bit: dnsmasq/Pi-hole query log -> FENGARDE TCP syslog 5515. Linted and run live on Linux containers 2026-11-05 (README Verification log).
# Observed (Fluent Bit 5.1.5): LF-terminated frames over TCP, each line wrapped as '<14>Mon DD HH:MM:SS pihole01 fluent-bit: <original line>'.
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

- Pi-hole reply/`forwarded`/`cached`/blocked lines: only `query[...]` lines become DNS events. Observed with the Vector path: a `reply` line (`<30>Nov  5 .. dnsmasq[123]: reply ...`) was dead-lettered by WS-2
  (`parser returned None`, the header has no host slot); blank lines ship as a bare `<30>` that is dead-lettered too. Vector (0.61.0) tail of a file with a query line: `dns_query`, class 4002.
- BIND `named` query logs (parser mentions them, not tested here).
- Client attribution behind a forwarding resolver (the `from` address is whatever dnsmasq saw).
