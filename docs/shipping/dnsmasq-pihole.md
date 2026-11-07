# dnsmasq / Pi-hole DNS query log

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, except [pihole-v6.dnsmasq.txt](samples/pihole-v6.dnsmasq.txt), a real capture from the official `pihole/pihole` image (see below);
> `tools/test_shipping_recipes.py` runs them all through WS-2.

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
parser docstring (documented shape; a real capture is [pihole-v6.dnsmasq.txt](samples/pihole-v6.dnsmasq.txt)) -> `dns_query`.

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

Sample: [wrapped form](samples/dnsmasq.fluentbit-wrapped.syslog.txt) -- the wrapping header here was written from a template; the
real header was observed in the live run and is exercised against the capture above. It shows the parser still matches inside such a line -> `dns_query`.

## Real Pi-hole capture

[samples/pihole-v6.dnsmasq.txt](samples/pihole-v6.dnsmasq.txt): `/var/log/pihole/pihole.log`, 81 lines, captured from `pihole/pihole:2026.10.1` (Pi-hole core v6.5, FTL v6.8, web v6.6.1, dnsmasq `pi-hole-v2.93+30`, Alpine) on 2026-11-05, Docker Desktop on Windows 11. The
log already had query logging on (v6 default); DNS traffic was generated with `nslookup`/`dig` inside the container and from a sibling container, including one domain added with `pihole deny`. Scrub: the sibling's bridge address 172.17.0.3
-> 192.0.2.5 and the Pi-hole's 172.17.0.2 -> 192.0.2.2; nothing else changed (loopback 127.0.0.1 clients and public resolver/answer addresses are as captured).
Both shippers were run on the copied file against a real ws1 TCP listener and the real WS-2 path (README Verification log); `tools/test_shipping_recipes.py` re-runs every line through the same path for both shapes (Vector `<30>` + line; Fluent Bit header as observed).

- 25 `query[...]` lines (A, AAAA, PTR, TXT) -> `dns_query` 4002 with the queried name, on both paths.
- Everything else (startup, `forwarded`, `reply`, `cached`, `config`, `Pi-hole hostname`, `exactly denied`; 56 lines) is **not** `dns_query`: Vector path -> dead-lettered (`parser returned None`, plus one blank line); Fluent Bit path -> `generic_syslog` 1002 events.
- A blocked query (`query[A] ads.tracker.example` followed by `exactly denied ads.tracker.example is 0.0.0.0`) becomes an ordinary DNS query event; the block outcome is on the next line and is not read, so blocked and allowed look alike.
- The two older samples remain as parser-docstring / template examples; the capture is the authoritative shape.

## Alternative: rsyslog / syslog-ng

dnsmasq already logs to syslog by default; forward it with [network-gear.md](network-gear.md)'s `rsyslog-forward.conf` /
`syslog-ng-forward.conf` instead of tailing a file.

## Not covered

- Pi-hole reply/`forwarded`/`cached`/blocked lines: only `query[...]` lines become DNS events. Observed with the Vector path: a `reply` line (`<30>Nov  5 .. dnsmasq[123]: reply ...`) was dead-lettered by WS-2
  (`parser returned None`, the header has no host slot); blank lines ship as a bare `<30>` that is dead-lettered too. Vector (0.61.0) tail of a file with a query line: `dns_query`, class 4002.
- BIND `named` query logs (parser mentions them, not tested here).
- Client attribution behind a forwarding resolver (the `from` address is whatever dnsmasq saw).
