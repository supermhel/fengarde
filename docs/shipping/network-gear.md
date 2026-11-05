# Network gear: OPNsense / pfSense and Proxmox (rsyslog, syslog-ng)

> **Status of this recipe.** The configs below were written from vendor documentation and were **not
> executed**: Vector, Fluent Bit, rsyslog and syslog-ng are not installed on the machine that produced them, so they are
> **not machine-linted** (`tools/lint_shipping_recipes.sh` does that when you have the tool). What a green test (per author run) covers is the
> FENGARDE half: each sample listed here goes through the real WS-2 path (`adapt_record` -> `resolve` -> parse -> OCSF
> validation) in `tools/test_shipping_recipes.py`. Whether your shipper emits exactly that sample shape is not proven by that test.

Path: syslog TCP 5515 ([../syslog-tcp.md](../syslog-tcp.md)), declared `generic_syslog` by the listener. The listener default is
newline (LF) framing, and it is listener-wide ([README](README.md#common-settings-and-framing)). rsyslog is configured with
`TCP_Framing="traditional"` (LF-delimited) to match. syslog-ng's `network()` framing is **unverified**: no framing option is set in
the config, so confirm that your syslog-ng version sends newline-delimited frames over `transport("tcp")` before relying on it. The TCP
listener is plaintext and unauthenticated: firewall it. The IP `192.0.2.10` is a documentation placeholder; see
[Reaching ws1 from another host](README.md#reaching-ws1-from-another-host).

| Source | What reaches FENGARDE | Parser |
|---|---|---|
| Proxmox host (Debian) sshd lines | forwarded syslog | `linux_ssh` |
| OPNsense / pfSense sshd lines | relayed syslog | `linux_ssh` |
| OPNsense / pfSense `filterlog` (firewall) | relayed syslog | `generic_syslog` only: **no firewall parser exists** |

## Proxmox (host forwards itself)

```ini rsyslog-forward.conf
# /etc/rsyslog.d/fengarde.conf  (Proxmox host or any Linux box) -- NOT executed here.
# "traditional" = LF-delimited, matches the FENGARDE TCP listener default (SYSLOG_TCP_FRAMING=newline).
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
*.* action(type="omfwd" Target="192.0.2.10" Port="5515" Protocol="tcp"
          TCP_Framing="traditional")
```

```ini syslog-ng-forward.conf
# syslog-ng on a Proxmox host or any Linux box -- NOT executed here.
# Framing of network(transport("tcp")) is UNVERIFIED: confirm it is newline-delimited (FENGARDE default). No framing option is set.
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
source s_local { system(); internal(); };
destination d_fengarde { network("192.0.2.10" port(5515) transport("tcp")); };
log { source(s_local); destination(d_fengarde); };
```

Sample: [Proxmox sshd failure](samples/proxmox-sshd.syslog.txt) -> `linux_ssh`. Line shape modelled on the journald/sshd
fixture, hostname `pve01` is a placeholder; not a capture from Proxmox.

## OPNsense / pfSense (relay)

Point the appliance's remote-syslog setting at a relay host on UDP 514; the relay forwards to FENGARDE over TCP. (Some builds
can send TCP directly; check yours.)

```ini rsyslog-relay.conf
# /etc/rsyslog.d/fengarde-relay.conf  (relay for OPNsense/pfSense) -- NOT executed here.
# SECURITY: imudp below listens on ALL interfaces, unauthenticated. To restrict, add address="<LAN IP of this relay>"
# to the input() line (imudp "address" parameter) and firewall UDP 514 to the appliance IPs.
# "traditional" = LF-delimited, matches the FENGARDE TCP listener default (SYSLOG_TCP_FRAMING=newline).
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfwd" Target="192.0.2.10" Port="5515" Protocol="tcp"
          TCP_Framing="traditional")
```

```ini syslog-ng-relay.conf
# syslog-ng relay for OPNsense/pfSense -- NOT executed here.
# SECURITY: network() below listens on ALL interfaces, unauthenticated. To restrict, add ip("<LAN IP of this relay>")
# inside the source's network() and firewall UDP 514 to the appliance IPs.
# Framing of the TCP destination is UNVERIFIED: confirm it is newline-delimited (FENGARDE default). No framing option is set.
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
source s_gear { network(port(514) transport("udp")); };
destination d_fengarde { network("192.0.2.10" port(5515) transport("tcp")); };
log { source(s_gear); destination(d_fengarde); };
```

**Hardening the relay.** As written, the relay binds UDP 514 on every interface and accepts syslog from anyone who can reach it
(unauthenticated, spoofable). Bind it to the LAN address facing the appliance (rsyslog `imudp` `address=` parameter; syslog-ng
`ip()` inside `network()`; both named in the config comments, not enabled, since the address is yours to fill in) and firewall
UDP 514 to the appliance IPs only. Those restriction options were not executed here.

Samples: [sshd failure](samples/opnsense-sshd.syslog.txt) -> `linux_ssh`; [filterlog block line](samples/pfsense-filterlog.syslog.txt) ->
`generic_syslog`. Both are illustrative: the filterlog CSV follows the field order Netgate documents for pfSense IPv4/TCP,
with documentation-range IPs and invented values; the sshd line is modelled on the repo's sshd fixtures. Neither is a capture.

## Not covered

- Firewall rule/connection semantics: `filterlog` is stored as a generic event; no detection rule reads its fields.
- Proxmox GUI/API auth (`pvedaemon`, `pveproxy`) and cluster/VM events.
- RFC 5424 structured data from the appliance (whatever the generic path does with it is unchanged by this recipe).
- TLS syslog; authenticated relay (the hardening note above is address binding and firewalling only).
