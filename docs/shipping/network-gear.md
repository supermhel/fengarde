# Network gear: OPNsense / pfSense and Proxmox (rsyslog, syslog-ng)

> **Status of this recipe.** The configs were linted with the official container images (Vector 0.61.0, Fluent Bit 5.1.5, rsyslog 8.2610.0,
> syslog-ng 4.12.0) and, where Linux-capable, run live on Docker Desktop against a real ws1 listener and the real WS-2 path
> (see the [Verification log](README.md#verification-log)). What was not run is stated below. The committed samples are still adapter
> fixtures / templates, not captures; `tools/test_shipping_recipes.py` runs them through WS-2.

Path: syslog TCP 5515 ([../syslog-tcp.md](../syslog-tcp.md)), declared `generic_syslog` by the listener. The listener default is
newline (LF) framing, and it is listener-wide ([README](README.md#common-settings-and-framing)). rsyslog is configured with
`TCP_Framing="traditional"` (LF-delimited) to match. **Verified live:** rsyslog 8.2610.0 (`TCP_Framing="traditional"`) and syslog-ng 4.12.0 (`network(transport("tcp"))`, no framing option) both sent LF-terminated frames
(raw bytes captured in front of the real listener); all four configs (forward and relay) delivered an sshd line that resolved to `linux_ssh` (3002). Observed caveats: `*.*` also forwards the
daemons' own startup messages (generic events, e.g. rsyslog's insecure-default TCP warning); the syslog-ng relay with its default `keep-hostname(no)` replaced the datagram's host with the sender's reverse-resolved name (`localhost` for a loopback sender, the sender container's name for a LAN one), so the committed relay config sets `options { keep-hostname(yes); };`, under which the datagram's own host name (`FWHOST` in the test) arrived intact. rsyslog's relay kept the datagram's host name without any option. The TCP
listener is plaintext and unauthenticated: firewall it. The IP `192.0.2.10` is a documentation placeholder; see
[Reaching ws1 from another host](README.md#reaching-ws1-from-another-host).

| Source | What reaches FENGARDE | Parser |
|---|---|---|
| Proxmox host (Debian) sshd lines | forwarded syslog | `linux_ssh` |
| OPNsense / pfSense sshd lines | relayed syslog | `linux_ssh` |
| OPNsense / pfSense `filterlog` (firewall) | relayed syslog | `generic_syslog` only: **no firewall parser exists** |

## Proxmox (host forwards itself)

```ini rsyslog-forward.conf
# /etc/rsyslog.d/fengarde.conf  (Proxmox host or any Linux box) -- Linted and run live on Linux containers 2026-11-05 (README Verification log).
# "traditional" = LF-delimited, matches the FENGARDE TCP listener default (SYSLOG_TCP_FRAMING=newline).
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
*.* action(type="omfwd" Target="192.0.2.10" Port="5515" Protocol="tcp"
          TCP_Framing="traditional")
```

```ini syslog-ng-forward.conf
# syslog-ng on a Proxmox host or any Linux box -- Linted and run live on Linux containers 2026-11-05 (README Verification log).
# Observed (syslog-ng 4.12.0): network(transport("tcp")) sends LF-terminated frames, matching the FENGARDE default; no framing option needed.
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
# /etc/rsyslog.d/fengarde-relay.conf  (relay for OPNsense/pfSense) -- Linted and run live on Linux containers 2026-11-05 (README Verification log).
# SECURITY: imudp below listens on ALL interfaces, unauthenticated. To restrict, add address="<LAN IP of this relay>"
# to the input() line (imudp "address" parameter) and firewall UDP 514 to the appliance IPs. Verified live (rsyslog 8.2610.0): with
# address="<relay LAN IP>" a datagram to that address was relayed and one to 127.0.0.1 was not (and the reverse with address="127.0.0.1").
# rsyslog relays the host name from the datagram unchanged by default (no extra option needed).
# "traditional" = LF-delimited, matches the FENGARDE TCP listener default (SYSLOG_TCP_FRAMING=newline).
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
module(load="imudp")
input(type="imudp" port="514")
*.* action(type="omfwd" Target="192.0.2.10" Port="5515" Protocol="tcp"
          TCP_Framing="traditional")
```

```ini syslog-ng-relay.conf
# syslog-ng relay for OPNsense/pfSense -- Linted and run live on Linux containers 2026-11-05 (README Verification log).
# SECURITY: network() below listens on ALL interfaces, unauthenticated. To restrict, add ip("<LAN IP of this relay>")
# inside the source's network() and firewall UDP 514 to the appliance IPs. Verified live (syslog-ng 4.12.0): with ip("<relay LAN IP>")
# a datagram to that address was relayed and one to 127.0.0.1 was not (and the reverse with ip("127.0.0.1")).
# Observed (syslog-ng 4.12.0): network(transport("tcp")) sends LF-terminated frames, matching the FENGARDE default; no framing option needed.
# 192.0.2.10 is a placeholder: see "Reaching ws1 from another host" in docs/shipping/README.md.
options { keep-hostname(yes); };
source s_gear { network(port(514) transport("udp")); };
destination d_fengarde { network("192.0.2.10" port(5515) transport("tcp")); };
# keep-hostname(yes) keeps the host name from the datagram. Observed with the syslog-ng default (no): the relayed HOST field became the sender's
# reverse-resolved name (localhost for a loopback sender, the sender container's name for a LAN sender), not the appliance's name.
log { source(s_gear); destination(d_fengarde); };
```

**Hardening the relay.** As written, the relay binds UDP 514 on every interface and accepts syslog from anyone who can reach it
(unauthenticated, spoofable). Bind it to the LAN address facing the appliance (rsyslog `imudp` `address=` parameter; syslog-ng
`ip()` inside `network()`; both named in the config comments, not enabled, since the address is yours to fill in) and firewall
UDP 514 to the appliance IPs only. Both restriction options were **verified live** (rsyslog 8.2610.0 `address=`, syslog-ng 4.12.0 `ip()`, containers on a user-defined Docker network): with the option set to the relay's LAN address a datagram sent to that address was relayed and one sent to `127.0.0.1` was not; set to `127.0.0.1` the reverse held; unrestricted, both were relayed. This proves the bind, not a firewall: it does not stop a host that can reach the bound address. rsyslog 8.2610.0 warns that `omfwd` plain TCP is the backward-compatible insecure default (no TLS), which is the point of the firewalling advice.

Samples: [sshd failure](samples/opnsense-sshd.syslog.txt) -> `linux_ssh`; [filterlog block line](samples/pfsense-filterlog.syslog.txt) ->
`generic_syslog`. Both are illustrative: the filterlog CSV follows the field order Netgate documents for pfSense IPv4/TCP,
with documentation-range IPs and invented values; the sshd line is modelled on the repo's sshd fixtures. Neither is a capture.

## Not covered

- Firewall rule/connection semantics: `filterlog` is stored as a generic event; no detection rule reads its fields.
- Proxmox GUI/API auth (`pvedaemon`, `pveproxy`) and cluster/VM events.
- RFC 5424 structured data from the appliance (whatever the generic path does with it is unchanged by this recipe).
- TLS syslog; authenticated relay (the hardening note above is address binding and firewalling only).
