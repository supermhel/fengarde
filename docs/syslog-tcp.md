# TCP syslog ingest (RFC 6587) — WP-1.2

Point rsyslog, syslog-ng, or any stream-capable sender at ws1's TCP listener.
Every decoded frame follows the same dispatch code as the UDP listener (token buckets, spool fallback, counters,
per-source metrics), but each listener has its own instance: the rate cap, the counters (`tcp_*` versus the unprefixed
UDP ones) and the spool (`SYSLOG_TCP_SPOOL_PATH`, replayed by a TCP drain loop) are per listener, not pooled.

**Exposure:** `5515/tcp` is published on all host interfaces, like UDP 5514, and is plaintext and unauthenticated (TLS is a
follow-up). Anyone who can reach it can inject syslog lines. Use `SYSLOG_TCP_HOST` and the compose port mapping
(`127.0.0.1:5515:5515/tcp`) to keep it host-local, and put it behind a firewall otherwise.

```
TCP 0.0.0.0:5515   (SYSLOG_TCP_HOST / SYSLOG_TCP_PORT, compose-published 5515:5515/tcp)
```

## Framing (`SYSLOG_TCP_FRAMING`)

| Value | Meaning |
|---|---|
| `newline` (default) | frames terminated by LF, trailing CR stripped. Netcat, `logger -n`, most one-shot tools. |
| `octet-counting` | RFC 6587 §3.4.1 `MSG-LEN SP SYSLOG-MSG`; used by rsyslog's `omfwd` TCP and syslog-ng relays. One trailing LF after the message is tolerated for interop. |

The listener holds a per-connection buffer, so a frame split across any
number of TCP segments (including a length header arriving separately from
its message) is reassembled; no worker is pinned by a slow sender — each
connection owns one thread, bounded by `SYSLOG_TCP_MAX_CONNECTIONS` (64) and
an idle timeout `SYSLOG_TCP_IDLE_TIMEOUT_S` (30 s).

## Limits and failure modes

| Condition | Behaviour |
|---|---|
| frame > `SYSLOG_TCP_MAX_FRAME_BYTES` (65536) | connection closed, counted in `tcp_syslog_events_oversize` |
| non-numeric / runaway length header (octet mode) | same |
| more than `SYSLOG_TCP_MAX_CONNECTIONS` peers | newest connection refused (closed), `tcp_syslog_conn_refused` |
| more than `SYSLOG_TCP_MAX_CONN_PER_PEER` (16) connections from one address | the extra one is refused, `tcp_syslog_conn_refused_peer` |
| connection closes with an unterminated last line (newline mode) | the line is dispatched; in octet mode an unfinished frame is counted in `tcp_syslog_truncated_frames` |
| connection silent past the idle timeout | closed, `tcp_syslog_idle_closed` |
| rate limit (`SYSLOG_TCP_MAX_EVENTS_PER_SEC`, default 2000/s per source) | frames shed + counted like UDP (connection stays up) |
| bus down | `SYSLOG_TCP_SPOOL_PATH` accepts to the bounded spool; without it, dropped+counted |

## rsyslog (octet-counting)

```
# /etc/rsyslog.d/fengarde.conf
*.* action(type="omfwd" Target="192.0.2.10" Port="5515" Protocol="tcp"
          TCP_Framing="octet-counting")
```

## syslog-ng / netcat (newline)

```
# syslog-ng destination
destination d_fengarde { network("192.0.2.10" port(5515) transport("tcp")); };
```

```
printf 'sshd: Failed password for admin from 198.51.100.1\n' | nc -q0 127.0.0.1 5515
```

Every record reaches `raw.events` as:
`{"source_type": "generic_syslog", "raw": "<frame text>", "meta": {received_at,
ingest_id, trace_id, tenant_id}}` with the frame's peer IP as the partition
key — WS-2 content-routes `generic_syslog` exactly as described in
`services/ws1-collectors/INTERFACE.md`.

## Verified against the compose stack

Produced on 2026-11-04 against `infra-ws1-collectors-1` built from the
WP-1.2 branch (compose project `infra`, redis = `siem-bus`):

```
$ docker compose ps ws1-collectors --format '{{.Ports}}'
0.0.0.0:5514->5514/udp, [::]:5514->5514/udp, 0.0.0.0:5515->5515/tcp,
[::]:5515->5515/tcp, 127.0.0.1:8554->8554/tcp

# one newline-framed line over TCP
$ python3 -c "
import socket
s = socket.create_connection(('127.0.0.1', 5515), timeout=5)
s.sendall(b'firewall: %ASA-4-106023: Deny tcp src outside:198.51.100.9/4444 '
          b'dst inside:10.0.0.5/22\n')
s.close()"

# /metrics shows the TCP share of the shared dispatch counters
$ curl -s http://127.0.0.1:8001/metrics   (inside the container)
tcp_events_produced: 1, tcp_events_dropped: 0, tcp_syslog_conn_accepted: 1,
tcp_syslog_conn_closed: 1

# the frame landed on raw.events with the full envelope
$ docker exec siem-bus redis-cli xrange raw.events - + COUNT 1
{"source_type": "generic_syslog",
 "raw": "firewall: %ASA-4-106023: Deny tcp src outside:198.51.100.9/4444 dst inside:10.0.0.5/22",
 "meta": {"received_at": …, "ingest_id": …,
          "trace_id": …, "tenant_id": "default"}}
```

## TLS

Not in this PR. RFC 5425 (TLS transport) is the follow-up PR: cert/key from
env vars, listener refuses to start on unreadable files, and the Caddy-based
TLS profile (WP-3.1) covers the HTTP endpoint in the meantime.

## Env

| Var | Default | Meaning |
|---|---|---|
| `SYSLOG_TCP_HOST` | `0.0.0.0` | bind address |
| `SYSLOG_TCP_PORT` | `5515` | bind port (checked by `infra/preflight.sh`) |
| `SYSLOG_TCP_FRAMING` | `newline` | `newline` or `octet-counting` |
| `SYSLOG_TCP_MAX_FRAME_BYTES` | `65536` | frame cap → oversize reject |
| `SYSLOG_TCP_MAX_CONNECTIONS` | `64` | concurrent peers |
| `SYSLOG_TCP_IDLE_TIMEOUT_S` | `30` | idle connection close |
| `SYSLOG_TCP_MAX_EVENTS_PER_SEC` | `2000` | per-source token bucket (shared dispatch) |
| `SYSLOG_TCP_SPOOL_PATH` | unset | bounded on-disk JSONL fallback when the bus is down |
| `SYSLOG_TCP_SPOOL_MAX_BYTES` | spool default | spool cap |