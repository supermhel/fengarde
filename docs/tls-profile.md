# TLS profile (WP-3.1)

`infra/docker-compose.tls.yml` puts **Caddy** in front of the console
(`ws7-dashboard`) and the HTTP/JSON ingest endpoint (`ws1-collectors`
`/v1/ingest`), and REMOVES every host publish of those two services — in
this profile the console and the HTTP ingest answer **only over TLS (443)**.
Syslog (5514/udp, 5515/tcp) is not proxied and no longer published at all, so
it is unreachable from outside the compose network until syslog-over-TLS
(RFC 5425, a WP-1.2 follow-up) exists.

> **Warning: loopback by default; do not expose the console on a LAN without authentication.**
> Caddy publishes `127.0.0.1:443` (like the base file's console at
> `127.0.0.1:8080`). Set `FENGARDE_TLS_BIND=<address>` (for example `0.0.0.0`)
> only on a network you trust: the console has no login by default, and
> `/api/config.js` returns the API key to any request that sends
> `Sec-Fetch-Site: same-origin`, which any non-browser client can do. TLS gives
> confidentiality in transit, not access control. Console authentication is
> separate owner-decided work (WP-6.1); until it lands, put an authenticating
> proxy or a firewall in front before binding beyond loopback. The HTTP ingest
> endpoint on the same port still requires its bearer token.

Local-CA default: the Caddyfile uses `tls internal`, so Caddy issues
certs from its own internal CA. No public DNS, no ACME, no cert files to
provision. (For a public domain: drop `tls internal` and use your real
hostname as the site name — the ACME HTTP challenge then needs port 80 —
exactly the documented Caddy approach in `docs/deployment.md`.)

## Run

```bash
cd infra
docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls up -d
```

Export ONLY the CA root certificate (public; the key stays in the volume) and
verify against it. Never use `curl -k`: with the bearer ingest token that
sends the token to anyone who can intercept the connection.

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls \
  cp caddy:/data/caddy/pki/authorities/local/root.crt ./fengarde-root.crt

curl --cacert ./fengarde-root.crt --resolve siem.internal:443:127.0.0.1 https://siem.internal/
printf '{"EventID": 4624, "Computer": "DC01", "TimeCreated": 1700000000000, "TargetUserName": "jdoe"}\n' \
  | curl --cacert ./fengarde-root.crt --resolve ingest.internal:443:127.0.0.1 \
      -X POST 'https://ingest.internal/v1/ingest?source_type=windows_eventlog&format=ndjson' \
      -H 'Authorization: Bearer <FENGARDE_INGEST_TOKEN>' \
      -H 'Content-Type: application/x-ndjson' --data-binary @-
```

`--resolve` maps the internal site names on a host that cannot resolve them.
Windows curl (Schannel) additionally needs `--ssl-no-revoke`: Caddy's local
certs carry no revocation endpoint, so Schannel reports "revocation status is
unknown". That flag only skips the revocation lookup; the chain and hostname
are still verified.

Back to the plaintext default:

```bash
docker compose -f docker-compose.yml -f docker-compose.tls.yml --profile tls down
docker compose -f docker-compose.yml up -d --remove-orphans
```

## What "only over TLS" means (and how it's enforced)

The override uses the compose-spec merge tag to REPLACE each service's ports
list instead of appending:

```yaml
services:
  ws7-dashboard:    { ports: !override [] }
  ws1-collectors:   { ports: !override [] }
```

`tools/test_tls_profile.py` (fast tier) renders the merged config
(`docker compose config --format json` when docker is available, else a YAML
merge) and asserts: no service publishes on all interfaces by default, `caddy`
publishes exactly `127.0.0.1:443/tcp` (`FENGARDE_TLS_BIND` overrides the
address), ws1/ws7 publish nothing, no UDP port is published, and Caddy's fixed
address is the only one trusted for `X-Forwarded-For` in ws1 and nginx. TLS termination inside ws1/ws7 remains out of scope.

## Client IP behind Caddy

Caddy overwrites `X-Forwarded-For` with the address it saw (it trusts no
upstream proxy by default), so a client cannot inject a fake hop through it.

- **Fixed Caddy address.** The profile gives the compose network a subnet
  (`172.31.250.0/24`, automatic addresses only from `172.31.250.128/25` so no other container can take Caddy's
  `.2` first) and Caddy the fixed address `172.31.250.2`. ws1 and ws7's
  nginx trust `X-Forwarded-For` from that ONE address only, so another
  container on the network that sends the header straight to ws1 or ws7 is an
  ordinary client and its header is ignored (it cannot pick its own client IP).
  The three values (compose `ipv4_address`, `INGEST_HTTP_TRUSTED_PROXIES`,
  `set_real_ip_from` in `infra/caddy/nginx-real-ip.conf`) must stay equal;
  `tools/test_tls_profile.py` checks it. If `172.31.250.0/24` clashes with a
  network you use, change all three.
- **ws1 ingest**: only a TCP peer equal to Caddy may supply the client address;
  `meta.shipper_ip` is then the real client (normalised, so IPv6 case and
  zero-compression variants give one key), `meta.shipper_proxy_ip` is Caddy, and
  the unlabelled rate-limit/partition key is per client instead of one shared
  bucket. See `docs/ingest-http.md`.
- **Console (ws7 nginx -> ws3)**: `infra/caddy/nginx-real-ip.conf` is mounted
  by the profile only; nginx then sets `$remote_addr` to the client from
  `X-Forwarded-For`, so ws3's opt-in `RATE_LIMIT_TRUST_PROXY_HEADER=1`
  buckets per client instead of per Caddy. The default (non-TLS) nginx is
  unchanged: the include matches no file.
- **Docker Desktop (Windows/macOS)**: connections reach Caddy through the VM's
  NAT, so the "client IP" is the NAT gateway (for example `172.21.0.1`), not
  the LAN host. Real client addresses need native Linux Docker (or a host
  network).

## The local CA and its risk

Caddy keeps the CA in the `caddy-data` volume at
`/data/caddy/pki/authorities/local/`. **`root.key` and `intermediate.key` are
stored unencrypted there** (mode 0600, owned by root in the container). Anyone
who can read that volume (docker group, host root, backups of the volume) can
mint a certificate for ANY hostname that every machine trusting this root will
accept.

- Do **not** run `caddy trust` and do not import the root into an OS/browser
  trust store on shared or general-purpose machines: that makes the key's
  compromise a compromise of every site those machines visit. Prefer pinning
  per client: `curl --cacert`, or a CA bundle given to the specific shipper.
- Export only `root.crt` (above). Never copy the `.key` files out.
- Rotation: to replace the CA, stop the profile, delete the `caddy-data`
  volume (`docker volume rm <project>_caddy-data`), start it again; Caddy
  generates a new root and certs, then redistribute the new `root.crt` and
  remove the old one from every client. Do this too if the volume or a backup
  of it may have been exposed. The root is valid for ten years by default.
- Stronger options: use your own CA and give Caddy files
  (`tls /path/cert.pem /path/key.pem`), ideally a **name-constrained
  intermediate** (X.509 NameConstraints permitting only
  `siem.internal`/`ingest.internal`) so a leaked key cannot impersonate other
  names; or use a public hostname with ACME. Caddy's own local root is not
  name-constrained.

## Verification record (manual — NOT reproduced by CI)

Run by hand on 2026-11-05 in a throwaway compose project on Docker Desktop
(Windows), ws1/ws7/Caddy/Redis real, ws3 replaced by a header-echo stub; the
token is a generated test value. CI cannot run this: it needs the docker
engine and builds the console image. CI covers only the static/merged-config
assertions in `tools/test_tls_profile.py` and the resolver unit tests in
`services/ws1-collectors/test_http_json_ingest_source_identity.py`.

```
$ curl --ssl-no-revoke --cacert fengarde-root.crt --resolve siem.internal:18443:127.0.0.1 https://siem.internal:18443/   -> 200
$ curl ... https://ingest.internal:18443/v1/ingest?... (no token)                                                         -> 401
$ curl ... (bearer token, 1 record)                                    -> {"accepted":1,"skipped":0,"errors":[]}  200
$ curl --resolve siem.internal:... (no --cacert)                       -> curl: (60) certificate not trusted, exit 60

# from a second container on the compose network (client 172.21.0.7, Caddy 172.21.0.6),
# sending a forged  X-Forwarded-For: 6.6.6.6  through Caddy:
raw.events meta: "shipper_ip": "172.21.0.7", "shipper_proxy_ip": "172.21.0.6"
ws3 stub (via ws7 nginx, forged XFF 9.9.9.9): X-Forwarded-For = 172.21.0.7
```

In this profile the console (ws7), the HTTP ingest (ws1 8554) and the syslog
listeners (ws1 5514/udp, 5515/tcp) have no host publish at all, and nothing
publishes on all interfaces (`docker compose config` lists only
`127.0.0.1:443` for caddy by default). The base file's OTHER services keep
their plaintext loopback publishes (redis 6379, opensearch 9200, dashboards
5601, inventory API 8000, ws6 and the other 127.0.0.1 ports): the profile
does not TLS-wrap them and does not remove them.

Update 2026-11-06 (review round 2, PR #162): the fixed Caddy address, the ipam
subnet and the loopback default for 443 were added after the manual run above;
that transcript predates them (its client and Caddy addresses were
Docker-assigned). The fixed-address behaviour was re-proven in a throwaway
network (see the CHANGELOG entry for this review round).
