# Deployment: putting FENGARDE behind TLS

FENGARDE itself does not terminate TLS anywhere (SECURITY.md §2: "no users,
roles, or TLS" is the honest v0.4 auth scope). If analysts need to reach the
dashboard from outside the machine it runs on, put a reverse proxy in front
of it — this doc is that missing piece, documented rather than built, per
the standing "document, don't build TLS" scope decision.

**This is a documentation-only addition.** Nothing in FENGARDE's own
containers or code changes; the example below runs *alongside* the existing
stack, not instead of it.

## What's already true without this doc

Per `infra/docker-compose.yml` (v0.4 Track S) and `SECURITY.md`:

- Redis (`6379`), OpenSearch (`9200`), OpenSearch Dashboards (`5601`), and
  the inventory API (`8000`) are bound to `127.0.0.1` by default — never
  reachable from another machine unless you deliberately rebind them.
- The FENGARDE dashboard (`8080`) is also `127.0.0.1`-bound by default.
- `FENGARDE_API_KEY` (shared-secret auth on the triage/inventory APIs) and
  dashboard basic-auth (`infra/docker-compose.auth.yml` override) are both
  opt-in.

So the starting point for "analysts need to reach this remotely" is: the
dashboard's `8080` port needs to become reachable from outside `127.0.0.1`,
and that exposure needs TLS + (at minimum) basic-auth in front of it, since
FENGARDE's own auth story stops at a shared API key, not per-user identity.

## Reverse-proxy TLS with Caddy

[Caddy](https://caddyserver.com/) is a reasonable default here: automatic
HTTPS (Let's Encrypt) with a ~10-line config, one static binary, no separate
cert-renewal cron job to maintain.

**Prerequisites:** a DNS A/AAAA record pointing your chosen hostname at this
machine, and port `443` (and `80`, for the ACME HTTP challenge) reachable
from wherever your analysts are — a VPN-only deployment can skip the public
DNS/ACME requirement and use Caddy's `tls internal` directive instead (see
the commented alternative below).

`Caddyfile` (place alongside `infra/docker-compose.yml`, or anywhere Caddy
can read it):

```caddyfile
# Public HTTPS in front of the FENGARDE dashboard. Caddy handles cert
# issuance/renewal automatically via Let's Encrypt -- no separate step.
siem.your-domain.example {
    # Second layer of auth in front of FENGARDE's own opt-in dashboard
    # basic-auth (infra/docker-compose.auth.yml) -- belt and suspenders,
    # since FENGARDE's own auth story is a shared secret, not per-user
    # identity (SECURITY.md sec2). Generate a hash with:
    #   caddy hash-password --plaintext 'your-password-here'
    basicauth /* {
        analyst $2a$14$REPLACE_WITH_A_REAL_BCRYPT_HASH
    }

    reverse_proxy 127.0.0.1:8080
}

# VPN-only alternative (no public DNS/ACME needed): replace the site block
# above with a self-signed cert Caddy manages internally --
#
#   siem.internal {
#       tls internal
#       basicauth /* { analyst $2a$14$... }
#       reverse_proxy 127.0.0.1:8080
#   }
#
# Analysts trust Caddy's local CA once (caddy trust) rather than getting a
# publicly-trusted cert -- appropriate when the dashboard is only ever
# reached over a VPN/private network anyway.
```

Run it (outside the FENGARDE compose stack, on the same host):

```sh
caddy run --config ./Caddyfile
```

Caddy now terminates TLS on `443`/`80` and proxies to the dashboard's
existing `127.0.0.1:8080` — no change to `infra/docker-compose.yml`, no
change to FENGARDE's own containers. The dashboard's own opt-in basic-auth
(`infra/docker-compose.auth.yml`) can still run underneath this as a second
layer if you want both.

## What this does NOT solve

- **Per-user identity/RBAC.** Caddy's `basicauth` here is one shared
  username/password for "an analyst," same class of limitation as
  `FENGARDE_API_KEY` — not real multi-user access control. That's tracked
  separately (the combined roadmap's M4 milestone,
  `docs/superpowers/specs/2026-07-15-fengarde-combined-plan.md`).
- **TLS between FENGARDE's own containers**, or for OpenSearch/Redis/
  Dashboards directly — those stay loopback-bound and reached only by other
  containers on the compose network, per SECURITY.md §1/§2's existing
  network-boundary mitigation. This doc is specifically about the one port
  (`8080`) a human needs to reach from outside the host.
- **The syslog UDP listener (`5514`)** — log sources reaching in over UDP
  aren't a TLS/reverse-proxy concern in the way an HTTP dashboard is;
  securing that ingestion path (if your log sources traverse an untrusted
  network) is a network-level decision (VPN, firewall rules, or an
  IPsec/WireGuard tunnel to the sources), out of scope for this doc.
