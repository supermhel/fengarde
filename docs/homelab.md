# Homelab deployment (WP-2.1)

A persistent, single-site FENGARDE install: collect everything from your own machines now, look at it later. This is the
compose override `infra/docker-compose.homelab.yml` layered on `infra/docker-compose.yml`. It changes only what a long-lived
home install needs (named volumes, loopback ports, memory ceilings, restart policy, no demo data). It is not HA and not
multi-tenant, and it does not add TLS (see [deployment.md](deployment.md)).

**Collect now, label later.** That is the owner's decision for this install: ingest first, tag/label the data afterwards.
The labelling tooling (WP-2.2) is **not built yet**. Today you can collect and search; nothing here lets you mark events as
benign or malicious.

## Start, stop

Prerequisites: Docker Engine / Docker Desktop with Compose **>= 2.24** (the override uses `!override`), and roughly 6 GiB of RAM
given to Docker (measured idle total of the stack below: about 2.1 GiB, OpenSearch is 1.75 GiB of it). On Linux/WSL2 the kernel
setting `vm.max_map_count` must be >= 262144 or OpenSearch will not boot (`infra/preflight.sh` checks this and the free ports;
it is a POSIX script and fails on native Windows shells).

```sh
# once: create infra/.env (git-ignored; do not overwrite one you already have). The ingest token is REQUIRED,
# the other two are strongly recommended.
printf 'FENGARDE_INGEST_TOKEN=%s\nREDIS_PASSWORD=%s\nFENGARDE_API_KEY=%s\n' \
  "$(openssl rand -hex 24)" "$(openssl rand -hex 16)" "$(openssl rand -hex 24)" > infra/.env

# start (builds the images the first time)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml up -d --build

# stop, keep all data
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml stop
# remove containers, keep all data (volumes survive `down`)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml down
```

Do **not** use `make down` on this install: it runs `down -v` and deletes the volumes. Containers have fixed names
(`siem-bus`, `siem-store`, ...), so only one FENGARDE stack can exist per Docker host. Dashboard: `http://127.0.0.1:8080`.
Containers restart on boot and on crash (`unless-stopped`) once Docker itself starts.

## Where data lives

Volumes have fixed names, independent of the checkout directory or compose project name. Change the prefix with
`FENGARDE_HOMELAB_VOL_PREFIX` (default `fengarde-homelab`) *before* the first start; changing it later points the stack at new,
empty volumes.

| Volume (`<prefix>-...`) | Holds | Loss means |
|---|---|---|
| `opensearch` | events, alerts, incidents, reports (the actual dataset) | all collected history |
| `redis` | the bus (AOF): events in flight between services | unprocessed backlog only |
| `ws3-data` | audit log, optional RBAC sqlite | audit trail / users |
| `tenants` | per-tenant rule on/off files written by the console | rule toggles |
| `inventory` | WS-6 device inventory | discovered assets |
| `ws1-spool` | zero-loss syslog spool (enabled by this override) | events buffered while the bus was down |

## Ports and LAN exposure

Everything is published to **loopback only** by default, including syslog UDP 5514 (the base file publishes that one on all
interfaces; this override narrows it).

| Port | What | Default | Opt in to the LAN |
|---|---|---|---|
| 5514/udp, 5515/tcp | syslog (plaintext, **unauthenticated**) | `127.0.0.1` | `FENGARDE_SYSLOG_BIND=<host LAN ip>` |
| 8554/tcp | HTTP `POST /v1/ingest` (bearer token, plaintext) | `127.0.0.1` | `FENGARDE_HTTP_INGEST_BIND=<host LAN ip>` |
| 8080 | dashboard | `127.0.0.1` | not in this override; see [deployment.md](deployment.md) |
| 6379, 9200, 5601, 8000 | Redis, OpenSearch, Dashboards, inventory API | `127.0.0.1` | leave closed |

To let other machines send, put the variable in `infra/.env` (use the host's LAN address; `0.0.0.0` means every interface) and
re-run `up -d`:

```sh
echo 'FENGARDE_SYSLOG_BIND=192.168.1.10' >> infra/.env
echo 'FENGARDE_HTTP_INGEST_BIND=192.168.1.10' >> infra/.env
```

Anyone who can reach 5514/5515 can inject log lines (no authentication, no TLS), and the HTTP token travels in cleartext. Restrict
both with the host firewall to your sender addresses (on Windows hosts: Windows Defender Firewall inbound rules for Docker's
ports). The listeners are on 5514/5515, not 514; point devices at those ports. RFC 6587 framing is `newline` by default; senders
that use octet-counting (rsyslog `omfwd` with `TCP_Framing="octet-counting"`) need `SYSLOG_TCP_FRAMING=octet-counting` set on
`ws1-collectors`, which then applies to every TCP sender.

## Retention

There is **no environment variable for retention**. Retention is the OpenSearch ISM policies in
`contracts/opensearch-mappings/ism-*.json`, installed by the `provision` service at start (`infra/provision.sh`) and attached
automatically by index-name pattern:

| Index pattern | Policy | Deleted after |
|---|---|---|
| `events-common-*` (everything this install sends lands here) | `events-common-90d` | 90 days |
| `events-dc-*` | `events-90d` | 90 days |
| `events-bank-*` | `events-400d-pci` | 400 days |
| `alerts-*`, `incidents-*`, `reports-*` | `*-365d` | 365 days |

Seen in the walkthrough below: a new `events-common-YYYY.MM.DD` index was managed by `events-common-90d` right away. To
change it, edit `min_index_age` in the matching JSON file and run
`docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml run --rm provision`. **Not verified here:**
editing and re-provisioning; per the OpenSearch ISM docs a changed policy does not move indices that are already managed
(that needs a `change_policy` call), so expect it to apply to newly created daily indices. Redis is not trimmed by age; it
only drops entries every consumer has acknowledged. OpenSearch protects its own disk with the standard allocation watermarks;
this repo adds no disk guard for it (`docs/ops-lifecycle.md`).

## Sending your sources

Recipes (config, parser, what each does and does not cover) live in `docs/shipping/` and land with
[PR #151](https://github.com/supermhel/fengarde/pull/151) (branch `wp/1.4-shipper-recipes`). **Until that PR merges the links
below are dead on `main`.** Transport details: [ingest-http.md](ingest-http.md), [syslog-tcp.md](syslog-tcp.md),
[input-adapters.md](input-adapters.md).

| Source | Recipe | Path |
|---|---|---|
| Windows Sysmon, Windows Security | [shipping/windows.md](shipping/windows.md) | HTTP 8554 |
| Linux sshd / auth | [shipping/linux-auth.md](shipping/linux-auth.md) | HTTP 8554 or syslog TCP 5515 |
| Docker containers | [shipping/docker.md](shipping/docker.md) | HTTP 8554 or syslog TCP 5515 |
| dnsmasq / Pi-hole | [shipping/dnsmasq-pihole.md](shipping/dnsmasq-pihole.md) | syslog TCP 5515 |
| n8n | [shipping/n8n.md](shipping/n8n.md) | HTTP 8554, `source_type=n8n_audit` |
| OPNsense / pfSense / Proxmox | [shipping/network-gear.md](shipping/network-gear.md) | syslog TCP 5515 |

Notes learned while testing this profile:

- HTTP `200 {"accepted":1}` means ws1 put the record on the bus, **not** that it was parsed. ws2 dead-letters records the
  parser rejects (a bare `EventID 4625` record was accepted and then dead-lettered; check
  `docker compose ... logs ws2-normalization | grep deadlettered`).
- Windows Security **4625** is owned by a different parser than `windows_eventlog`; see the recipe for which events are covered.
- OPNsense/pfSense `filterlog` has no firewall parser: it arrives as `generic_syslog`.

## Backup and wipe

Cold backup of the dataset (stop the stack first so OpenSearch is not mid-write). This was run for the `opensearch` volume
against a test stack:

```sh
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml stop
mkdir -p backups
docker run --rm -v fengarde-homelab-opensearch:/src:ro -v "$PWD/backups":/dst busybox:1.36 \
  tar czf /dst/opensearch-$(date +%Y%m%d).tgz -C /src .
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml start
```

Repeat for `redis`, `ws3-data`, `tenants`, `inventory` if you want them. Restore is the reverse (`tar xzf` into a new, empty
volume with the stack down); **restore was not run**. Users/contracts can also be bundled with `tools/backup.py`
([ops-lifecycle.md](ops-lifecycle.md)); OpenSearch online snapshots are not configured by this profile.

Wipe everything (irreversible; `down` alone never does this):

```sh
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml down -v
```

`down -v` removes the named volumes declared by the stack. If you ever set a different prefix, check with
`docker volume ls | grep <prefix>`.

## Known issues

- **Mock data on every ws1 start.** `ws1-collectors` seeds 9 bundled mock raw events and 2 mock assets each time it starts
  (`services/ws1-collectors/main.py`, log line `seeded`). There is no switch to turn this off. In the test run one of them became
  a `cisco_asa` event (`203.0.113.5` -> `10.0.0.10:22`, `src` country `RU`), and a restart added another copy with a new
  `ingest_id`, so they accumulate one per restart. Filter them out (`src_endpoint.ip: 203.0.113.5`) until a switch exists.
  The demo feeder (`devkit-feeder`, fake SSH brute-force burst) is disabled by this override; `--profile demo` brings it back.
- The `observability` profile (Prometheus, Grafana, GoatCounter) is untouched and not tuned for this install.

## What is NOT proven

Evidence level, honestly:

- **Ran (on 2026-11-05, Docker Desktop, 8 GiB, throwaway test stack with remapped host ports and a throwaway token):** config
  validates; all services healthy; one HTTP ingest record (`windows_eventlog` 4688) and one syslog TCP line (sshd failure) reached
  OpenSearch as OCSF events in `events-common-*`; wrong/missing token gives 401; `down` then `up` kept the data; a cold `tar`
  backup of the OpenSearch volume produced an archive.
- **Not run:** any real shipper (Vector, Fluent Bit, Winlogbeat, rsyslog, syslog-ng) against this stack; LAN publication
  (`FENGARDE_*_BIND` was only config-validated, not tested from another machine); octet-counting framing through compose;
  restore from backup; ISM policy edit and re-provision; the zero-loss spool actually draining after a bus outage (it is switched
  on and the log shows it enabled, nothing more); `vm.max_map_count` preflight (not runnable on the Windows test host); a
  long-running soak, disk growth, and memory ceilings under real load (limits are idle-measured plus margin).
- **Unit/synthetic only:** the HTTP and TCP listeners (WP-1.1, WP-1.2) have unit tests and the synthetic runs quoted in their
  docs; nothing here is evidence against real devices. The HTTP listener's own spool (`INGEST_HTTP_SPOOL_PATH`) has no drain
  loop, so this profile does not enable it: with the bus down and no spool, HTTP records are answered 503 and the shipper must retry
  (send `X-Fengarde-Idempotency-Key`).
- **Labelling (WP-2.2): not built.**
