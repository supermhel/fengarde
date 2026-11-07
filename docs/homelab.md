# Homelab deployment (WP-2.1)

A persistent, single-site FENGARDE install: collect everything from your own machines now, look at it later. This is the
compose override `infra/docker-compose.homelab.yml` layered on `infra/docker-compose.yml`. It changes only what a long-lived
home install needs (named volumes, loopback ports, memory ceilings, restart policy, no demo data). It is not HA and not
multi-tenant, and it does not add TLS (see [deployment.md](deployment.md)).

**Collect now, label later.** That is the owner's decision for this install: ingest first, tag/label the data afterwards.
The labelling tooling (WP-2.2) is **not built yet**. Today you can collect and search; nothing here lets you mark events as
benign or malicious.

## Start, stop

Prerequisites: Docker Engine / Docker Desktop with a Compose recent enough for the `!override` tag (tested with Compose v5.1.4 only.
From the source history, checked 2026-11-07: the `!override` tag first appears in compose-go v2.0.0-rc.3 (`loader/reset.go`; rc.2 has no mention) and Docker Compose v2.24.4 is the first release that pins rc.3 (v2.24.3 pins rc.2), so use **v2.24.4 or newer**. That is inferred from two files in the source, not tested on an older Compose, and the release notes do not state it). Memory: the container limits in the override add up to **9.5 GiB**
(`test_homelab_compose.py` keeps this number honest). That is a ceiling, not a reservation. Measured idle total of the whole
stack on a throwaway run (2026-11-06, `docker stats --no-stream`, no data ingested): about **2.0 GiB**, of which OpenSearch
1.6 GiB, OpenSearch Dashboards 0.17 GiB, each Python service 10-30 MiB, Redis 6 MiB. Give Docker at least 4 GiB for an idle
box, 8 GiB or more if you will ingest real traffic (not measured under load). OpenSearch's heap
(`FENGARDE_HOMELAB_OS_HEAP`, default 1g) must stay at or below half of its container limit
(`FENGARDE_HOMELAB_OS_MEM_LIMIT`, default 3g): raise the limit when you raise the heap. Compose cannot check that; the
test only checks the defaults. On Linux/WSL2 the kernel
setting `vm.max_map_count` must be >= 262144 or OpenSearch will not boot (`infra/preflight.sh` checks this and the free ports;
it is a POSIX script and fails on native Windows shells).

```sh
# once: create infra/.env (git-ignored). The ingest token is REQUIRED, the other two are strongly recommended.
# The guard matters: `>` truncates, and a second run would rotate the token and API key (every shipper then
# gets 401) and wipe LAN-bind settings you added later.
if [ -e infra/.env ]; then echo "infra/.env exists: leaving it alone"; else
  ( umask 077; printf 'FENGARDE_INGEST_TOKEN=%s\nREDIS_PASSWORD=%s\nFENGARDE_API_KEY=%s\n' \
    "$(openssl rand -hex 24)" "$(openssl rand -hex 16)" "$(openssl rand -hex 24)" > infra/.env )
fi

# start (builds the images the first time)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml up -d --build

# stop, keep all data
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml stop
# remove containers, keep all data (volumes survive `down`)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml down
```

Avoid `make down` on this install. It runs `down -v` against the **base file only**. Tested on a minimal two-file project
with the same layout (not on the full stack): that command removes the project's containers and network, but does **not**
delete volumes the override renamed, so the `<prefix>-*` data survives it. What it would delete are the base file's own
volumes (`infra_*`), which is your pre-migration copy if you came from the base stack (next section). Use the `down` above,
and `down -v` with both files only to wipe. Containers have fixed names (`siem-bus`, `siem-store`, ...), so only one FENGARDE
stack can exist per Docker host. Dashboard: `http://127.0.0.1:8080`.

A very first start on a slow or busy host can fail with `container ... is unhealthy` because OpenSearch needs longer than the
base healthcheck allows (seen on a loaded 8-core Docker Desktop VM while another OpenSearch ran). The containers keep running;
run the same `up -d` again once OpenSearch reports healthy.
Containers restart on boot and on crash (`unless-stopped`) once Docker itself starts.

## Coming from the base stack (volume migration)

If you already ran `docker compose -f infra/docker-compose.yml up` (or `make up`), your data is in the base file's volumes,
named `<project>_<volume>` where the project defaults to the compose directory name, i.e. `infra_os-data` and so on (check
with `docker volume ls`). The override uses different volumes, so starting it as-is starts **empty** and leaves the old data
where it was. The prefix variable cannot point at the old names (the volumes are also renamed, `os-data` -> `opensearch`).
Copy them across once, with the old stack stopped (not `down -v`) and before the first homelab start:

```sh
docker compose -f infra/docker-compose.yml stop        # NOT down -v; keeps the old volumes
export MSYS_NO_PATHCONV=1                              # Git Bash on Windows only (see Backup)
OLD=infra                                              # base project name
PREFIX=fengarde-homelab                                # your FENGARDE_HOMELAB_VOL_PREFIX
for pair in os-data:opensearch redis-data:redis ws3-indexer-data:ws3-data \
            tenants-config:tenants inventory-data:inventory ws1-spool:ws1-spool; do
  old="${OLD}_${pair%%:*}"; new="${PREFIX}-${pair##*:}"
  docker volume inspect "$old" >/dev/null 2>&1 || { echo "skip $old: not found"; continue; }
  docker run --rm -v "$old":/from:ro -v "$new":/to busybox:1.36 \
    sh -c '[ -z "$(ls -A /to)" ] || { echo "refusing: target not empty"; exit 1; }; cp -a /from/. /to/' \
    && echo "copied $old -> $new"
done
```

`cp -a` keeps ownership, modes and timestamps (OpenSearch needs uid 1000); the guard refuses to copy into a volume that
already holds data, so a rerun cannot mix two datasets. Tested on throwaway volumes with a nested tree, a dotfile, a symlink,
uid 1000 files and a 640 mode: the copy matched the source by owner, mode and md5, and a second run was refused. Not tested:
a copy of a real OpenSearch data directory followed by a start. Compose accepts a pre-created volume under the new name
(tested). Keep the old `infra_*` volumes until the homelab stack has shown your history; delete them yourself afterwards.

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

Anyone who can reach 5514/5515 can inject log lines (no authentication, no TLS), and the HTTP token travels in cleartext.
`FENGARDE_SYSLOG_BIND` moves **both** 5514/udp and 5515/tcp together; there is no per-protocol switch, so exposing only TCP
needs a compose edit or a firewall rule on 5514/udp. Binding to the host's LAN address (not `0.0.0.0`) is the first control.

Firewall caveat, **documented Docker behaviour, not tested here**: ports published by Docker are forwarded by Docker's own
iptables rules and skip the host's `ufw`/`firewalld` INPUT rules, so a `ufw deny 5514` can silently do nothing. Docker's
documented place for your own filtering is the `DOCKER-USER` chain. On Windows hosts the equivalent is Windows Defender
Firewall inbound rules for Docker Desktop (also untested here). Either way, verify from another machine that the port is
closed to addresses you did not allow. The listeners are on 5514/5515, not 514; point devices at those ports. RFC 6587 framing is `newline` by default; senders
that use octet-counting (rsyslog `omfwd` with `TCP_Framing="octet-counting"`) need `SYSLOG_TCP_FRAMING=octet-counting` set on
`ws1-collectors`, which then applies to every TCP sender.

## Redis memory cap

Redis (the bus) runs with `--maxmemory 768mb --maxmemory-policy noeviction` inside its 1 GiB container limit (the override
repeats the base command's flags: AOF and optional password). Without a cap, a stalled consumer would keep streams growing
until the container is OOM-killed. With it, Redis stays up and **refuses writes that would exceed the cap**.

Tested on a throwaway Redis started from this override, filled with 100 KB stream entries: at the cap `XADD` returned
`OOM command not allowed when used memory > 'maxmemory'` (1993 of 9000 attempts refused, memory stopped at 767.9 MiB),
`XREADGROUP`, `XACK` and `XTRIM` still worked, trimming freed the memory (12 MiB), and writes succeeded again. The container
was not killed. What the services do on that error is from reading the code, **not run**: ws1's syslog and HTTP paths treat
any bus write error like an outage (spool the line if a spool is on, else count it dropped / answer HTTP 503 so the shipper
retries); downstream services leave the message unacked and retry. The cap is a safety net, not capacity planning: if you hit
it, find the stalled consumer (`docker compose ... logs`), do not just raise the limit. Caveat found while testing: one large
Lua script can overshoot `maxmemory` (Redis checks before a script starts); FENGARDE's scripts are small.

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

ISM attaches a policy when an index is **created**, so an index created before `provision` finished would never expire. The
override therefore makes `ws3-indexer` (the only service that creates indexes) wait for `provision` to exit successfully
(`depends_on: provision: condition: service_completed_successfully`; `provision` is one-shot and exits 0 when done). Observed on
a throwaway stack: provision finished 09:37:21.48, ws3-indexer started 09:37:22.71, and the `reports-*` index it created was
managed by `reports-365d`. If `provision` fails, `ws3-indexer` does not start: read `docker compose ... logs provision`.
Indexes created by an earlier base-stack start can predate the policies; check with
`curl localhost:9200/_plugins/_ism/explain/<index>`.

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

Cold backup of the dataset (stop the stack first so OpenSearch is not mid-write). Volume names are
`<prefix>-<name>`; use your `FENGARDE_HOMELAB_VOL_PREFIX`.

```sh
export MSYS_NO_PATHCONV=1   # Git Bash on Windows only; see below
PREFIX=fengarde-homelab
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml stop
mkdir -p backups
for v in opensearch redis ws3-data tenants inventory ws1-spool; do
  docker volume inspect "$PREFIX-$v" >/dev/null 2>&1 || continue
  docker run --rm -v "$PREFIX-$v":/src:ro -v "$PWD/backups":/dst busybox:1.36 \
    tar czf "/dst/$v-$(date +%Y%m%d).tgz" -C /src .
done
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml start
```

`opensearch` is the one that matters; the others are optional. **Git Bash on Windows rewrites `/dst/...` into
`C:/Program Files/Git/dst/...`**; tested here: without `MSYS_NO_PATHCONV=1` the backup fails with `tar: can't open
'C:/Program Files/Git/dst/...'`, with it the archive is written. (PowerShell and WSL not tested.)

Restore into a new, empty volume with the stack down (the guard refuses a non-empty target):

```sh
export MSYS_NO_PATHCONV=1
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml down
docker run --rm -v "$PREFIX-opensearch":/dst -v "$PWD/backups":/src:ro busybox:1.36 \
  sh -c '[ -z "$(ls -A /dst)" ] || { echo "refusing: target not empty"; exit 1; }; tar xzf /src/opensearch-YYYYMMDD.tgz -C /dst'
```

Restore was run on a throwaway volume (a nested tree, dotfile, symlink, uid 1000 files, mode 640): owner, mode, md5, symlink
and file timestamps came back identical; only directory mtimes differ. **Not run:** restoring a real OpenSearch dataset and
starting OpenSearch on it. Users/contracts can also be bundled with `tools/backup.py` ([ops-lifecycle.md](ops-lifecycle.md));
OpenSearch online snapshots are not configured by this profile.

Wipe everything (irreversible; `down` alone never does this):

```sh
docker compose -f infra/docker-compose.yml -f infra/docker-compose.homelab.yml down -v
```

`down -v` removes the named volumes declared by the stack. If you ever set a different prefix, check with
`docker volume ls | grep <prefix>`.

## Known issues

- **Mock data on ws1 start.** By default `ws1-collectors` seeds 9 bundled mock raw events and 2 mock assets on every start
  (log line `seeded`); in a test run one became a fake `cisco_asa` deny (`203.0.113.5` -> `10.0.0.10:22`, country `RU`) and each
  restart added another copy. This override sets `WS1_SEED_MOCK=0` (log line `mock seed disabled`), so a homelab install gets
  none. `WS1_SEED_MOCK` is documented in [services/ws1-collectors/INTERFACE.md](../services/ws1-collectors/INTERFACE.md); only
  `0`/`false`/`no`/`off` disable the seed, and any other unrecognised value (`n`, `f`, `disable`) keeps it on and logs a warning.
  If you ran an earlier version of this override, filter the old ones out with `src_endpoint.ip: 203.0.113.5`.
  The demo feeder (`devkit-feeder`, fake SSH brute-force burst) is disabled by this override; `--profile demo` brings it back.
- The `observability` profile (Prometheus, Grafana, GoatCounter) is untouched and not tuned for this install.

## What is NOT proven

Evidence level, honestly:

- **Ran (on 2026-11-05, Docker Desktop, 8 GiB, throwaway test stack with remapped host ports and a throwaway token):** config
  validates; all services healthy; one HTTP ingest record (`windows_eventlog` 4688) and one syslog TCP line (sshd failure) reached
  OpenSearch as OCSF events in `events-common-*`; wrong/missing token gives 401; `down` then `up` kept the data; a cold `tar`
  backup of the OpenSearch volume produced an archive. On 2026-11-06, throwaway projects: Redis cap behaviour, volume
migration, backup and restore on throwaway volumes, `ws3-indexer` starting after `provision`, `make down` volume semantics
(minimal project), idle memory of the full stack.
- **Not run:** any real shipper (Vector, Fluent Bit, Winlogbeat, rsyslog, syslog-ng) against this stack; LAN publication
  (`FENGARDE_*_BIND` was only config-validated, not tested from another machine); octet-counting framing through compose;
  restore or migration of a real OpenSearch dataset; Docker-published ports versus `ufw`/`firewalld`; ISM policy edit and re-provision; the zero-loss spool actually draining after a bus outage (it is switched
  on and the log shows it enabled, nothing more); `vm.max_map_count` preflight (not runnable on the Windows test host); a
  long-running soak, disk growth, and memory ceilings under real load (limits are idle-measured plus margin).
- **Unit/synthetic only:** the HTTP and TCP listeners (WP-1.1, WP-1.2) have unit tests and the synthetic runs quoted in their
  docs; nothing here is evidence against real devices. The HTTP listener's own spool (`INGEST_HTTP_SPOOL_PATH`) has no drain
  loop, so this profile does not enable it: with the bus down and no spool, HTTP records are answered 503 and the shipper must retry
  (send `X-Fengarde-Idempotency-Key`).
- **Labelling (WP-2.2): not built.**
