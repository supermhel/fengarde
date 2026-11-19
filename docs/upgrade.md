# Upgrade, migration notes and rollback

Operator runbook for taking a running FENGARDE install across releases and
backing out cleanly when a release misbehaves. Applies to any compose
deployment (`infra/docker-compose.yml`, plus overlays like the homelab
profile); the same file-level steps apply to the operator's local state
whatever the hosting style.

> **Verification status (read this first).** `tools/backup.py` / `tools/restore.py`
> are tested on plain files and SQLite in temp directories
> (`tools/test_backup_restore.py`). The Docker-volume extraction and
> re-injection commands (`docker run --rm -v ...`, with the per-volume `chown`)
> were **run live once, on 2026-11-19**, on **Windows Docker Desktop against a
> single (non-HA) stack**: extract -> `backup.py` -> `restore.py` -> delete the
> SQLite files from the volumes -> re-inject -> `up -d` -> log in as restored
> users and read restored data (evidence: `docs/live-verification-2026-11-19.md`
> section 4, on branch `live-2026-11-19`; it lands with that integration). That
> run found the Windows Git Bash defect and the persistence defects documented
> below. **Still untested: a Linux host (the primary commands below were not the
> ones executed; the Windows variant was) and the HA profile
> (`infra/docker-compose.ha.yml`).** Rehearse on a throwaway stack before
> relying on it.

## What the default compose actually persists (read before backing up)

On the shipped `infra/docker-compose.yml` alone, **only the WS-3 audit log is a
persistent store you can back up.** The other examples in this runbook
(`rbac.sqlite`, `inventory.db`, a spool file) exist only after you opt in with
the settings below (an overlay or `infra/.env`):

| store | setting that makes it persistent | default on the shipped compose |
|---|---|---|
| WS-3 audit log | `FENGARDE_AUDIT_LOG=/app/ws3-indexer/data/audit.jsonl` | **set** (volume `ws3-indexer-data`) |
| RBAC users DB | `FENGARDE_RBAC_DB=/app/ws3-indexer/data/rbac.sqlite` on `ws3-indexer` (also needs `FENGARDE_ADMIN_PASSWORD` for the first-boot admin) | **off**: the line is commented out in the compose; RBAC is disabled and no DB exists |
| WS-6 inventory + API keys | `INVENTORY_DB=/data/inventory.db` on `ws6-inventory` (volume `inventory-data` is mounted at `/data`); `INVENTORY_KEYSTORE_DB` defaults to the same file | **not passed**: WS-6 runs on `:memory:`, nothing on disk |
| WS-1 spool (e.g. HTTP ingest) | a `*_SPOOL_PATH` file under `/var/lib/fengarde/spool/` on `ws1-collectors` (volume `ws1-spool`) | **not passed through** by the compose (for example `INGEST_HTTP_SPOOL_PATH`; the syslog one is only a commented example), so it needs an overlay |

Example overlay (`infra/docker-compose.override.yml` or any `-f` overlay):

```yaml
services:
  ws3-indexer:
    environment:
      - FENGARDE_RBAC_DB=/app/ws3-indexer/data/rbac.sqlite
      - FENGARDE_ADMIN_PASSWORD=${FENGARDE_ADMIN_PASSWORD}
  ws6-inventory:
    environment:
      - INVENTORY_DB=/data/inventory.db
```

Check which file names your stack really uses (`docker compose ... config`)
and pass those names to `backup.py` below; the names in the examples are the
ones from this table. A store you enable only AFTER an upgrade has nothing to
back up before it.

## Per-release upgrade note (convention)

Every release section in `CHANGELOG.md` documents its own upgrade contract
under an **Upgrade notes** heading (added by the release-prep commit):

```
## [0.12.0] - 2026-11-05

### Upgrade notes
- None (no schema/migration/backward-incompatible changes).
  Steps: stop the stack, `git pull` to the tag, restart, verify.
- If a release DOES change something:
  - "Breaks: ..." or "Migrates: ..." with the exact command/step an operator
    must run (e.g. a SQLite schema migration the service applies on first
    start -- read which one here, not by diffing).
  - Anything the service migrates automatically on startup is said so
    explicitly (e.g. the WS-6 keystore's pre-HMAC legacy-key migration:
    automatic, but re-provision keys from `FENGARDE_API_KEYS` only if those
    env vars are still set).
- Rollback of a release that only ever touches Docker images never needs the
  file restore below; a release that ships a migration DOES.
```

If a release's section lacks an **Upgrade notes** heading, the honest answer
for "what do I need to do to upgrade?" is "nothing extra -- the keep-a-changelog
release layout didn't add any" only for releases that truly have none; the
heading is mandatory once any release adds a migration or a breaking change.

## Standard upgrade procedure (no migration)

> **Warning: never use `make down` or `docker compose down -v` here.** Both
> delete the named volumes, which are exactly the stores this runbook backs up.
> Plain `docker compose ... down` (no `-v`) keeps them.

```sh
# 1. stop the stack (services only; keep names/volumes -- NO `-v`, NOT `make down`)
docker compose -f infra/docker-compose.yml -f <overlays...> down

# 2. back up the local stores. backup.py runs on the HOST and cannot see
#    Docker named volumes, so first copy the stores out of the (stopped)
#    stack's volumes. `docker volume ls` shows the real names
#    (<compose-project>_ws3-indexer-data, <project>_inventory-data,
#    <project>_ws1-spool). Run live only on Windows Docker Desktop -- see the note above.
mkdir -p stage/ws3 stage/inventory stage/spool
docker run --rm -v <project>_ws3-indexer-data:/src:ro -v "$PWD/stage/ws3":/dst alpine cp -a /src/. /dst/
docker run --rm -v <project>_inventory-data:/src:ro   -v "$PWD/stage/inventory":/dst alpine cp -a /src/. /dst/
docker run --rm -v <project>_ws1-spool:/src:ro        -v "$PWD/stage/spool":/dst alpine cp -a /src/. /dst/

#    `cp -a` keeps the container owner (uid 10001), so the host user cannot
#    read the copies and backup.py would fail with PermissionError. Hand the
#    staging copies to yourself first:
sudo chown -R "$(id -u):$(id -g)" stage

#    WINDOWS (Git Bash) VARIANT -- the three commands above do NOT work there.
#    MSYS rewrites the in-container `/src/.` into
#    `C:/Program Files/Git/src/.`, `cp` fails with "can't stat", and the
#    staging dirs stay EMPTY (a later backup.py then backs up nothing). Turn
#    path conversion off and give Docker a Windows host path (`pwd -W`):
#      export MSYS_NO_PATHCONV=1
#      docker run --rm -v <project>_ws3-indexer-data:/src:ro -v "$(pwd -W)/stage/ws3":/dst alpine cp -a /src/. /dst/
#      (same for inventory-data -> stage/inventory and ws1-spool -> stage/spool)
#    Check the dirs are non-empty before continuing. `sudo chown` does NOT
#    apply on Windows (no sudo; Docker Desktop bind mounts come out owned by
#    the host user and backup.py read them fine). Use the same
#    MSYS_NO_PATHCONV=1 + `$(pwd -W)` form for the re-injection commands in
#    the rollback section; the `chown 10001:10001` there runs INSIDE the
#    container and still applies. PowerShell or WSL also avoid the rewrite.

#    Then point backup.py at the EXTRACTED copies (container paths such as
#    /app/ws3-indexer/data/audit.jsonl do not exist on the host). File names
#    are the ones your overlay configured; examples:
python tools/backup.py --out ./backups \
    --audit-log stage/ws3/audit.jsonl \
    --rbac-db stage/ws3/rbac.sqlite \
    --inventory-db stage/inventory/inventory.db \
    --spool stage/spool/spool.jsonl
#    Omit a flag when you do not run that store -- on the default compose
#    that means ONLY `--audit-log` applies (see "What the default compose
#    actually persists" above; WS-6 runs on ":memory:" there and RBAC is off
#    until you set the env vars in that table).
#    --keystore-db / INVENTORY_KEYSTORE_DB defaults to the inventory DB
#    (same as ws6-inventory/app.py): ONE file holds assets AND API keys and is
#    archived as keystore/<name>.
#    backup.py prints "NOT backed up" on stderr (and in manifest.json) for
#    every store you did not configure -- read it.
#    (OpenSearch events/alerts, Redis state and the GeoIP map are NEVER in
#     this archive -- see "Honest scope".)

# 3. pull the new release (image hashes pinned per tag) and start
git pull --ff-only && git checkout v0.x.y
docker compose -f infra/docker-compose.yml -f <overlays...> up -d

# 4. verify: console loads, /api/ops/ws* all healthy, a test ingest round-trips
```

## Migration releases

Read the release's **Upgrade notes** section in `CHANGELOG.md` BEFORE pulling
the new images. Migrations in this repo are applied by the service itself on
first start against existing files (e.g. the WS-6 keystore schema/legacy-key
migration); the notes say which stores re-init and what the operator must set
after (e.g. re-issue inventory API keys, re-create RBAC users) when the
automatic path cannot carry data forward. Nothing here auto-rewrites existing
files backwards -- that is what makes rollback below safe.

## Documented rollback

Two independent layers; use the one that matches why you are backing out.

1. **Image rollback (no data step) -- only for a release with no migration.**
   Use this only when the failed release's **Upgrade notes** say "None" (no
   schema/migration change) and the failure is functional, not data corruption:
   ```sh
   git checkout <previous-tag>      # images rebuild from the pinned tag
   docker compose -f infra/docker-compose.yml -f <overlays...> up -d --build
   ```
   If the failed release's notes list **any** "Migrates:" entry, the new
   release has already rewritten that store on first start and the previous
   images may not read it: skip this layer and use the data restore (2).

2. **Data restore (backup-then-restore).** If state must go back to before the
   upgrade -- the archive from `tools/backup.py`:
   ```sh
   # a. stop (no -v, not `make down`: that deletes the volumes you restore into)
   docker compose -f infra/docker-compose.yml -f <overlays...> down
   # b. unpack + verify into a staging dir (nothing touches the volumes yet)
   python tools/restore.py ./backups/fengarde-backup-<timestamp>.tar.gz --dest ./restored
   #    restore.py prints the release the backup was taken on
   #    ("fengarde_release" in its JSON output). Roll back to THAT release:
   git checkout <fengarde_release from the output>
   # c. copy each restored file into its volume (table below), deleting any
   #    -wal/-shm/-journal next to an SQLite target in the volume first
   # d. start the previous release and verify (console, /api/ops/ws*, test ingest)
   docker compose -f infra/docker-compose.yml -f <overlays...> up -d --build
   ```
   **Verify after restore (the live run's check).** Starting healthy is not
   proof; read restored data back through the console API. With RBAC restored,
   log in as a user that exists only in the restored DB, then read a restored
   record (console port 8080):
   ```sh
   # login with a restored RBAC user -> session cookie (+ csrf_token in the body)
   curl -s -c jar.txt -H "X-Api-Key: $FENGARDE_API_KEY" -H 'Content-Type: application/json' \
        -d '{"username":"<restored-user>","password":"<its password>"}' \
        http://localhost:8080/api/auth/login          # expect HTTP 200
   # read one restored record with that session, e.g. inventory assets
   curl -s -b jar.txt -H "X-Api-Key: $FENGARDE_API_KEY" http://localhost:8080/api/inventory/assets
   ```
   Expect the login to succeed (200) and the assets you had before the upgrade
   to be listed. On the live run the restored users returned 200 and WS-6
   `/assets` with its key returned the restored assets. Omit `X-Api-Key` if
   you run without `FENGARDE_API_KEY`. Delete `jar.txt` afterwards.

   `--dest` is a staging ROOT, not your configured paths. Files land under
   it by archive folder and the tool prints the absolute `landed` paths:

   | archive path | put it back at |
   |---|---|
   | `rbac/<file>` | `$FENGARDE_RBAC_DB` (inside the `ws3-indexer-data` volume) |
   | `keystore/<file>` | `$INVENTORY_KEYSTORE_DB`, or `$INVENTORY_DB` when that is unset (inside `inventory-data`) |
   | `inventory/<file>` | `$INVENTORY_DB` when it differs from the keystore file |
   | `ws3/<file>` | `$FENGARDE_AUDIT_LOG` |
   | `ws1-spool/<n>/<file>` | the matching `*_SPOOL_PATH` |
   | `plugin-rules/<n>-<dir>/...` | the matching `FENGARDE_PLUGIN_RULE_DIRS` entry |
   | `contracts/...` | `./contracts/` in the checkout |

   Copy them into the volumes with the reverse of the extraction commands,
   **and fix ownership in the same container**. `restore.py` writes owner-only
   (`0600`) files; copied in as root they stay root-owned `0600` and the
   services (which run as `USER app`, uid 10001) cannot read them. Per volume
   (uid:gid as in `infra/docker-compose.yml`'s init containers):

   | volume | owner after copy |
   |---|---|
   | `ws3-indexer-data` (rbac, audit log) | `10001:10001` |
   | `inventory-data` (inventory/keystore DB) | `10001:10001` |
   | `ws1-spool` (spool + `.dead`) | `10001:999` |

   ```sh
   # example: RBAC DB + audit log into ws3-indexer-data; repeat per volume
   docker run --rm -v <project>_ws3-indexer-data:/dst -v "$PWD/restored/rbac":/src:ro alpine        sh -c 'cp /src/rbac.sqlite /dst/ && chown 10001:10001 /dst/rbac.sqlite && chmod 600 /dst/rbac.sqlite'
   ```
   Verify a service-uid read works before starting the stack:
   `docker run --rm --user 10001:10001 -v <project>_ws3-indexer-data:/d alpine cat /d/rbac.sqlite >/dev/null`.
   (Tested with a throwaway volume: a plain root `cp` of a `0600` file fails
   that read with "Permission denied"; the command above succeeds. Not run
   against a live Linux stack; the Windows live run re-injected with this same chown and the service uid read it.)

   A stale `-wal`/`-shm`/`-journal` beside an SQLite file
   replays post-backup rows into the restored DB (reproduced). `restore.py
   --force` only removes such sidecars **under `--dest`** (the staging dir,
   which normally has none); the real risk is in the **volume**, and
   `restore.py` cannot reach it. Delete those sidecars in the volume yourself
   before copying the DB in, e.g.
   `docker run --rm -v <volume>:/dst alpine sh -c 'rm -f /dst/<db>-wal /dst/<db>-shm /dst/<db>-journal'`.

   `restore.py` verifies every file's sha256 against the archive manifest
   BEFORE writing anything (the manifest is inside the same archive, so this
   detects corruption/truncation, **not** deliberate tampering: keep the archive
   somewhere trusted or sign it separately), refuses overwrites (including leftover SQLite
   sidecars) without `--force`, and rejects path-traversal/symlink-escape
   members (regression-tested in `tools/test_backup_restore.py`). Each file is
   written to a temp name and renamed into place with owner-only permissions.

## Honest scope

The archive covers, when you configure them: RBAC DB, WS-6 inventory/keystore
SQLite, WS-3 audit log, WS-1 spool files (plus each spool's `.dead`
dead-letter sidecar), plugin rule-pack directories and `contracts/`. Every
manifest records the release it was taken on (`fengarde_release`, from
`git describe`). It does **not** cover:

- **OpenSearch** events/alerts/reports: use OpenSearch's own snapshot
  repository (https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/).
- **Redis** bus streams, detection-window and entity state: use Redis RDB/AOF.
- **`FENGARDE_GEOIP_PATH`** operator GeoIP map: copy it yourself.
- Docker volumes themselves: extraction/re-injection is manual (above; run once on Windows Docker Desktop, single stack; not on Linux or HA).
- Spool files that do not exist yet (they are created on first shed).

Consistency: SQLite stores are snapshotted with SQLite's backup API; the
audit log is copied while holding its own `.lock`; spool files and plugin
rule dirs are plain copies, so stop the collectors first.

What is proven: `tools/test_backup_restore.py` (real SQLite + JSONL files,
mutate-then-restore, WAL-sidecar, lock, `%`-in-path and env-default
regressions, malformed-archive and Windows-path guards). What is not: any run
against a live compose stack (volume extraction/re-injection on Linux or against the HA profile; the one live run was Windows Docker Desktop, single stack, 2026-11-19). The `0600`
permission check runs on POSIX only (CI's Linux runner; skipped on Windows,
where `chmod` only toggles read-only).
