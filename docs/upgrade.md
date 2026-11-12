# Upgrade, migration notes and rollback

Operator runbook for taking a running FENGARDE install across releases and
backing out cleanly when a release misbehaves. Applies to any compose
deployment (`infra/docker-compose.yml`, plus overlays like the homelab
profile); the same file-level steps apply to the operator's local state
whatever the hosting style.

> **Verification status (read this first).** `tools/backup.py` / `tools/restore.py`
> are tested on plain files and SQLite in temp directories
> (`tools/test_backup_restore.py`). The Docker-volume extraction commands
> below (`docker run --rm -v ...`) are **untested**: they were written
> from `infra/docker-compose.yml` and have not been run against a live compose stack.
> Rehearse them on a throwaway stack before relying on them.

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

```sh
# 1. stop the stack (services only; keep names/volumes)
docker compose -f infra/docker-compose.yml -f <overlays...> down

# 2. back up the local stores. backup.py runs on the HOST and cannot see
#    Docker named volumes, so first copy the stores out of the (stopped)
#    stack's volumes. `docker volume ls` shows the real names
#    (<compose-project>_ws3-indexer-data, <project>_inventory-data,
#    <project>_ws1-spool). UNTESTED against a live stack -- see the note above.
mkdir -p stage/ws3 stage/inventory stage/spool
docker run --rm -v <project>_ws3-indexer-data:/src:ro -v "$PWD/stage/ws3":/dst alpine cp -a /src/. /dst/
docker run --rm -v <project>_inventory-data:/src:ro   -v "$PWD/stage/inventory":/dst alpine cp -a /src/. /dst/
docker run --rm -v <project>_ws1-spool:/src:ro        -v "$PWD/stage/spool":/dst alpine cp -a /src/. /dst/

#    Then point backup.py at the EXTRACTED copies (container paths such as
#    /app/ws3-indexer/data/audit.jsonl do not exist on the host). File names
#    are the ones your overlay configured; examples:
python tools/backup.py --out ./backups \
    --audit-log stage/ws3/audit.jsonl \
    --rbac-db stage/ws3/rbac.sqlite \
    --inventory-db stage/inventory/inventory.db \
    --spool stage/spool/spool.jsonl
#    Omit a flag when you do not run that store. The shipped compose does NOT
#    set INVENTORY_DB / INVENTORY_KEYSTORE_DB (WS-6 then runs on ":memory:"
#    and there is nothing to back up); set them in an overlay to persist.
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

1. **Image rollback (no data step).** If the failure is functional (a bug in
   the new release) rather than data corruption:
   ```sh
   git checkout <previous-tag>      # images rebuild from the pinned tag
   docker compose -f infra/docker-compose.yml -f <overlays...> up -d --build
   ```
   No restore step: local stores were not rewritten by the failed release
   (migrations are additive/forward-only on first start; a release that DID
   migrate a store says so in its Upgrade notes, and that store's pre-migration
   file is in your backup from step 2 above).

2. **Data restore (backup-then-restore).** If state must go back to before the
   upgrade -- the archive from `tools/backup.py`:
   ```sh
   docker compose -f infra/docker-compose.yml -f <overlays...> down
   python tools/restore.py ./backups/fengarde-backup-*.tar.gz --dest ./restored
   ```
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

   Copy them into the volumes with the reverse of the extraction commands
   (`docker run --rm -v <volume>:/dst -v "$PWD/restored/...":/src alpine cp ...`;
   also untested). When the target is an SQLite file that may carry
   leftover `-wal`/`-shm`/`-journal` files, `restore.py --force` deletes them
   (a stale WAL would replay post-backup rows into the restored DB, which
   was reproduced); without `--force` a leftover sidecar blocks the restore.
   When copying into a volume by hand, delete those sidecars yourself.

   `restore.py` verifies every file's sha256 against the archive manifest
   BEFORE writing anything, refuses overwrites (including leftover SQLite
   sidecars) without `--force`, and rejects path-traversal/symlink-escape
   members (regression-tested in `tools/test_backup_restore.py`). Then start
   the previous images.

## Honest scope

The archive covers, when you configure them: RBAC DB, WS-6 inventory/keystore
SQLite, WS-3 audit log, WS-1 spool files, plugin rule-pack directories and
`contracts/`. It does **not** cover:

- **OpenSearch** events/alerts/reports: use OpenSearch's own snapshot
  repository (https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/).
- **Redis** bus streams, detection-window and entity state: use Redis RDB/AOF.
- **`FENGARDE_GEOIP_PATH`** operator GeoIP map: copy it yourself.
- Docker volumes themselves: extraction/re-injection is manual (above, untested).
- Spool files that do not exist yet (they are created on first shed).

Consistency: SQLite stores are snapshotted with SQLite's backup API; the
audit log is copied while holding its own `.lock`; spool files and plugin
rule dirs are plain copies, so stop the collectors first.

What is proven: `tools/test_backup_restore.py` (real SQLite + JSONL files,
mutate-then-restore, WAL-sidecar, lock, `%`-in-path and env-default
regressions). What is not: any run against a live compose stack, and the
rollback claim that an image-only rollback needs no restore (a release that
already migrated a store on start, e.g. the WS-6 keystore schema migration,
needs the file restore).
