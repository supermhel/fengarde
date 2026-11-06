# Upgrade, migration notes and rollback

Operator runbook for taking a running FENGARDE install across releases and
backing out cleanly when a release misbehaves. Applies to any compose
deployment (`infra/docker-compose.yml`, plus overlays like the homelab
profile); the same file-level steps apply to the operator's local state
whatever the hosting style.

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

# 2. back up the local stores (see tools/backup.py --help):
#    RBAC DB + WS-6 keystore + WS-3 audit log + contracts in ONE archive
python tools/backup.py --out ./backups \
    --rbac-db "$FENGARDE_RBAC_DB" \
    --keystore-db "${INVENTORY_KEYSTORE_DB:-/data/keystore.db}" \
    --audit-log "$FENGARDE_AUDIT_LOG"
#    (OpenSearch events/alerts are NOT in this archive -- snapshot the
#     cluster with OpenSearch's own snapshot API if you need them back)

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
   # or --force into a live path after confirming the collision list is the
   # stores being rolled back
   ```
   `restore.py` verifies every file's sha256 against the archive manifest
   BEFORE writing anything, refuses overwrites without `--force`, and rejects
   path-traversal/symlink-escape members (regression-tested in
   `tools/test_backup_restore.py`). Restore the RBAC DB/keystore/audit files
   into their FENGARDE_* configured paths, then start the previous images.

## Honest scope

The backup archive covers local, host-only state: RBAC DB, WS-6 inventory
keystore, WS-3 audit log, contracts (rules/tenants/webhooks). **Event and
alert data live in OpenSearch and are NOT in the archive** -- a rollback that
needs the data back after a disaster must use OpenSearch's own snapshot
repository (https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/).
The zero-infra round-trip guarantee is proven by
`tools/test_backup_restore.py` (real SQLite + JSONL stores, mutate-then-restore).
