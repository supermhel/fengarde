# Ops lifecycle: migration, backup/restore, disk guardrails (M4.6)

Three independent, all zero-infra-testable pieces of running FENGARDE past
day one: upgrading a deployment's schemas without losing data, backing up
and restoring the state that lives only on your host, and refusing to grow
local disk-backed queues past a critically low free-space floor.

## Schema migration

**`services/shared/users.py`** (the RBAC user database, M4.2) is the one
persistent local datastore in this system, and the one place a real
"upgrade with data intact" claim is verifiable without a live cluster.
Schema version is tracked via SQLite's built-in `PRAGMA user_version` — no
extra bookkeeping table. `UserStore.__init__` calls `migrate()` on every
open, so a `users.db` file created by an older FENGARDE release upgrades in
place on next service start; existing accounts, roles, tenant assignments,
and password hashes survive untouched. See
`services/shared/test_users_migration.py` for the proof (a real
hand-built v1 DB, upgraded, data checked byte-for-byte).

**`tools/migrate_opensearch.py`** does the equivalent for OpenSearch index
templates: each `contracts/opensearch-mappings/*.json` carries a
`template.mappings._meta.mapping_version`. The tool GETs the currently
installed template, compares versions, and only PUTs (`ensure_template`)
what actually changed — plan-then-apply, auditable, idempotent.

```sh
python tools/migrate_opensearch.py --dry-run    # see what would change
python tools/migrate_opensearch.py              # apply it
```

**Honest scope:** this manages index TEMPLATES (mappings) only. It does
NOT install ILM/retention policies — `contracts/opensearch-mappings/
ilm-policies.json` is written in Elasticsearch ILM syntax, but this stack
runs OpenSearch, whose Index State Management (ISM) plugin uses a
different policy schema at a different endpoint. This was already an
honest no-op placeholder in `infra/provision.sh` before this tool existed;
see `SSOT.md` §2 for the tracked gap. Fixing it needs a live cluster to
verify the real ISM policy bodies against — out of scope for a repo whose
test path can't stand one up.

Like the rest of `storage/opensearch.py`, `migrate_opensearch.py`'s logic
is proven at the wire-format level against a fake transport
(`tools/test_migrate_opensearch.py`), not against a live cluster.

## Backup and restore

**`tools/backup.py`** bundles the two things that live only on this host
and aren't already in version control into one checksummed `.tar.gz`:

- The RBAC user database (`--rbac-db`, defaults to `$FENGARDE_RBAC_DB`),
  snapshotted via SQLite's `.backup()` API — safe to run against a DB a
  live service still has open, unlike a raw file copy.
- `contracts/` — rules, tenant configs, webhook configs. Most of this is
  already in git, but an operator's local `contracts/tenants/*.yml` /
  `contracts/webhooks/*.yml` additions may not be committed anywhere else.

```sh
python tools/backup.py --out ./backups
python tools/backup.py --out ./backups --rbac-db /data/users.db
python tools/backup.py --out ./backups --no-contracts   # RBAC DB only
```

**`tools/restore.py`** verifies every file's sha256 against the archive's
`manifest.json` BEFORE writing anything — a truncated or tampered archive
is rejected with nothing written to disk. Refuses to overwrite an existing
file unless `--force`.

```sh
python tools/restore.py fengarde-backup-20260716T120000Z.tar.gz --dest ./restored
python tools/restore.py backup.tar.gz --dest ./restored --force
```

**Honest scope:** this does NOT back up OpenSearch index data (events,
alerts, reports). That needs OpenSearch's own native snapshot/restore API
against a configured snapshot repository — a live-cluster operation this
repo's zero-infra test path can't exercise, and reimplementing it here
would be an untested wrapper around a tool that already does this
correctly. See [OpenSearch's snapshot docs](https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/).

## Disk guardrails

**`services/shared/diskguard.py::check_disk_headroom()`** is a real,
`shutil.disk_usage()`-based check: does the volume containing a given path
have enough free space, by both an absolute floor (default 512MiB) and a
percentage floor (default 5%) — both must pass, since an absolute floor
alone is wrong for a huge volume and a percentage floor alone is wrong for
a tiny one.

It's wired into `services/ws1-collectors/collectors/spool.py`'s
`BoundedSpool.append()`: the opt-in zero-loss syslog spool (`SYSLOG_SPOOL_
PATH`, see `docs/agent-monitoring.md`'s sibling coverage in `SECURITY.md`
§8) now refuses to grow further once the underlying volume — not just the
spool's own `max_bytes` cap — is critically low on free space. A generous
`SYSLOG_SPOOL_MAX_BYTES` still shares its disk with the OpenSearch data
directory and every other local write; this closes that gap.

```python
from shared.diskguard import check_disk_headroom
ok, detail = check_disk_headroom("/data/spool", min_free_bytes=1_000_000_000, min_free_pct=10.0)
```

Any other local disk-backed writer can reuse this the same way; it isn't
spool-specific.

## What this does NOT give you

- No OpenSearch/Redis data backup or migration — both need a live cluster
  this repo's test path can't exercise; use each system's own native
  tooling (OpenSearch snapshots, Redis `BGSAVE`/AOF).
- No automatic/scheduled backups — `tools/backup.py` is a command you run
  (via cron, a systemd timer, or your orchestrator's job scheduler), not a
  background service.
- No cross-version compatibility guarantee for the backup archive format
  itself — `manifest.json`'s shape can change between FENGARDE releases
  like any other internal interface.
- No disk-headroom guardrail on OpenSearch's own data volume — that's
  OpenSearch's `cluster.routing.allocation.disk.watermark.*` settings,
  already a mature, separate mechanism; `diskguard.py` covers this
  repo's OWN local writers (currently just the syslog spool).
