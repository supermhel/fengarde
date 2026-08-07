"""WS-6 inventory store (SQLite).

Implements the asset model of Contract C: MAC is the stable primary key, IP is
historised as intervals so `/assets/resolve?ip=&at=` is historically correct under
DHCP churn. Pure stdlib (sqlite3) so it runs with no external dependencies.

F1 (2026-07-29 audit): every table is additionally keyed by `tenant_id`
(default `"default"`), matching the convention `contracts/tenants/README.md`
and WS-3/WS-4 already use. Before this fix `assets` had NO tenant column at
all (`mac TEXT PRIMARY KEY`), so two MSP customers sharing one deployment
whose devices happened to share a MAC (locally-administered/randomized MACs,
VM/container virtual NICs) would silently overwrite each other's asset
record, and any caller holding the one shared API key could enumerate every
tenant's inventory. `tenant_id` now participates in the primary key
(`PRIMARY KEY (tenant_id, mac)`), so the same MAC in two tenants is two
distinct rows, and every read is scoped to the caller-supplied tenant_id.
A caller that never passes tenant_id gets exactly the pre-fix, single-tenant
behavior (`"default"` for everything) -- zero migration, zero behavior
change for the only deployment topology that exists today.
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Make `shared` resolvable regardless of how store.py is imported (the
# service entrypoints and test harnesses set sys.path inconsistently).
_SERVICES_DIR = Path(__file__).resolve().parent.parent
if str(_SERVICES_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVICES_DIR))

from shared.log import get_logger  # noqa: E402

_log = get_logger("ws6-inventory")

# Mirrors shared.envelope.valid_tenant_id's pattern exactly (lowercase
# alnum/hyphen, 1-63 chars, no leading/trailing hyphen) without importing
# `shared` -- WS-6's Docker image deliberately doesn't bundle it (same reason
# authz.py is a standalone duplicate here, see that file's header comment).
_TENANT_ID_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DEFAULT_TENANT = "default"


class InvalidTenantId(ValueError):
    """Raised for a tenant_id that isn't safe to use as a lookup key.
    Rejected, never normalized/merged -- same rationale as WS-3's router.py
    _validated_tenant: silently lowercasing "Acme"/"ACME" to the same value
    would merge two different customers' data, the exact isolation bug this
    column exists to prevent."""


def _validated_tenant(tenant_id) -> str:
    if tenant_id is None:
        return DEFAULT_TENANT
    if tenant_id == DEFAULT_TENANT:
        return DEFAULT_TENANT
    if not isinstance(tenant_id, str) or not _TENANT_ID_PATTERN.match(tenant_id):
        raise InvalidTenantId(
            f"invalid tenant_id {tenant_id!r}: must be lowercase alphanumeric/hyphen, "
            f"1-63 chars, no leading/trailing hyphen")
    return tenant_id


_BASELINE_SECONDS_DEFAULT = 3600
# A baseline window exists to cover initial population, which is a minutes-to-
# hours job. Anything longer is far more likely a typo or a stale env var than
# an intent, and its effect -- new-device detection silently suppressed for
# months -- looks exactly like "no intrusions", the same indistinguishable
# failure the rule-health watchdog exists to prevent. Clamp loudly instead.
_BASELINE_SECONDS_MAX = 86400


def _baseline_seconds() -> int:
    """Length of a tenant's initial-population window, in seconds.

    Read per call (not cached at import) so a test or operator can change it
    without rebuilding the store. 0 disables baselining entirely: every
    first-ever sighting is alertable immediately. Values above
    ``_BASELINE_SECONDS_MAX`` are clamped, with a warning -- a window measured
    in months would disable the detection without ever saying so.
    """
    raw = os.getenv("INVENTORY_BASELINE_SECONDS")
    if raw is None:
        return _BASELINE_SECONDS_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        _log.warn(
            f"INVENTORY_BASELINE_SECONDS={raw!r} is not an integer; "
            f"using default {_BASELINE_SECONDS_DEFAULT}s"
        )
        return _BASELINE_SECONDS_DEFAULT
    if value < 0:
        _log.warn(
            f"INVENTORY_BASELINE_SECONDS={value} is negative; "
            f"treating as 0 (no baseline window)"
        )
        return 0
    if value > _BASELINE_SECONDS_MAX:
        _log.warn(
            f"INVENTORY_BASELINE_SECONDS={value} exceeds the "
            f"{_BASELINE_SECONDS_MAX}s cap; clamping. A longer window would "
            f"suppress new-device detection indistinguishably from silence."
        )
        return _BASELINE_SECONDS_MAX
    return value


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _normalize_seen_at(seen) -> str:
    """M2 (2026-07-30 audit): _parse() (used by resolve() and the H2
    staleness check) assumes an ISO-8601 string, but WS-1's snmp_collector
    and syslog_collector both emit `seen_at` as a raw epoch-seconds int (the
    `assets.updates` bus topic shape WS-6's INTERFACE.md documents). SQLite's
    TEXT affinity silently stringified that int on write with no error --
    corruption only surfaced later as a resolve() crash or raw digits in the
    dashboard. Normalize once, at the one write choke point, so every caller
    (epoch int/float or ISO-8601 string) lands on the same on-disk shape."""
    if isinstance(seen, bool):
        return _now_iso()
    if isinstance(seen, (int, float)):
        return datetime.fromtimestamp(seen, tz=timezone.utc).isoformat()
    if isinstance(seen, str) and seen:
        return seen
    return _now_iso()


class InventoryStore:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        # upsert() is a SELECT-then-INSERT/UPDATE read-modify-write on a shared
        # connection served from the API's request threads. Without
        # serialization two concurrent observations of the SAME new mac both
        # see row=None and both INSERT -> the second hits the PRIMARY KEY and
        # raises IntegrityError (surfaced to the client as a 500). This lock
        # makes the whole read-modify-write atomic. Writes are cheap; the API
        # is single-process, so an in-process lock is the right-sized fix.
        self._write_lock = threading.Lock()
        self._init()

    def _init(self):
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self._migrate_pre_tenant_schema()
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT NOT NULL,
              vendor TEXT, hostname TEXT, ip_current TEXT,
              sector TEXT, type TEXT, last_seen TEXT, status TEXT DEFAULT 'active',
              PRIMARY KEY (tenant_id, mac)
            );
            CREATE TABLE IF NOT EXISTS ip_history (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT, ip TEXT, from_ts TEXT, to_ts TEXT
            );
            CREATE TABLE IF NOT EXISTS protocols (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT, protocol TEXT, UNIQUE(tenant_id, mac, protocol)
            );
            -- P2-6 (2026-07-21 audit): _hydrate() (called by every get/list/
            -- resolve row) ran "WHERE mac=?" against ip_history/protocols with
            -- no index -- a full table scan per hydrated asset. resolve()
            -- separately scanned all of ip_history by ip with no index either.
            -- These three cover both access patterns (now tenant-scoped too)
            -- without changing any query's shape.
            CREATE INDEX IF NOT EXISTS idx_ip_history_tenant_mac ON ip_history(tenant_id, mac);
            CREATE INDEX IF NOT EXISTS idx_ip_history_tenant_ip ON ip_history(tenant_id, ip);
            CREATE INDEX IF NOT EXISTS idx_protocols_tenant_mac ON protocols(tenant_id, mac);
            -- M7 Track Y: per-tenant baseline window for new-device detection.
            -- A first-ever sighting is only *alertable* once this tenant's
            -- baseline has closed; before then it is initial population. See
            -- _baseline_closed() for why this is per tenant and not global.
            CREATE TABLE IF NOT EXISTS tenant_state (
              tenant_id TEXT PRIMARY KEY,
              baseline_until TEXT NOT NULL
            );
            """
        )
        # P2-6: WAL journal mode batches the fsync cost across commits instead
        # of one fsync-the-whole-file per upsert() (the default DELETE/
        # rollback-journal mode's durability model) -- still crash-safe (WAL
        # is SQLite's recommended mode for concurrent single-writer/multi-
        # reader use, which is exactly this store's access pattern), just
        # without paying a full-file fsync on every single observation.
        # NOT attempted: batching multiple upsert()s into one commit --
        # nothing in this codebase calls upsert() more than once per request
        # (app.py:139 is the only caller, one observation per HTTP POST), so
        # there is no existing call site to batch across without inventing an
        # API nobody uses yet.
        self.db.commit()

    def _migrate_pre_tenant_schema(self) -> None:
        """F1 (2026-07-29 audit): a DB file created before tenant_id existed
        has `assets(mac PRIMARY KEY, ...)` with no tenant column at all --
        every row implicitly belonged to one shared tenant. Rebuild the three
        tables under the new (tenant_id, mac) key, tagging every pre-existing
        row 'default' so a single-tenant deployment's data and behavior are
        byte-for-byte unchanged (every read defaults tenant_id='default' too).
        No-op on a fresh DB (nothing to migrate) or an already-migrated one."""
        tables = {r["name"] for r in self.db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "assets" not in tables:
            return  # fresh DB -- executescript below creates the new schema directly
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(assets)").fetchall()}
        if "tenant_id" in cols:
            return  # already migrated
        self.db.executescript(
            """
            ALTER TABLE assets RENAME TO assets_pre_tenant;
            ALTER TABLE ip_history RENAME TO ip_history_pre_tenant;
            ALTER TABLE protocols RENAME TO protocols_pre_tenant;
            CREATE TABLE assets (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT NOT NULL,
              vendor TEXT, hostname TEXT, ip_current TEXT,
              sector TEXT, type TEXT, last_seen TEXT, status TEXT DEFAULT 'active',
              PRIMARY KEY (tenant_id, mac)
            );
            CREATE TABLE ip_history (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT, ip TEXT, from_ts TEXT, to_ts TEXT
            );
            CREATE TABLE protocols (
              tenant_id TEXT NOT NULL DEFAULT 'default',
              mac TEXT, protocol TEXT, UNIQUE(tenant_id, mac, protocol)
            );
            INSERT INTO assets(tenant_id,mac,vendor,hostname,ip_current,sector,type,last_seen,status)
              SELECT 'default',mac,vendor,hostname,ip_current,sector,type,last_seen,status
              FROM assets_pre_tenant;
            INSERT INTO ip_history(tenant_id,mac,ip,from_ts,to_ts)
              SELECT 'default',mac,ip,from_ts,to_ts FROM ip_history_pre_tenant;
            INSERT OR IGNORE INTO protocols(tenant_id,mac,protocol)
              SELECT 'default',mac,protocol FROM protocols_pre_tenant;
            DROP TABLE assets_pre_tenant;
            DROP TABLE ip_history_pre_tenant;
            DROP TABLE protocols_pre_tenant;
            """
        )
        self.db.commit()

    # ---- writes ---------------------------------------------------------
    def upsert(self, obs: dict) -> dict | None:
        """Upsert from an Observation {mac, ip, hostname?, protocol?, seen_at,
        tenant_id?}. tenant_id defaults to "default" when absent (backward
        compatible with every pre-F1 caller)."""
        asset, _ = self.upsert_with_diff(obs)
        return asset

    def upsert_with_diff(self, obs: dict) -> tuple[dict | None, bool]:
        """:meth:`upsert`, plus whether this observation is an ALERTABLE
        first-ever sighting of the MAC for its tenant (M7 Track Y).

        The bool is False -- not just for a MAC already on file -- but also for
        any first sighting that lands inside the tenant's baseline window, so
        standing up the service against an existing segment populates the
        inventory instead of emitting one alert per device already there.
        """
        mac = obs.get("mac")
        if not mac:
            return None, False  # inventory is MAC-keyed (Contract C)
        tenant_id = _validated_tenant(obs.get("tenant_id"))
        with self._write_lock:
            return self._upsert_locked(obs, mac, tenant_id)

    def _baseline_closed(self, tenant_id: str) -> bool:
        """Whether `tenant_id`'s initial-population window has elapsed.

        Per tenant, not global: in an MSP deployment each customer is onboarded
        at its own time, so a global flag would let tenant B's first-ever
        devices alert as intrusions merely because tenant A was onboarded a
        month earlier.

        The window is opened lazily, on the tenant's first observation. A
        tenant that ALREADY has assets when its row is first created is an
        existing deployment upgrading into this feature, not a fresh install --
        its inventory is already the baseline, so the window is opened closed
        rather than suppressing a genuine new device for the next hour.
        """
        row = self.db.execute(
            "SELECT baseline_until FROM tenant_state WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        if row is None:
            already_populated = self.db.execute(
                "SELECT 1 FROM assets WHERE tenant_id=? LIMIT 1", (tenant_id,)
            ).fetchone() is not None
            seconds = 0 if already_populated else _baseline_seconds()
            until = datetime.now(tz=timezone.utc) + timedelta(seconds=seconds)
            self.db.execute(
                "INSERT INTO tenant_state(tenant_id, baseline_until) VALUES(?,?)",
                (tenant_id, until.isoformat()),
            )
            return seconds <= 0
        try:
            return datetime.now(tz=timezone.utc) >= _parse(row["baseline_until"])
        except (ValueError, TypeError):
            # Unparseable marker: fail toward alerting rather than silently
            # suppressing new-device detection forever.
            return True

    def _upsert_locked(self, obs: dict, mac: str, tenant_id: str) -> tuple[dict | None, bool]:
        ip = obs.get("ip")
        seen = _normalize_seen_at(obs.get("seen_at"))
        row = self.db.execute(
            "SELECT * FROM assets WHERE tenant_id=? AND mac=?", (tenant_id, mac)
        ).fetchone()
        # Evaluated before the INSERT below so the tenant's own baseline row is
        # created off the pre-insert asset count.
        is_new_device = row is None and self._baseline_closed(tenant_id)

        if row is None:
            self.db.execute(
                "INSERT INTO assets(tenant_id,mac,hostname,ip_current,last_seen,status) "
                "VALUES(?,?,?,?,?, 'active')",
                (tenant_id, mac, obs.get("hostname"), ip, seen),
            )
            if ip:
                self.db.execute(
                    "INSERT INTO ip_history(tenant_id,mac,ip,from_ts,to_ts) VALUES(?,?,?,?,NULL)",
                    (tenant_id, mac, ip, seen),
                )
        else:
            # H2 (2026-07-30 audit): delivery is at-least-once everywhere and
            # this HTTP API has no cross-request ordering guarantee, so a
            # delayed/redelivered observation can arrive AFTER a newer one.
            # Applying it unconditionally regresses ip_current/last_seen and
            # inverts the open ip_history interval (to_ts before from_ts).
            # If parsing fails, fail open (apply) -- same as pre-fix
            # behavior -- since we can't prove this observation is stale.
            try:
                stale = _parse(seen) < _parse(row["last_seen"])
            except (ValueError, TypeError):
                stale = False
            if not stale:
                if ip and ip != row["ip_current"]:
                    # close the open interval, open a new one
                    self.db.execute(
                        "UPDATE ip_history SET to_ts=? WHERE tenant_id=? AND mac=? AND to_ts IS NULL",
                        (seen, tenant_id, mac),
                    )
                    self.db.execute(
                        "INSERT INTO ip_history(tenant_id,mac,ip,from_ts,to_ts) VALUES(?,?,?,?,NULL)",
                        (tenant_id, mac, ip, seen),
                    )
                    self.db.execute(
                        "UPDATE assets SET ip_current=? WHERE tenant_id=? AND mac=?",
                        (ip, tenant_id, mac),
                    )
                self.db.execute(
                    "UPDATE assets SET last_seen=?, hostname=COALESCE(?,hostname) "
                    "WHERE tenant_id=? AND mac=?",
                    (seen, obs.get("hostname"), tenant_id, mac),
                )

        if obs.get("protocol"):
            self.db.execute(
                "INSERT OR IGNORE INTO protocols(tenant_id,mac,protocol) VALUES(?,?,?)",
                (tenant_id, mac, obs["protocol"]),
            )
        self.db.commit()
        return self.get(mac, tenant_id=tenant_id), is_new_device

    # ---- reads ----------------------------------------------------------
    def get(self, mac: str, tenant_id: str | None = None) -> dict | None:
        tenant_id = _validated_tenant(tenant_id)
        row = self.db.execute(
            "SELECT * FROM assets WHERE tenant_id=? AND mac=?", (tenant_id, mac)
        ).fetchone()
        if not row:
            return None
        return self._hydrate(row)

    def list(self, ip=None, mac=None, sector=None, status=None, limit=50,
              tenant_id: str | None = None) -> list[dict]:
        tenant_id = _validated_tenant(tenant_id)
        q = "SELECT * FROM assets WHERE tenant_id=?"
        args: list = [tenant_id]
        if mac:
            q += " AND mac=?"; args.append(mac)
        if ip:
            q += " AND ip_current=?"; args.append(ip)
        if sector:
            q += " AND sector=?"; args.append(sector)
        if status:
            q += " AND status=?"; args.append(status)
        q += " LIMIT ?"; args.append(limit)
        return [self._hydrate(r) for r in self.db.execute(q, args).fetchall()]

    def resolve(self, ip: str, at: str, tenant_id: str | None = None) -> dict | None:
        """Which MAC held `ip` at instant `at` (historically correct), scoped
        to one tenant's ip_history."""
        tenant_id = _validated_tenant(tenant_id)
        at_dt = _parse(at)
        rows = self.db.execute(
            "SELECT * FROM ip_history WHERE tenant_id=? AND ip=?", (tenant_id, ip)
        ).fetchall()
        for r in rows:
            frm = _parse(r["from_ts"])
            to = _parse(r["to_ts"]) if r["to_ts"] else None
            if frm <= at_dt and (to is None or at_dt < to):
                return self.get(r["mac"], tenant_id=tenant_id)
        return None

    # ---- helpers --------------------------------------------------------
    def _hydrate(self, row) -> dict:
        mac = row["mac"]
        tenant_id = row["tenant_id"]
        hist = [
            {"ip": h["ip"], "from": h["from_ts"], "to": h["to_ts"]}
            for h in self.db.execute(
                "SELECT * FROM ip_history WHERE tenant_id=? AND mac=? ORDER BY from_ts",
                (tenant_id, mac),
            ).fetchall()
        ]
        protos = [
            p["protocol"]
            for p in self.db.execute(
                "SELECT protocol FROM protocols WHERE tenant_id=? AND mac=?", (tenant_id, mac)
            ).fetchall()
        ]
        return {
            "mac": mac, "tenant_id": tenant_id, "vendor": row["vendor"], "hostname": row["hostname"],
            "ip_current": row["ip_current"], "ip_history": hist,
            "protocols_seen": protos, "sector": row["sector"], "type": row["type"],
            "last_seen": row["last_seen"], "status": row["status"],
        }
