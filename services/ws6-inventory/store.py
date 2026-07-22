"""WS-6 inventory store (SQLite).

Implements the asset model of Contract C: MAC is the stable primary key, IP is
historised as intervals so `/assets/resolve?ip=&at=` is historically correct under
DHCP churn. Pure stdlib (sqlite3) so it runs with no external dependencies.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


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
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS assets (
              mac TEXT PRIMARY KEY,
              vendor TEXT, hostname TEXT, ip_current TEXT,
              sector TEXT, type TEXT, last_seen TEXT, status TEXT DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS ip_history (
              mac TEXT, ip TEXT, from_ts TEXT, to_ts TEXT,
              FOREIGN KEY(mac) REFERENCES assets(mac)
            );
            CREATE TABLE IF NOT EXISTS protocols (
              mac TEXT, protocol TEXT, UNIQUE(mac, protocol)
            );
            -- P2-6 (2026-07-21 audit): _hydrate() (called by every get/list/
            -- resolve row) ran "WHERE mac=?" against ip_history/protocols with
            -- no index -- a full table scan per hydrated asset. resolve()
            -- separately scanned all of ip_history by ip with no index either.
            -- These three cover both access patterns without changing any
            -- query's shape.
            CREATE INDEX IF NOT EXISTS idx_ip_history_mac ON ip_history(mac);
            CREATE INDEX IF NOT EXISTS idx_ip_history_ip ON ip_history(ip);
            CREATE INDEX IF NOT EXISTS idx_protocols_mac ON protocols(mac);
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
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.commit()

    # ---- writes ---------------------------------------------------------
    def upsert(self, obs: dict) -> dict | None:
        """Upsert from an Observation {mac, ip, hostname?, protocol?, seen_at}."""
        mac = obs.get("mac")
        if not mac:
            return None  # inventory is MAC-keyed (Contract C)
        with self._write_lock:
            return self._upsert_locked(obs, mac)

    def _upsert_locked(self, obs: dict, mac: str) -> dict | None:
        ip = obs.get("ip")
        seen = obs.get("seen_at") or _now_iso()
        row = self.db.execute("SELECT * FROM assets WHERE mac=?", (mac,)).fetchone()

        if row is None:
            self.db.execute(
                "INSERT INTO assets(mac,hostname,ip_current,last_seen,status) "
                "VALUES(?,?,?,?, 'active')",
                (mac, obs.get("hostname"), ip, seen),
            )
            if ip:
                self.db.execute(
                    "INSERT INTO ip_history(mac,ip,from_ts,to_ts) VALUES(?,?,?,NULL)",
                    (mac, ip, seen),
                )
        else:
            if ip and ip != row["ip_current"]:
                # close the open interval, open a new one
                self.db.execute(
                    "UPDATE ip_history SET to_ts=? WHERE mac=? AND to_ts IS NULL",
                    (seen, mac),
                )
                self.db.execute(
                    "INSERT INTO ip_history(mac,ip,from_ts,to_ts) VALUES(?,?,?,NULL)",
                    (mac, ip, seen),
                )
                self.db.execute("UPDATE assets SET ip_current=? WHERE mac=?", (ip, mac))
            self.db.execute(
                "UPDATE assets SET last_seen=?, hostname=COALESCE(?,hostname) WHERE mac=?",
                (seen, obs.get("hostname"), mac),
            )

        if obs.get("protocol"):
            self.db.execute(
                "INSERT OR IGNORE INTO protocols(mac,protocol) VALUES(?,?)",
                (mac, obs["protocol"]),
            )
        self.db.commit()
        return self.get(mac)

    # ---- reads ----------------------------------------------------------
    def get(self, mac: str) -> dict | None:
        row = self.db.execute("SELECT * FROM assets WHERE mac=?", (mac,)).fetchone()
        if not row:
            return None
        return self._hydrate(row)

    def list(self, ip=None, mac=None, sector=None, status=None, limit=50) -> list[dict]:
        q = "SELECT * FROM assets WHERE 1=1"
        args = []
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

    def resolve(self, ip: str, at: str) -> dict | None:
        """Which MAC held `ip` at instant `at` (historically correct)."""
        at_dt = _parse(at)
        rows = self.db.execute("SELECT * FROM ip_history WHERE ip=?", (ip,)).fetchall()
        for r in rows:
            frm = _parse(r["from_ts"])
            to = _parse(r["to_ts"]) if r["to_ts"] else None
            if frm <= at_dt and (to is None or at_dt < to):
                return self.get(r["mac"])
        return None

    # ---- helpers --------------------------------------------------------
    def _hydrate(self, row) -> dict:
        mac = row["mac"]
        hist = [
            {"ip": h["ip"], "from": h["from_ts"], "to": h["to_ts"]}
            for h in self.db.execute(
                "SELECT * FROM ip_history WHERE mac=? ORDER BY from_ts", (mac,)
            ).fetchall()
        ]
        protos = [
            p["protocol"]
            for p in self.db.execute("SELECT protocol FROM protocols WHERE mac=?", (mac,)).fetchall()
        ]
        return {
            "mac": mac, "vendor": row["vendor"], "hostname": row["hostname"],
            "ip_current": row["ip_current"], "ip_history": hist,
            "protocols_seen": protos, "sector": row["sector"], "type": row["type"],
            "last_seen": row["last_seen"], "status": row["status"],
        }
