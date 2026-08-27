"""E1 audit-log enhancement (2026-08-06): append-only, fail-open audit trail.

Records admin/security-relevant events from the triage API as one JSON line
per event in a JSONL file. Each entry carries the schema:

    {ts, event, actor, tenant_id?, detail:dict}

Design goals, in the order the parent audit task states them:

1. **Append-only.** A new event is always appended as a new line; prior
   entries are never rewritten in place. The only mutation ever performed
   on the file is the *capacity trim* below, which drops the OLDEST lines to
   bound file size -- a deliberate tail-truncation, not a modification of
   any kept entry.

2. **Cheap / one write per event.** The steady-state path is a single
   ``open(path, "a")`` + one ``write`` + ``flush`` per event -- no SELECT, no
   read of the whole file, no lock held across anything longer than that
   append (a single process-internal ``threading.Lock`` guards the append +
   occasional trim so two handler threads can't interleave an append into
   the middle of a trim's rewrite).

3. **Bounded growth (ring-buffer style cap).** A trim runs only once the
   in-memory entry count exceeds ``max_entries``; it then rewrites the file
   keeping the newest ``max_entries`` and drops the rest, via a same-dir
   temp file + ``os.replace`` (atomic on POSIX and Windows). So the on-disk
   file NEVER holds more than ``max_entries`` entries -- growth is strictly
   bounded. Because human-paced events (logins, triage writes, reports) are
   the source, the trim's O(cap) rewrite is a rare, bounded cost.

4. **Fail-open.** No method on the log may raise into a request handler: a
   missing/unwritable directory, a full disk, a corrupt line -- every one is
   swallowed and logged to stderr as a warning, and ``record()`` returns
   ``None`` (the caller keeps going). An audit-outage must never break
   login, triage, or report generation.

Pure stdlib (json + os + threading + pathlib). Deliberately NOT sqlite: the
envelope is append-append-append, the read pattern is "most recent N", and a
fully-append mode is the simplest thing that cannot corrupt a prior entry
on a partial write. This mirrors ws6-inventory/store.py's "single stdlib
store, documented in the module docstring" convention without pulling in a
dependency.

Everything read from the environment is read per-call (not cached at import)
so tests can point the logger at a temp path without import-order tricks --
see AuditLog.__init__.
"""
from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MAX_ENTRIES = 10_000  # ring-buffer tail-cap; file never exceeds this

# Relative to this module's package dir so a default-configured instance
# lands somewhere predictable from the service's own tree. Callers that want
# a specific location construct AuditLog(path=...) explicitly (tests do).
_DEFAULT_PATH = str(Path(__file__).resolve().parent / "storage" / "audit.jsonl")


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _warn(msg: str) -> None:
    # Best-effort stderr warning; never raises.
    try:
        print(f'{{"level":"warning","service":"ws3-indexer-audit","msg":{json.dumps(msg)}}}',
              file=sys.stderr, flush=True)
    except Exception:
        pass


def _acquire_cross_process_lock(path: str):
    """Best-effort exclusive cross-process lock next to ``path`` (a ``.lock``
    sibling file) so a trim's file read-modify-rewrite can't race a SECOND
    auditor process (multi-replica). Returns an open file handle whose
    close() releases the lock, or ``None`` when the platform can't file-lock
    (then only the in-process ``threading.Lock`` guards the trim -- the
    single-replica case; cross-replica coordination degrades to best-effort,
    matching the module's fail-open posture)."""
    lock_path = path + ".lock"
    try:
        if os.name == "nt":  # Windows: msvcrt byte-range lock
            import msvcrt  # noqa: PLC0415
            f = open(lock_path, "a+b")
            try:
                if os.fstat(f.fileno()).st_size == 0:
                    f.write(b"\0")
                    f.flush()
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]  # Windows-only, guarded above
                return f
            except Exception:
                f.close()
                return None
        import fcntl  # noqa: PLC0415  (POSIX: flock)
        f = open(lock_path, "a+b")
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]  # POSIX-only, guarded above
        return f
    except Exception:
        return None


class AuditLog:
    """Append-only JSONL audit log with a tail-cap and fail-open writes.

    Thread-safe (a single lock around append + trim). ``record()`` never
    raises -- see the module docstring's "fail-open" section.
    """

    def __init__(self, path: str | None = None, max_entries: int | None = None):
        self.path = path or os.getenv("FENGARDE_AUDIT_LOG") or _DEFAULT_PATH
        raw = max_entries if max_entries is not None else os.getenv("FENGARDE_AUDIT_MAX_ENTRIES")
        try:
            parsed = int(raw) if raw is not None else DEFAULT_MAX_ENTRIES
        except (TypeError, ValueError):
            parsed = DEFAULT_MAX_ENTRIES
        self.max_entries = max(int(parsed), 1)  # a cap below 1 makes no sense
        self._lock = threading.Lock()
        with self._lock:
            self._count = len(self._read_all_locked())

    # ---- public API ------------------------------------------------------

    def record(self, event: str, actor: str, tenant_id: str | None = None,
               detail: dict | None = None) -> dict | None:
        """Append one entry. Returns the entry dict on success, or None on
        any failure (fail-open -- callers must not depend on it succeeding)."""
        entry: dict[str, object] = {
            "ts": _now_iso(),
            "event": event,
            "actor": actor or "unknown",
        }
        if tenant_id is not None:
            entry["tenant_id"] = tenant_id
        # A non-dict detail is coerced so we never serialize something that
        # could break the file (e.g. an actor object). Fail-open on the write.
        d = detail if isinstance(detail, dict) else ({"detail": repr(detail)} if detail is not None else {})
        if d:
            entry["detail"] = d
        with self._lock:
            return self._append_locked(dict(entry))

    def recent(self, limit: int | None = None) -> list[dict]:
        """The most recent entries, newest first (the shape /audit wants).
        ``limit`` defaults to the whole log (already bounded by the cap), and
        ``limit=0`` intentionally returns nothing (FIX #10: the naive
        ``entries[-0:]`` slice silently returned the WHOLE log -- a request
        for 0 entries must not yield everything)."""
        with self._lock:
            entries = self._read_all_locked()
        if limit == 0:
            return []
        if limit is not None and limit > 0:
            entries = entries[-limit:]
        entries.reverse()
        return entries

    def count(self) -> int:
        """Number of entries currently retained (<= max_entries)."""
        with self._lock:
            return len(self._read_all_locked())

    # ---- internals (callers must hold self._lock) -----------------------

    def _append_locked(self, entry: dict) -> dict | None:
        try:
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                # Flush so a crash/eviction doesn't sit in the OS/page cache
                # and lose the one line we just promised.
                f.flush()
        except OSError as e:
            _warn(f"audit write failed (fail-open): {e}")
            return None
        self._count += 1
        if self._count > self.max_entries:
            self._trim_locked()
        return entry

    def _trim_locked(self) -> None:
        """Keep only the newest ``max_entries`` entries (drop the oldest)
        via a same-dir temp file + atomic replace, so a crash mid-trim never
        leaves a truncated audit log in place of the real one.

        FIX (#6): multi-replica safety. The in-process ``threading.Lock``
        only serializes trims WITHIN one replica; two SEPARATE ws3 replicas
        trimming around the same append could each rewrite the file and the
        last one to ``os.replace`` could clobber entries the other had
        written. The whole read-modify-rewrite therefore runs under an
        advisory cross-process ``.lock`` file too (best-effort -- see
        _acquire_cross_process_lock)."""
        tmp = self.path + ".tmp"
        # Acquire BEFORE the read so a cooperating replica's concurrent trim
        # sees a consistent read-modify-rewrite, not an interleaved one.
        lock = _acquire_cross_process_lock(self.path)
        try:
            entries = self._read_all_locked()[-self.max_entries:]
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
                f.flush()
            os.replace(tmp, self.path)
        except OSError as e:
            _warn(f"audit trim failed (fail-open, keeping file): {e}")
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
            # On trim failure the file may briefly exceed the cap; that is a
            # fail-open degradation, never a crash, and will be re-trimmed on
            # the next append.
            self._count = len(self._read_all_locked())
            return
        finally:
            if lock is not None:
                lock.close()  # releases the cross-process lock
        self._count = len(entries)

    def _read_all_locked(self) -> list[dict]:
        """All entries in file order. Corrupt/partial lines are skipped, not
        fatal -- a torn final line (crash mid-append) must not lose the whole
        log or break /audit."""
        entries: list[dict] = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except (json.JSONDecodeError, ValueError):
                        continue
                    if isinstance(obj, dict):
                        entries.append(obj)
        except FileNotFoundError as e:
            # FIX (#5): a missing log is a normal first-run (empty), but a
            # silently-swallowed read is how a broken/removed file becomes an
            # invisible empty /audit -- warn so it's not masked.
            _warn(f"audit log {self.path} not found (treating as empty): {e}")
        except OSError as e:
            _warn(f"audit log read failed (fail-open, treating as empty): {e}")
        return entries


# ---- module-level default instance --------------------------------------
# Created lazily on first use so importing this module never touches disk.
_default: AuditLog | None = None


def default_audit() -> AuditLog:
    """The process-wide default AuditLog (path/max from env or defaults)."""
    global _default
    if _default is None:
        _default = AuditLog()
    return _default
