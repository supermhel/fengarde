"""B2 fallback: a bounded on-disk spool for true zero-loss-under-flood.

The default B2 answer (docs/superpowers/specs/2026-07-02-fengarde-v0.3-improvement-
plan.md, and CHANGELOG's "v0.3 B2") is shed-at-the-edge: a token bucket drops
excess datagrams before they ever reach the bus, protecting Redis from an
unbounded flood at the cost of losing the shed events. That's the right
default for most deployments (a dropped log during an actual DDoS is an
acceptable trade against an OOM'd SIEM), but it is NOT zero-loss.

If a deployment needs zero-loss-under-flood (e.g. a bank's audit-completeness
requirement extends to burst traffic, not just steady state), this module is
the opt-in second tier: instead of dropping a shed event, write it to a
bounded local file (FIFO, capped total bytes) and replay it into the bus once
capacity returns. This is still not INFINITE-loss-under-flood -- a spool has
a hard byte cap, so a flood that outlasts the cap still loses events past
that point -- but the loss boundary becomes an explicit, configurable,
observable number instead of "everything above the rate limit, forever."

Disabled by default (no behavior change unless SYSLOG_SPOOL_PATH is set).
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from shared.diskguard import (
    check_disk_headroom, DEFAULT_MIN_FREE_BYTES, DEFAULT_MIN_FREE_PCT,
)

DEFAULT_MAX_BYTES = 64 * 1024 * 1024  # 64 MiB


class BoundedSpool:
    """A FIFO, byte-capped, disk-backed queue of JSON-serializable dicts.

    One JSON object per line (JSONL). `append()` refuses once the file would
    exceed `max_bytes` -- the event is then truly lost (the caller counts
    this distinctly from a spooled event so operators can see the boundary
    being hit). `drain_into()` replays entries in FIFO order via a caller-
    supplied produce function, stopping at the first failure to preserve
    order (a later entry succeeding while an earlier one is still stuck would
    silently reorder events on replay).

    Single-process only (a `threading.Lock`, not a file lock) -- matches
    SyslogUDPServer's single-process deployment model.
    """

    def __init__(self, path: Path | str, max_bytes: int = DEFAULT_MAX_BYTES, *,
                 min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
                 min_free_pct: float = DEFAULT_MIN_FREE_PCT,
                 logger=None):
        self.path = Path(path)
        self.max_bytes = max_bytes
        # M4.6: a guardrail on the VOLUME's free space, independent of
        # max_bytes -- a generous per-spool byte cap still shares its disk
        # with the OpenSearch data dir, service logs, etc. See
        # shared/diskguard.py for why both an absolute and a percentage
        # floor are checked.
        self.min_free_bytes = min_free_bytes
        self.min_free_pct = min_free_pct
        # Gap-hunt (2026-08-26) #74/#75: the spool used to be silent about
        # every loss class -- corrupt lines skipped with a bare `continue`,
        # and the three append-refusal reasons (byte cap, disk-headroom
        # refusal, write OSError) collapsing into one undocumented False.
        # Optional logger (same pattern as TenantTokenBuckets) + counters
        # make the loss boundary observable; None keeps tests/embedded use
        # silent.
        self._log = logger
        self.corrupt_lines_skipped = 0
        self._last_refusal_log: "dict[str, float]" = {}
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_dir():
            # Live-Docker-caught (2026-08-21, ingestion-edge-redundancy step
            # 1): pointing SYSLOG_SPOOL_PATH at a directory (e.g. a named
            # volume's mount point itself, an easy mistake -- "give me a
            # spool location" reads as "give me a directory") used to be
            # silently accepted here, then every append()/drain_into() call
            # hit IsADirectoryError, caught by their own broad
            # `except OSError`, and no-op'd forever with zero error and zero
            # log -- a completely inert spool that LOOKED enabled ("syslog
            # zero-loss spool enabled" logged at startup) while losing every
            # event exactly as if it had never been turned on. Fail loud at
            # construction instead, same posture as RedisSessionStore
            # refusing to start without a signing secret -- a misconfigured
            # zero-loss feature must not silently degrade to zero-loss's
            # opposite.
            raise IsADirectoryError(
                f"SYSLOG_SPOOL_PATH must be a FILE path, not a directory: "
                f"{self.path} is a directory. Point it at a file inside your "
                f"mounted volume, e.g. {self.path}/spool.jsonl")
        if not self.path.exists():
            self.path.touch()
        # Determine the tail's well-formedness ONCE (a crash mid-append from a
        # PRIOR process may have left a partial, non-newline-terminated record).
        # After this process's first append or rewrite the file is guaranteed
        # newline-terminated, so _tail_known_good stays True and the O(1)
        # append path never re-reads the tail (the O(n) regression a naive
        # per-append guard would introduce).
        self._tail_known_good = self._check_tail_newline()

    def _check_tail_newline(self) -> bool:
        """True if the spool file is empty or its last byte is a newline."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return True
        if size == 0:
            return True
        try:
            with self.path.open("rb") as f:
                f.seek(-1, 2)
                return f.read(1) == b"\n"
        except OSError:
            return True  # best-effort; a failure to read degrades to "safe"

    def append(self, event: dict) -> bool:
        """Append one event. Returns False (event NOT spooled, truly lost) if
        the spool is at capacity, the underlying VOLUME is critically low on
        free space, OR the write itself fails (disk full, permission error,
        etc.) -- all three are "this event didn't make it into the spool" to
        the caller, so none of them ever raise out of append().

        Gap-hunt (2026-08-26) #73: the three refusal classes are now logged
        distinctly (throttled) via the optional logger instead of collapsing
        into one silent False, so an operator raising the byte cap can see
        when the real cause was a permissions/mount error. The same fix keeps
        the file well-formed under a torn tail: if the last byte on disk is
        not ``\\n`` (a crash mid-append left a partial record), the new record
        is written on a line of its OWN (a terminator ``\\n`` first) instead of
        being concatenated onto the partial record -- a concatenation would
        silently corrupt the new *and* the old record into one unparseable
        line.
        """
        line = json.dumps(event, ensure_ascii=False) + "\n"
        encoded = line.encode("utf-8")
        with self._lock:
            disk_ok, _detail = check_disk_headroom(
                self.path.parent, min_free_bytes=self.min_free_bytes, min_free_pct=self.min_free_pct)
            if not disk_ok:
                self._log_refusal("disk", min_free_bytes=self.min_free_bytes,
                                  detail=str(_detail))
                return False
            try:
                current = self.path.stat().st_size
            except OSError:
                current = 0
            # Torn-tail guard: only a non-empty file that does not end in a
            # newline needs a terminator byte prepended. The tail state was
            # checked ONCE at construction; every write this process performs
            # is newline-terminated, so after the first successful append the
            # flag is True and this read is skipped entirely (perf: the
            # 20k-append spool-drain test stays near-linear).
            prefix = b""
            if not self._tail_known_good and current > 0:
                try:
                    with self.path.open("rb") as f:
                        f.seek(-1, 2)
                        prefix = b"\n" if f.read(1) != b"\n" else b""
                except OSError:
                    prefix = b""
            if current + len(prefix) + len(encoded) > self.max_bytes:
                self._log_refusal("cap", max_bytes=self.max_bytes,
                                  size=current + len(prefix) + len(encoded))
                return False
            try:
                with self.path.open("ab") as f:
                    if prefix:
                        f.write(prefix)
                    f.write(encoded)
            except OSError as exc:
                self._log_refusal("write", error=str(exc), path=str(self.path))
                return False
            self._tail_known_good = True
            return True

    def _log_refusal(self, reason: str, **fields) -> None:
        """Throttled (1/sec per reason) structured warning for an append()
        refusal, keeping the three loss classes (disk-headroom, byte-cap,
        write-OSError) distinguishable in logs -- but NOT turning a flood
        into a log flood (same posture as the server's shed throttle)."""
        if self._log is None:
            return
        now = time.monotonic()
        if now - self._last_refusal_log.get(reason, 0.0) < 1.0:
            return
        self._last_refusal_log[reason] = now
        self._log.warn("spool append refused", reason=reason, **fields)

    def pending_count(self) -> int:
        with self._lock:
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    return sum(1 for _ in f)
            except OSError:
                return 0

    def pending_bytes(self) -> int:
        with self._lock:
            try:
                return self.path.stat().st_size
            except OSError:
                return 0

    def drain_into(self, produce: Callable[[dict], None], *, limit: Optional[int] = None) -> int:
        """Replay spooled events in FIFO order via `produce(event) -> None`
        (raises on failure). Stops at the first failure (order-preserving) and
        rewrites the spool file to contain only the un-replayed remainder --
        so a crash between drain and rewrite re-replays at most the batch
        already in flight, never silently drops it. Returns count replayed.

        P1-6 (2026-07-21 audit): two fixes to the flood-recovery path itself:

        1. **O(n) instead of O(n^2).** The old version did
           ``remaining = remaining[1:]`` once per line -- a full list
           reallocation per iteration, O(n) work times n lines. Every line in
           ``lines`` is visited in order exactly once and either "consumed"
           (blank/corrupt/produced) or left as the stopping point, so the
           final remainder is always a single contiguous slice of the
           original list -- computed once via one index, not incrementally.
        2. **`produce()` (network I/O -- `bus.produce`, a Redis round-trip)
           no longer runs under ``self._lock``.** The lock used to be held
           for the entire drain, so ``SyslogUDPServer._try_spool()`` (called
           from every UDP handler while the rate limit is active) blocked on
           it for as long as the whole batch took -- stalling live datagram
           handling, i.e. re-creating kernel-level drops (P0-4) via a
           different path. The file is snapshotted under the lock, produced
           against OUTSIDE it, then the lock is re-acquired only to compute
           and write the final remainder. Concurrent `append()`s during that
           window are never lost: since this is the only method that ever
           rewrites the file (append() only appends) and only one
           drain thread exists (single-process spool-drain loop), the
           snapshot's line count `n` is guaranteed to be a stable prefix of
           the file when the lock is re-acquired -- any new content is simply
           `current_lines[n:]`, appended after our replayed/remaining split.
        """
        with self._lock:
            try:
                lines = self.path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return 0
            if not lines:
                return 0
        n = len(lines)

        replayed = 0
        i = 0
        while i < n:
            if limit is not None and replayed >= limit:
                break
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                # corrupt line (e.g. a torn write from a crash mid-append)
                # -- drop just this one line, don't block the rest of the
                # spool behind unparseable data forever.
                i += 1
                continue
            try:
                produce(event)  # network I/O -- deliberately outside the lock
            except Exception:
                break  # bus still unavailable / still over capacity; stop here
            replayed += 1
            i += 1

        with self._lock:
            try:
                current_lines = self.path.read_text(encoding="utf-8").splitlines()
            except OSError:
                current_lines = lines  # best-effort: fall back to our snapshot
            newly_appended = current_lines[n:]  # anything appended since our read
            remaining = lines[i:] + newly_appended
            if replayed or remaining != current_lines:
                self._rewrite(remaining)
        return replayed

    def _rewrite(self, lines: list[str]) -> None:
        """Atomically replace the spool file's contents (temp file + os.replace)
        so a crash mid-rewrite never leaves a truncated/corrupt spool."""
        fd, tmp_path = tempfile.mkstemp(dir=str(self.path.parent), prefix=".spool-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for line in lines:
                    f.write(line + "\n")
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        # Rewritten output is newline-terminated by construction.
        self._tail_known_good = True
