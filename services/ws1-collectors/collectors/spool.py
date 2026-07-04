"""B2 fallback: a bounded on-disk spool for true zero-loss-under-flood.

The default B2 answer (docs/superpowers/specs/2026-07-02-argus-v0.3-improvement-
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
from pathlib import Path
from typing import Callable, Optional

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

    def __init__(self, path: Path | str, max_bytes: int = DEFAULT_MAX_BYTES):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, event: dict) -> bool:
        """Append one event. Returns False (event NOT spooled, truly lost) if
        the spool is at capacity OR the write itself fails (disk full,
        permission error, etc.) -- both are "this event didn't make it into
        the spool" to the caller, so neither ever raises out of append()."""
        line = json.dumps(event, ensure_ascii=False) + "\n"
        encoded = line.encode("utf-8")
        with self._lock:
            try:
                current = self.path.stat().st_size
            except OSError:
                current = 0
            if current + len(encoded) > self.max_bytes:
                return False
            try:
                with self.path.open("ab") as f:
                    f.write(encoded)
            except OSError:
                return False
            return True

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
        """
        with self._lock:
            try:
                lines = self.path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return 0
            if not lines:
                return 0

            replayed = 0
            remaining = list(lines)
            for line in lines:
                if limit is not None and replayed >= limit:
                    break
                if not line.strip():
                    remaining = remaining[1:]
                    continue
                try:
                    event = json.loads(line)
                except (ValueError, TypeError):
                    # corrupt line (e.g. a torn write from a crash mid-append)
                    # -- drop just this one line, don't block the rest of the
                    # spool behind unparseable data forever.
                    remaining = remaining[1:]
                    continue
                try:
                    produce(event)
                except Exception:
                    break  # bus still unavailable / still over capacity; stop here
                replayed += 1
                remaining = remaining[1:]

            if replayed or (len(remaining) != len(lines)):
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
