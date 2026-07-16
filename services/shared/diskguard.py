"""M4.6 ops lifecycle: a real, stdlib-only disk-headroom guardrail.

``shutil.disk_usage()`` against a real filesystem path -- no live
infrastructure needed to test (a temp directory has a real, measurable
filesystem). Intended for local, disk-backed features that need to refuse
to grow further once the underlying VOLUME is critically low on free
space, independent of any self-imposed byte cap that feature might already
have -- a generous ``BoundedSpool(max_bytes=...)`` still shares its disk
with the OpenSearch data directory, other services' logs, etc.

Currently wired into ``services/ws1-collectors/collectors/spool.py``'s
``BoundedSpool.append()``; any other local writer can reuse
:func:`check_disk_headroom` the same way.
"""
from __future__ import annotations

import shutil
from pathlib import Path

DEFAULT_MIN_FREE_BYTES = 512 * 1024 * 1024  # 512 MiB
DEFAULT_MIN_FREE_PCT = 5.0                  # 5%


def check_disk_headroom(path, *, min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
                         min_free_pct: float = DEFAULT_MIN_FREE_PCT) -> tuple[bool, dict]:
    """Return ``(ok, detail)`` for the volume containing ``path``.

    ``ok`` is False if free space is below EITHER the absolute or the
    percentage floor -- an absolute floor alone is wrong for a huge volume
    (512MiB free on a 10TB disk is still fine), and a percentage floor
    alone is wrong for a tiny volume (5% of a 1GiB disk is only ~50MiB, too
    tight). Both must pass for ``ok`` to be True.

    ``path`` need not exist yet: this walks up to the nearest existing
    ancestor directory, matching how a caller about to CREATE a file there
    would want the check evaluated.

    Never raises: an unreadable/nonexistent volume reports ``ok=False``
    with the reason in ``detail``, rather than propagating an ``OSError``
    into a caller (like the spool) that must stay fail-closed on a disk
    problem, not crash the process over it.
    """
    p = Path(path)
    while not p.exists():
        parent = p.parent
        if parent == p:  # reached the filesystem root without finding anything real
            break
        p = parent
    try:
        usage = shutil.disk_usage(p)
    except OSError as exc:
        return False, {"reason": "disk_usage failed", "error": str(exc), "path": str(p)}
    free_pct = (usage.free / usage.total * 100.0) if usage.total else 0.0
    ok = usage.free >= min_free_bytes and free_pct >= min_free_pct
    return ok, {
        "path": str(p), "total_bytes": usage.total, "free_bytes": usage.free,
        "free_pct": round(free_pct, 2),
        "min_free_bytes": min_free_bytes, "min_free_pct": min_free_pct,
    }
