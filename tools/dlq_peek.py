#!/usr/bin/env python3
"""Dead-letter queue inspector (P1.2).

The pipeline routes un-processable messages to ``<topic>.deadletter`` streams
(a poison message after max_redeliveries, or a parse/validate failure in WS-2).
Before v0.4 nothing ever looked at them -- they were a black hole. This tool
makes the DLQ visible and, opt-in, drainable.

Usage (needs Redis; this is an operational tool, not part of the zero-infra gate):

    python tools/dlq_peek.py                 # list every *.deadletter stream + counts
    python tools/dlq_peek.py --show 5        # + up to 5 recent sample entries each
    python tools/dlq_peek.py --json          # machine-readable summary
    python tools/dlq_peek.py --requeue raw.events.deadletter
                                             # re-produce entries back to raw.events
                                             # and trim the DLQ (asks first)

Requeue is deliberately explicit and per-stream: fixing the root cause first,
then replaying, is the intended flow. The base topic is the DLQ name minus the
``.deadletter`` suffix.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

_SUFFIX = ".deadletter"


def _connect(url: str):
    try:
        import redis  # type: ignore
    except ImportError:
        sys.exit("redis-py not installed; this tool needs it (pip install redis).")
    try:
        r = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=3)
        r.ping()
        return r
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"cannot reach Redis at {url}: {exc}")


def _dlq_streams(r) -> list[str]:
    """Every stream key ending in .deadletter (SCAN, so it's safe on a big db)."""
    out = []
    for key in r.scan_iter(match=f"*{_SUFFIX}", count=100):
        try:
            if r.type(key) == "stream":
                out.append(key)
        except Exception:  # noqa: BLE001
            continue
    return sorted(out)


def _summary(r, show: int) -> list[dict]:
    rows = []
    for stream in _dlq_streams(r):
        count = int(r.xlen(stream))
        samples = []
        if show > 0 and count:
            for _id, fields in r.xrevrange(stream, count=show):
                # entries carry {payload/errors/...}; keep it short
                samples.append({k: (v[:200] if isinstance(v, str) else v)
                                for k, v in fields.items()})
        rows.append({"stream": stream, "count": count, "samples": samples})
    return rows


def _requeue(r, dlq: str) -> None:
    if not dlq.endswith(_SUFFIX):
        sys.exit(f"'{dlq}' is not a *.deadletter stream")
    base = dlq[: -len(_SUFFIX)]
    n = int(r.xlen(dlq))
    if not n:
        print(f"{dlq} is empty; nothing to requeue.")
        return
    reply = input(f"Re-produce {n} entries from {dlq} back to {base} and trim the "
                  f"DLQ? [y/N] ").strip().lower()
    if reply != "y":
        print("aborted.")
        return
    moved = 0
    for _id, fields in r.xrange(dlq):
        # The DLQ entry wraps the original payload under 'payload' (runner) or
        # is the WS-2 dead-letter shape; re-produce the raw fields as-is.
        r.xadd(base, fields)
        r.xdel(dlq, _id)
        moved += 1
    print(f"requeued {moved} entrie(s) to {base}.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Inspect/drain the pipeline's dead-letter queues.")
    ap.add_argument("--url", default=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    ap.add_argument("--show", type=int, default=0, metavar="N",
                    help="show up to N recent sample entries per stream")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--requeue", metavar="DLQ_STREAM",
                    help="re-produce a <topic>.deadletter stream back to <topic>")
    args = ap.parse_args()

    r = _connect(args.url)

    if args.requeue:
        _requeue(r, args.requeue)
        return

    rows = _summary(r, args.show)
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    if not rows:
        print("No dead-letter streams. Clean.")
        return
    total = sum(row["count"] for row in rows)
    print(f"Dead-letter streams ({total} message(s) total):\n")
    for row in rows:
        print(f"  {row['stream']}: {row['count']}")
        for s in row["samples"]:
            print(f"      - {json.dumps(s)[:200]}")
    print("\nRoot-cause the failures, then replay with --requeue <stream>.")


if __name__ == "__main__":
    main()
