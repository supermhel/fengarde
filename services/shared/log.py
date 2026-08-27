"""Structured JSON logging (G-06 / T1).

One-line JSON logs: ``{ts, level, service, trace_id, msg, ...}``. A ``trace_id``
context variable lets a single event be followed across services (set it from a
bus message's id/ingest_id at the top of a handler). Replaces bare ``print()`` in
long-running service code so logs are machine-parseable and greppable.

    from shared.log import get_logger, set_trace_id
    log = get_logger("ws4-detection")
    set_trace_id(msg.id)
    log.info("scored event", score=70, rule="brute-force")
"""
from __future__ import annotations

import contextvars
import json
import os
import sys
import time

_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="-")

# P2-3 (2026-07-21 audit): every record was JSON-dumped + stdout-flushed
# unconditionally, so a service pinned to "warn"/"error" in production still
# paid the full serialize+syscall cost on every log.info() call in its hot
# path. FENGARDE_LOG_LEVEL (default "info", matching prior always-on
# behavior) gates _emit() before any of that work happens.
_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}

# R3-#67 (2026-08-27): these own the record identity -- a caller field
# named like one used to clobber it via rec.update(), corrupting the line.
_RESERVED_FIELDS = frozenset({"ts", "level", "service", "trace_id", "msg"})


def _min_level() -> int:
    name = os.environ.get("FENGARDE_LOG_LEVEL", "info").lower()
    return _LEVELS.get(name, _LEVELS["info"])


def set_trace_id(tid: str | None) -> None:
    _trace_id.set(tid or "-")


class Logger:
    def __init__(self, service: str):
        self.service = service

    def _emit(self, level: str, msg: str, **fields) -> None:
        self._emit_impl(level, msg, force=False, **fields)

    def _emit_impl(self, level: str, msg: str, force: bool, **fields) -> None:
        if not force and _LEVELS.get(level, 0) < _min_level():
            return
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level,
            "service": self.service,
            "trace_id": _trace_id.get(),
            "msg": msg,
        }
        if fields:
            for k, v in fields.items():
                if k in _RESERVED_FIELDS:
                    # R3-#67 (2026-08-27): a field that collides with a
                    # reserved identity key is DROPPED -- the identity wins,
                    # so the JSON line stays well-formed.
                    continue
                rec[k] = v
        # ensure_ascii=False keeps non-ASCII readable; default=str avoids crashes
        # on unusual field types. One JSON object per line.
        sys.stdout.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        sys.stdout.flush()

    def debug(self, msg: str, **fields) -> None:
        self._emit("debug", msg, **fields)

    def info(self, msg: str, **fields) -> None:
        self._emit("info", msg, **fields)

    def warn(self, msg: str, **fields) -> None:
        self._emit("warn", msg, **fields)

    def error(self, msg: str, **fields) -> None:
        self._emit("error", msg, **fields)

    def always(self, msg: str, **fields) -> None:
        """Un-gated warn (R3-#66, 2026-08-27): emitted regardless of
        FENGARDE_LOG_LEVEL. Reserved for operator-facing warnings that must
        never be silently dropped by the level gate -- a security control
        disabling itself, an allowlist failing closed, a config
        misconfiguration. Prefer it only where a silenced signal is worse
        than a small amount of log noise."""
        self._emit_impl("warn", msg, force=True, **fields)


def get_logger(service: str) -> Logger:
    return Logger(service)
