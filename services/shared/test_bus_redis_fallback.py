"""Code-quality #1 (2026-07-29 audit): Bus()'s redis-setup exception handling.

`Bus()` used to catch bare `Exception` around `_RedisBus(...)` construction
and silently fall back to `_MemoryBus()` with no log line -- so a service
that asked for `BUS_BACKEND=redis` (every topic, every workstream) could be
silently isolated from the rest of the pipeline by ANY constructor failure,
not just the documented "redis-py isn't installed" case. Fixed to catch only
`ImportError` (logged) and let everything else propagate.

No live Redis required: the ImportError path is forced via a `sys.modules`
poison (the standard way to make `import redis` fail deterministically), and
the "must propagate" path is forced via a config value that can't parse,
never an actual network call (`redis.Redis.from_url` doesn't connect eagerly).

Run: python services/shared/test_bus_redis_fallback.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(SERVICES))

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _reload_bus():
    """Fresh import of shared.bus so module-level state (if any) doesn't
    leak between the differently-patched scenarios below."""
    sys.modules.pop("shared.bus", None)
    import shared.bus as bus_mod
    return bus_mod


def test_import_error_falls_back_to_memory_bus():
    """The documented case: redis-py not installed -> silent, logged fallback."""
    old_backend = os.environ.get("BUS_BACKEND")
    old_redis_mod = sys.modules.get("redis")
    os.environ["BUS_BACKEND"] = "redis"
    sys.modules["redis"] = None  # poison: forces `import redis` to raise ImportError
    try:
        bus_mod = _reload_bus()
        bus = bus_mod.Bus()
        check(type(bus).__name__ == "_MemoryBus",
              f"ImportError must fall back to _MemoryBus, got {type(bus).__name__}")
    finally:
        if old_redis_mod is not None:
            sys.modules["redis"] = old_redis_mod
        else:
            sys.modules.pop("redis", None)
        if old_backend is None:
            os.environ.pop("BUS_BACKEND", None)
        else:
            os.environ["BUS_BACKEND"] = old_backend
        _reload_bus()


def test_non_import_error_propagates_not_swallowed():
    """A non-ImportError constructor failure (e.g. a malformed tunable) must
    NOT be silently downgraded to an isolated in-memory bus -- that used to
    happen with zero operator visibility. It must raise, so a broken config
    crashes loudly at startup instead of quietly losing every message."""
    old_backend = os.environ.get("BUS_BACKEND")
    old_count = os.environ.get("BUS_XREADGROUP_COUNT")
    os.environ["BUS_BACKEND"] = "redis"
    os.environ["BUS_XREADGROUP_COUNT"] = "not-a-number"  # int() raises ValueError
    try:
        bus_mod = _reload_bus()
        try:
            bus_mod.Bus()
            check(False, "a non-ImportError constructor failure must propagate, "
                         "not silently return a _MemoryBus")
        except ImportError:
            check(False, "unexpected ImportError -- test setup didn't force the "
                         "intended ValueError path")
        except ValueError:
            pass  # expected: the malformed BUS_XREADGROUP_COUNT propagates
    finally:
        if old_count is None:
            os.environ.pop("BUS_XREADGROUP_COUNT", None)
        else:
            os.environ["BUS_XREADGROUP_COUNT"] = old_count
        if old_backend is None:
            os.environ.pop("BUS_BACKEND", None)
        else:
            os.environ["BUS_BACKEND"] = old_backend
        _reload_bus()


def main():
    test_import_error_falls_back_to_memory_bus()
    test_non_import_error_propagates_not_swallowed()
    if FAILS:
        print(f"[FAIL] bus redis-fallback narrowing: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] Bus() redis-setup exception handling: ImportError falls back + logs, "
          "anything else propagates")


if __name__ == "__main__":
    main()
