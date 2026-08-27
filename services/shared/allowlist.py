"""CIDR/exact-match allowlists (A3), shared across workstreams.

Moved here 2026-08-18 from ``services/ws4-detection/engine.py`` (where it
originated) so WS-8 correlation can reuse it for its shared-infrastructure
IP allowlist without a cross-workstream source import (the same "promote to
shared/ instead of cross-importing" move already applied to
``services/shared/window.py`` and, earlier, ``services/{ws6-inventory =>
shared}/mfa.py``). WS-4's `not_in` rule operator (`engine.py`) is the
original and still-primary caller; behavior is byte-identical, this is a
pure relocation.

Loaded once per caller-defined "load pass" and shared via a module-level
cache keyed by directory+name, so repeated lookups of the same allowlist
don't re-read/re-parse the file. A missing/malformed allowlist makes the
ALLOWLIST ITSELF fail closed (``Allowlist.matches()`` always returns
``False`` -- it can never suppress/match anything), which is what makes a
caller's own use of it fail OPEN in whatever direction that caller's logic
runs (WS-4's `not_in` selection keeps matching/firing; WS-8's `ip:` track
gate opens tracks for everyone, same as an intentionally-empty allowlist).
A warning is printed once per load pass so the misconfiguration is visible.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from shared.log import get_logger

_log = get_logger("shared.allowlist")

_ALLOWLIST_CACHE: dict[str, "Allowlist"] = {}


class Allowlist:
    """A loaded allowlist: exact-match strings plus optional CIDR ranges.

    `ok` is False when the file was missing/malformed; matches() then always
    returns False -- the ALLOWLIST fails closed (never suppresses/matches)
    instead of raising. See the module docstring for what that means for
    each caller's own fail-open/fail-closed posture.
    """

    def __init__(self, entries: list, ok: bool = True):
        self.ok = ok
        self.exact: set[str] = set()
        self.nets: list = []
        for entry in entries or []:
            if not isinstance(entry, str):
                continue
            self.exact.add(entry)
            try:
                self.nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass  # not CIDR-shaped; exact-match only

    def matches(self, value) -> bool:
        if not self.ok:
            return False
        if value is None:
            return False
        s = str(value)
        if s in self.exact:
            return True
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return False
        for net in self.nets:
            try:
                if addr in net:
                    return True
            except TypeError:
                continue  # mismatched IP version (v4 addr vs v6 net etc.)
        return False


def load_allowlist(allowlists_dir: Path, name: str) -> Allowlist:
    """Load (and cache) an allowlist by name from <allowlists_dir>/<name>.yml."""
    cache_key = f"{Path(allowlists_dir).resolve()}::{name}"
    if cache_key in _ALLOWLIST_CACHE:
        return _ALLOWLIST_CACHE[cache_key]

    path = Path(allowlists_dir) / f"{name}.yml"
    allowlist: Allowlist
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = raw.get("entries") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            raise ValueError("allowlist file missing a list 'entries:' key")
        allowlist = Allowlist(entries, ok=True)
    except Exception as exc:  # missing file, bad YAML, bad shape -> fails closed (see docstring)
        # R3-#66 (2026-08-27): `.always` (un-gated) rather than `.warn` -- the
        # level gate above would otherwise drop this at
        # FENGARDE_LOG_LEVEL=error, and an operator running error-only logs
        # would get zero signal that an allowlist was silently failing closed.
        _log.always(
            f"allowlist '{name}' failed to load ({exc}); it will never "
            f"match/suppress anything until fixed (fails closed)."
        )
        allowlist = Allowlist([], ok=False)

    _ALLOWLIST_CACHE[cache_key] = allowlist
    return allowlist


def invalidate_dir(allowlists_dir: Path) -> None:
    """Drop every cached allowlist loaded from ``allowlists_dir``.

    A caller that re-loads allowlists from the same directory on each pass
    (WS-4's ``load_rules``, called by the rule hot-reload watcher) needs this
    so a broken allowlist (``ok=False``, cached) doesn't stay cached forever
    after an operator fixes the file on disk -- without it, a `not_in`
    suppression the operator just repaired would silently stay disabled
    (fail-open noise) instead of resuming."""
    resolved_str = str(Path(allowlists_dir).resolve())
    for key in [k for k in _ALLOWLIST_CACHE if k.startswith(resolved_str + "::")]:
        del _ALLOWLIST_CACHE[key]
