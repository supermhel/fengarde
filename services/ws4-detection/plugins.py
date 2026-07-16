"""M4.5: entry-points-based rule-pack plugin discovery.

An external pip package can ship additional detection rules WITHOUT forking
this repo by registering a ``fengarde.rule_packs`` entry point that resolves
to a directory of rule YAML files (same shape as ``contracts/rules/*.yml``):

    # the plugin package's pyproject.toml
    [project.entry-points."fengarde.rule_packs"]
    my_rules = "my_fengarde_plugin.rules:rules_dir"

where ``rules_dir`` is a zero-argument callable returning a ``Path`` (a
plain string/Path value also works -- see :func:`discover_rule_pack_dirs`).
See docs/plugin-development.md for a full worked example and
``services/ws4-detection/test_fixtures/`` for the example this module's own
tests exercise via real ``importlib.metadata`` ``EntryPoint`` objects.

**Security note (SECURITY.md SS3):** rule files are executed by this engine
-- loading a third-party package's rules means trusting its ``condition``
strings exactly as much as you'd trust code from that package. This module
only DISCOVERS what's installed; nothing here downloads or auto-installs a
plugin, that's ``pip install``, an operator's own action. A plugin rule
whose ``id`` collides with an already-loaded rule (built-in or an
earlier-discovered plugin) is skipped -- whichever loaded first wins, so a
plugin can extend detection but never silently REPLACE an existing rule's
condition.
"""
from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

_GROUP = "fengarde.rule_packs"


def discover_rule_pack_dirs(eps: list[EntryPoint] | None = None) -> list[tuple[str, Path]]:
    """Return ``(plugin_name, rules_dir)`` for every installed, loadable
    ``fengarde.rule_packs`` entry point whose target resolves to an existing
    directory. ``eps`` defaults to the real installed entry points; tests
    pass a hand-built list of real ``EntryPoint`` objects (see
    ``services/ws2-normalization/parsers/plugins.py``'s docstring for why
    that's still a genuine ``.load()`` exercise, not a mock).

    A plugin whose entry point fails to import, or whose target isn't a
    real directory, is skipped individually -- never prevents detection
    from starting."""
    if eps is None:
        try:
            eps = list(entry_points(group=_GROUP))
        except Exception:
            eps = []
    found: list[tuple[str, Path]] = []
    for ep in eps:
        try:
            target = ep.load()
            value = target() if callable(target) else target
            path = Path(value)
        except Exception:
            continue
        if path.is_dir():
            found.append((ep.name, path))
    return found
