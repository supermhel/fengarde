"""M4.5: entry-points-based parser plugin discovery.

An external pip package can ship an additional WS-2 parser WITHOUT forking
this repo by registering a ``fengarde.parsers`` entry point whose value is a
``Parser`` subclass:

    # the plugin package's pyproject.toml
    [project.entry-points."fengarde.parsers"]
    my_source = "my_fengarde_plugin.parser:MySourceParser"

See docs/plugin-development.md for a full worked example (parser + rule
pack) and ``services/ws2-normalization/parsers/test_fixtures/`` for the
example this module's own tests exercise via real ``importlib.metadata``
``EntryPoint`` objects (genuinely calling ``.load()`` -- real import +
getattr, not a mocked stand-in for it).

A plugin parser is purely ADDITIVE: if its ``SOURCE_TYPE`` collides with a
built-in parser's (or another plugin's, entry points are unordered), it is
skipped and whichever registered first wins -- an external package must
never be able to silently change how this repo parses a source it already
ships a parser for.
"""
from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points

from .base import Parser

_GROUP = "fengarde.parsers"


def discover_plugin_parsers(existing_source_types,
                             eps: list[EntryPoint] | None = None) -> dict[str, Parser]:
    """Return ``{SOURCE_TYPE: instance}`` for every installed, loadable
    ``fengarde.parsers`` entry point whose target is a real ``Parser``
    subclass and whose ``SOURCE_TYPE`` isn't already taken.

    ``eps`` defaults to the real, installed entry points
    (``importlib.metadata.entry_points(group=...)``); tests pass a hand-built
    list of real ``EntryPoint`` objects pointing at fixture modules instead
    of requiring an actual ``pip install`` of a throwaway package -- ``.load()``
    still does a genuine ``importlib.import_module`` + ``getattr`` either way.

    A plugin that fails to import, isn't a ``Parser`` subclass, or collides
    on ``SOURCE_TYPE`` is skipped individually: one broken/malicious plugin
    package must never prevent normalization from starting at all, matching
    this repo's fail-open-on-a-single-bad-config posture everywhere else
    (``contracts/tenants``, ``contracts/allowlists``).

    A load/import failure or a wrong-type target is LOGGED (gap-hunt
    finding, 2026-08-23: this used to swallow both with a bare ``except:
    continue`` and no log line at all -- completely indistinguishable from
    "no plugin installed," unlike ws4-detection/plugins.py's sibling
    ``discover_rule_pack_dirs``, which already logged the equivalent case.
    docs/plugin-development.md never disclosed the asymmetry either). A
    ``SOURCE_TYPE`` collision stays a silent skip -- that's an installed,
    WORKING plugin correctly deferring to a built-in/earlier plugin, not a
    broken one; nothing here needs an operator's attention."""
    if eps is None:
        try:
            eps = list(entry_points(group=_GROUP))
        except Exception:
            eps = []
    found: dict[str, Parser] = {}
    for ep in eps:
        try:
            cls = ep.load()
            if not (isinstance(cls, type) and issubclass(cls, Parser)):
                from shared.log import get_logger
                get_logger("ws2-normalization").warn(
                    f"parser plugin {ep.name!r} target is not a Parser subclass; skipped")
                continue
            instance = cls()
        except Exception as exc:
            from shared.log import get_logger
            get_logger("ws2-normalization").warn(
                f"parser plugin {ep.name!r} failed to load ({exc}); skipped")
            continue
        source_type = getattr(instance, "SOURCE_TYPE", "")
        if not source_type or source_type in existing_source_types or source_type in found:
            continue
        found[source_type] = instance
    return found
