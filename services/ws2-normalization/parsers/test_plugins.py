"""M4.5 parser plugin discovery tests.

Uses REAL importlib.metadata.EntryPoint objects pointing at
parsers/test_fixtures/example_plugin_parser.py (a fixture standing in for a
third-party pip package) instead of requiring an actual `pip install` of a
throwaway package into the test environment. EntryPoint.load() still does a
genuine import_module + getattr against real files -- only the SOURCE of the
entry-point list is substituted, not what loading one does.

Run: python services/ws2-normalization/parsers/test_plugins.py
"""
from __future__ import annotations

import sys
from importlib.metadata import EntryPoint
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))   # for `parsers` (this dir's own tests' convention)
sys.path.insert(0, str(SERVICES))      # for `shared`

from parsers.plugins import discover_plugin_parsers  # noqa: E402
from parsers.base import Parser  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def _ep(name: str, value: str) -> EntryPoint:
    return EntryPoint(name=name, value=value, group="fengarde.parsers")


_FIXTURE = "parsers.test_fixtures.example_plugin_parser"


def test_a_well_formed_plugin_is_discovered_and_loadable():
    eps = [_ep("example", f"{_FIXTURE}:ExamplePluginParser")]
    found = discover_plugin_parsers(existing_source_types=set(), eps=eps)
    check("example_plugin_source" in found, f"the plugin's SOURCE_TYPE must be discovered, got {list(found)}")
    instance = found["example_plugin_source"]
    check(isinstance(instance, Parser), "the discovered plugin must be a real Parser instance")
    # Prove .load() genuinely ran the fixture's parse() logic, not a stub.
    event = instance.parse({"raw": {"src_ip": "10.0.0.9", "time_ms": 123}, "source_type": "example_plugin_source"})
    check(event is not None and event["src_endpoint"]["ip"] == "10.0.0.9",
          "the loaded plugin instance must actually parse, proving real code ran")


def test_colliding_source_type_is_skipped_builtin_wins():
    eps = [_ep("colliding", f"{_FIXTURE}:CollidingParser")]
    found = discover_plugin_parsers(existing_source_types={"linux_ssh"}, eps=eps)
    check(found == {}, f"a plugin claiming an existing SOURCE_TYPE must be skipped entirely, got {found}")


def test_non_parser_class_is_skipped_not_crashed():
    eps = [_ep("wrong-type", f"{_FIXTURE}:NotAParser")]
    found = discover_plugin_parsers(existing_source_types=set(), eps=eps)
    check(found == {}, "a plugin whose target isn't a Parser subclass must be silently skipped")


def test_broken_entry_point_does_not_crash_discovery():
    eps = [
        # NOTE: the module name deliberately avoids any real top-level stdlib
        # module (e.g. `this` triggers the "import this" easter egg on import)
        # -- it must fail cleanly with ModuleNotFoundError, no side effects.
        _ep("broken-module", "nonexistent_fengarde_test_plugin_module.sub:Whatever"),
        _ep("broken-attr", f"{_FIXTURE}:ThisClassDoesNotExist"),
        _ep("good", f"{_FIXTURE}:ExamplePluginParser"),
    ]
    found = discover_plugin_parsers(existing_source_types=set(), eps=eps)
    check(list(found) == ["example_plugin_source"],
          f"two broken entry points must not prevent the good one from loading, got {list(found)}")


def test_no_entry_points_is_a_clean_noop():
    check(discover_plugin_parsers(existing_source_types=set(), eps=[]) == {},
          "zero entry points must yield zero plugin parsers, not raise")


def test_real_registry_includes_no_plugins_by_default():
    # Sanity: this repo ships zero fengarde.parsers entry points installed
    # into the actual test environment, so the REAL discover_plugin_parsers()
    # (no `eps` override -- the default codepath parsers/__init__.py uses)
    # must return nothing here. This is the "opt-in, zero behavior change"
    # claim, proven rather than assumed.
    found = discover_plugin_parsers(existing_source_types=set())
    check(found == {}, f"no plugin packages are installed in this environment, expected {{}}, got {found}")


def main():
    test_a_well_formed_plugin_is_discovered_and_loadable()
    test_colliding_source_type_is_skipped_builtin_wins()
    test_non_parser_class_is_skipped_not_crashed()
    test_broken_entry_point_does_not_crash_discovery()
    test_no_entry_points_is_a_clean_noop()
    test_real_registry_includes_no_plugins_by_default()

    if FAILS:
        print(f"[FAIL] parser plugins: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] M4.5 parser plugin discovery: well-formed plugin loaded via a REAL "
          "importlib.metadata.EntryPoint.load() (genuine import+getattr), SOURCE_TYPE "
          "collision skipped (built-in wins), non-Parser target skipped, broken entry "
          "points don't crash discovery, real (empty) environment sanity check")


if __name__ == "__main__":
    main()
