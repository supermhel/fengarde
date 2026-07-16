"""Fixture "external plugin" module for test_plugins.py.

Stands in for a THIRD-PARTY pip package's parser module -- lives inside this
repo only so the test doesn't require actually `pip install`-ing a throwaway
package into the test environment. `EntryPoint.load()` still does a genuine
`importlib.import_module("services.ws2-normalization.parsers.test_fixtures."
"example_plugin_parser")` + `getattr(module, "ExamplePluginParser")` against
this real file -- nothing about the loading mechanism itself is mocked.
"""
from __future__ import annotations

from typing import Optional

from ..base import Parser


class ExamplePluginParser(Parser):
    """A well-formed plugin parser with a SOURCE_TYPE no built-in parser owns."""

    SOURCE_TYPE = "example_plugin_source"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "example-plugin"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw") or {}
        event = self.base_event(
            class_uid=1001, activity_id=1, severity_id=1,
            time_ms=int(rec.get("time_ms", 0)), meta=raw.get("meta"),
        )
        event["src_endpoint"] = {"ip": rec.get("src_ip", "0.0.0.0")}
        return event


class CollidingParser(Parser):
    """Deliberately claims a SOURCE_TYPE a built-in parser already owns, to
    prove discover_plugin_parsers() skips it rather than letting a plugin
    silently override how an already-supported source gets parsed."""

    SOURCE_TYPE = "linux_ssh"

    def parse(self, raw: dict) -> Optional[dict]:
        raise AssertionError("must never be called -- the built-in must win this collision")


class NotAParser:
    """Not a Parser subclass at all -- proves a malformed plugin entry point
    (wrong type) is skipped instead of crashing discovery."""
