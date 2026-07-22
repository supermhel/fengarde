#!/usr/bin/env python3
"""M4.6 ops lifecycle: versioned OpenSearch index-template migration.

Each ``contracts/opensearch-mappings/*.json`` template file carries a
``template.mappings._meta.mapping_version``. This tool GETs the currently
installed template (if any), compares its ``mapping_version`` to the
file's, and PUTs (creates/updates) only when they differ -- an idempotent,
auditable, plan-then-apply alternative to ``infra/provision.sh``'s
unconditional "always re-PUT everything" loop, and the thing a real
upgrade step calls.

**Honest scope:** this manages TEMPLATES only (``events-bank``,
``events-common``, ``events-dc``, ``assets``, ``alerts``). The
``ism-*.json`` files in the same directory are ISM *retention policies*
(a different resource at ``_plugins/_ism/policies/<name>``, installed by
``infra/provision.sh``) and are skipped here -- they are not index
templates and have no ``mapping_version``.

The logic here is proven at the wire-format level against a fake
transport (``tools/test_migrate_opensearch.py``) and, since 2026-07-21,
exercised against a live OpenSearch cluster by the ``make test-live``
lane (``services/ws3-indexer/storage/test_opensearch_live.py``).

Usage:
    python tools/migrate_opensearch.py              # plan + apply drifted templates
    python tools/migrate_opensearch.py --dry-run     # plan only, apply nothing
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "services" / "ws3-indexer"))

from storage.opensearch import OpenSearchStore  # noqa: E402

MAPPINGS_DIR = ROOT / "contracts" / "opensearch-mappings"
_SKIP_PREFIX = "ism-"  # ISM policy files are not index templates; see module docstring


def _mapping_version(template: dict) -> int:
    meta = (template.get("template") or {}).get("mappings", {}).get("_meta") or {}
    return meta.get("mapping_version", 0)


def load_templates(mappings_dir: Path = MAPPINGS_DIR) -> dict[str, dict]:
    """{template_name: template_body} for every *.json in mappings_dir
    except the ISM policy files (a different resource entirely, see module
    docstring). template_name == filename minus ``.json``, matching
    infra/provision.sh's existing naming convention."""
    templates = {}
    for path in sorted(Path(mappings_dir).glob("*.json")):
        if path.name.startswith(_SKIP_PREFIX):
            continue
        templates[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return templates


def installed_version(store: OpenSearchStore, name: str) -> int | None:
    """Currently installed mapping_version for template `name`, or None if
    nothing is installed under that name yet (first-ever provisioning, or
    an installed template that predates _meta -- both should be treated as
    "needs applying")."""
    try:
        result = store._request("GET", f"/_index_template/{name}")
    except Exception:
        return None
    installed = result.get("index_templates") or []
    if not installed:
        return None
    return _mapping_version(installed[0].get("index_template", {}))


def plan(store: OpenSearchStore, mappings_dir: Path = MAPPINGS_DIR) -> list[dict]:
    """[{"name", "desired_version", "installed_version", "action"}] for
    every template file. action is "apply" if versions differ (including
    "nothing installed yet"), "skip" if already current. Read-only --
    never writes anything."""
    steps = []
    for name, template in load_templates(mappings_dir).items():
        desired = _mapping_version(template)
        installed = installed_version(store, name)
        action = "skip" if installed == desired else "apply"
        steps.append({"name": name, "desired_version": desired,
                      "installed_version": installed, "action": action})
    return steps


def apply(store: OpenSearchStore, steps: list[dict], mappings_dir: Path = MAPPINGS_DIR) -> list[str]:
    """PUT every step marked "apply" (via ensure_template, idempotent).
    Returns the names actually written."""
    templates = load_templates(mappings_dir)
    applied = []
    for step in steps:
        if step["action"] != "apply":
            continue
        store.ensure_template(step["name"], templates[step["name"]])
        applied.append(step["name"])
    return applied


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="print the plan, apply nothing")
    parser.add_argument("--url", default=os.getenv("OPENSEARCH_URL", "http://localhost:9200"))
    args = parser.parse_args()

    store = OpenSearchStore(url=args.url)
    steps = plan(store)
    print(json.dumps({"plan": steps}, indent=2))
    if args.dry_run:
        return
    applied = apply(store, steps)
    print(json.dumps({"applied": applied}))


if __name__ == "__main__":
    main()
