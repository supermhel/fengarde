# Writing a FENGARDE plugin (M4.5)

You can ship an additional log-source parser and/or additional detection
rules for FENGARDE as your own installable pip package — **no fork of this
repo required**. FENGARDE discovers plugins via standard Python
[entry points](https://packaging.python.org/en/latest/specifications/entry-points/),
the same mechanism `pytest` plugins, `flake8` checks, and countless other
tools use.

**Honest scope, read this first:** this is a discovery mechanism, not a
sandbox. A plugin's parser code and rule `condition` strings run with the
same trust level as this repo's own code (SECURITY.md §3 already treats
rule files as code an operator must review) — only install plugin packages
you've reviewed and trust, exactly like any other Python dependency.

## What a plugin can add

| Extension point | Entry-point group | Target shape |
|---|---|---|
| A new WS-2 log-source parser | `fengarde.parsers` | A `Parser` subclass (`services/ws2-normalization/parsers/base.py`) |
| A rule pack | `fengarde.rule_packs` | A callable (or plain path) returning a directory of `*.yml` rule files, same shape as `contracts/rules/*.yml` |

Both are purely **additive**: a plugin parser whose `SOURCE_TYPE` collides
with a built-in one is skipped (the built-in wins); a plugin rule whose
`id` collides with an already-loaded rule (built-in or another plugin,
whichever loaded first) is skipped too. A plugin extends FENGARDE, it can
never silently override behavior this repo already ships.

## A worked example

Directory layout for a plugin package (e.g. `fengarde-acme-plugin`):

```
fengarde-acme-plugin/
  pyproject.toml
  acme_plugin/
    __init__.py
    parser.py
    rules/
      acme_suspicious_thing.yml
```

`acme_plugin/parser.py`:

```python
from typing import Optional
from parsers.base import Parser  # FENGARDE's Parser base class

class AcmeWidgetParser(Parser):
    SOURCE_TYPE = "acme_widget"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "acme-widget"}

    def parse(self, raw: dict) -> Optional[dict]:
        rec = raw.get("raw") or {}
        event = self.base_event(
            class_uid=4001, activity_id=1, severity_id=1,
            time_ms=int(rec.get("ts", 0)), meta=raw.get("meta"),
        )
        event["src_endpoint"] = {"ip": rec.get("src_ip", "0.0.0.0")}
        return event
```

`acme_plugin/rules/acme_suspicious_thing.yml` — any rule matching the
grammar documented in `contracts/sigma-convention.md` and validated by
`tools/validate_rules.py`:

```yaml
title: Acme widget flagged a suspicious thing
id: <a fresh, real UUID -- generate your own, never reuse one from contracts/rules/>
level: medium
logsource: { category: network_activity }
detection:
  suspicious: { class_uid: 4001, "unmapped.acme.flag": true }
  condition: suspicious
siem: { sector: common, score_weight: 30 }
```

`pyproject.toml`:

```toml
[project]
name = "fengarde-acme-plugin"
version = "0.1.0"

[project.entry-points."fengarde.parsers"]
acme_widget = "acme_plugin.parser:AcmeWidgetParser"

[project.entry-points."fengarde.rule_packs"]
acme_rules = "acme_plugin:rules_dir"
```

`acme_plugin/__init__.py` — the rule-pack entry point target is a
zero-argument callable returning the rules directory (a plain string/Path
constant also works, but a callable lets you compute the path relative to
installed package data reliably):

```python
from pathlib import Path

def rules_dir() -> Path:
    return Path(__file__).parent / "rules"
```

Install it (into the same environment FENGARDE's `services/` run in):

```sh
pip install -e ./fengarde-acme-plugin
```

Restart `ws2-normalization` and `ws4-detection`. On next startup:

- `services/ws2-normalization/parsers/__init__.py` calls
  `discover_plugin_parsers()`, which finds your `fengarde.parsers` entry
  point and adds `AcmeWidgetParser` to the registry under `acme_widget`.
- `services/ws4-detection/main.py`'s `Detector` calls
  `discover_rule_pack_dirs()`, finds your `fengarde.rule_packs` entry
  point, and merges every `*.yml` in `rules_dir()` into the active rule set
  (subject to the collision rule above).

No FENGARDE code changed. No fork needed.

## What this does NOT give you

- **No sandboxing.** A plugin's parser code executes with full process
  privileges, same as any imported Python module; its rule conditions are
  parsed by the same boolean grammar (no `eval()`, see `engine.py`) as
  built-in rules — safe from RCE, but still logic you should read before
  trusting.
- **No plugin marketplace/registry.** Discovery is `pip install` + Python
  entry points; there's no FENGARDE-hosted index of plugins (yet).
- **No versioned plugin ABI.** `Parser` and the rule YAML grammar can
  change between FENGARDE releases like any other internal interface —
  there's no compatibility contract beyond "this doc reflects the current
  `main`."
- **No per-tenant plugin scoping.** A discovered plugin parser/rule pack is
  available to every tenant on this deployment; use per-tenant rule
  enablement (`contracts/tenants/<id>.yml`, see its README) to disable a
  plugin rule for specific tenants after it loads.
- **Anti-dormancy (`tools/check_rule_producers.py`) does not cover plugin
  rules.** That CI gate only proves `contracts/rules/*.yml` is satisfiable
  by this repo's own parsers — a plugin author is responsible for proving
  their own rules actually fire against their own parser's output.
