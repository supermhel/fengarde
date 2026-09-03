# OT point configuration (WP-2-E)

Machine-readable description of **known OT points** — addresses, semantics,
criticality, allowed writers, and maintenance windows — as **config, not
inference**. This is the Phase-2 externalization of point knowledge: a
register number is an address, not a meaning. `40001` does not generically
mean "cooling"; it means what a deployment's point map says it means. This
directory is the place that map lives.

This directory is a **frozen-contract-ish config surface** in the same
opt-in spirit as `contracts/tenants/` and `contracts/webhooks/`: nothing in
the pipeline reads these files yet (see "Relationship to current code"
below), and the shipped sample is exactly that — a *sample*, not a claim
about any real plant floor.

## Directory layout

```
contracts/ot-points/
├── README.md               # this convention/schema document
├── writer-categories.yml   # controlled vocabulary for allowed_writers
└── <device-id>.yml         # one file per device/PLC, e.g. plc-line3.yml
```

## Schema

Each `<device-id>.yml` is one YAML document:

```yaml
version: 1                      # schema version of THIS file (frozen per version)
device:
  id: plc-line3                 # device identifier
  protocol: modbus_tcp          # only protocol modeled today
  unit_id: 1                    # Modbus unit id, when the protocol has one
  provenance: "..."             # honest origin of this point map (see Ground truth)

# OPTIONAL (WP-3-E): business/operational-impact attributes this device
# belongs to. Top-level, alongside `device:`. Every field optional; absent =
# no claim (ship safe by default). Values are the deployment's own facts
# (asset register, service catalogue), config not inference.
business_context:
  plant: line-3-hall-b              # SAMPLE — deployment asset register name
  production_line: line-3           # SAMPLE
  business_service: cooling-subsystem   # SAMPLE — deployment service catalogue
  owner: ops-team-cooling           # SAMPLE — team name, never a person's account
  operational_state: production     # enum: production | maintenance | decommissioned
  safety_relevance: advisory        # enum: none | advisory | safety-instrumented

# OPTIONAL: documents the parser's coarse default that this config would
# (in a later package) refine. Not a point declaration itself.
parser_default:
  holding_register_range: [40001, 40010)   # modbus_anomaly.py._EXPECTED_WRITE_ADDRESSES

points:
  - id: setpoint                       # stable point id for this device
    space: holding_register            # holding_register | coil | input_register | discrete_input
    index: 0                           # 0-indexed protocol offset (REG_SETPOINT=0 ...)
    wire_address: 40001                # config/PLC-visible 5-digit address (40000+index for holding)
    function_codes: [3, 6]             # read/write codes this point legitimately sees
    meaning: "Cooling setpoint temperature"
    meaning_known: true                # honest "if known" framing — false means "best guess, verify"
    criticality: high                  # low | medium | high | critical
    allowed_writers:
      - category: engineering_workstation
      - category: maintenance_tool
        detail: "field laptop, credentials: engineer-maintenance"
    maintenance_window:                # when writes to this point are EXPECTED
      days: [mon, tue, wed, thu, fri]
      start: "08:00:00"
      end: "18:00:00"
      timezone: "Europe/Berlin"
      write_expectation: "writes expected only inside the window; anything else warrants review"
    notes: "sample entry — window must be confirmed by the deployment"
```

Field obligations:

| field | required | notes |
|---|---|---|
| `version` | yes | this file's schema version |
| `device.id` | yes | unique per deployment |
| `device.protocol` | yes | `modbus_tcp` today |
| `device.unit_id` | no | where the protocol has unit ids |
| `device.provenance` | yes | where the point map came from — never omit |
| `points[].id` | yes | stable, unique |
| `points[].space` | yes | governs `wire_address` numbering |
| `points[].index` | yes | 0-indexed protocol offset |
| `points[].wire_address` | yes | 5-digit address as a PLC config would show it |
| `points[].function_codes` | yes | codes a legitimate access to this point uses |
| `points[].meaning` | yes | semantic meaning |
| `points[].meaning_known` | yes | `true` = confirmed by deployment/vendor; `false` = derived guess, labeled |
| `points[].criticality` | yes | `low` \| `medium` \| `high` \| `critical` |
| `points[].allowed_writers` | yes | non-empty list; categories from `writer-categories.yml` |
| `points[].maintenance_window` | yes | `days` (ISO weekday abbreviations), `start`/`end` (HH:MM:SS), `timezone` (IANA), `write_expectation` |
| `points[].notes` | no | anything else, honestly |
| `business_context.plant` | no | plant name from the deployment's own asset register — omit unless confirmed; a sample value must never read as a claim about a real plant |
| `business_context.production_line` | no | production line identifier, per the deployment's own naming — omit if not confirmed |
| `business_context.business_service` | no | business service this device belongs to, from the deployment's service catalogue |
| `business_context.owner` | no | owning team name — a team, never a person's account, never credentials |
| `business_context.operational_state` | no | `production` \| `maintenance` \| `decommissioned` — the deployment's own declared state, never inferred |
| `business_context.safety_relevance` | no | `none` \| `advisory` \| `safety-instrumented` — SIF membership per the deployment's safety case, never assumed |

**Honest scope (WP-3-E): `business_context` is schema-only.** No parser,
rule, or loader reads this block today — the same status this README states
for the whole directory. It exists so the business/operational-impact
attributes have a config surface to live on before any later package wires
them in; adding or omitting it changes **zero** behavior.

Wire-address numbering follows the Modbus Application Protocol V1.1b3
5-digit data-address table, the same convention the holding-register block
in `modbus_anomaly.py` uses:

- holding register offset `N` (0 = first register) → `wire_address = 40001 + N`
  (40001, 40002, … — matches `REG_SETPOINT=0` → 40001, `REG_LEVEL=1` → 40002)
- coil offset `N` (0 = first coil) → `wire_address = 00001 + N` in the 0xxxx
  coil space (coil offset 0 → `00001`)

## Ground truth (this repo's only honest source: its own twin)

The sample `plc-line3.yml` is derived from the repo's **PLC simulator
twin** — `eval/twin/plc_sim.py` (a loopback-only tank/pump process sim
exposing a small register/coil map). Honest provenance, two facts:

1. **The `.py` sources under `eval/twin/` are ABSENT from this checkout**
   (the directory contains only stale `__pycache__/` — `plc_sim.cpython-312.pyc`,
   `negative_controls.cpython-312.pyc`, …). The register/coil index values in
   the sample therefore come from the WP-2-E task brief, and are
   cross-checked against what IS verifiable in-repo: the constant names
   (`REG_SETPOINT`, `REG_LEVEL`, `REG_PUMP_STATE`, `COIL_PUMP_ENABLE`) and
   function codes (1 read coils, 3 read holding, 5 write single coil,
   6 write single register) were confirmed present in the compiled
   `plc_sim` code object, and the derived wire addresses sit inside/park
   outside the parser's declared range exactly as documented below.
   A deployment replacing the sample must write its OWN point map from its
   OWN device/vendor knowledge.
2. **The sample round-trips with the live parser contract** — see the
   cross-check at the bottom of this README.

## Relationship to current code

| artifact | role |
|---|---|
| `services/ws2-normalization/parsers/modbus_anomaly.py` | parser; classifies observed Modbus frames (`class_uid: 4001`) |
| `... _EXPECTED_WRITE_ADDRESSES = range(40001, 40010)` | the parser's **coarse hardcoded default**: a write function code (05/06/15/16) targeting an address outside 40001–40009 is `unauthorized_write` |
| `contracts/rules/ot_modbus_unauthorized_write.yml` (id `9c1d2e3f-4a5b-4c6d-8e7f-1a2b3c4d5e6f`) | the rule that keys on `unmapped.ot.anomaly_type: unauthorized_write` and fires (single-shot, level high) |
| `contracts/ot-points/*.yml` (**this directory**) | the place a deployment expresses **richer** point knowledge: coil-space points, per-point semantics, allowed writers, maintenance windows |

`_EXPECTED_WRITE_ADDRESSES` is exactly what this config is meant to
supersede in a later package: it is a holding-register-only range with no
semantics attached. Its own module docstring already frames it as the
coarse, documented heuristic that "a real deployment would override … via
its own allowlist" — this directory is that allowlist's config form.

## The false-positive finding this surface is built to express (FPR, 2026-08-28)

Measured on the Phase-1 eval twin: the `approved-maintenance-window`
scenario fired `ot_modbus_unauthorized_write` for a **legitimate
maintenance-window write to the COIL address space**.

Mechanism, step by step:

1. A maintenance engineer performs an approved action during a declared
   window: write coil `00001` (function code 5, Write Single Coil) on the
   pump-enable point.
2. The parser checks `address not in _EXPECTED_WRITE_ADDRESSES` →
   `00001 not in range(40001, 40010)` → **`unauthorized_write`**.
3. `ot_modbus_unauthorized_write.yml` fires (level high), even though the
   write was legitimate and in-window.

Root cause: the parser's expected range covers **holding registers only**
(40001–40010) and knows nothing about coil-space points, writers, or
windows. The coil write is *numerically* out of range, so the coarse
heuristic cannot distinguish "write to an unknown address" from "write to a
known coil, by an allowed writer, inside its window".

**This directory is the honest vehicle for that nuance**: a deployment
declares the coil point (`space: coil`, `wire_address: 00001`), its allowed
writers, and its maintenance window — the information needed to decide that
an in-window, allowed-writer coil write is expected rather than anomalous.
`plc-line3.yml` contains exactly such an entry (point `pump_enable`).

**Honest scope: this config is NOT wired into the parser.** Nothing in
`services/ws2-normalization/` or any rule reads `contracts/ot-points/`
today; no loader exists; deploying this directory changes **zero** behavior,
and the FPR stands until a later package (out of scope for WP-2-E) consumes
this config to enrich the parser's expected-write decision. Do not claim
otherwise. The parser default remains the coarse range until that package
lands, by design — it fails toward flagging, never toward silent
pass-through, and a coil write falling back to `unauthorized_write` is the
documented tradeoff the rule's own description accepts.

## Conventions

- **Config, not inference**: files here state facts a deployment has decided;
  they never compute or guess at detection behavior.
- **Honest `if known` framing**: `meaning_known: false` is an honest guess;
  omitting the field is not. `provenance` is mandatory.
- **No secrets**: never put credentials here (SECURITY.md §4). Writer
  categories reference actor/source categories, not keys.
- **Ship safe by default**: the shipped sample is labelled `sample` and
  carries the twin-derived provenance above; an empty deployment is free to
  delete it and start from `writer-categories.yml` alone (same
  opt-in shape as `contracts/tenants/`).
- **Validation**: every YAML under this directory must pass
  `yaml.safe_load` (see below). No schema validator exists in-tree yet — a
  later package that wires this config in should add one (same pattern as
  `tools/validate_rules.py` for `contracts/rules/`).

## Validation

```sh
cd "C:/Users/Mel Dylan Djomou/Claude/Projects/SIEM App"
for f in contracts/ot-points/*.yml; do \
  .venv/Scripts/python.exe -c "import sys,yaml; yaml.safe_load(open('$f', encoding='utf-8')); print('OK', '$f')"; \
done
```

## Cross-check of the sample against the twin register map

| constant (twin) | index | space | derived wire address | in parser default range 40001–40010? |
|---|---|---|---|---|
| `REG_SETPOINT` | 0 | holding register | 40001 | ✅ in range |
| `REG_LEVEL` | 1 | holding register | 40002 | ✅ in range |
| `REG_PUMP_STATE` | 2 | holding register | 40003 | ✅ in range |
| `COIL_PUMP_ENABLE` | 0 | coil (0xxxx) | 00001 | ❌ OUT of range → `unauthorized_write` (the FPR) |

The first three round-trip as non-anomalous writes under the current
parser; the coil point is precisely the case the parser cannot currently
bless — recorded here as config, resolved later by wiring.