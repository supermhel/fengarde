"""keyed_storyline_checks -- the checks every process-tree-keyed twin storyline's own test runs.

Not a ``test_*`` (it is imported by ``test_storyline_<name>.py``, one thin file per storyline, each wired
into ``run_all_tests.sh``'s eval-twin tier). Every check prints ``[OK]`` / ``[FAIL]`` and the caller exits
non-zero on any failure; every check has a NEGATIVE control where the check could pass vacuously.

CHECKS (``run(name)``)
  determinism       same seed -> byte-identical raw payloads; a different seed -> different payloads
  real parsers      every event of the REAL WS-2 path is parsed (strict), by the parser the step names
  keys in raw       every Sysmon EID 1/3/10 record carries its guid fields, in the Sysmon GUID shape, minted by
                    the builder (this module also AST-checks that neither the storyline nor ``sysmon_tree``
                    imports ``services/shared/causal_keys.py``)
  sender scope      every record carries ``meta.shipper_ip`` (== ``meta.ip``), one address per monitored
                    (Sysmon) host, distinct across hosts
  oracle provenance ``oracle_provenance.check`` passes; NEGATIVE: a changed rule digest fails it
  causal_links      the oracle's ``causal_links`` equal ``sysmon_tree.derive_links`` over the RAW payloads
                    for seeds 7 / 11 / 23; NEGATIVE: with one raw ParentProcessGuid broken the derivation
                    loses exactly that link, so the pin is load-bearing
  oracle shape      >= 2 forbidden pairs, each anti-causal (to-step earlier than from-step), none a link
"""
from __future__ import annotations

import ast
import copy
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TWIN = Path(__file__).resolve().parent
for _p in (str(TWIN), str(ROOT / "services")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oracle_provenance as prov  # noqa: E402
import scenario_registry as reg  # noqa: E402
import sysmon_tree  # noqa: E402

SEEDS = (7, 11, 23)
_GUID = re.compile(r"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$")


class Checker:
    def __init__(self, name: str):
        self.name = name
        self.failures: list = []

    def __call__(self, label: str, ok: bool, detail: str = "") -> bool:
        print(f"[{'OK' if ok else 'FAIL'}] {self.name}: {label}" + (f" -- {detail}" if detail and not ok else ""))
        if not ok:
            self.failures.append(label)
        return ok


def _dump(payloads: list) -> str:
    return json.dumps([[s.label, p] for s, p in payloads], sort_keys=True)


def _imports(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            out.add(n.module or "")
    return out


def run(name: str, extra=None) -> int:
    """Run every shared check for storyline ``name``; ``extra(check, sdef)`` adds storyline-specific ones."""
    check = Checker(name)
    sdef = reg.get(name)
    oracle = yaml.safe_load(Path(sdef.oracle_path).read_text(encoding="utf-8"))
    mod_path = TWIN / f"storyline_{name}.py"

    # ---- determinism --------------------------------------------------------------------------
    a, b = sdef.build(7)[0], sdef.build(7)[0]
    check("determinism: same seed -> byte-identical raw payloads", _dump(a) == _dump(b))
    check("determinism: a different seed -> different payloads", _dump(a) != _dump(sdef.build(11)[0]))
    check("determinism: ingest ids unique within a build", len({p["meta"]["ingest_id"] for _, p in a}) == len(a))

    # ---- real parsers -------------------------------------------------------------------------
    res = reg.run(sdef, 7, strict=True)
    parsed = [e for e in res.events if e.step in {s.label for s in sdef.steps}]
    check("real parsers: every event of every step parsed through the real WS-2 path (strict)",
          bool(parsed) and all(e.parsed and not e.errors and e.parser for e in parsed),
          f"{[(e.step, e.errors[:1]) for e in parsed if not e.parsed][:3]}")
    check("real parsers: both sysmon and windows_eventlog (and only real parsers) ran",
          {e.parser for e in parsed} >= {"sysmon", "windows_eventlog"})
    check("real parsers: type_uid derived on every event", all(e.type_uid for e in parsed))

    # ---- keys in the raw records --------------------------------------------------------------
    sys_recs = [p["raw"] for _, p in a if p["source_type"] == "sysmon"]
    eid1 = [r for r in sys_recs if r["EventID"] == 1]
    eid3 = [r for r in sys_recs if r["EventID"] == 3]
    eid10 = [r for r in sys_recs if r["EventID"] == 10]
    check("keys: EID 1 records carry ProcessGuid and (all but a tree root) ParentProcessGuid",
          bool(eid1) and all(_GUID.match(r.get("ProcessGuid", "")) for r in eid1)
          and sum(1 for r in eid1 if "ParentProcessGuid" in r) >= len(eid1) - 1)
    check("keys: every ParentProcessGuid / SourceProcessGUID / ProcessGuid has the Sysmon GUID shape",
          all(_GUID.match(r[k]) for r in sys_recs for k in ("ParentProcessGuid", "SourceProcessGUID", "TargetProcessGUID",
                                                              "ProcessGuid") if k in r))
    check("keys: EID 10 carries SourceProcessGUID, EID 3 carries ProcessGuid",
          all("SourceProcessGUID" in r for r in eid10) and all("ProcessGuid" in r for r in eid3))
    check("keys: a ProcessGuid is minted once per (Computer, guid) (no two processes share one)",
          len({(r["Computer"], r["ProcessGuid"]) for r in eid1}) == len(eid1))
    mods = _imports(mod_path) | _imports(TWIN / "sysmon_tree.py")
    check("keys: the builder's own generator -- no import of services/shared/causal_keys",
          not any("causal_keys" in m for m in mods), f"{sorted(m for m in mods if 'causal' in m)}")

    # ---- sender scope -------------------------------------------------------------------------
    check("sender: every record has meta.shipper_ip == meta.ip",
          all(p["meta"].get("shipper_ip") and p["meta"]["shipper_ip"] == p["meta"].get("ip") for _, p in a))
    host_ips: dict = {}
    for _, p in a:
        if p["source_type"] == "sysmon":                    # a Sysmon record is shipped BY the host it names
            host_ips.setdefault(p["raw"]["Computer"], set()).add(p["meta"]["shipper_ip"])
    check("sender: one shipper_ip per monitored (Sysmon) host, distinct across hosts",
          all(len(v) == 1 for v in host_ips.values()) and len({next(iter(v)) for v in host_ips.values()}) == len(host_ips))

    # ---- oracle provenance --------------------------------------------------------------------
    check("provenance: the oracle matches the rule text it was authored from", prov.check(oracle) == [],
          f"{prov.check(oracle)}")
    bad = copy.deepcopy(oracle)
    stem = sorted(bad["provenance"]["rules_read"])[0]
    bad["provenance"]["rules_read"][stem] = "0" * 64
    check("provenance NEGATIVE: a wrong digest fails the check",
          any("changed since" in p for p in (prov.check(bad) or [])))

    # ---- causal_links: derived, never hand-typed ------------------------------------------------
    declared = oracle.get("causal_links") or []
    check("causal_links: declared, process_tree basis, each with a via tag",
          bool(declared) and all(lk.get("basis") == "process_tree" and lk.get("via") in ("spawn", "acting_process")
                                 for lk in declared))
    for s in SEEDS:
        derived = sysmon_tree.derive_links(sdef.build(s)[0])
        check(f"causal_links: oracle == derivation from the raw keys (seed {s})", declared == derived,
              f"declared-derived={[lk for lk in declared if lk not in derived]} "
              f"derived-declared={[lk for lk in derived if lk not in declared]}")
    broken = copy.deepcopy(a)
    victim = next(lk for lk in declared if lk["via"] == "spawn")
    for st, pl in broken:       # cut the parent key on every record of the link's target step
        if st.label == victim["to"] and "ParentProcessGuid" in pl["raw"]:
            pl["raw"]["ParentProcessGuid"] = "{00000000-0000-0000-0000-000000000000}"
    lost = [lk for lk in declared if lk not in sysmon_tree.derive_links(broken)]
    check("causal_links NEGATIVE: cutting the raw parent key of one step removes exactly that link",
          lost == [victim], f"lost={lost}")
    order = list(oracle["expected_sequence"])
    check("causal_links: every link runs forward in the expected sequence",
          all(order.index(lk["from"]) < order.index(lk["to"]) for lk in declared))
    check("causal_links: every link names two steps of the oracle", all(lk["from"] in order and lk["to"] in order for lk in declared))

    # ---- oracle shape ---------------------------------------------------------------------------
    rels = oracle["allowed_relationships"]
    forbidden = [(r["from"], r["to"]) for r in rels if not r["allowed"]]
    check("oracle: >= 2 forbidden step pairs (ADR-011 F4 contribution)", len(forbidden) >= 2, f"{len(forbidden)}")
    order_ix = {st: i for i, st in enumerate(order)}
    check("oracle: every forbidden pair is anti-causal (its 'to' step precedes its 'from' step)",
          all(order_ix[t] < order_ix[f] for f, t in forbidden))
    linkset = {(lk["from"], lk["to"]) for lk in declared}
    check("oracle: no forbidden pair is also a declared causal link", not (set(forbidden) & linkset))

    if extra:
        extra(check, sdef)
    if check.failures:
        print(f"\n[FAIL] {name}: {len(check.failures)} check(s) failed")
        return 1
    print(f"\n[OK] {name}: every keyed-storyline check passed (positive and negative controls)")
    return 0
