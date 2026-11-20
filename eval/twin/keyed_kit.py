"""keyed_kit -- helpers shared by the ``storyline_<name>_keyed.py`` modules (ADR-012 WP 7).

Not itself a storyline (its name deliberately does not match the registry's ``storyline_*.py``
discovery glob). Pure functions of their arguments: no wall clock, no randomness, no I/O except the
oracle writer's explicit file write.

WHAT A KEYED TWIN IS. A keyed twin WRAPS an original storyline: it calls the original builder
unchanged, deep-copies its raw records and ADDS two things, nothing else:

  * Sysmon-shaped process-tree keys (``ProcessGuid`` / ``ParentProcessGuid``; ``SourceProcessGUID`` on
    an EventID 10) on the records whose step has a process in the twin's declared process tree, and
  * a distinct ``meta.shipper_ip`` per emitting host (the sender identity ADR-012 puts in the key hash).

The original storyline's module, oracle, baseline and frozen ``baseline_scenarios`` rows are never
touched; a keyed twin is a NEW registry entry with its own name (``<original>_keyed``).

WHY THE KEY GENERATOR IS HERE AND NOT SHARED. ADR-012 "Risks / Twin circularity": if the builder and
the parser derive keys with the same helper, truth and prediction are not independent. ``guid`` below
is the builder's own generator (sha256 over a labelled tuple). It must never import, and is not
derived from, ``services/shared/causal_keys.py`` or any service code; ``test_keyed_twins.py`` enforces
that with an AST scan.

TRUTH IS DERIVED FROM THE RAW RECORDS THE BUILDER EMITS. ``derive_links`` pairs events whose
``ParentProcessGuid`` equals another event's ``ProcessGuid`` on the SAME host (parent -> child, the
ADR's ``process_tree`` rule), and lifts that to step pairs. It reads no parser output and no alert, so
the oracle's ``causal_links`` cannot drift with ws4/ws8 behaviour.

INDEPENDENCE. A keyed twin replays the original's events, rules and attack shape; it only adds keys.
It is therefore NOT an independent scenario: the oracle records ``keyed_twin.independent_of_original:
false`` and ``counts_toward_n: 0`` so any minimum-n guard counts the pair once.

REALISM LIMIT (stated per link, ``child_key_shape``). A real Sysmon EID 1 carries both
``ProcessGuid`` and ``ParentProcessGuid``; EID 3/10/11 and the Windows/MCP records natively carry no
parent GUID. A link whose child record is not an EID 1 is marked ``twin_enrichment``: it models what a
collector that joins process lineage onto the event would emit, and is UNVERIFIED against a real
capture (ADR-012 WP 1 is the missing input).
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import yaml

TWIN = Path(__file__).resolve().parent

#: seeds the derived link set must be identical over (structure varies with the seed; links must not)
LINK_SEEDS = (7, 11, 13, 17, 23)

_HOST_FIELDS = ("Computer", "host", "hostname", "Hostname")


# ---------------------------------------------------------------------------
# the builder's own key generator (independent of services/shared/causal_keys.py)
# ---------------------------------------------------------------------------
def guid(seed: int, host: str, proc: str) -> str:
    """A Sysmon-shaped ProcessGuid (``{8-4-4-4-12}`` lower-case hex) for process ``proc`` on ``host``.
    Deterministic; the host is part of the input so two hosts never share a GUID by accident."""
    h = hashlib.sha256(f"fengarde-keyed-twin|{seed}|{host}|{proc}".encode()).hexdigest()
    return "{%s-%s-%s-%s-%s}" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])


def shipper_ip(host: str) -> str:
    """A deterministic sender address ``10.100-199.x.y`` for ``host`` (a pure function of the host name, so the
    same host gets the same address in the attack and in a decoy; distinct hosts differ)."""
    h = hashlib.sha256(f"fengarde-keyed-twin-sender|{host}".encode()).digest()
    return f"10.{100 + h[0] % 100}.{h[1]}.{1 + h[2] % 254}"


def host_of(source_type: str, raw, overrides: dict | None = None) -> str:
    """The host a record was emitted on. ``overrides`` maps source_type -> host for sources whose raw
    record names no host (the MCP agent runs on the CI runner). Hostless sources (cef, cloudtrail,
    active_directory, ...) are one collector per source type."""
    if overrides and source_type in overrides:
        return overrides[source_type]
    if isinstance(raw, dict):
        for k in _HOST_FIELDS:
            v = raw.get(k)
            if isinstance(v, str) and v:
                return v
    return f"collector-{source_type}"


# ---------------------------------------------------------------------------
# applying keys to a copy of the original payloads
# ---------------------------------------------------------------------------
def _instance(name: str, k: int) -> str:
    """``sc#`` -> one process per event (``sc0``, ``sc1``); a name with no ``#`` is one process."""
    return f"{name[:-1]}{k}" if name.endswith("#") else name


def key_payloads(payloads, *, seed: int, procs: dict, bind: dict, host_overrides: dict | None = None) -> list:
    """Deep copy of ``payloads`` with the keys added.

    ``procs``: ``{proc: (parent_proc | None, image)}`` -- the process tree the twin models.
    ``bind``: ``{step_label: proc}`` -- the process that PRODUCED the step's records. ``proc`` may end
    in ``#`` (one process per event of the step, each a child of the same parent). A step not in
    ``bind`` gets no process keys (it still gets a ``shipper_ip``).
    """
    out: list = []
    seen: dict = {}
    for spec, payload in payloads:
        p = copy.deepcopy(payload)
        raw = p.get("raw")
        host = host_of(p.get("source_type") or spec.source_type, raw, host_overrides)
        p["meta"]["shipper_ip"] = shipper_ip(host)
        label = spec.label
        k = seen.get(label, 0)
        seen[label] = k + 1
        proc = bind.get(label)
        if proc is not None and isinstance(raw, dict):
            parent = procs[proc][0]
            raw["ProcessGuid"] = guid(seed, host, _instance(proc, k))
            if parent is not None:
                pinst = _instance(parent, k) if parent.endswith("#") else parent
                raw["ParentProcessGuid"] = guid(seed, host, pinst)
            if p.get("source_type") == "sysmon" and raw.get("EventID") == 10:
                raw["SourceProcessGUID"] = raw["ProcessGuid"]       # EID 10's native name for the same key
        out.append((spec, p))
    return out


def key_decoys(decoys, *, host_overrides: dict | None = None) -> list:
    """Decoys carry a ``shipper_ip`` for their own host and NO process keys (a benign look-alike is not
    in the attack's tree: the correlator must keep it out)."""
    out: list = []
    for spec, payload in decoys:
        p = copy.deepcopy(payload)
        p["meta"]["shipper_ip"] = shipper_ip(host_of(p.get("source_type") or spec.source_type, p.get("raw"),
                                                    host_overrides))
        out.append((spec, p))
    return out


# ---------------------------------------------------------------------------
# truth: derived from the raw records the builder emits
# ---------------------------------------------------------------------------
def derive_links(payloads, *, host_overrides: dict | None = None) -> dict:
    """``{"events": [(parent_idx, child_idx), ...], "steps": {(parent_step, child_step): shape}}``.

    A link is ``child.ParentProcessGuid == parent.ProcessGuid`` on the same host, parent -> child,
    between two DIFFERENT steps. ``shape`` is ``sysmon_eid1_native`` when every child record that
    carries the pair is a Sysmon EID 1, else ``twin_enrichment``. Reads raw records only."""
    by_guid: dict = {}
    for i, (spec, p) in enumerate(payloads):
        raw = p.get("raw")
        if isinstance(raw, dict) and raw.get("ProcessGuid"):
            host = host_of(p.get("source_type") or spec.source_type, raw, host_overrides)
            by_guid.setdefault((host, raw["ProcessGuid"]), []).append(i)
    events: list = []
    shapes: dict = {}
    for j, (spec, p) in enumerate(payloads):
        raw = p.get("raw")
        if not (isinstance(raw, dict) and raw.get("ParentProcessGuid")):
            continue
        host = host_of(p.get("source_type") or spec.source_type, raw, host_overrides)
        for i in by_guid.get((host, raw["ParentProcessGuid"]), ()):
            pstep = payloads[i][0].label
            if pstep == spec.label:
                continue
            events.append((i, j))
            native = p.get("source_type") == "sysmon" and raw.get("EventID") == 1
            key = (pstep, spec.label)
            prev = shapes.get(key)
            shapes[key] = "sysmon_eid1_native" if native and prev in (None, "sysmon_eid1_native") else "twin_enrichment"
    return {"events": events, "steps": shapes}


def derive_over_seeds(sdef, host_overrides: dict | None = None, seeds=LINK_SEEDS) -> dict:
    """The step-level link set, which must be IDENTICAL on every seed (the structure varies with the
    seed, the causal truth must not). Raises if it is not."""
    per_seed = {}
    for s in seeds:
        payloads = sdef.build(s)[0]
        per_seed[s] = derive_links(payloads, host_overrides=host_overrides)["steps"]
    first = per_seed[seeds[0]]
    for s, got in per_seed.items():
        if got != first:
            raise RuntimeError(f"{sdef.name}: derived causal links differ across seeds "
                               f"(seed {seeds[0]}: {sorted(first)}, seed {s}: {sorted(got)})")
    return first


def step_order(sdef) -> list:
    return [s.label for s in sdef.steps]


# ---------------------------------------------------------------------------
# the oracle: the original's text + a generated, derived block
# ---------------------------------------------------------------------------
def links_digest(links: list) -> str:
    return hashlib.sha256(json.dumps(links, sort_keys=True).encode()).hexdigest()


def oracle_block(*, original: str, module: str, links: dict, order: list, non_links: list,
                 host_overrides: dict | None) -> dict:
    """The appended oracle fields. ``links`` is ``derive_over_seeds`` output; ``non_links`` is
    ``[(from, to, reason)]`` pairs the twin deliberately separates (checked NOT to be derived links)."""
    rows = [{"from": a, "to": b, "basis": "process_tree", "child_key_shape": shape}
            for (a, b), shape in sorted(links.items(), key=lambda kv: (order.index(kv[0][0]), order.index(kv[0][1])))]
    clash = {(a, b) for a, b, _ in non_links} & set(links)
    if clash:
        raise RuntimeError(f"declared non-links are derived links: {sorted(clash)}")
    block: dict = {
        "keyed_twin": {
            "of": original,
            "independent_of_original": False,
            "counts_toward_n": 0,
            "reason": ("a keyed twin replays the original's events, rules and attack shape and only adds "
                       "process-tree keys and per-host sender addresses; report it with its original as ONE "
                       "scenario (ADR-012 section 3), never as a second independent sample"),
        },
        "causal_links": rows,
        "causal_non_links": [{"from": a, "to": b, "reason": r} for a, b, r in non_links],
        "causal_links_provenance": {
            "derived_by": "eval/twin/keyed_kit.py derive_links (raw-record ParentProcessGuid == ProcessGuid, same host)",
            "builder": f"eval/twin/{module}.py",
            "key_generator": "eval/twin/keyed_kit.py guid (own sha256 generator; not services/shared/causal_keys.py)",
            "links_sha256": links_digest(rows),
            "seeds_checked": ",".join(str(s) for s in LINK_SEEDS),
            "pipeline_output_consulted": False,
            "shares_key_code_with_parsers": False,
        },
    }
    return block


_ID_LINE = re.compile(r'^(oracle_id:\s*")([^"]+)(-v\d+")', re.M)
_SCOPE_LINE = re.compile(r'^(scope:\s*")([^"]+)(")', re.M)


def render_oracle(original_oracle_path: Path, block: dict, *, module: str, original: str) -> str:
    """The keyed oracle text: the original oracle verbatim (so its provenance pins, expectations and
    comments are exactly the ones already reviewed) with a generated header, a renamed id/scope and the
    derived block appended. Deterministic."""
    text = Path(original_oracle_path).read_text(encoding="utf-8")
    if not _ID_LINE.search(text) or not _SCOPE_LINE.search(text):
        raise RuntimeError(f"{original_oracle_path.name}: cannot find oracle_id / scope lines to rename")
    text = _ID_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}-keyed{m.group(3)}", text, count=1)
    text = _SCOPE_LINE.sub(lambda m: f"{m.group(1)}{m.group(2)}-keyed{m.group(3)}", text, count=1)
    header = (
        "# =============================================================================\n"
        f"# GENERATED by eval/twin/keyed_kit.py from {original_oracle_path.name} + the builder in\n"
        f"# eval/twin/{module}.py (ADR-012 WP 7). DO NOT EDIT BY HAND: test_keyed_twins.py regenerates it and\n"
        "# fails on any difference. Everything below the original oracle text is derived from the raw records\n"
        "# the keyed builder emits (never from a parser or alert).\n"
        f"# This is a KEYED TWIN of `{original}`: same events, same rules, same expectations -- it only adds\n"
        "# Sysmon-shaped process-tree keys and per-host sender addresses. It is NOT an independent scenario\n"
        "# (keyed_twin.independent_of_original: false, counts_toward_n: 0).\n"
        "# =============================================================================\n")
    tail = ("\n# ---- derived by keyed_kit (ADR-012 WP 7): causal truth for the process_tree basis ----\n"
            + yaml.safe_dump(block, sort_keys=False, default_flow_style=False, width=110))
    return header + text.rstrip("\n") + "\n" + tail


def write_oracle(sdef, original_sdef, *, module: str, non_links: list, host_overrides: dict | None) -> str:
    links = derive_over_seeds(sdef, host_overrides)
    block = oracle_block(original=original_sdef.name, module=module, links=links, order=step_order(sdef),
                         non_links=non_links, host_overrides=host_overrides)
    return render_oracle(original_sdef.oracle_path, block, module=module, original=original_sdef.name)


def main(argv=None) -> int:  # pragma: no cover - maintenance helper: regenerate the four keyed oracles
    import importlib
    import sys
    if str(TWIN) not in sys.path:
        sys.path.insert(0, str(TWIN))
    check = "--check" in (argv if argv is not None else sys.argv[1:])
    bad = 0
    for name in ("win_credential_theft", "ransomware", "phishing_bec", "supply_chain_ci"):
        mod = importlib.import_module(f"storyline_{name}_keyed")
        text = mod.render_oracle_text()
        path = mod.STORYLINE.oracle_path
        if check:
            same = path.exists() and path.read_text(encoding="utf-8") == text
            print(f"[{'OK' if same else 'FAIL'}] {path.name} {'matches' if same else 'differs from'} the derived text")
            bad += 0 if same else 1
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {path.name}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
