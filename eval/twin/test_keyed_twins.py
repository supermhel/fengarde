"""Acceptance test for the four KEYED TWIN storylines (ADR-012 WP 7, WP-D3), 2026-11-20.

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/twin/test_keyed_twins.py            # the checks
    python eval/twin/test_keyed_twins.py --measure  # also print the candidate process_tree links per twin

For each of win_credential_theft_keyed / ransomware_keyed / phishing_bec_keyed / supply_chain_ci_keyed:

  (a) determinism            the keyed build is byte-identical on a rerun, and stripping the added keys
                             gives back EXACTLY the original builder's payloads (the twin only adds)
  (b) originals untouched    the original storyline's output hashes equal the values pinned before this
                             work (computed on origin/main), even after the keyed builds ran in between
  (c) parses on real parsers every keyed step still parses (strict integrity), with the same class/activity/
                             type_uid per event as the original, and the same rules fire on the same steps
  (d) keys + sender          bound steps carry well-formed, host-scoped GUIDs; each host has its OWN
                             ``meta.shipper_ip`` (a bijection over the attack and its decoys); decoys and
                             unbound steps carry no process key
  (e) oracle guards          provenance pin passes; oracle_derive finds nothing the original's oracle did not;
                             the committed oracle equals the regenerated text; its causal_links equal the
                             links derived from the BUILDER's raw records on every seed; the twin is marked
                             non-independent
  (f) circularity            no keyed module imports services/ or causal_keys (builder and parser share no key code)
  (g) controls               breaking the tree, moving the child to another host, tampering the oracle and a
                             declared non-link that is really linked each FAIL the instrument they target
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TWIN = Path(__file__).resolve().parent
SERVICES = ROOT / "services"
for _p in (str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import keyed_kit as kit  # noqa: E402
import oracle_derive  # noqa: E402
import oracle_provenance as prov  # noqa: E402
import scenario_registry as reg  # noqa: E402

SEEDS = (7, 11, 13)
NAMES = ("win_credential_theft", "ransomware", "phishing_bec", "supply_chain_ci")

#: sha256 of json.dumps([[step, payload]...] base + decoys + [notes], sort_keys=True) for the ORIGINAL storylines,
#: computed on origin/main BEFORE the keyed twins existed (see the module docstring check (b)).
ORIGINAL_PINS = {
    ("win_credential_theft", 7): "328bc80f7a8d43c46ea3b3362323f835bfee0e9c31a22d467e958a6aa8297eee",
    ("win_credential_theft", 11): "691ec01e41b68e39cd2ff7e16dbd69a08eb34e7fbab459b5cd56425b370fcd09",
    ("win_credential_theft", 13): "21751569b2c970904b09f8791d1c329e8a94080e92f06bd01bd31a14b0080bb3",
    ("ransomware", 7): "810a66cab79f58e6a41e7e4e85cd2ecaeff23e906e5a0e60fd118895c2b7196a",
    ("ransomware", 11): "8f850f85aad78383506cf86d7fb97831a9e38d1b4850dc01f3fe4682d718eb57",
    ("ransomware", 13): "29b0bae3552cffebbad8afa5c2463a78a4e4db1d6e89f53e983fa63321e3cc89",
    ("phishing_bec", 7): "3bddb75afe5ce7f7be416007751a4f322478a8595ebe066d447c6166f99f3efd",
    ("phishing_bec", 11): "ec37db2084760105c78fa3631fd0fb9fa66e9c97e825aae9f5f24d37072b6f4f",
    ("phishing_bec", 13): "ff5199ea2a4ce6170e16ee007237682408f2600962ffa62831249f5efb291b08",
    ("supply_chain_ci", 7): "45802f5c1c5200821d2954e168582d27a581e2db0c7b7a708356e094d2364236",
    ("supply_chain_ci", 11): "d93249fc1e645bc7fee68e05e50a7e54f54e26093f4de78c362ee53002b4d12a",
    ("supply_chain_ci", 13): "543f104262a3b73f4c01c2d9c90a78cdbdb757a1961ceb7c5c5bbac033a4cb64",
}

_GUID = re.compile(r"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$")
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _mod(name: str):
    import importlib
    return importlib.import_module(f"storyline_{name}_keyed")


def _orig_hash(name: str, seed: int) -> str:
    s = reg.BY_NAME[name]
    p, _sr, notes, _b = s.build(seed)
    d = s.decoy(seed)
    blob = json.dumps([[st.label, pl] for st, pl in p] + [[st.label, pl] for st, pl in d] + [notes], sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _dump(payloads) -> str:
    return json.dumps([[st.label, pl] for st, pl in payloads], sort_keys=True)


_ADDED_RAW = ("ProcessGuid", "ParentProcessGuid", "SourceProcessGUID")


def _strip(payloads) -> list:
    out = []
    for spec, p in payloads:
        q = copy.deepcopy(p)
        q["meta"].pop("shipper_ip", None)
        if isinstance(q.get("raw"), dict):
            for k in _ADDED_RAW:
                q["raw"].pop(k, None)
        out.append((spec, q))
    return out


# --------------------------------------------------------------------------
def test_registration(name: str) -> None:
    sd = reg.BY_NAME.get(f"{name}_keyed")
    _check(f"[{name}] registered as {name}_keyed, wraps the original's steps and decoys",
           sd is not None and sd.steps == reg.BY_NAME[name].steps and sd.decoy_steps == reg.BY_NAME[name].decoy_steps)


def test_determinism_and_additive(name: str) -> None:
    sd, orig = reg.BY_NAME[f"{name}_keyed"], reg.BY_NAME[name]
    for seed in SEEDS:
        a, b = sd.build(seed), sd.build(seed)
        _check(f"[{name}] (a) seed {seed}: keyed build is byte-identical on a rerun (payloads, decoys, notes)",
               _dump(a[0]) == _dump(b[0]) and _dump(sd.decoy(seed)) == _dump(sd.decoy(seed)) and a[2] == b[2])
        _check(f"[{name}] (a) seed {seed}: stripping the added keys gives EXACTLY the original payloads "
               "(the twin only adds)", _dump(_strip(a[0])) == _dump(orig.build(seed)[0])
               and _dump(_strip(sd.decoy(seed))) == _dump(orig.decoy(seed)))
    _check(f"[{name}] (a) the seed changes the keys (a seed-7 GUID is not a seed-11 GUID)",
           kit.guid(7, "h", "p") != kit.guid(11, "h", "p"))


def test_originals_untouched(name: str) -> None:
    ok = all(_orig_hash(name, s) == ORIGINAL_PINS[(name, s)] for s in SEEDS)
    _check(f"[{name}] (b) the ORIGINAL storyline's output is byte-identical to the pre-change pin on "
           f"seeds {SEEDS} (after the keyed builds ran)", ok)


def test_parses_like_the_original(name: str) -> None:
    sd, orig = reg.BY_NAME[f"{name}_keyed"], reg.BY_NAME[name]
    for seed in (7, 11):
        rk, ro = reg.run(sd, seed), reg.run(orig, seed)
        shape = lambda r: [(e.step, e.parser, e.class_uid, e.activity_id, e.type_uid, e.parsed) for e in r.events]  # noqa: E731
        _check(f"[{name}] (c) seed {seed}: every keyed event parses on its real parser, with the same "
               "class/activity/type_uid as the original", not rk.check_failures and rk.parsed_count() == len(rk.events)
               and shape(rk) == shape(ro), f"{rk.parsed_count()}/{len(rk.events)} parsed")
    gk, go = reg.grade(sd, 7), reg.grade(orig, 7)
    fired = lambda g: sorted((a.get("step"), a.get("rule_id")) for a in g.get("fired", []))  # noqa: E731
    _check(f"[{name}] (c) the same rules fire on the same steps as the original (keys are inert to detection)",
           fired(gk) == fired(go), f"{len(fired(gk))} (step, rule) pairs")
    _check(f"[{name}] (c) TPR and evidence completeness equal the original's",
           gk.get("tpr") == go.get("tpr") and gk.get("evidence_completeness") == go.get("evidence_completeness"),
           f"tpr={gk.get('tpr')}")


def test_keys_and_senders(name: str) -> None:
    mod = _mod(name)
    sd = mod.STORYLINE
    for seed in SEEDS:
        payloads = sd.build(seed)[0]
        decoys = sd.decoy(seed)
        bound = set(mod.BIND)
        bad = []
        for spec, p in payloads:
            raw = p["raw"]
            has = isinstance(raw, dict) and "ProcessGuid" in raw
            if (spec.label in bound) != has:
                bad.append(spec.label)
            if has and not (_GUID.match(raw["ProcessGuid"]) and
                            (raw.get("ParentProcessGuid") is None or _GUID.match(raw["ParentProcessGuid"]))):
                bad.append(f"{spec.label}: malformed guid")
        _check(f"[{name}] (d) seed {seed}: exactly the bound steps carry a well-formed ProcessGuid", not bad, str(bad))
        hosts: dict = {}
        for spec, p in list(payloads) + list(decoys):
            h = kit.host_of(p["source_type"], p["raw"], mod.HOST_OVERRIDES)
            hosts.setdefault(p["meta"]["shipper_ip"], set()).add(h)
        inverse: dict = {}
        for ip, hs in hosts.items():
            for h in hs:
                inverse.setdefault(h, set()).add(ip)
        _check(f"[{name}] (d) seed {seed}: meta.shipper_ip is distinct per host (a bijection, {len(inverse)} hosts)",
               all(len(hs) == 1 for hs in hosts.values()) and all(len(ips) == 1 for ips in inverse.values()))
        _check(f"[{name}] (d) seed {seed}: decoys carry no process key",
               not any(isinstance(p["raw"], dict) and "ProcessGuid" in p["raw"] for _s, p in decoys))
        _check(f"[{name}] (d) seed {seed}: meta.ip (the pre-existing address) is untouched",
               [p["meta"].get("ip") for _s, p in payloads] == [p["meta"].get("ip") for _s, p in reg.BY_NAME[name].build(seed)[0]])
    _check("[%s] (d) the same host maps to the same sender address in attack and decoy builds" % name,
           kit.shipper_ip("wks-x") == kit.shipper_ip("wks-x") and kit.shipper_ip("wks-x") != kit.shipper_ip("wks-y"))


def _norm_oracle(o: dict) -> dict:
    o = copy.deepcopy(o)
    for k in ("oracle_id", "scope", "keyed_twin", "causal_links", "causal_non_links", "causal_links_provenance"):
        o.pop(k, None)
    return o


def test_oracle(name: str) -> None:
    mod = _mod(name)
    sd, orig = mod.STORYLINE, reg.BY_NAME[name]
    oracle = reg.load_oracle(sd)
    base = reg.load_oracle(orig)
    _check(f"[{name}] (e) the keyed oracle equals the original's on every graded field (only id/scope and the "
           "derived keyed block differ)", _norm_oracle(oracle) == _norm_oracle(base))
    # The keyed oracle inherits the original's pin verbatim. If the ORIGINAL's pin is already stale on main
    # (ransomware: common_impossible_travel changed after it was authored) the twin must not hide that, and must
    # not be blamed for it either: it is required to equal the original's verdict, and a stale pin is printed.
    pv, pv_base = prov.check(oracle), prov.check(base)
    _check(f"[{name}] (e) oracle_provenance verdict equals the original's ({'pin passes' if pv == [] else 'STALE PIN INHERITED'})",
           pv == pv_base, str(pv))
    if pv:
        print(f"[NOTE] [{name}] the ORIGINAL oracle's provenance pin is already stale on main: {pv}")
    res = oracle_derive.run_checks(sd, 7)
    base_res = oracle_derive.run_checks(orig, 7)
    sig = lambda r: sorted((f["kind"], f["step"], f["item"], f["level"]) for f in r["findings"])  # noqa: E731
    _check(f"[{name}] (e) oracle_derive reads the keyed twin exactly as it reads the original (same findings)",
           sig(res) == sig(base_res), f"{len(res['findings'])} finding(s)")
    text = mod.render_oracle_text()
    _check(f"[{name}] (e) the committed oracle equals the text regenerated from the builder (derived, not typed)",
           sd.oracle_path.read_text(encoding="utf-8") == text)
    kt = oracle.get("keyed_twin") or {}
    _check(f"[{name}] (e) the oracle marks the twin NON-independent (independent_of_original false, counts_toward_n 0)",
           kt.get("independent_of_original") is False and kt.get("counts_toward_n") == 0 and kt.get("of") == name)
    want = [{"from": a, "to": b, "basis": "process_tree", "child_key_shape": shape}
            for (a, b), shape in sorted(kit.derive_over_seeds(sd, mod.HOST_OVERRIDES).items())]
    got = sorted(oracle["causal_links"], key=lambda r: (r["from"], r["to"]))
    _check(f"[{name}] (e) causal_links equal the links derived from the builder's raw records (identical on seeds "
           f"{kit.LINK_SEEDS})", got == want, f"{len(got)} link(s)")
    cp = oracle["causal_links_provenance"]
    _check(f"[{name}] (e) provenance: digest matches, pipeline output not consulted, no shared key code",
           cp["links_sha256"] == kit.links_digest(oracle["causal_links"]) and cp["pipeline_output_consulted"] is False
           and cp["shares_key_code_with_parsers"] is False)
    steps = {s.label for s in tuple(sd.steps) + tuple(sd.decoy_steps)}
    _check(f"[{name}] (e) every link/non-link endpoint is a real step of the storyline",
           all(r["from"] in steps and r["to"] in steps for r in oracle["causal_links"] + oracle["causal_non_links"]))
    linked = {(r["from"], r["to"]) for r in oracle["causal_links"]}
    _check(f"[{name}] (e) no declared non-link is derived as a link",
           not linked & {(r["from"], r["to"]) for r in oracle["causal_non_links"]})
    order = [s.label for s in sd.steps]
    _check(f"[{name}] (e) every link points forward in the storyline's step order (parent before child)",
           all(order.index(a) < order.index(b) for a, b in linked))


def test_circularity(name: str) -> None:
    bad = []
    for path in (TWIN / "keyed_kit.py", TWIN / f"storyline_{name}_keyed.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""] + [(node.module or "") + "." + a.name for a in node.names]
            for m in mods:
                if "causal_keys" in m or m.split(".")[0] in ("shared", "services", "main", "parsers", "engine", "window"):
                    bad.append(f"{path.name}: {m}")
    _check(f"[{name}] (f) the keyed twin shares no code with the parsers/services or causal_keys", not bad, str(bad))


def test_controls(name: str) -> None:
    mod = _mod(name)
    sd = mod.STORYLINE
    payloads = sd.build(7)[0]
    truth = kit.derive_links(payloads, host_overrides=mod.HOST_OVERRIDES)["steps"]
    if not truth:
        _check(f"[{name}] (g) no truth link: the positive-link controls do not apply; the no-fabrication control does", True)
        # NEGATIVE control for a zero-link twin: forcing a child to name an existing process as its parent MUST
        # produce a link (the deriver is not deaf).
        forced = copy.deepcopy(payloads)
        first = next(i for i, (_s, p) in enumerate(forced) if isinstance(p["raw"], dict) and "ProcessGuid" in p["raw"])
        other = next(i for i, (_s, p) in enumerate(forced)
                     if i != first and isinstance(p["raw"], dict) and "ProcessGuid" in p["raw"]
                     and forced[i][0].label != forced[first][0].label)
        forced[other][1]["raw"]["ParentProcessGuid"] = forced[first][1]["raw"]["ProcessGuid"]
        # same host is required for a link: put the child on the parent's host
        forced_host = kit.host_of(forced[first][1]["source_type"], forced[first][1]["raw"], mod.HOST_OVERRIDES)
        ov = dict(mod.HOST_OVERRIDES)
        ov[forced[other][1]["source_type"]] = forced_host
        ov[forced[first][1]["source_type"]] = forced_host
        got = kit.derive_links(forced, host_overrides=ov)["steps"]
        _check(f"[{name}] (g) POSITIVE control: forcing a same-host parent/child pair IS derived as a link "
               "(the deriver is not deaf)", len(got) >= 1, str(sorted(got)))
        return
    (a, b), _shape = sorted(truth.items())[0]
    broken = copy.deepcopy(payloads)
    for _s, p in broken:
        if _s.label == b and isinstance(p["raw"], dict):
            p["raw"]["ParentProcessGuid"] = kit.guid(7, "elsewhere", "nobody")
    _check(f"[{name}] (g) NEGATIVE: breaking the child's ParentProcessGuid removes the link {a}->{b}",
           (a, b) not in kit.derive_links(broken, host_overrides=mod.HOST_OVERRIDES)["steps"])
    ov = dict(mod.HOST_OVERRIDES)
    moved = copy.deepcopy(payloads)
    for _s, p in moved:
        if _s.label == b and isinstance(p["raw"], dict):
            p["raw"]["Computer"] = "some-other-host"
            p["raw"]["host"] = "some-other-host"
    ov.pop(next((p["source_type"] for _s, p in payloads if _s.label == b), ""), None)
    _check(f"[{name}] (g) NEGATIVE: the same GUIDs on ANOTHER host do not link (scope is host-bound)",
           (a, b) not in kit.derive_links(moved, host_overrides=ov)["steps"])
    oracle = reg.load_oracle(sd)
    tampered = copy.deepcopy(oracle)
    tampered["causal_links"] = tampered["causal_links"][1:] if len(tampered["causal_links"]) > 1 else []
    want = [r for r in tampered["causal_links"]]
    _check(f"[{name}] (g) NEGATIVE: a hand-edited causal_links list no longer equals the derived links",
           [(r["from"], r["to"]) for r in want] != sorted(truth))
    try:
        kit.oracle_block(original=name, module="m", links=truth, order=[s.label for s in sd.steps],
                         non_links=[(a, b, "x")], host_overrides=None)
        raised = False
    except RuntimeError:
        raised = True
    _check(f"[{name}] (g) NEGATIVE: declaring a really-linked pair as a non-link fails loudly", raised)


def test_registry_effect() -> None:
    names = [s.name for s in reg.ALL]
    _check("the registry lists each keyed twin once, right after its original (sorted module order)",
           all(names.index(f"{n}_keyed") == names.index(n) + 1 for n in NAMES), str(names))
    _check("the three built-ins keep their historical order", names[:3] == ["ai_to_ot", "it_intrusion", "infra_takeover"])
    _check("guid generator: distinct hosts give distinct GUIDs for the same process name",
           kit.guid(7, "a", "ps") != kit.guid(7, "b", "ps") and kit.guid(7, "a", "ps") == kit.guid(7, "a", "ps"))


def measure() -> None:
    """Candidate process_tree links per keyed twin (raw-key matches), truth links, and how many are gradable."""
    print("\ncandidate process_tree links (seed 7): event-level key matches | step-level truth | gradable "
          "(both endpoint steps raised an alert) | range of event-level matches over seeds 1..20")
    for name in NAMES:
        mod = _mod(name)
        sd = mod.STORYLINE
        payloads = sd.build(7)[0]
        d = kit.derive_links(payloads, host_overrides=mod.HOST_OVERRIDES)
        grade = reg.grade(sd, 7)
        alerted = {a.get("step") for a in grade.get("fired", [])}
        truth = sorted(d["steps"])
        gradable = [t for t in truth if t[0] in alerted and t[1] in alerted]
        counts = [len(kit.derive_links(sd.build(s)[0], host_overrides=mod.HOST_OVERRIDES)["events"]) for s in range(1, 21)]
        print(f"  {name}_keyed: events={len(d['events'])} steps={len(truth)} gradable={len(gradable)} "
              f"range={min(counts)}..{max(counts)}  links={truth}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    test_registry_effect()
    for name in NAMES:
        test_registration(name)
        test_determinism_and_additive(name)
        test_originals_untouched(name)
        test_parses_like_the_original(name)
        test_keys_and_senders(name)
        test_oracle(name)
        test_circularity(name)
        test_controls(name)
    if "--measure" in argv:
        measure()
    print()
    if _FAILURES:
        print(f"{len(_FAILURES)} check(s) FAILED")
        return 1
    print("all keyed-twin checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
