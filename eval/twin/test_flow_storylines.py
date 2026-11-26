"""Acceptance test for the three ``flow_*`` storylines (ADR-012 WP 7, basis ``network_flow``), 2026-11-20.

Standalone (NOT pytest): ``[OK]``/``[FAIL]`` lines, exit 0 only when every check passes. Run:

    python eval/twin/test_flow_storylines.py

What is pinned, per storyline (``flow_suricata_c2_exfil``, ``flow_zeek_ot_pivot``,
``flow_suricata_modbus_sabotage``), each check with a negative control where one is meaningful:

  (a) determinism            same seed -> identical payloads; a different seed changes the structure
  (b) real parsers           every payload parses on its REAL parser, no dead letters
  (c) key bookkeeping        the book's (step, key) notes equal the keys read back from the RAW records
  (d) truth derivation       the oracle's ``causal_links`` equal the links derived from the builder's own keys
                             (tamper / shuffle / cross-scope controls prove the derivation has teeth)
  (e) independence           no builder module imports ``causal_keys`` or reads a parsed event
  (f) oracle guards          provenance pins hold; every link names expected steps; forbidden pairs declared
  (g) sender identity        every sensor ships under its own ``meta.shipper_ip``, distinct across sensors
  (h) scope                  the bystander control carries a key that a value comparison WOULD link
  (i) parser key carriage    which record kinds keep their flow key through the real parser (reported)
  (j) ADR-012 n bar          links per storyline / share / total: >= 18 gradable links over >= 3 storylines, none above
                             8 (20 % of the ADR 40-link total)
  (k) ADR-011 F4             >= 2 forbidden pairs per storyline survive to distinct timed edges (a1 funnel)
  (l) trigger claims         every step the builder declares a TRIGGER step raises its own alert on the REAL detector,
                             that alert carries a flow key, and no alert id is shared by two attack steps (no fold)
  (m) graded links           the REAL ws4 -> ws8 pipeline emits the truth: every truth link gradable, matched, precision
                             1.0 / recall 1.0 on seed 7, and the key_shuffle control collapses the pooled metrics
"""
from __future__ import annotations

import ast
import copy
import importlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TWIN = Path(__file__).resolve().parent
ADVERSARIAL = ROOT / "eval" / "adversarial"
SERVICES = ROOT / "services"
MEASURE = ROOT / "docs" / "adr" / "011-measurements"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import layer_a  # noqa: E402,F401  (import order: report.py collision guard, as test_storylines_wide)
import flow_kit  # noqa: E402
import oracle_provenance as prov  # noqa: E402
import scenario  # noqa: E402
import scenario_registry as reg  # noqa: E402

SEED = 7
NAMES = ("flow_suricata_c2_exfil", "flow_zeek_ot_pivot", "flow_suricata_modbus_sabotage",
         "flow_suricata_ci_runner_tunnels")
MODS = {n: importlib.import_module("storyline_" + n) for n in NAMES}
SDEF = {n: reg.BY_NAME[n] for n in NAMES}
_FAILURES: list = []


def _check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        _FAILURES.append(name)


def _raw_key(payload: dict):
    """The flow key as the RAW record carries it: Suricata ``flow_id`` / Zeek ``uid`` (None for other sources)."""
    st = payload.get("source_type")
    if st not in ("suricata_eve", "zeek_json"):
        return None
    rec = payload["raw"]
    rec = json.loads(rec) if isinstance(rec, str) else rec
    return str(rec.get("flow_id") if st == "suricata_eve" else rec.get("uid"))


def _links(name: str, seed: int = SEED) -> list:
    return MODS[name].derive_causal_links(seed)


# --------------------------------------------------------------------------
def test_determinism_and_parsers() -> dict:
    results = {}
    for n in NAMES:
        sd = SDEF[n]
        a, b = sd.build(SEED), sd.build(SEED)
        _check(f"(a) {n}: the same seed yields identical payloads", a[0] == b[0] and a[2] == b[2])
        other = sd.build(SEED + 4)
        _check(f"(a) {n}: a different seed changes the structure (keys, addresses or counts)", other[0] != a[0])
        _check(f"(a) {n}: the derived truth links do not depend on the seed", _links(n, SEED) == _links(n, SEED + 4))
        result = scenario.run_chain(SEED, strict=True, steps=tuple(sd.steps) + tuple(sd.decoy_steps),
                                    payload_source=sd.build)
        results[n] = result
        _check(f"(b) {n}: every payload parses on its real parser (strict run_chain, no dead letters)",
               not result.check_failures and all(e.parsed for e in result.events),
               f"{len(result.events)} events")
        dec = sd.decoy(SEED)
        _check(f"(b) {n}: the decoy payloads are deterministic and parse",
               dec == sd.decoy(SEED) and len(dec) > 0)
    return results


def test_bookkeeping() -> None:
    for n in NAMES:
        book, _notes = MODS[n]._make(SEED)
        raw_keys = sorted(k for _s, p in book.payloads if (k := _raw_key(p)) is not None)
        noted = sorted(k for _st, _ns, _sc, k, _ts in book.notes + book.context)
        _check(f"(c) {n}: the book's keys (trigger + context) equal the keys read back from the RAW records",
               raw_keys == noted, f"{len(noted)} keyed records")
        _check(f"(c) {n}: trigger notes are a proper subset: every truth endpoint is a declared trigger record",
               0 < len(book.notes) < len(noted))
        steps = {s.label for s in SDEF[n].steps} | {s.label for s in SDEF[n].decoy_steps}
        _check(f"(c) {n}: every payload belongs to a declared step", {s.label for s, _p in book.payloads} <= steps)


def test_truth_derivation() -> None:
    for n in NAMES:
        oracle = reg.load_oracle(SDEF[n])
        want = [(lk["from"], lk["to"], lk["basis"]) for lk in oracle.get("causal_links") or []]
        got = [(lk["from"], lk["to"], lk["basis"]) for lk in _links(n)]
        _check(f"(d) {n}: oracle causal_links == links derived from the builder's own flow keys",
               want == got and len(want) > 0, f"{len(want)} links")
        _check(f"(d) {n}: every link is basis network_flow", all(b == "network_flow" for _f, _t, b in want))
        # NEGATIVE: a tampered oracle list is detected
        tampered = want[:-1]
        _check(f"(d) {n}: NEGATIVE: a link deleted from the oracle no longer equals the derivation", tampered != got)
        # NEGATIVE: key_shuffle -- permute the keys among records of one scope; the derived links must change
        book, _x = MODS[n]._make(SEED)
        order = MODS[n].STEP_ORDER
        by_scope: dict = {}
        for i, (_st, _ns, scope, _k, _ts) in enumerate(book.notes):
            by_scope.setdefault(scope, []).append(i)
        shuffled = list(book.notes)
        rng = random.Random(99)
        for idxs in by_scope.values():
            keys = [book.notes[i][3] for i in idxs]
            rng.shuffle(keys)
            for i, k in zip(idxs, keys):
                shuffled[i] = shuffled[i][:3] + (k,) + shuffled[i][4:]
        _check(f"(d) {n}: NEGATIVE: key_shuffle (keys permuted inside each scope) changes the derived links",
               flow_kit.derive_links(shuffled, order) != flow_kit.derive_links(book.notes, order))
        # NEGATIVE: key_drop -- no keys, no links
        _check(f"(d) {n}: NEGATIVE: key_drop (no keys) derives no link", flow_kit.derive_links([], order) == [])
    # scope controls on the derivation itself
    order = ["a", "b"]
    same = [("a", "network_flow", "suricata:s1", "42", 1), ("b", "network_flow", "suricata:s1", "42", 2)]
    cross = [("a", "network_flow", "suricata:s1", "42", 1), ("b", "network_flow", "suricata:s2", "42", 2)]
    _check("(d) POSITIVE: the same key in the same scope links the two steps",
           flow_kit.derive_links(same, order) == [{"from": "a", "to": "b", "basis": "network_flow"}])
    _check("(d) NEGATIVE: the same key VALUE on a different sensor does not link (scope is part of the key)",
           flow_kit.derive_links(cross, order) == [])
    chain = [("a", "network_flow", "z", "k", 1), ("b", "network_flow", "z", "k", 2), ("c", "network_flow", "z", "k", 3)]
    _check("(d) a group over three steps yields the neighbour chain (2 links), never a clique (3)",
           len(flow_kit.derive_links(chain, ["a", "b", "c"])) == 2)


def test_independence() -> None:
    files = [TWIN / "flow_kit.py"] + [TWIN / f"storyline_{n}.py" for n in NAMES]
    bad = []
    for f in files:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""]
            for m in mods:
                if "causal_keys" in m or m.split(".")[0] in ("parsers", "ws2", "main", "report", "engine", "window"):
                    bad.append(f"{f.name} imports {m}")
    _check("(e) the builders import neither causal_keys nor any parser/engine/report module (truth is independent)",
           not bad, "; ".join(bad))
    text = (TWIN / "flow_kit.py").read_text(encoding="utf-8")
    _check("(e) flow_kit reads no parsed event (no 'unmapped' access, no 'normalize')",
           "unmapped" not in text.replace("unmapped.", "").split('"""', 2)[-1] and "normalize" not in text.split('"""', 2)[-1])


def test_oracle_guards() -> None:
    for n in NAMES:
        oracle = reg.load_oracle(SDEF[n])
        _check(f"(f) {n}: the oracle still matches the rule text it was authored from (provenance pin)",
               prov.check(oracle) == [], str(prov.check(oracle)))
        seq = set(oracle["expected_sequence"])
        links = oracle.get("causal_links") or []
        _check(f"(f) {n}: every causal link names two steps of expected_sequence",
               all(lk["from"] in seq and lk["to"] in seq for lk in links))
        rel = oracle["allowed_relationships"]
        forb = [r for r in rel if not r["allowed"]]
        alert_steps = {k for k, v in oracle["detection_points"].items() if v.get("expected_rules")}
        pairs = [r for r in forb if r["from"] in alert_steps and r["to"] in alert_steps]
        _check(f"(f) {n}: >= 2 forbidden pairs have two alert-raising steps (the candidates for ADR-011 F4)",
               len(pairs) >= 2, f"{len(pairs)} of {len(forb)} forbidden")
        bystanders = [r for r in forb if r["to"] not in seq]
        _check(f"(f) {n}: a bystander control is declared forbidden and sits outside expected_sequence",
               len(bystanders) >= 1 and all(r["to"] in {s.label for s in SDEF[n].decoy_steps} for r in bystanders))
        linked = {lk["from"] for lk in links} | {lk["to"] for lk in links}
        _check(f"(f) {n}: no truth link touches a bystander step", not (linked & {r["to"] for r in bystanders}))
        o2 = copy.deepcopy(oracle)
        o2["provenance"]["pipeline_run_before_authoring"] = True
        _check(f"(f) {n}: NEGATIVE: an oracle admitting the pipeline ran first FAILS the pin",
               any("pipeline_run_before_authoring" in p for p in prov.check(o2)))


def test_sender_identity() -> None:
    for n in NAMES:
        book, _x = MODS[n]._make(SEED)
        by_sensor: dict = {}
        for _s, p in book.payloads:
            if p["source_type"] in ("suricata_eve", "zeek_json"):
                by_sensor.setdefault(p["meta"].get("shipper_ip"), set()).add(p["meta"].get("ip"))
        _check(f"(g) {n}: every sensor record carries meta.shipper_ip, one meta.ip per shipper",
               None not in by_sensor and all(len(v) == 1 for v in by_sensor.values()), str(sorted(by_sensor)))
    sensors = {s.ip for m in MODS.values() for s in vars(m).values() if isinstance(s, flow_kit.Sensor)}
    count = sum(1 for m in MODS.values() for s in vars(m).values() if isinstance(s, flow_kit.Sensor))
    _check("(g) sensor shipper addresses are distinct across sensors and storylines", len(sensors) == count,
           f"{count} sensors")


def test_scope_bystander() -> None:
    for n, scopes in (("flow_suricata_c2_exfil", {"suricata:perimeter-ids", "suricata:dmz-ids"}),
                      ("flow_suricata_ci_runner_tunnels", {"suricata:build-edge-ids", "suricata:ci-ids-b"})):
        book, _x = MODS[n]._make(SEED)
        by_key: dict = {}
        for _st, _ns, scope, key, _ts in book.notes + book.context:
            by_key.setdefault(key, set()).add(scope)
        shared = [k for k, sc in by_key.items() if len(sc) > 1]
        _check(f"(h) {n}: one flow_id VALUE appears on two sensors (a value-only join would link)",
               len(shared) == 1 and by_key[shared[0]] == scopes, str(shared))
        _check("(h) ... and the derivation, scoped, gives that bystander no link",
               not any("bystander" in lk["from"] + lk["to"] for lk in _links(n)))
    for n, step in (("flow_zeek_ot_pivot", "bystander_hmi_poll"), ("flow_suricata_modbus_sabotage", "bystander_historian_poll")):
        book, _x = MODS[n]._make(SEED)
        mine = {k for st, _ns, _sc, k, _ts in book.notes + book.context if st == step}
        attack = {k for st, _ns, _sc, k, _ts in book.notes + book.context if st != step}
        _check(f"(h) {n}: the bystander polls the same PLC over its OWN flow key (shared entity, no shared key)",
               len(mine) == 1 and not (mine & attack))


def test_parser_key_carriage(results: dict) -> None:
    carried: dict = {}
    for n, result in results.items():
        for ev in result.events:
            p = ev.raw_payload
            raw_key = _raw_key(p)
            if raw_key is None or not ev.event:
                continue
            rec = json.loads(p["raw"]) if isinstance(p["raw"], str) else p["raw"]
            kind = rec.get("event_type") or ("zeek_dns" if "query" in rec else "zeek_modbus" if "func" in rec else "zeek_conn")
            u = ev.event.get("unmapped") or {}
            found = {str((u.get("ids") or {}).get("flow_id")), str(((u.get("suricata") or {}).get("flow") or {}).get("flow_id")),
                     str((u.get("dns") or {}).get("uid")), str(((u.get("zeek") or {}).get("conn") or {}).get("uid"))}
            ok = raw_key in found
            c = carried.setdefault(kind, [0, 0])
            c[0] += ok
            c[1] += 1
    for kind, (ok, total) in sorted(carried.items()):
        print(f"      parser key carriage: {kind:<12} {ok}/{total} records keep their flow key through the real parser")
    for kind in ("alert", "flow", "zeek_conn", "zeek_dns"):
        _check(f"(i) the real parser keeps the flow key on every {kind} record", kind in carried and carried[kind][0] == carried[kind][1])  # noqa: E501


def test_bar() -> dict:
    counts = {n: len(_links(n)) for n in NAMES}
    total = sum(counts.values())
    share = {n: round(100.0 * c / total, 1) for n, c in counts.items()}
    print(f"      network_flow truth links: {counts} total={total} shares of these(%)={share}")
    _check("(j) >= 18 network_flow truth links in total (every one gradable: see (m))", total >= 18, str(total))
    _check("(j) across >= 3 storylines", sum(1 for c in counts.values() if c > 0) >= 3)
    _check("(j) no storyline holds more than 8 links (20 % of the ADR 40-link total)", max(counts.values()) <= 8,
           str(counts))
    for n in NAMES:
        oracle = reg.load_oracle(SDEF[n])
        alert = {k for k, v in oracle["detection_points"].items() if v.get("expected_rules")}
        links = oracle["causal_links"]
        _check(f"(j) {n}: every truth link has two alert-raising endpoints (trigger-level truth)",
               all(lk["from"] in alert and lk["to"] in alert for lk in links), f"{len(links)} links")
    return counts


def test_f4() -> None:
    sys.path.insert(0, str(MEASURE))
    import a1  # noqa: PLC0415
    import cap  # noqa: PLC0415
    for n in NAMES:
        c = cap.capture(SDEF[n])
        A, gl = a1.prep(c)
        rows = [a1.pair_flags(A, gl, rel) for rel in A["rels"]]
        f4 = [r for r in rows if not r["allowed"] and r["F4"]]
        print(f"      {n}: forbidden pairs at F4 = {[(r['f'], r['t']) for r in f4]}")
        _check(f"(k) {n}: >= 2 forbidden pairs survive to distinct timed edges of one incident graph (ADR-011 F4)",
               len(f4) >= 2, f"{len(f4)}")
        byst = [r for r in rows if not r["allowed"] and r["t"].startswith("bystander")]
        _check(f"(k) {n}: the bystander pair does not (it is unjoined and unalerted)", all(not r["F3"] for r in byst))


def _pipeline(n: str, seed: int = SEED):
    """Real parsers -> real ws4 alerts (``report._build_chain_alerts``), for storyline ``n``."""
    import report  # noqa: PLC0415
    sd = SDEF[n]
    r = scenario.run_chain(seed, strict=True, steps=tuple(sd.steps) + tuple(sd.decoy_steps), payload_source=sd.build)
    items_all = report._build_chain_alerts(r.events)
    attack = {s.label for s in sd.steps}
    return items_all, [i for i in items_all if i["step"] in attack]


def test_trigger_claims() -> None:
    for n in NAMES:
        book, _x = MODS[n]._make(SEED)
        trig_steps = {st for st, _ns, _sc, _k, _ts in book.notes}
        items_all, items = _pipeline(n)
        alerted = {i["step"] for i in items}
        _check(f"(l) {n}: every declared trigger step raises an alert on the real detector",
               trig_steps <= alerted, str(sorted(trig_steps - alerted)))
        keyed = {i["step"] for i in items if i["alert"].get("causal_keys")}
        _check(f"(l) {n}: ... and that alert carries a flow causal key (the trigger event's)", trig_steps <= keyed,
               str(sorted(trig_steps - keyed)))
        by_id: dict = {}
        for i in items:
            by_id.setdefault(i["alert"]["alert_id"], set()).add(i["step"])
        folded = {k: v for k, v in by_id.items() if len(v) > 1}
        _check(f"(l) {n}: NO alert id is shared by two attack steps (no fold: every step owns its alert)",
               not folded, str(folded))
        byst = {i["step"] for i in items_all if i["step"].startswith("bystander")}
        _check(f"(l) {n}: the bystander raises no alert", not byst)


def test_graded_links() -> None:
    import causal_links as cl  # noqa: PLC0415
    import key_controls as kc  # noqa: PLC0415
    results, shuffled = [], []
    for n in NAMES:
        items_all, items = _pipeline(n)
        alerts = [i["alert"] for i in items_all]
        truth = reg.load_oracle(SDEF[n])["causal_links"]
        g = cl.grade_storyline(n, kc.run_correlation(alerts), truth, items)
        results.append(g)
        _check(f"(m) {n}: every truth link is gradable (both endpoint steps alert)",
               g["n_gradable"] == g["n_truth"] == len(truth) and not g["non_gradable"],
               f"{g['n_gradable']}/{g['n_truth']}")
        _check(f"(m) {n}: ws8 emits every gradable link and nothing else (precision 1.0, recall 1.0)",
               g["matched"] == g["n_gradable"] and g["n_predicted"] == g["matched"] and g["unmapped"] == 0,
               f"matched {g['matched']} predicted {g['n_predicted']} unmapped {g['unmapped']}")
        _check(f"(m) {n}: every matched link points the way the truth does and is not order-conflicted",
               g["direction_accuracy"]["value"] == 1.0)
        case = {"name": n, "alerts": alerts, "items": items, "truth": truth}
        shuffled.append(kc.run_controls(case, SEED)["key_shuffle"])
    pooled, shuf = cl.combine(results), cl.combine(shuffled)
    sc = cl.shuffle_collapsed(pooled, shuf)
    print(f"      pooled: gradable {pooled['n_gradable']}, precision {pooled['precision']['value']}, recall "
          f"{pooled['recall']['value']}; key_shuffle precision {shuf['precision']['value']} recall {shuf['recall']['value']}")
    _check("(m) pooled: >= 18 gradable links, all matched",
           pooled["n_gradable"] >= 18 and pooled["matched"] == pooled["n_gradable"])
    _check("(m) pooled: key_shuffle collapses precision AND recall to <= 0.25 x baseline", sc["ok"], str(sc))
    _check("(m) NEGATIVE: an uncollapsed 'shuffle' (the baseline itself) fails the collapse check",
           not cl.shuffle_collapsed(pooled, pooled)["ok"])


def main() -> int:
    results = test_determinism_and_parsers()
    test_bookkeeping()
    test_truth_derivation()
    test_independence()
    test_oracle_guards()
    test_sender_identity()
    test_scope_bystander()
    test_parser_key_carriage(results)
    test_bar()
    test_f4()
    test_trigger_claims()
    test_graded_links()
    print()
    if _FAILURES:
        print(f"FAILED {len(_FAILURES)} check(s): {_FAILURES}")
        return 1
    print("ALL flow_* storyline checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
