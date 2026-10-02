"""evasion_axes -- the measuring library behind ``evasion_cost``: how far must an
attacker bend a burst before a stateful rule-set stops firing, and by what means?

WHY THIS EXISTS (2026-10-02)
    ``evasion_search`` measures four axes (loss, uniform slow-down, address
    spread, account spread) for six burst steps and ignores everything else a
    real adversary can do. This library adds the axes that matter and a place to
    state the answer as a COST (several incommensurable numbers) instead of a
    pass/fail:

      loss             events the attacker must forgo (linear scan: not assumed monotone)
      timing           the OPTIMAL slow schedule (exact: a greedy minimum, not a uniform
                       stretch) and, for a periodicity rule, the jitter that breaks it
      key spread       fewest keys of each kind that evade, and the JOINT frontier over two
                       kinds (a companion rule is exactly what makes one kind "immune")
      obfuscation      re-spelling an identity the log source treats as ONE entity
                       (identity canonicalisation) and field injection (attribution
                       forgery), each judged against a cited equivalence table
      clock authority  which timestamp the parser trusts (record vs receipt)

EVERY MEASUREMENT HAS AN INDEPENDENT PREDICTION
    ``predict_set`` replays the burst's NORMALISED events against the rule's declared
    parameters (threshold, window, group_by, distinct_field, periodicity) with its own
    ten-line window model -- no import of the engine's counter. Measured != predicted
    on any cell is a finding about either the pipeline or the predictor; ``agree`` is
    carried on every number so a disagreement cannot hide.

CLASSIFICATION IS BY TABLE, NEVER BY TUNING
    ``evasion_tables.yaml`` says which log fields an attacker controls and which
    spellings a source treats as one identity. An evasion is BUG when it
    preserves identity (or violates field isolation), INHERENT when it needs a
    genuinely different entity, NOT_REACHABLE when the attacker cannot influence
    the field. The tables are security-judgement inputs: every row is
    ``ratified: false`` until the owner signs it, and an unratified row can only
    ever produce an INFO line, never a gate failure.

STDLIB + PyYAML (already imported by evasion_search). Deterministic: no wall clock,
no randomness; every number is a pure function of (scenario, seed, rules).
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADVERSARIAL = Path(__file__).resolve().parent
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
for _p in (str(ADVERSARIAL), str(TWIN), str(SERVICES)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import yaml  # noqa: E402

import evasion_search as es  # noqa: E402
import mutate_generic as mg  # noqa: E402
import probe_session as ps  # noqa: E402
import rule_probes as rp  # noqa: E402
import scenario_registry as reg  # noqa: E402

RULES_DIR = ROOT / "contracts" / "rules"
ALLOWLISTS_DIR = ROOT / "contracts" / "allowlists"
TABLES_PATH = ADVERSARIAL / "evasion_tables.yaml"

#: group_by OCSF path -> key KIND. A kind is a thing an attacker can multiply
#: (addresses, accounts, domains ...). A group_by outside this table is reported
#: ``unsearchable_key`` and counted by the coverage gate -- never silently skipped.
KEY_KINDS = {
    "src_endpoint.ip": "ip",
    "actor.user.name": "account",
    "dst_endpoint.ip": "dst_ip",
    "unmapped.dns.parent_domain": "parent_domain",
    "src_endpoint.hostname": "host",
    "unmapped.mcp.session_id": "session",
    "unmapped.db.object": "db_object",
    "unmapped.target_user.name": "target_account",
    "unmapped.ot.server_id": "ot_server",
}

#: rule-set key -> (scenario, step): the storyline burst that exercises it. Every
#: other stateful rule-set uses a ``rule_probes`` template.
STORYLINE_BURSTS = {
    "common_port_scan": ("it_intrusion", "recon_port_scan"),
    "common_bruteforce": ("it_intrusion", "ssh_bruteforce"),
    "common_lateral_movement": ("it_intrusion", "lateral_movement"),
    "common_dns_exfil": ("it_intrusion", "dns_exfil"),
    "dc_mass_vm_delete": ("infra_takeover", "mass_vm_delete"),
}

#: Largest key count / spread searched before "immune" is declared.
_GRID_K_2 = 6          # joint frontier: K up to 6 for two kinds
_GRID_K_3 = 4          # ... and up to 4 for three (no shipped rule-set has three kinds)


# ===========================================================================
# Rule model (read straight from the YAML -- independent of the engine)
# ===========================================================================
@dataclass(frozen=True)
class RuleParams:
    id: str
    name: str
    threshold: int
    window_seconds: int
    group_by: str
    distinct_field: str | None
    periodicity: dict | None
    companion_of: str | None
    level: str
    detection: dict = field(compare=False, hash=False, default_factory=dict)

    @property
    def window_ms(self) -> int:
        return int(round(self.window_seconds * 1000))

    @property
    def kind(self) -> str | None:
        return KEY_KINDS.get(self.group_by)


def _norm_bytes(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n")


def _allowlist_refs(node) -> list:
    """Names under any ``not_in:`` key in a detection block (recursive)."""
    out: list = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "not_in" and isinstance(v, str):
                out.append(v)
            else:
                out.extend(_allowlist_refs(v))
    elif isinstance(node, list):
        for v in node:
            out.extend(_allowlist_refs(v))
    return out


def load_stateful_rules(rules_dir=None) -> dict:
    """name (file stem) -> RuleParams for every stateful rule in ``rules_dir``."""
    rules_dir = Path(rules_dir) if rules_dir is not None else RULES_DIR
    out: dict = {}
    for f in sorted(rules_dir.glob("*.yml")):
        d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        siem = d.get("siem") or {}
        if not d.get("id") or siem.get("threshold") is None or siem.get("window_seconds") is None:
            continue
        out[f.stem] = RuleParams(
            id=d["id"], name=f.stem, threshold=int(siem["threshold"]),
            window_seconds=int(siem["window_seconds"]), group_by=siem.get("group_by", "src_endpoint.ip"),
            distinct_field=siem.get("distinct_field"), periodicity=siem.get("periodicity"),
            companion_of=siem.get("companion_of") if isinstance(siem.get("companion_of"), str) else None,
            level=d.get("level", "medium"), detection=d.get("detection") or {})
    return out


@dataclass
class RuleSet:
    """A rule plus the companion rules that restate it on another key."""
    key: str
    rules: list
    orphan: bool = False        # a companion whose sibling is not loaded

    @property
    def ids(self) -> set:
        return {r.id for r in self.rules}

    @property
    def names(self) -> list:
        return [r.name for r in self.rules]

    @property
    def kinds(self) -> list:
        """Ordered unique group kinds (None entries are unsearchable keys)."""
        seen: list = []
        for r in self.rules:
            if r.kind not in seen:
                seen.append(r.kind)
        return seen

    @property
    def periodic(self) -> bool:
        return any(r.periodicity for r in self.rules)

    def params(self) -> dict:
        return {r.name: {"threshold": r.threshold, "window_seconds": r.window_seconds,
                         "group_by": r.group_by, "distinct_field": r.distinct_field,
                         "periodicity": r.periodicity, "companion_of": r.companion_of}
                for r in self.rules}

    def fingerprint(self, allowlists_dir=None) -> str:
        """sha256 over everything that decides how evadable the set is: the YAML
        parameters, the companions' ids, the SELECTION clauses (a narrowed
        predicate or a ``not_in`` changes evasion cost as surely as a threshold)
        and the content of every allowlist file a ``not_in`` references."""
        allowlists_dir = Path(allowlists_dir) if allowlists_dir is not None else ALLOWLISTS_DIR
        parts: list = []
        for r in sorted(self.rules, key=lambda x: x.name):
            refs = sorted(set(_allowlist_refs(r.detection)))
            shas = {}
            for ref in refs:
                p = allowlists_dir / f"{ref}.yml"
                shas[ref] = (hashlib.sha256(_norm_bytes(p.read_bytes())).hexdigest()
                             if p.exists() else "MISSING")
            parts.append({"name": r.name, "id": r.id, "threshold": r.threshold,
                          "window_seconds": r.window_seconds, "group_by": r.group_by,
                          "distinct_field": r.distinct_field, "periodicity": r.periodicity,
                          "companion_of": r.companion_of, "detection": r.detection, "allowlists": shas})
        blob = json.dumps(parts, sort_keys=True, default=repr)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_rule_sets(rules_dir=None) -> dict:
    """rule-set key (the primary rule's stem) -> RuleSet. A companion whose
    sibling is not loaded becomes an ``orphan`` set of its own -- losing the
    sibling is a change the floor check must see, not a silent re-grouping."""
    rules = load_stateful_rules(rules_dir)
    by_id = {r.id: r for r in rules.values()}
    sets: dict = {}
    for name in sorted(rules):
        r = rules[name]
        if r.companion_of is None or r.companion_of not in by_id:
            sets[name] = RuleSet(name, [r], orphan=r.companion_of is not None)
    for name in sorted(rules):
        r = rules[name]
        if r.companion_of is not None and r.companion_of in by_id:
            sets[by_id[r.companion_of].name].rules.append(r)
    return dict(sorted(sets.items()))


# ===========================================================================
# Bursts and key setters
# ===========================================================================
@dataclass
class Burst:
    key: str
    step: str
    payloads: list                       # the step's OWN events (spec, payload)
    setters: dict                        # kind -> fn(payload, j) -> bool
    source: str
    production_reachable: bool = True
    reachability_basis: str = ""

    @property
    def n(self) -> int:
        return len(self.payloads)


_ASA_DST = re.compile(r"(dst \w+:)(\d{1,3}(?:\.\d{1,3}){3})")
_DNS_Q = re.compile(r"(query\[\w+\]\s+)(\S+)(\s+from )")


def _set_ip(p: dict, j: int) -> bool:
    return mg.set_src_ip(p, f"198.18.77.{j + 10}")


def _set_account(p: dict, j: int) -> bool:
    base = mg.get_actor(p)
    if base is None:
        return False
    return True if j == 0 else mg.set_actor(p, f"{base}-{j + 1}")


def _set_dst_ip(p: dict, j: int) -> bool:
    if p.get("source_type") != "cisco_asa" or not isinstance(p.get("raw"), str):
        return False
    new, n = _ASA_DST.subn(lambda m: m.group(1) + f"10.0.1.{j + 10}", p["raw"], count=1)
    p["raw"] = new
    return n == 1


def _set_parent_domain(p: dict, j: int) -> bool:
    if p.get("source_type") != "dns_query" or not isinstance(p.get("raw"), str):
        return False

    def sub(m):
        labels = m.group(2).rstrip(".").split(".")
        if len(labels) < 2:
            return m.group(0)
        return m.group(1) + ".".join(labels[:-2] + [f"tun{j}", labels[-1]]) + m.group(3)
    new, n = _DNS_Q.subn(sub, p["raw"], count=1)
    p["raw"] = new
    return n == 1


_STORYLINE_SETTERS = {"ip": _set_ip, "account": _set_account, "dst_ip": _set_dst_ip,
                      "parent_domain": _set_parent_domain}


def reference_burst(key: str, seed: int = 7) -> Burst | None:
    """The burst the cost of rule-set ``key`` is measured on, or None when no
    storyline and no probe template exists for it (the coverage gate then fails
    unless a dated waiver exists)."""
    if key in STORYLINE_BURSTS:
        scen, step = STORYLINE_BURSTS[key]
        payloads = reg.get(scen).build(seed)[0]
        sub = [x for x in payloads if x[0].label == step]
        return Burst(key, step, sub, dict(_STORYLINE_SETTERS), f"storyline:{scen}/{step}")
    probes = rp.all_probes()
    if key in probes:
        pr = probes[key]
        return Burst(key, pr.step, pr.payloads(), dict(pr.setters), f"probe:{pr.key}",
                     pr.production_reachable, pr.reachability_basis)
    return None


# ===========================================================================
# The lab: measured detection + independent prediction for one rule-set
# ===========================================================================
def _dig(ev, dotted: str):
    cur = ev
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _cv(times: list):
    """Coefficient of variation of consecutive deltas (population stdev / mean)."""
    if len(times) < 3:
        return None
    deltas = [b - a for a, b in zip(times, times[1:])]
    mean = sum(deltas) / len(deltas)
    if mean <= 0:
        return None
    var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    return math.sqrt(var) / mean


def predict_rule(rule: RuleParams, events: list) -> bool:
    """Would ``rule`` fire on ``events`` (normalised OCSF, arrival order)?

    An independent ten-line window model: the count at an event is the number
    of earlier-or-equal events of its group with ``time >= t - W`` (inclusive
    edge, as the YAML window is read). Assumes arrival order == time order."""
    window = rule.window_ms
    groups: dict = defaultdict(list)
    for ev in events:
        g = _dig(ev, rule.group_by)
        if g is None:
            continue
        t = ev.get("time")
        dv = None
        if rule.distinct_field:
            dv = _dig(ev, rule.distinct_field)
            if dv is None:
                continue
        lst = groups[str(g)]
        lst.append((t, dv))
        live = [(tt, v) for tt, v in lst if tt >= t - window]
        count = len({v for _, v in live}) if rule.distinct_field else len(live)
        if count < rule.threshold:
            continue
        if rule.periodicity:
            cv = _cv(sorted(tt for tt, _ in live))
            if cv is not None and cv <= rule.periodicity.get("max_cv", 1.0):
                return True
        else:
            return True
    return False


def predict_set(rs: RuleSet, events: list) -> bool:
    return any(predict_rule(r, events) for r in rs.rules)


class Lab:
    """One rule-set, one burst, one probe: ``detected`` is the measurement and
    ``predicted`` the independent model. Both take a payload list."""

    def __init__(self, probe: ps.FastProbe, rs: RuleSet, burst: Burst) -> None:
        self.probe, self.rs, self.burst = probe, rs, burst

    def detected(self, payloads: list) -> bool:
        fired = self.probe.detect(ps.payloads_to_pairs(payloads))
        return any(a.get("step") == self.burst.step and a.get("rule_id") in self.rs.ids for a in fired)

    def predicted(self, payloads: list) -> bool:
        return predict_set(self.rs, self.probe.normalized(ps.payloads_to_pairs(payloads)))

    def both(self, payloads: list) -> tuple:
        return self.detected(payloads), self.predicted(payloads)


# ===========================================================================
# Perturbations
# ===========================================================================
def assign_keys(payloads: list, order: list, counts: dict, setters: dict) -> list:
    """Round-robin the burst over ``counts[kind]`` keys per kind with a mixed-radix
    assignment: the first kind in ``order`` is ``rank % a``, the next
    ``(rank // a) % b``, and so on. A kind with one key is left untouched."""
    out = copy.deepcopy(payloads)
    stride = 1
    for kind in order:
        k = counts.get(kind, 1)
        if k > 1:
            for rank, (_spec, p) in enumerate(out):
                setters[kind](p, (rank // stride) % k)
            stride *= k
    return out


def event_times(payloads: list) -> list:
    return [mg.get_time(p) for _s, p in payloads]


def set_time_all(p: dict, ts: int) -> bool:
    """``mutate_generic.set_time`` plus the ``timestamp`` key it does not know
    (db_audit reads the record's own ``timestamp``, so moving only the envelope
    clock would silently leave that source's events where they were)."""
    ok = mg.set_time(p, ts)
    raw = p.get("raw")
    if isinstance(raw, dict) and "timestamp" in raw:
        raw["timestamp"] = ts
        ok = True
    return ok


def apply_offsets(payloads: list, offsets_ms: list) -> list:
    out = copy.deepcopy(payloads)
    t0 = min(event_times(out))
    for (_s, p), off in zip(out, offsets_ms):
        set_time_all(p, t0 + off)
    return out


def times_follow(lab, payloads: list, offsets_ms: list) -> bool:
    """Verify-by-parse for the timing axis: the NORMALISED event times are the
    requested ones. False means a schedule would be applied to the raw fields
    but the parser reads the time from somewhere this library does not move --
    every timing number would then describe nothing."""
    t0 = min(event_times(payloads))
    want = [t0 + o for o in offsets_ms]
    got = [e.get("time") for e in lab.probe.normalized(ps.payloads_to_pairs(apply_offsets(payloads, offsets_ms)))]
    return got == want


def optimal_slow_offsets(n: int, constraints: list, *, min_gap: int = 1, slack: int = 1) -> list:
    """The EARLIEST offsets (ms) at which ``n`` events can be delivered so that
    no ``T`` of them fall inside any ``W`` window, for every ``(T, W_ms)``.

    Greedy and exact: each event is placed as soon as every constraint allows
    (``o[i] >= o[i-(T-1)] + W + slack``); a pointwise-minimal schedule exists
    because the constraints are monotone. ``slack=1`` is the strict edge (the
    window keeps an event exactly ``W`` old, so ``W + 1`` ms must separate the
    first and the T-th event); ``slack=0`` is the schedule ONE MILLISECOND
    FASTER, which must therefore be detected -- the boundary control."""
    offsets: list = []
    for i in range(n):
        v = offsets[-1] + min_gap if offsets else 0
        for t, w in constraints:
            if t >= 2 and i - (t - 1) >= 0:
                v = max(v, offsets[i - (t - 1)] + w + slack)
        offsets.append(v)
    return offsets


def regular_slow_offsets(n: int, constraints: list, *, slack: int = 1) -> list:
    """Evenly spaced events whose spacing is the smallest that keeps every
    window below its threshold. For a PERIODICITY rule the cheapest slow
    schedule must stay regular -- a clumped one would evade through the
    coefficient of variation instead and would not measure the window."""
    gap = max(math.ceil((w + slack) / (t - 1)) for t, w in constraints if t >= 2)
    return [i * gap for i in range(n)]


def jitter_offsets(n: int, period_ms: int, jitter_permille: int) -> list:
    """Alternating intervals ``p(1+J)``, ``p(1-J)`` -- a deterministic jitter
    whose coefficient of variation is ~J (no randomness to seed)."""
    out, t = [0], 0
    for i in range(n - 1):
        f = 1000 + jitter_permille if i % 2 == 0 else 1000 - jitter_permille
        t += period_ms * f // 1000
        out.append(t)
    return out


# ===========================================================================
# Searches (each returns measured / predicted / agree)
# ===========================================================================
def _first_true(lo: int, hi: int, pred) -> int:
    return es._first_true(lo, hi, pred)


def search_loss(lab: Lab) -> dict:
    """Fewest events the attacker must forgo (evenly spread) so the set goes
    dark. A linear scan, not a bisection: a periodicity rule is not monotone in
    loss (removing events changes the spacing), so monotonicity is not assumed."""
    pl, n, step = lab.burst.payloads, lab.burst.n, lab.burst.step
    m = p = None
    for r in range(1, n + 1):
        thinned = es._thin_step(pl, step, r)
        d, q = lab.both(thinned)
        if m is None and not d:
            m = r
        if p is None and not q:
            p = r
        if m is not None and p is not None:
            break
    return {"forgone_events": m, "predicted": p, "agree": m == p}


def search_spread(lab: Lab, kind: str) -> dict:
    """Fewest keys of ``kind`` (round-robin, every other kind untouched) that
    evade. ``None`` == immune: even one key per event is still detected -- a
    companion rule keyed on another kind is what produces that result."""
    pl, n = lab.burst.payloads, lab.burst.n
    setters = lab.burst.setters

    def at(k):
        return assign_keys(pl, [kind], {kind: k}, setters)

    def dark_m(k):
        return not lab.detected(at(k))

    def dark_p(k):
        return not lab.predicted(at(k))

    def solve(dark):
        if n < 2 or not dark(n):
            return None
        k = _first_true(2, n, dark)
        if k > 2 and not dark(k - 1):
            return k                                   # bisection result confirmed one below
        if k > 2:                                      # non-monotone: fall back to a scan
            return next((x for x in range(2, n + 1) if dark(x)), None)
        return k
    m, p = solve(dark_m), solve(dark_p)
    return {"min_keys": "immune" if m is None else m,
            "predicted": "immune" if p is None else p, "agree": m == p}


def search_joint(lab: Lab, kinds: list) -> dict:
    """The joint Pareto frontier over two kinds: the minimal (a, b) key counts
    that evade, measured on every grid cell and compared with the independent
    prediction cell by cell."""
    assert len(kinds) in (2, 3), "joint frontier is defined for 2 or 3 kinds"
    kmax = _GRID_K_2 if len(kinds) == 2 else _GRID_K_3
    pl, setters = lab.burst.payloads, lab.burst.setters
    cells: dict = {}
    idx = [range(1, kmax + 1)] * len(kinds)
    grid = [()]
    for r in idx:
        grid = [g + (v,) for g in grid for v in r]
    mism = []
    for g in grid:
        counts = dict(zip(kinds, g))
        d, q = lab.both(assign_keys(pl, kinds, counts, setters))
        cells[g] = (d, q)
        if d != q:
            mism.append(list(g))

    def frontier(which):
        dark = [g for g, v in cells.items() if not v[which]]
        return sorted(g for g in dark
                      if not any(h != g and all(h[i] <= g[i] for i in range(len(g))) for h in dark))
    fm, fp = frontier(0), frontier(1)
    return {"kinds": list(kinds), "grid_max": kmax, "frontier": [list(g) for g in fm],
            "predicted": [list(g) for g in fp], "agree": fm == fp, "mismatched_cells": mism}


def search_schedule(lab: Lab) -> dict:
    """Optimal slow delivery of the burst's n events (earliest schedule that
    keeps every rule below threshold) plus its boundary control and the cost of
    the uniform stretch ``evasion_search`` measures, for comparison."""
    pl, n = lab.burst.payloads, lab.burst.n
    cons = [(r.threshold, r.window_ms) for r in lab.rs.rules]
    maker = regular_slow_offsets if lab.rs.periodic else optimal_slow_offsets
    off = maker(n, cons)
    if not times_follow(lab, pl, off):
        return {"searched": False, "agree": True,
                "reason": "the parser's event time does not follow the raw time fields this library moves"}
    sched = apply_offsets(pl, off)
    ev_m, ev_p = lab.both(sched)
    fast = apply_offsets(pl, maker(n, cons, slack=0))
    fa_m, fa_p = lab.both(fast)
    times = event_times(pl)
    span = max(times) - min(times)
    extra_ms = max(0, off[-1] - span)
    uni = es._search_stretch(pl, lab.burst.step, lab.rs.ids)
    uni_extra = None
    if uni is not None and uni < es._STRETCH_CAP_PCT:
        uni_extra = max(0, (span * (uni + 1) // 100) - span)
    ok = (not ev_m) and (not ev_p) and fa_m and fa_p
    leq = True if uni_extra is None else extra_ms <= uni_extra
    # sustained rate: events per second per key a stealthy attacker can keep up forever
    rate = round((n - 1) / (off[-1] / 1000.0), 6) if off[-1] > 0 else None
    return {"schedule": "regular" if lab.rs.periodic else "optimal", "extra_seconds": round(extra_ms / 1000.0, 3),
            "evades": not ev_m, "predicted_evades": not ev_p,
            "one_ms_faster_detected": fa_m, "predicted_one_ms_faster_detected": fa_p,
            "uniform_extra_seconds": None if uni_extra is None else round(uni_extra / 1000.0, 3),
            "optimal_le_uniform": leq, "sustained_events_per_second": rate, "agree": ok and leq,
            "offsets_ms_tail": off[-3:]}


def search_jitter(lab: Lab) -> dict:
    """Smallest jitter (permille of the period) at which a periodicity rule
    stops firing, against the independent model. Only for periodic rule-sets."""
    pl, n = lab.burst.payloads, lab.burst.n
    times = event_times(pl)
    period = (times[-1] - times[0]) // max(1, n - 1)

    def at(j):
        return apply_offsets(pl, jitter_offsets(n, period, j))

    def solve(fn):
        if fn(0):
            return None if fn(999) else _first_true(1, 999, lambda j: not fn(j))
        return 0
    m = solve(lambda j: lab.detected(at(j)))
    p = solve(lambda j: lab.predicted(at(j)))
    cv = next((r.periodicity.get("max_cv") for r in lab.rs.rules if r.periodicity), None)
    return {"min_jitter_permille": m, "predicted": p, "declared_max_cv_permille":
            None if cv is None else int(round(cv * 1000)), "agree": m == p}


# ===========================================================================
# Obfuscation: identity canonicalisation (F2) and attribution forgery (F3)
# ===========================================================================
def load_tables(path=None) -> dict:
    p = Path(path) if path is not None else TABLES_PATH
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


#: spelling operators. The KEY of each is the equivalence tag a table row lists
#: when the source treats the respelling as the SAME entity.
RESPELL_OPS = {
    "casefold": lambda s: s.upper() if s != s.upper() else s.lower(),
    "strip": lambda s: s + " ",
    "domain_prefix": lambda s: "CORP\\" + s,
    "upn_suffix": lambda s: s + "@corp.local",
    "trailing_dot": lambda s: s + ".",
}


def _respell_account(p: dict, op: str) -> bool:
    base = mg.get_actor(p)
    return base is not None and mg.set_actor(p, RESPELL_OPS[op](base))


def _respell_parent_domain(p: dict, op: str) -> bool:
    if p.get("source_type") != "dns_query" or not isinstance(p.get("raw"), str):
        return False
    new, n = _DNS_Q.subn(lambda m: m.group(1) + RESPELL_OPS[op](m.group(2).rstrip(".")) + m.group(3),
                         p["raw"], count=1)
    p["raw"] = new
    return n == 1


_RESPELLERS = {"account": _respell_account, "target_account": None, "parent_domain": _respell_parent_domain}


def _respell_target_account(p: dict, op: str) -> bool:
    raw = p.get("raw")
    if not isinstance(raw, dict) or "TargetUserName" not in raw:
        return False
    raw["TargetUserName"] = RESPELL_OPS[op](str(raw["TargetUserName"]))
    return True


_RESPELLERS["target_account"] = _respell_target_account


def source_types(burst: Burst) -> list:
    return sorted({p["source_type"] for _s, p in burst.payloads})


def respelling_axis(lab: Lab, tables: dict) -> dict:
    """Joint split of the burst over two keys of every kind PLUS a respelling of
    the identity kind on the odd events, judged against the identity table.

    ``respelling_evades`` is True when an identity-PRESERVING respelling (one the
    source's table lists as the same entity) evades the set -- a BUG by table.
    A respelling the table says is a DIFFERENT entity that evades is INHERENT
    (it costs a real second identity). A respelling that is still detected is
    ROBUST. Everything else is reported ``not_searched`` with its reason."""
    res = {"ops": [], "respelling_evades": False, "respelling_inherent": False,
           "not_searched": []}
    kinds = [k for k in lab.rs.kinds if k is not None]
    ident_kinds = [k for k in kinds if k in _RESPELLERS]
    if not ident_kinds:
        res["not_searched"].append({"reason": "no account/domain-valued group key in this rule-set"})
        return res
    pl, setters = lab.burst.payloads, lab.burst.setters
    ident = tables.get("identity", {})
    for st in source_types(lab.burst):
        for kind in ident_kinds:
            row = (ident.get(f"{st}.{kind}") or {})
            if not row:
                res["not_searched"].append({"source_type": st, "kind": kind,
                                            "reason": "no identity-equivalence row for this source/kind"})
                continue
            equiv = set(row.get("equivalent_ops") or [])
            if str(row.get("attacker_controlled", "conditional")) == "no":
                res["not_searched"].append({"source_type": st, "kind": kind, "class": "NOT_REACHABLE",
                                            "reason": "table: the attacker cannot influence this field"})
                continue
            for op in row.get("try_ops") or []:
                base = copy.deepcopy(pl)
                # split every OTHER kind in two (coupled to rank parity) so companion rules are split too
                others = [k for k in kinds if k != kind and k in setters]
                for rank, (_s, p) in enumerate(base):
                    if rank % 2:
                        for k in others:
                            setters[k](p, 1)
                ctrl_d = lab.detected(copy.deepcopy(base))      # split on the other kinds, spelling untouched
                changed = 0
                for rank, (_s, p) in enumerate(base):
                    if rank % 2 and _RESPELLERS[kind](p, op):
                        changed += 1
                if not changed:
                    res["not_searched"].append({"source_type": st, "kind": kind, "op": op,
                                                "reason": "operator changed zero events"})
                    continue
                d, q = lab.both(base)
                evades = not d
                preserving = op in equiv
                cls = ("BUG" if (evades and preserving) else "INHERENT" if evades else "ROBUST")
                res["ops"].append({"source_type": st, "kind": kind, "op": op, "identity_preserving": preserving,
                                   "control_split_without_respelling_detected": ctrl_d,
                                   "evades": evades, "predicted_evades": not q, "agree": (not d) == (not q),
                                   "class": cls, "ratified": bool(row.get("ratified", False)),
                                   "basis": row.get("basis", "")})
                if evades and preserving and ctrl_d:
                    res["respelling_evades"] = True
                if evades and not preserving:
                    res["respelling_inherent"] = True
    return res


# --- attribution forgery (F3) -------------------------------------------------
_SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+) ssh2")


def forge_ssh_username(p: dict, fake_ip: str, fake_user: str) -> bool:
    """Rewrite a linux_ssh failure so the attacker-chosen USERNAME carries a
    forged ``from <ip>`` clause: what sshd logs when the attacker types
    ``<fake_user> from <fake_ip> port 1 ssh2 Failed password for <real_user>``."""
    raw = p.get("raw")
    if p.get("source_type") != "linux_ssh" or not isinstance(raw, str):
        return False
    m = _SSH_FAIL.search(raw)
    if not m:
        return False
    real_user, real_ip, port = m.group(1), m.group(2), m.group(3)
    forged = (f"Failed password for invalid user {fake_user} from {fake_ip} port 1 ssh2 "
              f"Failed password for {real_user} from {real_ip} port {port} ssh2")
    p["raw"] = raw[:m.start()] + forged + raw[m.end():]
    return True


def rename_ssh_user(p: dict, new_user: str) -> bool:
    return mg.set_actor(p, new_user)


_ISOLATION_PATHS = ("src_endpoint.ip", "actor.user.name", "class_uid", "activity_id", "time",
                    "dst_endpoint.hostname", "unmapped.dns.parent_domain", "src_endpoint.hostname")


def field_isolation_check(probe: ps.FastProbe, payload: dict, mutate, mapped_path: str) -> dict:
    """WS-2-only invariant: mutating ONE raw field must change ONLY the OCSF path
    it maps to. Returns the set of other paths that moved -- attribution forgery
    is exactly "I typed a username and the SOURCE ADDRESS changed"."""
    base = probe.normalized([(payload["source_type"], payload["raw"], payload.get("meta"))])
    mut = copy.deepcopy(payload)
    ok = mutate(mut)
    after = probe.normalized([(mut["source_type"], mut["raw"], mut.get("meta"))]) if ok else []
    if not base or not after:
        return {"applicable": False, "isolated": None, "moved": []}
    moved = [pth for pth in _ISOLATION_PATHS if _dig(base[0], pth) != _dig(after[0], pth)]
    other = [pth for pth in moved if pth != mapped_path]
    return {"applicable": True, "isolated": not other, "moved": moved, "violations": other}


def forgery_axis(lab: Lab, tables: dict) -> dict:
    """End-to-end consequence of a field-isolation violation: with the
    attacker's username forging the source address on the odd events, the log-
    visible (ip, account) pairs split in two from ONE real source.
    ``forgery_evades`` is True only when the field is attacker-controlled (per
    the table), isolation is violated AND the forged burst evades the set while
    an honest same-shape control (no forgery) is detected."""
    res = {"forgery_evades": False, "applicable": False, "isolation": None, "reason": ""}
    if "linux_ssh" not in source_types(lab.burst):
        res["reason"] = "no source in this burst with an injectable free-text field"
        return res
    row = (tables.get("attacker_control") or {}).get("linux_ssh.username") or {}
    if row.get("attacker_controlled") not in ("yes", "conditional"):
        res["reason"] = "table: linux_ssh.username is not attacker-controlled"
        return res
    pl = lab.burst.payloads
    probe_payload = copy.deepcopy(pl[0][1])
    iso = field_isolation_check(lab.probe, probe_payload,
                                lambda p: forge_ssh_username(p, "198.18.9.9", "x"), "actor.user.name")
    ctrl = field_isolation_check(lab.probe, probe_payload, lambda p: rename_ssh_user(p, "deploy2"),
                                 "actor.user.name")
    res.update({"applicable": bool(iso.get("applicable")), "isolation": iso, "isolation_control_rename": ctrl,
                "attacker_controlled": row.get("attacker_controlled"), "ratified": bool(row.get("ratified", False)),
                "basis": row.get("basis", "")})
    if not (iso.get("applicable") and iso.get("isolated") is False):
        return res
    forged = copy.deepcopy(pl)
    for rank, (_s, p) in enumerate(forged):
        if rank % 2:
            forge_ssh_username(p, "198.18.9.9", "x")
    honest_one = lab.detected(copy.deepcopy(pl))
    d, q = lab.both(forged)
    res.update({"honest_unsplit_detected": honest_one, "forged_detected": d, "predicted_forged_detected": q,
                "agree": d == q, "forgery_evades": bool(honest_one and not d)})
    return res


# ===========================================================================
# Clock authority (F4)
# ===========================================================================
_RECORD_CLOCK_KEYS = ("TimeCreated", "createdTime", "ts", "time", "eventTime", "timestamp")


def set_record_clock(p: dict, ts: int) -> bool:
    """Move ONLY the record's own timestamp (never ``meta.received_at``)."""
    raw = p.get("raw")
    if not isinstance(raw, dict):
        return False
    changed = False
    for key in _RECORD_CLOCK_KEYS:
        if key in raw:
            raw[key] = (datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if key == "eventTime" else ts)
            changed = True
    return changed


def clock_authority(probe: ps.FastProbe, payload: dict) -> dict:
    """Which clock does the parser trust for this source? Measured, not read:
    shift each clock alone by an hour and see whether the OCSF ``time`` moves."""
    def norm_time(p):
        ev = probe.normalized([(p["source_type"], p["raw"], p.get("meta"))])
        return ev[0]["time"] if ev else None
    base = norm_time(payload)
    env = copy.deepcopy(payload)
    env.setdefault("meta", {})["received_at"] = (env["meta"].get("received_at") or 0) + 3_600_000
    rec = copy.deepcopy(payload)
    has_rec = set_record_clock(rec, (mg.get_time(payload) or 0) + 3_600_000)
    env_moves = base is not None and norm_time(env) != base
    rec_moves = bool(has_rec) and base is not None and norm_time(rec) != base
    return {"receipt_clock_moves_event_time": env_moves, "record_clock_moves_event_time": rec_moves,
            "authority": "record" if rec_moves else "receipt"}


def clock_forgeable(lab: Lab) -> dict:
    """Can the attacker stretch the burst by forging ONLY the record clock?
    The optimal slow schedule is applied to the record clock alone and the
    receipt clock left at the true time."""
    pl, n = lab.burst.payloads, lab.burst.n
    if lab.rs.periodic:
        cons = [(r.threshold, r.window_ms) for r in lab.rs.rules]
        off = regular_slow_offsets(n, cons)
    else:
        off = optimal_slow_offsets(n, [(r.threshold, r.window_ms) for r in lab.rs.rules])
    auth = {st: clock_authority(lab.probe, next(p for _s, p in pl if p["source_type"] == st))
            for st in source_types(lab.burst)}
    forged = copy.deepcopy(pl)
    t0 = min(event_times(forged))
    moved = 0
    for (_s, p), o in zip(forged, off):
        moved += 1 if set_record_clock(p, t0 + o) else 0
    detected = lab.detected(forged) if moved else True
    return {"authority": {k: v["authority"] for k, v in sorted(auth.items())},
            "record_clock_only_evades": bool(moved) and not detected,
            "clock_forgeable": bool(moved) and not detected}


# ===========================================================================
# Verify-by-parse: a setter must really move the key the rule reads
# ===========================================================================
def verify_setter(lab: Lab, kind: str, k: int = 3) -> dict:
    """Apply ``k`` keys of ``kind`` and count the distinct values the rule's group
    path takes in the NORMALISED events. A setter that does not move the field
    would make every spread search report "immune" about nothing."""
    path = next((r.group_by for r in lab.rs.rules if r.kind == kind), None)
    if path is None or kind not in lab.burst.setters:
        return {"kind": kind, "applicable": False, "distinct": 0}
    pl = assign_keys(lab.burst.payloads, [kind], {kind: k}, lab.burst.setters)
    events = lab.probe.normalized(ps.payloads_to_pairs(pl))
    vals = {str(_dig(e, path)) for e in events if _dig(e, path) is not None}
    return {"kind": kind, "applicable": True, "path": path, "distinct": len(vals), "expected": min(k, len(events))}
