"""scorecard_registry -- the single place every fact in ``eval/SCORECARD.md``.

This module is PURE DATA. It performs no file I/O at import time and imports
nothing outside the standard library, so a test or a lint can import it
cheaply (and so importing it cannot pull in ``report``/``services`` path
setup, which the registry must not depend on -- see the guard for limit #1,
which reads its evidence out of the *artifact*, never by importing
``eval/twin/oracle_consistency.py``).

What lives here
---------------
``ARTIFACTS``         the gate-written JSON artifacts the card is rendered from,
                      each with its OWN provenance rule (the artifacts do not
                      share a shape -- see ``seed_path``/``basis_path``).
``METRICS``           every metric the card may render, with its direction, its
                      blind spot, and the negative control that can prove it
                      can move (or ``None``, rendered as a bold NONE).
``LIMITS``            the "what this harness cannot prove" bullets. Each one is
                      tied to a measured fact through an optional ``guard``
                      callable, so the sentence EXPIRES when it stops being true
                      instead of quietly outliving its evidence.
``ALIASES``           the doc-lint's metric vocabulary (``mttd_seconds`` and
                      ``mttd`` are the same claim; ``attribution_accuracy`` is
                      deliberately the ONLY attribution alias -- a bare
                      ``attribution`` would match prose about the ATT&CK
                      ``attribution`` column and dates).
``VOLATILE``          key names the renderer must NEVER read (wall-clock and
                      date fields). A test asserts no registry path points into
                      one of them.
``CONTROLS``          ``ControlRef``s: a test file plus a needle. Existence is
                      checked, gate-wiring is checked, and -- because a needle
                      can sit in a function nothing calls -- the enclosing
                      function is resolved with ``ast`` and required to be
                      CALLED from the module's ``main()``/``__main__`` block
                      (the dormant-test class this repo already fixed once, in
                      a9b9313 / tools/check_lane_coverage.py).
``RATCHET_BASELINE_FILE`` the step-6 atom baseline. (Its predecessor named a
                      FUTURE file, ``eval/scorecard.floor.json``, so the guard of
                      "this card does not block a regression" would expire when
                      the ratchet landed. The ratchet landed under a different
                      name and the sentence stayed "OK" while false -- exactly
                      the failure the constant existed to prevent; external
                      review 2026-10-14. The limit is now about what the landed
                      ratchet does NOT cover, see ``RATCHET_ATOMS``.)

Maintenance note (ordering coupling)
------------------------------------
``tools/generate_scorecard.py --check`` must run AFTER every instrument stanza
in ``run_all_tests.sh``: a new instrument added BELOW the scorecard stanza
would produce an artifact after the card was already checked. The gate-wiring
test in ``tools/test_generate_scorecard.py`` asserts the order over the
instrument list in ``INSTRUMENTS_RUN_BEFORE_CHECK``; add a new instrument to
that tuple in the same PR that adds it to the gate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

# --------------------------------------------------------------------------
# Repository-relative inputs
# --------------------------------------------------------------------------
#: The committed atom baseline of eval/twin/ratchet.py (see the module docstring).
RATCHET_BASELINE_FILE = "eval/twin/baseline_scenarios.json"

#: metric key -> the ratchet atom prefix that freezes it (``{s}`` = storyline).
#: A metric absent here is rendered on the card but NOT ratcheted; the
#: ``ratchet_scope`` limit lists those, and its guard fails if a prefix below
#: matches no committed atom (a stale claim that something is ratcheted).
RATCHET_ATOMS: dict[str, str] = {
    "tpr": "scn/{s}/base/tpr",
    "chain_fidelity": "scn/{s}/base/chain_fidelity",
    "false_correlation_rate": "scn/{s}/base/false_correlation_rate",
    "directional_discrimination": "scn/{s}/base/directional_discrimination",
    "alert_order_ok": "scn/{s}/base/alert_order_ok",
    "incident_membership_ok": "scn/{s}/base/incident_membership_ok",
    "mutation_robustness": "scn/{s}/mut/",
    "mutation_variants": "scn/{s}/mut/",
    "fpr": "twin/fpr",
    "mttd_seconds": "twin/mttd_seconds",
    "mtti": "twin/mtti",
    "evidence_completeness": "twin/evidence_completeness",
    "alert_reduction_ratio": "twin/alert_reduction_ratio",
    "severity_calibration_error": "twin/severity_calibration_error",
    "attribution_accuracy": "twin/attribution_accuracy",
    "mutation_robustness_twin": "lane_a/mut/",
    "layer_a_mutation_robustness": "lane_a/mut/",
    "corpus_cases_matched": "corpus_b/",
    "evasion_rows_searched": "scn/{s}/evasion/",
    "evasion_boundary_agreement": "scn/{s}/evasion/",
}

#: The card itself.
CARD_PATH = "eval/SCORECARD.md"

#: Files the doc lint reads. SSOT.md is scanned in sections 2 and 3 only.
DOC_LINT_FILES = ("README.md", "SSOT.md")
SSOT_SCANNED_SECTIONS = ("2", "3")

#: ``run_all_tests.sh`` is read by the gate-wiring check, the control-wiring
#: check and the limit-#9 guard.
GATE_SH = "run_all_tests.sh"

#: Instrument invocations that MUST appear in the gate BEFORE the scorecard
#: ``--check`` stanza, in (a) the order the gate runs them and (b) the same order
#: ``--run`` replays them. Keep this in sync with ``run_all_tests.sh``.
INSTRUMENTS_RUN_BEFORE_CHECK: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("fire_check", ("eval/attack/fire_check.py",)),
    ("oracle_consistency", ("eval/twin/oracle_consistency.py",
                            "--out", "eval/twin/out/oracle_consistency.latest.json")),
    ("layer_a", ("eval/adversarial/layer_a.py", "--seed", "7")),
    ("corpus_b", ("eval/adversarial/corpus_b.py",)),
    ("scenario_matrix", ("eval/adversarial/scenario_matrix.py", "--seed", "7")),
    ("evasion", ("eval/adversarial/evasion_search.py", "--seed", "7")),
    ("twin", ("eval/twin/report.py", "--no-trend", "--out",
              "eval/twin/report.latest.json")),
)

#: The gate stanza text the wiring check looks for (the anchored form).
CHECK_STANZA = "tools/generate_scorecard.py --check"

# --------------------------------------------------------------------------
# Freshness inputs
# --------------------------------------------------------------------------
# The artifacts are gitignored and a developer can hold an older one. The
# freshness guard compares every artifact's mtime against the newest input file
# the instruments read. The globs below are the COMPLETE set of non-``tools/``
# inputs (the spec's original glob missed ``contracts/scoring.yaml``,
# ``contracts/ot-points/``, ``contracts/enrichment/`` and ``contracts/tenants/``,
# all of which ``services/ws4-detection/main.py`` loads -- so a scoring.yaml
# edit could move severity and peak-score metrics while an old artifact still
# passed). A test asserts every ``_CONTRACTS`` directory ws4 loads is covered.
FRESHNESS_INPUT_GLOBS: tuple[str, ...] = (
    "contracts/rules/*.yml",
    "contracts/rules/*.yaml",
    "contracts/allowlists/*.yml",
    "contracts/allowlists/*.yaml",
    "contracts/scoring.yaml",
    "contracts/ot-points/*.yml",
    "contracts/ot-points/*.yaml",
    "contracts/enrichment/*.yml",
    "contracts/enrichment/*.yaml",
    "contracts/tenants/*.yml",
    "contracts/tenants/*.yaml",
    "services/**/*.py",
    "services/**/*.yml",
    "services/**/*.yaml",
    "services/**/*.json",
    "eval/**/*.py",
    "eval/twin/oracle.yaml",
    "eval/twin/oracle_*.yaml",
    "eval/adversarial/*.yaml",
    "eval/attack/coverage_layer.py",
    # tools/ modules an instrument imports (the rest of tools/ is excluded on
    # purpose): fire_check replays check_rule_producers' FIXTURES, and every
    # load_rules() call validates through validate_rules (2026-10-14 review).
    "tools/check_rule_producers.py",
    "tools/validate_rules.py",
    "tools/validate_contract.py",         # shared/ocsf.py validates every event through it
)

#: ws4-detection's contract roots, asserted covered by FRESHNESS_INPUT_GLOBS.
WS4_CONTRACT_DIRS: tuple[str, ...] = (
    "contracts/rules",
    "contracts/allowlists",
    "contracts/tenants",
    "contracts/ot-points",
)
WS4_CONTRACT_FILES: tuple[str, ...] = ("contracts/scoring.yaml",)

# --------------------------------------------------------------------------
# Volatile fields the renderer must never read
# --------------------------------------------------------------------------
VOLATILE: tuple[str, ...] = (
    "date",
    "elapsed_seconds",
    "assembly_median_ms",
    "assembly_samples_ms",
    "incident_reconstruction_time_ms",
)

# --------------------------------------------------------------------------
# Storylines
# --------------------------------------------------------------------------
#: Registered storylines. ``phishing_bec`` was added to
#: ``scenario_registry.ALL`` AFTER the design spec was written (the spec assumes
#: three). The generator CROSS-CHECKS this tuple against the artifact's own
#: ``scenario_list`` and refuses to render if they disagree, so a new storyline
#: cannot silently disappear from the card. It is a deliberate snapshot: every
#: storyline that lands must extend this list in the same commit (5th storyline
#: ``ot_opcua_sabotage``, 2026-10-14).
STORYLINES: tuple[str, ...] = ("ai_to_ot", "it_intrusion", "infra_takeover",
                               "phishing_bec", "ot_opcua_sabotage")

#: ``eval/twin/report.latest.json`` and ``matrix.latest.json`` cover this
#: storyline only; every twin-only metric reads ``twin_only``.
TWIN_STORYLINE = "ai_to_ot"


# --------------------------------------------------------------------------
# Artifacts
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ArtifactSpec:
    key: str
    path: str                      # repo-relative POSIX path
    producer: str                  # the gate command that writes it
    kind: str                      # "dict" | "list"
    required_keys: tuple[str, ...]
    seed_path: str | None          # dotted path; None = artifact carries no seed
    basis_path: str | None         # dotted path; None = artifact carries no basis
    seed_per_scenario: bool = False    # dict[scenario] -> {seed, basis}
    note: str = ""


ARTIFACTS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec(
        key="layer_a",
        path="eval/adversarial/out/matrix.latest.json",
        producer="python eval/adversarial/layer_a.py --seed 7",
        kind="dict",
        required_keys=("seed", "basis", "lanes", "baseline", "rows", "per_axis", "overall"),
        seed_path="seed",
        basis_path="basis",
        note="Layer A mutation matrix (AI-to-OT only).",
    ),
    ArtifactSpec(
        key="scenario_matrix",
        path="eval/adversarial/out/scenario_matrix.latest.json",
        producer="python eval/adversarial/scenario_matrix.py --seed 7",
        kind="dict",
        required_keys=("seed", "basis", "scenario_list", "inputs_fingerprint",
                       "scenarios", "pooled", "metric_controls"),
        seed_path="seed",
        basis_path="basis",
        note="Per-storyline mutation lane; the only source of per-storyline baselines.",
    ),
    ArtifactSpec(
        key="evasion",
        path="eval/adversarial/out/evasion_search.latest.json",
        producer="python eval/adversarial/evasion_search.py --seed 7",
        kind="dict",
        required_keys=("seed", "basis", "scenarios"),
        seed_path="seed",
        basis_path="basis",
        note="Measured volume boundary per burst step vs the rule's declared threshold.",
    ),
    ArtifactSpec(
        key="corpus_b",
        path="eval/adversarial/out/corpus.latest.json",
        producer="python eval/adversarial/corpus_b.py",
        kind="dict",
        required_keys=("schema", "basis", "seed", "per_case", "incidents_promoted"),
        seed_path="seed",
        basis_path="basis",
        note="Layer B curated corpus.",
    ),
    ArtifactSpec(
        key="twin",
        path="eval/twin/report.latest.json",
        producer="python eval/twin/report.py --no-trend --out eval/twin/report.latest.json",
        kind="dict",
        required_keys=("report", "metrics", "context", "finding"),
        seed_path="report.seed",
        basis_path="report.basis",
        note="Twin scorecard (AI-to-OT only); seed/basis live under `report.`.",
    ),
    ArtifactSpec(
        key="fire_check",
        path="eval/attack/out/fire_check.json",
        producer="python eval/attack/fire_check.py",
        kind="list",
        required_keys=("id", "title", "framework", "tactic", "technique", "fired",
                       "harness_blocked", "boundary", "near_miss"),
        seed_path=None,       # a bare list: no seed and no basis anywhere
        basis_path=None,
        note="A bare LIST of tagged-rule results; it carries no seed and no basis.",
    ),
    ArtifactSpec(
        key="oracle_consistency",
        path="eval/twin/out/oracle_consistency.latest.json",
        producer=("python eval/twin/oracle_consistency.py --out "
                  "eval/twin/out/oracle_consistency.latest.json"),
        kind="dict",
        required_keys=(),     # top level is keyed by SCENARIO name; each value is validated
        seed_path=None,       # seed/basis are PER SCENARIO: {scenario: {seed, basis}}
        basis_path=None,
        seed_per_scenario=True,
        note="``--out`` writes {scenario: {seed, basis, new, accepted_count, ...}}.",
    ),
)

ARTIFACTS_BY_KEY: dict[str, ArtifactSpec] = {a.key: a for a in ARTIFACTS}


# --------------------------------------------------------------------------
# Controls
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class ControlRef:
    """A negative control: the cited assertion must EXIST, its file must be
    gate-wired, and its enclosing function must be CALLED from the module's
    ``main()``/``__main__`` block."""
    test_file: str          # repo-relative POSIX path
    needle: str             # unique substring inside the enclosing function
    what: str               # one line: what this control can prove


CONTROLS: dict[str, ControlRef] = {
    "matrix_gate": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_matrix_gate",
        "the per-storyline pass-rate gate flips red on a dropped variant"),
    "evasion_search": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_evasion_search",
        "a measured boundary that disagrees with the declared threshold is caught"),
    "directional_discrimination": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_directional_discrimination",
        "the join predicate is proven order-blind, so chain_fidelity/FCR are entity-sharing"),
    "decoy_contamination": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_decoy_contamination",
        "a decoy on the attacker's own entity IS absorbed (the trade-off is measured)"),
    "alert_order": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_alert_order",
        "a reversed chain makes alert_order_ok say no"),
    "burst_mttd": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_burst_mttd",
        "mttd for a burst step is the firing event, not the first event"),
    "oracle_reconciliation": ControlRef(
        "eval/adversarial/test_scenario_harness.py",
        "def test_oracle_reconciliation",
        "an oracle/reality disagreement cannot pass silently"),
    "false_correlation": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_false_correlation",
        "the forbidden-pair denominator is independent of the function under test"),
    "alert_reduction": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_alert_reduction",
        "the alert-reduction ratio is checked against an independent count"),
    "reconstruction": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_reconstruction",
        "the evidence package is buildable and hash-chain-verified"),
    "investigation": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_investigation",
        "the analyst-walk step count is measured, not asserted"),
    "severity_confusion": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_severity_confusion",
        "the severity confusion matrix is cross-checked against the alert list"),
    "mttr_null": ControlRef(
        "eval/twin/test_phase3_5.py",
        "def _test_mttr_null",
        "MTTR is null because no closure event exists -- asserted, not assumed"),
    "fire_check_boundary": ControlRef(
        "eval/attack/test_fire_check.py",
        "def test_under_threshold_probe_catches_an_off_by_one_rule",
        "the under-threshold probe catches an off-by-one threshold rule"),
    "fire_check_near_miss": ControlRef(
        "eval/attack/test_fire_check.py",
        "def test_near_miss_probe_catches_a_predicate_that_is_not_load_bearing",
        "the near-miss probe catches a stateless rule ignoring a declared predicate"),
    "fire_check_gate_e2e": ControlRef(
        "eval/attack/test_fire_check.py",
        "def test_gate_exits_nonzero_end_to_end_on_a_too_loose_rule",
        "fire_check's own main() exit code goes red on a too-loose rule"),
    "negative_controls": ControlRef(
        "eval/twin/negative_controls.py",
        "def is_incident",
        "an INCIDENT-level negative control is the definition FPR is measured against"),
    "phishing_bec": ControlRef(
        "eval/twin/test_storylines_wide.py",
        "def test_phishing_bec",
        "the fourth storyline's gaps, rules and step dependencies hold"),
    "provenance": ControlRef(
        "eval/twin/test_storylines_wide.py",
        "def test_provenance",
        "every oracle declares its provenance (self-authored vs derived)"),
    "layer_a_determinism": ControlRef(
        "eval/adversarial/test_layer_a.py",
        "def _test_determinism",
        "two full Layer A runs are byte-identical (the license to block)"),
    "layer_a_sensitivity": ControlRef(
        "eval/adversarial/test_layer_a.py",
        "def _test_sensitivity",
        "the lane moves BOTH ways: evasion red / survivor green"),
    "layer_a_coverage": ControlRef(
        "eval/adversarial/test_layer_a.py",
        "def _test_coverage",
        "a weakened rule measurably stops firing (the lane is sensitive to rule weakening)"),
}


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class MetricSpec:
    key: str
    label: str
    direction: str                    # higher_better | lower_better | flag | info
    blind_spot: str
    source: str                       # artifact key
    extract: Callable[[dict, str], Any]
    control_key: str | None = None
    scope: str = "storyline"          # storyline | twin_only | global
    render: Callable[[Any], str] | None = None
    alias_key: str | None = None      # doc-lint vocabulary bucket (defaults to key)


def _f(v: Any) -> str:
    """Stable scalar rendering. Floats print as their shortest round-trip repr
    (the same text the artifacts' own JSON holds), so two renders agree
    byte-for-byte."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, dict):
        return " ".join(f"{k}={_f(v[k])}" for k in sorted(v))
    return str(v)


def _round4(x: float) -> float:
    return round(x, 4)


# ---- extractors -----------------------------------------------------------
def _sm(d: dict, storyline: str, *path: str) -> Any:
    """scenario_matrix.scenarios[storyline].baseline.<path>"""
    node: Any = d["scenarios"].get(storyline)
    if node is None:
        return None
    for p in path:
        if not isinstance(node, dict):
            return None
        node = node.get(p)
    return node


def _sm_eligible(d: dict, storyline: str) -> list[dict]:
    node = d["scenarios"].get(storyline) or {}
    return [r for r in node.get("rows", []) if r.get("applicable") is True]


def _sm_robustness(d: dict, storyline: str) -> Any:
    """Read the INSTRUMENT's own per-scenario overall block when present; fall
    back to recomputing only for a fixture that omits it."""
    node = d["scenarios"].get(storyline) or {}
    overall = node.get("overall") or {}
    if "mutation_robustness" in overall:
        return overall["mutation_robustness"]
    rows = _sm_eligible(d, storyline)
    if not rows:
        return None
    return _round4(sum(1 for r in rows if r.get("pass")) / len(rows))


def _sm_applicable(d: dict, storyline: str) -> Any:
    node = d["scenarios"].get(storyline) or {}
    overall = node.get("overall") or {}
    if "applicable" in overall:
        return overall["applicable"]
    return len(_sm_eligible(d, storyline))


def _evas(d: dict, storyline: str, field: str) -> Any:
    rows = (d["scenarios"].get(storyline) or {}).get("rows", [])
    searched = [r for r in rows if r.get("searched")]
    if field == "searched":
        return len(searched)
    if field == "rows":
        return len(rows)
    if field == "agree":
        if not searched:
            return None
        return f"{sum(1 for r in searched if r.get('all_agree'))}/{len(searched)}"
    return None


def _oracle_consistency(d: dict, field: str) -> Any:
    """Sum one field over every scenario. ``new``, ``stale_allowlist_entries``
    and ``decorative_expectations`` are LISTS (one entry per finding) and count
    by length; ``accepted_count`` is an int. Anything else is a shape the card
    cannot read, and it raises rather than counting as 0: ``int(list)`` used to
    raise TypeError, which was swallowed, so the three list metrics rendered 0
    whatever the artifact held (external review 2026-10-14)."""
    total = 0
    for sc, f in d.items():
        v = f.get(field)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            total += len(v)
        elif isinstance(v, int) and not isinstance(v, bool):
            total += v
        else:
            raise TypeError(f"oracle_consistency.{sc}.{field} is a {type(v).__name__}, "
                            f"expected a list or an int")
    return total


def _corpus(d: dict, field: str) -> Any:
    if field == "matched":
        cases = d["per_case"]
        return f"{sum(1 for c in cases if not c.get('missed'))}/{len(cases)}"
    return d.get(field)


# Per-storyline metrics are read out of scenario_matrix (present for every
# registered storyline); twin-only metrics come from report.latest.json.
METRICS: tuple[MetricSpec, ...] = (
    MetricSpec(
        key="tpr",
        label="tpr",
        direction="higher_better",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "tpr"),
        control_key="oracle_reconciliation",
        blind_spot=(
            "Step COVERAGE, not rule completeness: the denominator excludes "
            "`no_rule_exists` gap steps (report._grade_chain skips them), so a gap can "
            "never lower TPR. Detection is judged by an oracle-listed rule, or by "
            "ATT&CK tactic equivalence in the mutation lane."),
    ),
    MetricSpec(
        key="chain_fidelity",
        label="chain_fidelity",
        direction="higher_better",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "chain_fidelity"),
        control_key="directional_discrimination",
        blind_spot=(
            "Measures entity SHARING, not causal order: the join predicate answers "
            "'joined' for a step pair and for the same pair reversed "
            "(directional_discrimination is 0.0), so it reports 'is there an entity "
            "bridge', never 'was the chain reconstructed'."),
    ),
    MetricSpec(
        key="false_correlation_rate",
        label="false_correlation_rate",
        direction="lower_better",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "false_correlation_rate"),
        control_key="directional_discrimination",
        blind_spot=(
            "Same order-blind predicate as chain_fidelity: a saturated 1.0 cannot "
            "distinguish a mutation that INDUCES false correlation from one that merely "
            "fails to improve an already-saturated number."),
    ),
    MetricSpec(
        key="directional_discrimination",
        label="directional_discrimination",
        direction="higher_better",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "directional_discrimination"),
        control_key="directional_discrimination",
        blind_spot=(
            "The honest counterweight to the two rows above: 0.0 means the legacy join "
            "cannot tell a causal direction from its reverse. Order is graded separately "
            "(alert_order_ok; causal_order_* in the twin)."),
    ),
    MetricSpec(
        key="alert_order_ok",
        label="alert_order_ok",
        direction="flag",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "alert_order_ok"),
        control_key="alert_order",
        blind_spot=(
            "Only meaningful with at least two alerting steps; with fewer it is None, "
            "and None is reported as null rather than folded to true."),
    ),
    MetricSpec(
        key="incident_membership_ok",
        label="incident_membership_ok",
        direction="flag",
        source="scenario_matrix",
        extract=lambda d, s: _sm(d, s, "baseline", "incident_membership_ok"),
        control_key=None,
        blind_spot=(
            "Whether ONE incident spans the whole oracle chain. A storyline that pivots "
            "across entities (it_intrusion) reports false: no single entity bridges it. "
            "Reported as measured; campaign persistence is an owner decision "
            "(ADR-009/010 'tracks never merge' stays ratified)."),
    ),
    MetricSpec(
        key="mutation_robustness",
        label="mutation_robustness",
        direction="higher_better",
        source="scenario_matrix",
        extract=_sm_robustness,
        control_key="matrix_gate",
        blind_spot=(
            "Measured RELATIVE to a baseline whose fidelity and FCR are already degraded; "
            "a mutation that changes nothing is N/A and is EXCLUDED from the denominator "
            "(the 'variants' cell shows how many were applicable)."),
    ),
    MetricSpec(
        key="mutation_variants",
        label="mutation_variants (applicable)",
        direction="info",
        source="scenario_matrix",
        extract=_sm_applicable,
        control_key="matrix_gate",
        blind_spot=(
            "The denominator of the row above; N/A variants (single-shot rules that "
            "cannot be volume-evaded) are not counted."),
    ),
    MetricSpec(
        key="fpr",
        label="fpr",
        direction="lower_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["fpr"],
        control_key=None,
        blind_spot=(
            "Measured over four benign scenarios, and the proof that it can go non-zero "
            "was found -- and FIXED -- before this card existed: an approved-maintenance "
            "window write once scored an incident (1/4 = 0.25) and is now DOWNGRADED, not "
            "suppressed. No control here can still make it non-zero, so it is NONE."),
    ),
    MetricSpec(
        key="mttd_seconds",
        label="mttd_seconds",
        direction="lower_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["mttd_seconds"],
        control_key="burst_mttd",
        blind_spot=(
            "For a burst step it is the FIRING event, not the first event (fixed on "
            "01-Oct-2026): a 15-connection port scan 'detected at 0.0s' meant 'visible on "
            "its 15th connection', which is why the number moved to the firing event."),
    ),
    MetricSpec(
        key="mtti",
        label="mtti",
        direction="lower_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["mtti"],
        control_key="investigation",
        blind_spot=(
            "Step count over the picked incident's OWN graph, times a documented "
            "30 s/step conversion: steps are measured, the seconds are a model."),
    ),
    MetricSpec(
        key="mttr",
        label="mttr",
        direction="lower_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["mttr"],
        control_key="mttr_null",
        blind_spot=(
            "An honest null, with a stated reason: no remediation/closure event is "
            "replayed, so incidents never close in the simulation. A real MTTR needs a "
            "live replay or a design partner."),
    ),
    MetricSpec(
        key="evidence_completeness",
        label="evidence_completeness",
        direction="higher_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["evidence_completeness"],
        control_key="reconstruction",
        blind_spot=(
            "Fractions of blocks built into the evidence package, not fractions of "
            "real-world evidence an investigator would need."),
    ),
    MetricSpec(
        key="alert_reduction_ratio",
        label="alert_reduction_ratio",
        direction="higher_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["alert_reduction_ratio"],
        control_key="alert_reduction",
        blind_spot=(
            "Raw alerts absorbed into incidents, checked against an independently "
            "counted alert total; a high ratio also means more alerts folded into one "
            "incident, which is not the same as fewer false positives."),
    ),
    MetricSpec(
        key="severity_calibration_error",
        label="severity_calibration_error",
        direction="lower_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["severity_calibration_error"],
        control_key="severity_confusion",
        blind_spot=(
            "Derived from the confusion matrix over the alerts this chain fired; it says "
            "nothing about severities on traffic the chain does not produce."),
    ),
    MetricSpec(
        key="peak_alert_score",
        label="peak_alert_score",
        direction="info",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["peak_alert_score"],
        control_key=None,
        blind_spot=(
            "A single chain's peak score. Nothing here proves the scoring ceiling is "
            "right for a different chain, and companion rules deliberately add no weight."),
    ),
    MetricSpec(
        key="severity_in_band",
        label="severity_in_band",
        direction="flag",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["severity_in_band"],
        control_key="severity_confusion",
        blind_spot=(
            "The oracle's declared band, graded on this chain only."),
    ),
    MetricSpec(
        key="causal_order_fidelity",
        label="causal_order_fidelity",
        direction="higher_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["causal_order_fidelity"],
        control_key="alert_order",
        blind_spot=(
            "Timestamp-based, and co-reported with order_concordance, which is 1.0 BY "
            "CONSTRUCTION on the harness's own chains: it records that the ingested clock "
            "agrees with the oracle's order, NOT that WS-8 reconstructs causal order."),
    ),
    MetricSpec(
        key="order_concordance",
        label="order_concordance",
        direction="info",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["order_concordance"],
        control_key="alert_order",
        blind_spot=(
            "A timestamp invariant (1.0 by construction), kept for transparency, not as "
            "evidence of causal reconstruction."),
    ),
    MetricSpec(
        key="attribution_accuracy",
        label="attribution_accuracy",
        direction="higher_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["attribution_accuracy"],
        control_key=None,
        blind_spot=(
            "Computed over actor-bearing steps of ONE self-authored chain; there is no "
            "independent attribution oracle and no control here can move it. NONE."),
    ),
    MetricSpec(
        key="degradation_behavior",
        label="degradation_behavior",
        direction="info",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["degradation_behavior"],
        control_key=None,
        blind_spot=(
            "Reports that each degradation is deterministic and that loss is a strict "
            "subset; it is a property of the rig, not a detection quality measure."),
    ),
    MetricSpec(
        key="mutation_robustness_twin",
        label="mutation_robustness (twin, reads Layer A)",
        direction="higher_better",
        source="twin",
        scope="twin_only",
        extract=lambda d, s: d["metrics"]["mutation_robustness"],
        control_key="layer_a_determinism",
        alias_key="mutation_robustness",
        blind_spot=(
            "The twin scorecard reads the Layer A artifact, so this is the same number "
            "as the Layer A row: relative to a degraded baseline, AI-to-OT only, and "
            "the 3 WS-8 join-class rows are counted as failures."),
    ),
    MetricSpec(
        key="layer_a_mutation_robustness",
        label="mutation_robustness (Layer A)",
        direction="higher_better",
        source="layer_a",
        scope="twin_only",
        extract=lambda d, s: d["overall"]["mutation_robustness"],
        control_key="layer_a_coverage",
        blind_spot=(
            "Layer A covers the AI-to-OT chain only, and 3 of its rows are WS-8 "
            "join-class failures that need a change to the ratified WS-8 invariant "
            "to close -- they are counted as failures, not hidden."),
    ),
    MetricSpec(
        key="decorative_expectations",
        label="decorative_expectations (all storylines)",
        direction="lower_better",
        source="oracle_consistency",
        scope="global",
        extract=lambda d, s: _oracle_consistency(d, "decorative_expectations"),
        control_key="oracle_reconciliation",
        blind_spot=(
            "A rule listed at a step that did NOT fire there. Per-technique coverage is "
            "credited from MEASURED firing (fire_check), so a decorative expectation is "
            "never counted as coverage; this row counts them so the omission is visible."),
    ),
    MetricSpec(
        key="oracle_new_disagreements",
        label="oracle_new_disagreements (all storylines)",
        direction="lower_better",
        source="oracle_consistency",
        scope="global",
        extract=lambda d, s: _oracle_consistency(d, "new"),
        control_key="oracle_reconciliation",
        blind_spot=(
            "Counts disagreements NOT on the frozen waiver list. The list itself is "
            "checked for staleness separately (accepted_count / stale_allowlist_entries)."),
    ),
    MetricSpec(
        key="oracle_accepted_disagreements",
        label="oracle_accepted_disagreements (all storylines)",
        direction="lower_better",
        source="oracle_consistency",
        scope="global",
        extract=lambda d, s: _oracle_consistency(d, "accepted_count"),
        control_key="oracle_reconciliation",
        blind_spot=(
            "A non-zero value means the answer key and reality disagree somewhere the "
            "project has knowingly accepted; the reason lives in the artifact, not here."),
    ),
    MetricSpec(
        key="oracle_stale_allowlist_entries",
        label="oracle_stale_allowlist_entries (all storylines)",
        direction="lower_better",
        source="oracle_consistency",
        scope="global",
        extract=lambda d, s: _oracle_consistency(d, "stale_allowlist_entries"),
        control_key="oracle_reconciliation",
        blind_spot=(
            "A waiver that no longer reproduces. Non-zero means the allowlist outlived "
            "the disagreement it was written for."),
    ),
    MetricSpec(
        key="corpus_cases_matched",
        label="corpus cases fully matched",
        direction="higher_better",
        source="corpus_b",
        scope="global",
        extract=lambda d, s: _corpus(d, "matched"),
        control_key="layer_a_coverage",
        blind_spot=(
            "Eight hand-curated cases. A miss is reported per case in the artifact; this "
            "cell says how many had NO missed rule, not how well the rules generalise."),
    ),
    MetricSpec(
        key="corpus_incidents_promoted",
        label="corpus incidents promoted",
        direction="info",
        source="corpus_b",
        scope="global",
        extract=lambda d, s: _corpus(d, "incidents_promoted"),
        control_key=None,
        blind_spot=(
            "One deliberate shared-attacker merge is expected; the cross-case merge "
            "cleanliness flag is what proves no incident spans two corpus groups."),
    ),
    MetricSpec(
        key="evasion_rows_searched",
        label="evasion rows searched (this storyline)",
        direction="info",
        source="evasion",
        extract=lambda d, s: _evas(d, s, "searched"),
        control_key="evasion_search",
        blind_spot=(
            "A step is searched only when it has more than one event: a single-event "
            "step has no volume boundary to bisect, so 0 searched is a scope limit, "
            "not an evasion result."),
    ),
    MetricSpec(
        key="evasion_boundary_agreement",
        label="evasion boundary agreement",
        direction="higher_better",
        source="evasion",
        extract=lambda d, s: _evas(d, s, "agree"),
        control_key="evasion_search",
        blind_spot=(
            "'measured == predicted-from-declared': the artifact's own `predicted` is "
            "derived from the rule YAML's declared threshold/window/group_by. An "
            "axis whose row shows `immune`/null is a PREDICTED-IMMUNE agreement, not a "
            "measurement, and a rule with no group_by-relative count is vacuous there."),
    ),
)

METRICS_BY_KEY: dict[str, MetricSpec] = {m.key: m for m in METRICS}


# --------------------------------------------------------------------------
# Limits: "what this harness cannot prove", each tied to a measurable fact
# --------------------------------------------------------------------------
GuardFn = Callable[[dict, Any], "tuple[bool, str]"]


@dataclass(frozen=True)
class LimitSpec:
    key: str
    text: str
    guard: GuardFn | None = None
    static: bool = False


def active_gate_text(text: str) -> str:
    """``run_all_tests.sh`` without its comment lines. Every wiring check reads
    this: on the raw text a commented-out ``# $PY eval/...`` line counted as a
    wired stanza, so a gate with every instrument disabled passed (external
    review 2026-10-14)."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _gate_problem(root, pipe: str) -> str | None:
    m = re.finditer(pipe, active_gate_text((root / GATE_SH).read_text(encoding="utf-8")))
    hits = [x.group(0) for x in m]
    if hits:
        return f"{GATE_SH} runs {hits[0]!r}"
    return None


def _g_tpr(arts, root):
    """Evidence for "TPR is step coverage, gaps are excluded from the denominator".

    NOTE (reported, not silently substituted): the critic's proposed evidence --
    ``accepted_count == 0`` for every scenario -- does NOT hold on the real tree.
    The artifact reports accepted_count 2/2/1/2 (four frozen, dated forbidden-edge
    waivers) and ``oracle_consistency.py`` exits 0 with them. That is the
    instrument working as designed (an accepted disagreement is reported, never
    hidden), so the guard is built from what this limit actually claims:
    no NEW unwaived drift, and no waiver that has outlived its disagreement
    (``stale_allowlist_entries`` empty everywhere).
    """
    oc = arts.get("oracle_consistency")
    if not oc:
        return False, "no oracle_consistency artifact"
    bad_new, bad_stale, missing_sem = [], [], []
    for sc, f in sorted(oc.items()):
        if f.get("new"):
            bad_new.append(f"{sc}({len(f['new'])})")
        if f.get("stale_allowlist_entries"):
            bad_stale.append(f"{sc}({len(f['stale_allowlist_entries'])})")
        if not f.get("tpr_semantics"):
            missing_sem.append(sc)
    if bad_new:
        return False, ("NEW unwaived oracle/reality disagreement on: " + ", ".join(bad_new)
                       + " -- the answer key and reality now disagree; the TPR caveat "
                         "needs re-reading")
    if bad_stale:
        return False, ("a frozen waiver no longer reproduces on: " + ", ".join(bad_stale)
                       + " -- the allowlist outlived its disagreement")
    if missing_sem:
        return False, ("no tpr_semantics statement on: " + ", ".join(missing_sem))
    accepted = sum(int(f.get("accepted_count") or 0) for f in oc.values())
    sem = str(next(iter(oc.values())).get("tpr_semantics", ""))
    return True, (f"{len(oc)} scenario(s): 0 new disagreement, 0 stale waiver; "
                  f"{accepted} frozen dated waiver(s) reported; artifact states TPR is "
                  f"step coverage ({sem[:70]}...)")


def _g_entity_sharing(arts, root):
    sm = arts.get("scenario_matrix")
    if not sm:
        return False, "no scenario_matrix artifact"
    hi = []
    for sc, node in sorted(sm["scenarios"].items()):
        dd = (node.get("baseline") or {}).get("directional_discrimination")
        if dd is not None and float(dd) >= 0.5:
            hi.append(f"{sc}={dd}")
    if hi:
        return False, ("directional_discrimination has stopped being order-blind ("
                       + ", ".join(hi) + ") -- chain_fidelity/FCR now carry ORDER "
                       "information and this caveat must be rewritten")
    vals = ", ".join(f"{sc}={(sm['scenarios'][sc].get('baseline') or {}).get('directional_discrimination')}"
                     for sc in sorted(sm["scenarios"]))
    return True, f"directional_discrimination ({vals}) < 0.5 on every storyline"


def _g_alert_order(arts, root):
    """alert_order_ok is only meaningful with >=2 alerting (non-gap) steps."""
    sm = arts.get("scenario_matrix")
    if not sm:
        return False, "no scenario_matrix artifact"
    den = arts.get("__denominator__", {})
    ok = True
    ev = []
    for sc, node in sorted(sm["scenarios"].items()):
        non_gap, n_steps, n_gaps = den.get(sc, (0, 0, 0))
        val = (node.get("baseline") or {}).get("alert_order_ok")
        txt = f"{sc}: {non_gap} non-gap step(s) of {n_steps}, alert_order_ok={_f(val)}"
        if non_gap < 2 and val is not None:
            ok = False
            txt += " -- UNSUPPORTED: <2 steps but a truthy value"
        ev.append(txt)
    return ok, "; ".join(ev)


def _g_decision(arts, root):
    """Evidence for "null when no decoys; a measured value otherwise".

    The first version returned OK unconditionally (external review 2026-10-14).
    It now fails when no storyline measures decoys at all (the sentence would
    describe nothing) or when a measured value is not a fraction in [0, 1]. The
    pooling half of the sentence is the ``decoy_contamination`` CONTROL's job
    (a decoy on the attacker's own entity IS absorbed), not this guard's."""
    sm = arts.get("scenario_matrix")
    if not sm:
        return False, "no scenario_matrix artifact"
    with_decoys, bad = [], []
    for sc, node in sorted(sm["scenarios"].items()):
        vals = [r.get("decoy_contamination") for r in node.get("rows", [])
                if r.get("decoy_contamination") is not None]
        if vals:
            with_decoys.append(f"{sc}(max {max(vals)})")
            bad += [f"{sc}={v}" for v in vals
                    if not isinstance(v, (int, float)) or isinstance(v, bool) or not 0 <= v <= 1]
    if not with_decoys:
        return False, "no storyline measures decoy contamination -- the bullet describes nothing"
    if bad:
        return False, "decoy_contamination outside [0, 1]: " + ", ".join(bad)
    nulls = sorted(set(sm["scenarios"]) - {w.split("(")[0] for w in with_decoys})
    return True, ("measured on " + ", ".join(with_decoys) + "; null on "
                  + (", ".join(nulls) or "none"))


def _g_relative_baseline(arts, root):
    sm = arts.get("scenario_matrix")
    if sm:
        sound = [sc for sc, n in sorted(sm["scenarios"].items())
                 if (n.get("baseline_quality") or {}).get("sound_reference")]
        if sound:
            return False, ("baseline_quality.sound_reference is true for " + ", ".join(sound)
                           + " -- the baseline is no longer degraded, so this caveat expires")
    la = arts.get("layer_a")
    if la and (la.get("baseline_quality") or {}).get("sound_reference"):
        return False, "layer_a baseline_quality.sound_reference is true -- caveat expires"
    dds = []
    if sm:
        for sc, n in sorted(sm["scenarios"].items()):
            bq = n.get("baseline_quality") or {}
            dds.append(f"{sc}: fcr={bq.get('false_correlation_rate')} "
                       f"dd={bq.get('directional_discrimination')}")
    if la:
        dds.append(f"layer_a: fcr={(la.get('baseline_quality') or {}).get('false_correlation_rate')}")
    return True, "sound_reference=false everywhere; " + "; ".join(dds)


def _g_declared_boundary(arts, root):
    ev = arts.get("evasion")
    if not ev:
        return False, "no evasion artifact"
    bad = []
    n = 0
    for sc, node in sorted(ev["scenarios"].items()):
        for r in node.get("rows", []):
            if not r.get("searched"):
                continue
            n += 1
            if not r.get("all_agree"):
                bad.append(f"{sc}.{r.get('step')}")
    if bad:
        return False, ("measured != predicted-from-declared at: " + ", ".join(bad)
                       + " -- the boundary is no longer the declared one")
    return True, (f"{n} searched row(s): all_agree=true, so measured == "
                  f"predicted-from-declared at every searched boundary")


def _g_own_fixture(arts, root):
    fc = arts.get("fire_check")
    if not fc:
        return False, "no fire_check artifact"
    rows = len(fc)
    not_fired = [r["id"] for r in fc if not r.get("fired")]
    blocked = [r["id"] for r in fc if r.get("harness_blocked")]
    if not_fired or blocked:
        return False, (f"{len(not_fired)} rule(s) did not fire and {len(blocked)} "
                       f"harness-blocked -- the own-fixture reading must be re-checked")
    return True, f"{rows} tagged rule(s), every one fired on its own producer fixture"


def _g_no_third_party(arts, root):
    pipe = re.compile(r"\$PY\s+eval/detection_accuracy/(?:evtx|splunk)_eval\.py")
    prob = _gate_problem(root, pipe)
    if prob:
        return False, (prob + " -- a third-party-corpus lane is now in the blocking gate, "
                             "so this bullet is false")
    return True, (f"{GATE_SH}: 0 matches for the ANCHORED "
                  f"'$PY eval/detection_accuracy/(evtx OR splunk)_eval.py'; the H7 "
                  f"oracle-vs-engine test it does run (test_evtx_eval.py) uses no "
                  f"third-party corpus")


def _g_two_rule_steps(arts, root):
    """Evidence for "a step mapped to two techniques credits both"."""
    idx = arts.get("__oracle_index_rules__", {})
    if not idx:
        return False, "no oracle step index (oracles unreadable) -- cannot measure " \
                      "multi-rule steps"
    multi = {k: v["rule_ids"] for k, v in sorted(idx.items()) if len(v["rule_ids"]) > 1}
    if not multi:
        # the bullet is about multi-rule steps; with none it describes nothing
        return False, "no oracle step carries more than one expected rule -- rewrite the bullet"
    detail = ", ".join(f"{k} ({len(v)})" for k, v in list(multi.items())[:4])
    return True, (f"{len(multi)} oracle step(s) carry >1 expected rule and are credited "
                  f"to every one of them: {detail}")


def _g_ratchet_scope(arts, root):
    """Evidence for "the ratchet freezes atoms; these card metrics have none".

    Fails when the baseline is missing (then NOTHING is ratcheted and the
    sentence is wrong the other way), when a RATCHET_ATOMS prefix matches no
    committed atom (a stale "this is ratcheted" claim), and when every card
    metric is ratcheted (the sentence has expired)."""
    import json
    p = root / RATCHET_BASELINE_FILE
    if not p.exists():
        return False, f"{RATCHET_BASELINE_FILE} is missing -- no metric is ratcheted at all"
    atoms = (json.loads(p.read_text(encoding="utf-8")).get("atoms") or {})
    stale = []
    for key, prefix in sorted(RATCHET_ATOMS.items()):
        wanted = [prefix.format(s=s) for s in STORYLINES] if "{s}" in prefix else [prefix]
        if not any(a.startswith(w) for a in atoms for w in wanted):
            stale.append(f"{key}->{prefix}")
    if stale:
        return False, "RATCHET_ATOMS names prefixes with no committed atom: " + ", ".join(stale)
    loose = [m.key for m in METRICS if m.key not in RATCHET_ATOMS]
    if not loose:
        return False, "every card metric is ratcheted now -- rewrite the bullet"
    return True, (f"{len(atoms)} atoms in {RATCHET_BASELINE_FILE}; "
                  f"{len(METRICS) - len(loose)} of {len(METRICS)} card metrics ratcheted; "
                  f"not ratcheted: {', '.join(loose)}")


LIMITS: tuple[LimitSpec, ...] = (
    LimitSpec(
        "tpr_is_step_coverage",
        "TPR is step COVERAGE: a step counts when ANY oracle-listed rule fires there, "
        "and steps the oracle records as `no_rule_exists` are excluded from the "
        "denominator, so a declared gap can never lower TPR.",
        _g_tpr),
    LimitSpec(
        "mttd_is_firing_event",
        "For a burst step, mttd_seconds is measured to the FIRING event, not to the "
        "first event of the burst; it is a detection latency, not an exposure window.",
        static=True),
    LimitSpec(
        "fidelity_is_entity_sharing",
        "chain_fidelity and false_correlation_rate measure entity SHARING, not causal "
        "order: the legacy join predicate answers 'joined' for a pair and for that pair "
        "reversed, so both numbers describe 'is there an entity bridge', never 'was the "
        "causal chain reconstructed'.",
        _g_entity_sharing),
    LimitSpec(
        "alert_order_needs_two",
        "alert_order_ok is only meaningful with at least two alerting steps; where a "
        "storyline has fewer, it is reported as null rather than folded to true.",
        _g_alert_order),
    LimitSpec(
        "decoy_scope",
        "decoy_contamination is null when a storyline declares no decoys, and a benign "
        "scanner sitting on the attacker's own target is POOLED into the attack incident "
        "by design -- a documented trade-off, not an oversight.",
        _g_decision),
    LimitSpec(
        "relative_to_degraded_baseline",
        "mutation_robustness is measured RELATIVE to a baseline whose chain fidelity and "
        "false-correlation rate are already degraded, and variants that change nothing "
        "(N/A) are excluded from the denominator.",
        _g_relative_baseline),
    LimitSpec(
        "evasion_is_declared_boundary",
        "The evasion search finds the boundary the rule YAML DECLARES. It proves the "
        "engine honours the rules as written, not that the rules are the right ones.",
        _g_declared_boundary),
    LimitSpec(
        "fire_check_is_own_fixture",
        "fire_check proves declared-vs-fired on each rule's OWN producer fixture. It is "
        "not a real-world detection result and says nothing about traffic the fixture "
        "does not model.",
        _g_own_fixture),
    LimitSpec(
        "no_third_party_corpus_in_gate",
        "No third-party labelled corpus runs in the blocking lane: run_all_tests.sh never "
        "invokes evtx_eval.py or splunk_eval.py, which are dataset-gated and opt-in only.",
        _g_no_third_party),
    LimitSpec(
        "oracles_are_self_authored",
        "The oracles are self-authored: the answer key and the system under test were "
        "written by the same project. oracle_consistency reconciles them against an "
        "independently derived oracle, which bounds but does not remove that bias.",
        static=True),
    LimitSpec(
        "attribution_is_per_step",
        "Per-technique attribution is per STEP, not per event: a step mapped to two "
        "techniques credits both, and mutation attrition on a multi-rule step can "
        "overstate one technique.",
        _g_two_rule_steps),
    LimitSpec(
        "ratchet_scope",
        "`--check` proves the committed card matches a fresh render; it blocks nothing by "
        "itself. The atom ratchet (`eval/twin/ratchet.py check`, a gate stanza) blocks an "
        "unwaived drop of every atom it measures, but several card metrics have no atom "
        "behind them, and for those accepting a worse number is still a card regeneration "
        "plus a commit.",
        _g_ratchet_scope),
)


# --------------------------------------------------------------------------
# Doc lint vocabulary
# --------------------------------------------------------------------------
#: alias (lower-cased) -> canonical metric key. The scan requires an
#: alias-plus-number FORM (`metric=`, `metric:` or `metric <number>`), which
#: keeps prose out; a bare `attribution` is deliberately absent (it matches the
#: ATT&CK attribution column and dates).
ALIASES: dict[str, str] = {
    "tpr": "tpr",
    "fpr": "fpr",
    "mttd_seconds": "mttd_seconds",
    "mttd": "mttd_seconds",
    "mtti": "mtti",
    "mttr": "mttr",
    "chain_fidelity": "chain_fidelity",
    "false_correlation_rate": "false_correlation_rate",
    "fcr": "false_correlation_rate",
    "alert_reduction_ratio": "alert_reduction_ratio",
    "arr": "alert_reduction_ratio",
    "evidence_completeness": "evidence_completeness",
    "severity_calibration_error": "severity_calibration_error",
    "peak_alert_score": "peak_alert_score",
    "severity_in_band": "severity_in_band",
    "directional_discrimination": "directional_discrimination",
    "incident_membership_ok": "incident_membership_ok",
    "alert_order_ok": "alert_order_ok",
    "attribution_accuracy": "attribution_accuracy",
    "mutation_robustness": "mutation_robustness",
}

#: The marker that exempts a doc line from the lint.
HISTORICAL_TAG = "[historical numbers"
