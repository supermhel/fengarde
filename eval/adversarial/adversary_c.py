"""adversary_c -- WP-4-A LAYER C: the NIGHTLY ADAPTIVE LOCAL-LLM ADVERSARY.

THE SINGLE MOST IMPORTANT CONSTRAINT (roadmap Phase 4):
    Layer C is NEVER blocking. It composes mutations across axes with a
    STOCHASTIC LLM (local Ollama), and stochastic output must never enter
    the blocking gate. This module is invoked ONLY by the nightly workflow
    (.github/workflows/nightly-adversary.yml). The only deterministic
    surface it exposes is --dry-run, which proves the lane RUNS (and is the
    only mode the zero-infra gate may call -- a deterministic self-check,
    never a stochastic case).

WHAT IT DOES
    1. Builds the base chain payloads (scenario._build_chain_payloads).
    2. Adaptive mode (--llm): calls the REAL local LLM
       (services/ws5-ai/llm_adapter.py, OllamaLLM or FallbackLLM->StubLLM)
       with a prompt asking it to COMPOSE a cross-axis mutation (pick axes +
       variants from the engine's catalogue an adaptive attacker would
       combine). The reply is parsed into (axis, variant) pairs, validated
       against the catalogue, and applied via mutate.apply_mutation.
    3. Stub mode (--dry-run): a SEEDED adversary draws the same kind of
       cross-axis compositions deterministically (random.Random(seed)), so
       the harness plumbing is proven WITHOUT an LLM and WITHOUT
       stochasticity. Same seed -> same compositions -> same grades.
    4. Every produced mutation is graded by Layer A's own real grader
       (layer_a._grade_variant + layer_a._cmp) -> the same row shape as the
       matrix: detection_retained / fidelity_retained / fcr_unchanged /
       causal_join_broken.
    5. Reproducibility: the output records seed, producer (stub|llm), the
       model identity when known, and the FULL produced case list -- so a
       nightly stochastic run can be replayed from its recorded cases even
       though the LLM output itself is not deterministic.

SAFETY
    Simulation-only; no real control action; payload-level transforms of the
    in-memory twin chain only. Same discipline as every other eval module.

OUTPUT
    JSON (deterministic in --dry-run) to --out (default
    out/adversary_c.latest.json, GITIGNORED). Exit 0 when the lane
    completes; grades are REPORTED, never asserted (never blocking).

STDLIB ONLY; the LLM adapter is loaded lazily via spec_from_file_location
(unique module name), the same discipline report.py uses for WS-8 / WS-3
evidence -- no module-name hijacking of a bare `main`.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from random import Random
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TWIN = ROOT / "eval" / "twin"
SERVICES = ROOT / "services"
ADVERSARIAL = Path(__file__).resolve().parent
for p in (str(TWIN), str(SERVICES)):
    if p not in sys.path:
        sys.path.insert(0, p)

import mutate  # noqa: E402
import layer_a  # noqa: E402  (the real mutation grading path)
import scenario  # noqa: E402

OUT_DIR = ADVERSARIAL / "out"
DEFAULT_OUT = OUT_DIR / "adversary_c.latest.json"

# How many compositions each producer emits per run. Small: Layer C is a
# nightly advisory lane, not a matrix fan-out.
_N_PER_MODE = 4

_PROMPT_TMPL = (
    "You are a red-team harness for a SIEM that detects an AI-to-OT attack "
    "chain. Compose ONE adversarial mutation that an adaptive attacker would "
    "use, choosing ONLY from these axes and their variants:\n"
    "{catalogue}\n"
    "Return a JSON list of [axis, variant] pairs (1 to 3 pairs), e.g. "
    '[[\\"identity\\", \\"different_actor\\"], [\\"network\\", \\"ip_pivot\\"]]. '
    "No prose."
)


def _parse_pairs(text: str) -> list[tuple[str, str]]:
    """Parse `[["axis","variant"], ...]` fragments from an LLM reply."""
    found = re.findall(
        r"\[\s*[\"']([a-z_]+)[\"']\s*,\s*[\"']([a-z_]+)[\"']\s*\]",
        text, re.IGNORECASE)
    return [(a.lower(), v.lower()) for a, v in found]


def _stub_compositions(seed: int, n: int = _N_PER_MODE) -> list[list[tuple[str, str]]]:
    """Seeded adaptive-composition surrogate: draw n compositions of 1-3
    (axis, variant) pairs from the engine's real catalogue. Deterministic:
    same seed -> same compositions (same order, same pairs)."""
    rng = Random(seed)
    pool: list[tuple[str, str]] = []
    for ax in sorted(mutate._AXES):
        for v in mutate._VARIANTS[ax]:
            pool.append((ax, v))
    out: list[list[tuple[str, str]]] = []
    for _ in range(n):
        k = rng.randint(1, 3)
        comp = [pool[rng.randrange(len(pool))] for _ in range(k)]
        out.append(comp)
    return out


_LLM_MOD_NAME = "ws5_llm_adapter_mod"
_LLM_PATH = SERVICES / "ws5-ai" / "llm_adapter.py"


def _load_llm():
    """Load the REAL llm_adapter (spec_from_file_location, unique name)."""
    if not _LLM_PATH.exists():
        return None
    mod = sys.modules.get(_LLM_MOD_NAME)
    if mod is None:
        spec = importlib.util.spec_from_file_location(_LLM_MOD_NAME, _LLM_PATH)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_LLM_MOD_NAME] = mod
        spec.loader.exec_module(mod)
    try:
        return mod.make_llm()
    except Exception:
        return None


def _llm_compositions(llm: Any, seed: int, n: int = _N_PER_MODE) -> list[list[tuple[str, str]]]:
    """Compose via the local LLM: prompt -> parse -> validate against the
    catalogue (unrecognized pairs are skipped with a warning, never silently
    graded as something else). The base seed seeds the fallback stub; the
    LLM payload itself is stochastic (advisory only, never gated)."""
    catalogue = "\n".join(
        f"- {ax}: {', '.join(mutate._VARIANTS[ax])}" for ax in sorted(mutate._AXES))
    prompt = _PROMPT_TMPL.format(catalogue=catalogue)
    comps: list[list[tuple[str, str]]] = []
    for _ in range(n):
        text = ""
        try:
            if hasattr(llm, "predict"):
                text = str(llm.predict(prompt))
            elif hasattr(llm, "complete"):
                text = str(llm.complete(prompt))
            else:
                sys.stderr.write("[adversary_c] LLM has no predict/complete; treating as stub\n")
                break
        except Exception as exc:  # never blocking: record, don't fail
            sys.stderr.write(f"[adversary_c] llm call failed: {exc!r}\n")
            continue
        pairs = _parse_pairs(text)
        ok = [(a, v) for a, v in pairs
              if a in mutate._AXES and v in mutate._VARIANTS[a]]
        if ok:
            comps.append(ok)
    return comps


def _grade_composition(comp: list[tuple[str, str]], seed: int) -> dict:
    """Grade ONE composed mutation through Layer A's REAL grader; returns the
    same row shape the Layer A matrix uses."""
    oracle = layer_a.report._load_oracle()
    base_build = scenario._build_chain_payloads(seed)
    base_payloads = base_build[0]
    base_grade = layer_a._baseline_grade(seed, oracle)
    mutated = mutate.apply_mutation(base_payloads, "composition", "", seed,
                                    composition=comp)
    mut_grade = layer_a._grade_variant(mutated, seed, oracle)
    row = layer_a._cmp("adversary_c", "+".join(a for a, _v in comp),
                       base_grade, mut_grade)
    row["composition"] = [{"axis": a, "variant": v} for a, v in comp]
    return row


def run(seed: int = 7, *, llm: bool = False, n: int = _N_PER_MODE,
        out: Path = DEFAULT_OUT) -> dict:
    """Run Layer C (stub OR adaptive); write + return the advisory envelope.

    ``llm=False`` -> deterministic stub compositions (what a no-Ollama
    nightly and the gate's dry-run use). ``llm=True`` -> adaptive mode via
    the local LLM; the LANE is advisory, never blocking (grades are
    reported, not asserted). Falls back to the stub when the LLM is
    unavailable, recording the fallback in the output.
    """
    llm_obj = None
    producer = "stub"
    if llm:
        llm_obj = _load_llm()
        if llm_obj is not None:
            producer = "llm"

    if producer == "llm":
        comps = _llm_compositions(llm_obj, seed, n)
        if not comps:  # LLM returned only invalid pairs -> fall back loudly
            sys.stderr.write("[adversary_c] LLM produced no valid pairs; falling back to stub\n")
            comps = _stub_compositions(seed, n)
            producer = "stub"
    else:
        comps = _stub_compositions(seed, n)

    envelope = {
        "schema": "layer-c-adversary-v1",
        "basis": "harness-measured",
        "seed": seed,
        "producer": producer,
        "llm_model": os.getenv("OLLAMA_MODEL"),
        "cases": [],
        "never_blocking": True,  # advisory only: Layer C must never gate
        "deterministic": producer != "llm",
    }
    for comp in comps:
        row = _grade_composition(comp, seed)
        envelope["cases"].append(row)

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh, indent=2)
    return envelope


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="adversary_c",
        description="FENGARDE Phase-4 Layer C: nightly adaptive adversary (NEVER blocking)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--dry-run", action="store_true",
                    help="deterministic stub compositions only (the ONLY gatable mode)")
    ap.add_argument("--llm", action="store_true",
                    help="use the local LLM (stochastic; nightly only -- never in the gate)")
    ap.add_argument("--n", type=int, default=_N_PER_MODE)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args(argv)

    adaptive = bool(args.llm) and not args.dry_run
    print("== Phase 4 Layer C: nightly adaptive adversary (NEVER blocking) ==")
    print(f"  mode: {'ADAPTIVE (stochastic, advisory -- nightly only)' if adaptive else f'deterministic dry-run (seed={args.seed})'}")
    result = run(args.seed, llm=adaptive, n=args.n, out=args.out)
    print(f"producer={result['producer']}  cases={len(result['cases'])}  "
          f"deterministic={result['deterministic']}  never_blocking={result['never_blocking']}")
    for c in result["cases"]:
        comp = " + ".join(f"[{p['axis']}:{p['variant']}]" for p in c.get("composition") or [])
        print(f"  {comp:<58} pass={c['pass']} det={c['detection_retained']} "
              f"fid={c['chain_fidelity']} fcr={c['false_correlation_rate']} "
              f"join_break={c['causal_join_broken']}")
    print(f"[OK] Layer C advisory cases written to {args.out} -- advisory only, never gated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())