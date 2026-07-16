#!/usr/bin/env python3
"""M5 eval harness: ≥10 synthetic incidents -> NIS2 template drafts ->
checklist assertions. CI-runnable in template mode (zero infra, zero LLM,
zero paid dependency) -- this is what "eval/report_generator/" being
"CI-runnable in template mode" means in the combined plan: a deterministic
harness that runs the SAME builtin template code path this repo ships,
never an LLM judged for quality.

Checklist per (scenario, stage, language) -- every generated draft must:
  1. carry the mandatory disclaimer (contracts/reporting.md hard rule),
  2. have status == "draft" (hard rule),
  3. reflect the source alert's rule_title and alert_id verbatim (no
     fact from the input silently dropped),
  4. carry the NIS2-vs-DORA scope caveat (never silently omitted),
  5. cite its public sources (Art. 23 NIS2 + SS32 BSIG),
  6. never fabricate an entity-identity fact -- every such field is an
     explicit placeholder, not a guess.

Run: python eval/report_generator/run_eval.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services" / "ws3-indexer"))
sys.path.insert(0, str(ROOT / "services"))

import nis2_template  # noqa: E402
from scenarios import SCENARIOS  # noqa: E402

FAILURES: list[str] = []


def _checklist(name: str, stage: str, lang: str, alert: dict, report: dict) -> list[str]:
    problems = []
    body = report.get("body", "")

    if not report.get("disclaimer") or report["disclaimer"] not in body:
        problems.append("disclaimer missing from body or report envelope")
    if report.get("status") != "draft":
        problems.append(f"status must be 'draft', got {report.get('status')!r}")

    rule_title = alert.get("rule_title")
    if rule_title and rule_title not in body:
        problems.append("rule_title from the input alert is absent from the draft")
    alert_id = alert.get("alert_id")
    if alert_id and alert_id not in body:
        problems.append("alert_id from the input alert is absent from the draft")

    if "DORA" not in body:
        problems.append("NIS2-vs-DORA scope caveat missing")
    if not report.get("citations"):
        problems.append("citations missing (must cite Art. 23 NIS2 + SS32 BSIG)")

    placeholder = nis2_template._PLACEHOLDER[lang]
    if placeholder not in body:
        problems.append("no [ANALYST MUST PROVIDE]-style placeholder found -- "
                        "entity facts must never be silently fabricated")

    return problems


def main() -> int:
    total = 0
    for name, alert, triage in SCENARIOS:
        for stage in nis2_template.STAGES:
            for lang in nis2_template.LANGUAGES:
                total += 1
                report = nis2_template.build_report(alert, triage, stage=stage, lang=lang)
                problems = _checklist(name, stage, lang, alert, report)
                if problems:
                    for p in problems:
                        FAILURES.append(f"{name} [{stage}/{lang}]: {p}")

    print(f"eval/report_generator: {len(SCENARIOS)} scenarios x "
          f"{len(nis2_template.STAGES)} stages x {len(nis2_template.LANGUAGES)} languages "
          f"= {total} drafts checked")
    if FAILURES:
        print(f"[FAIL] {len(FAILURES)} checklist violation(s):")
        for f in FAILURES:
            print("   -", f)
        return 1
    print(f"[OK] all {total} drafts pass every checklist item "
          f"(disclaimer, draft status, facts-from-input preserved, "
          f"DORA scope caveat, citations, entity facts never fabricated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
