"""Numbers that the docs quote about the labelled set, computed from `labelled_cases.json`.

`RESULTS.md` is rendered from these (never typed), and `test_llm_triage_eval.py` fails if the text that
SSOT.md / README.md carry about the label ceiling drifts from them.

Signature = (the rule titles that fired, the event's `siem.source_type`). It is the coarsest thing a model
can see that still names the detection: two alerts with the same signature look identical in everything
except the event body (users, addresses, times, counts). If one signature holds both labels, no function of
the signature alone can get both right, so predicting each signature's majority label gives the best
accuracy any signature-only judge could reach. That is the "label ceiling". It says nothing about what a
model could do with the event body; it only shows that the body, not the rule, has to carry the difference.
"""
from __future__ import annotations

from collections import Counter, defaultdict


def signature(case: dict) -> tuple:
    return (tuple(case["request"]["reason"]), case["request"]["event"]["siem"]["source_type"])


def label_ceiling(cases: list[dict]) -> dict:
    by_sig: dict = defaultdict(Counter)
    for c in cases:
        by_sig[signature(c)][c["label"]] += 1
    n = len(cases)
    ceiling = sum(max(v.values()) for v in by_sig.values())
    return {"n": n, "signatures": len(by_sig), "mixed": sum(len(v) > 1 for v in by_sig.values()),
            "ceiling": ceiling, "ceiling_pct": f"{100 * ceiling / n:.1f}%" if n else "n/a"}


def ceiling_phrase(cases: list[dict]) -> str:
    """The sentence fragment the docs use, e.g. '9 of 33 distinct (rule, source) signatures ... 44/54 = 81.5%'."""
    s = label_ceiling(cases)
    return (f"{s['mixed']} of {s['signatures']} distinct (rule, source) signatures hold both labels; "
            f"a verdict from (rule, source) alone is capped at {s['ceiling']}/{s['n']} = {s['ceiling_pct']}")


def share(k: int, n: int) -> str:
    """One percentage format everywhere (computed from the counts, never from a rounded float)."""
    return f"{100 * k / n:.1f}%" if n else "n/a"
