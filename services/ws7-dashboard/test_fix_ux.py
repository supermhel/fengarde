"""WS-7 UX-fix static test (E11 alert lifecycle/playbooks, E12 saved
searches, E13 dark mode) -- static checks, no browser needed.

Asserts:
  * E12: the saved-search feature exists (Save-filter control, saved-search
    dropdown, localStorage persistence key) and re-applies a saved filter.
  * E13: the theme is driven by CSS custom properties with an html.dark
    override, a theme toggle button exists, preference is persisted in
    localStorage, and prefers-color-scheme is respected.
  * E11: the triage status control stays within the statuses the backend
    triage API accepts ({new,triaged,closed,false_positive,true_positive} --
    triage_api.py::_STATUSES); the richer lifecycle steps the backend does
    NOT accept (investigating/contained) must appear only as analyst
    guidance text, never as selectable triage options; a read-only playbook
    display (rule.playbook markdown) is rendered near the alert.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FAILS: list[str] = []

# Statuses the backend triage API actually persists (triage_api.py::_STATUSES).
BACKEND_STATUSES = {"new", "triaged", "closed", "false_positive", "true_positive"}
# Richer lifecycle steps NOT accepted by the backend -- guidance text only.
GUIDANCE_ONLY = {"investigating", "contained"}


def check(c, m):
    if not c:
        FAILS.append(m)


def run():
    html = (HERE / "index.html").read_text(encoding="utf-8")

    # ---- E12: saved searches (pure client-side, localStorage) ----
    check('id="saveFilter"' in html, "E12: missing Save-filter button")
    check('id="savedSearches"' in html, "E12: missing saved-searches dropdown")
    check('id="alertSearch"' in html, "E12: missing alert search input")
    check('id="sevFilter"' in html, "E12: missing severity filter")
    check('id="statusFilter"' in html, "E12: missing status filter")
    check('"fengarde.savedSearches"' in html,
          "E12: saved searches not persisted under a localStorage key")
    check("localStorage.getItem(SAVED_KEY)" in html or "localStorage.getItem(\"fengarde.savedSearches\")" in html,
          "E12: saved searches do not read from localStorage")
    check("saveCurrentFilter" in html, "E12: no saveCurrentFilter() implementation")
    check("applyAlertFilter" in html, "E12: no applyAlertFilter() implementation")

    # ---- E13: dark mode via CSS variables + toggle ----
    check("html.dark" in html, "E13: no html.dark theme override")
    check("--bg:" in html and "--panel:" in html and "--txt:" in html,
          "E13: core colors not defined as CSS custom properties")
    check("var(--bg)" in html and "var(--panel)" in html and "var(--txt)" in html,
          "E13: CSS rules do not consume the custom properties")
    check('id="themeToggle"' in html, "E13: missing theme toggle button")
    check('"fengarde.theme"' in html, "E13: theme preference not persisted in localStorage")
    check("prefers-color-scheme" in html, "E13: prefers-color-scheme not respected")

    # ---- E11: lifecycle statuses -- backend-accepted only in the dropdown ----
    # The status dropdown options must never include a value the backend
    # rejects (investigating/contained)...
    check("TRIAGE_STATUSES" in html, "E11: TRIAGE_STATUSES constant missing")
    check("triageStatusOptions" in html, "E11: triageStatusOptions() missing")
    for s in BACKEND_STATUSES:
        check(f'value="{s}"' in html or f'"{s}"' in html,
              f"E11: backend-accepted status {s!r} missing from UI")
    for s in sorted(GUIDANCE_ONLY):
        # ...they may appear as analyst guidance (lifecycle hint text)...
        check(s in html, f"E11: lifecycle step {s!r} missing entirely from guidance")
        # ...but must NOT appear as a <select> option value.
        check(f'<option value="{s}"' not in html,
              f"E11: {s!r} is a selectable triage option but the backend rejects it")
    # the lifecycle-hint guidance block exists
    check("lifecycle-hint" in html, "E11: missing analyst lifecycle guidance area")

    # ---- E11: playbook display (read-only rule.playbook markdown) ----
    check("playbook" in html, "E11: no playbook support at all")
    check("details.playbook" in html or 'class="playbook"' in html,
          "E11: no per-alert playbook disclosure element")
    check("playbook-body" in html, "E11: no playbook body element")
    check("enrichPlaybooks" in html, "E11: no playbook enrichment logic")
    check("RULE_PLAYBOOK" in html, "E11: no rule->playbook lookup cache")


def main():
    run()
    if FAILS:
        print(f"[FAIL] WS-7 UX-fix: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] WS-7 UX-fix test PASS")


if __name__ == "__main__":
    main()
