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
    # R4-#69: the substring checks below can't catch a JS SYNTAX error -- run
    # `node --check` on the inline <script> too (mirrors test_contract's
    # node_check_inline_js). Fails loudly if node is missing.
    _node_check_inline_js(html)


def _node_check_inline_js(html: str):
    import re
    import shutil
    import subprocess
    import tempfile

    scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script[^>]*>", html, re.S | re.I)
    # Strip the leading `//<![CDATA[` / `//]]>` wrappers some inline scripts use.
    js = "\n".join(s.strip() for s in scripts)
    if not js.strip():
        FAILS.append("no inline <script> block found to node --check")
        return
    node = shutil.which("node")
    if not node:
        FAILS.append("node not installed -- cannot node --check inline JS; a JS "
                     "syntax error would pass the substring tests (R3-#69)")
        return
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js)
        tmp = f.name
    try:
        cp = subprocess.run([node, "--check", tmp], capture_output=True, text=True)
        if cp.returncode != 0:
            FAILS.append(f"inline JS failed node --check:\n{cp.stderr.strip()[:500]}")
    finally:
        try:
            import os
            os.unlink(tmp)
        except OSError:
            pass

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

    # ---- Gap-hunt #52/#53: client presents the API key (fix both together) ----
    # nginx must REQUIRE the caller-presented key on the write routes, never
    # inject a server-side one (the #52 bypass); the JS must send it on every
    # request via _fetch() reading /api/config.js (the #53 blinding fix).
    check("_fetch(" in html and "X-Api-Key" in html,
          "WS-7: no key-injecting fetch wrapper (gap-hunt #53)")
    check('window.FENGARDE_API_KEY' in html,
          "WS-7: no same-origin config bootstrap for the API key (gap #53)")

    # ---- 2026-08-26: pipeline Monitoring view ----
    # A dedicated end-to-end view (raw -> normalized -> scored -> indexed)
    # built entirely from the real /api/ops/* metrics and live alert/event
    # feeds -- never fabricated. Static assertions on the delivered HTML/JS
    # so a future refactor can't silently drop the feature.
    check('data-view="monitor"' in html, "monitor: no nav entry for the pipeline view")
    check('id="monitor"' in html, "monitor: no <section id=monitor> view")
    check("pipelineFlow" in html, "monitor: no #pipelineFlow container")
    check("renderMonitoring" in html, "monitor: no renderMonitoring() function")
    check("PIPE_STAGES" in html, "monitor: no PIPE_STAGES pipeline definition")
    check("getOpsMetrics" in html, "monitor: does not read the real /api/ops/* metrics")
    check("flowHealth" in html, "monitor: no health signal line")


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
