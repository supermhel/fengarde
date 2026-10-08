"""Keep pytest from collecting the standalone acceptance scripts that import report.py.

test_layer_a.py is NOT a pytest test module (see its own docstring) -- it
must run only via `python eval/adversarial/test_layer_a.py` (or through
run_all_tests.sh / make adversarial), because importing it unconditionally
triggers report.py's module-collision discipline: a pre-seed of
sys.modules["main"] with the ws4-detection module for the lazy WS-4/WS-8
loaders. If pytest ever collected test_layer_a.py alongside another
test_*.py file elsewhere in the repo that does its own bare `import main`
for a DIFFERENT service, whichever imports first would silently win
sys.modules["main"] for the rest of that pytest session -- collection-order
-dependent, unrelated-looking failures. `collect_ignore` here stops pytest
from importing this file at all, matching how the repo actually runs it.

test_order_controls.py (2026-10-02) is the same kind of script: it imports report.py
(directly, to pre-seed sys.modules["main"], and through scenario_registry.grade) and runs
via ``python eval/adversarial/test_order_controls.py`` / run_all_tests.sh. It is listed
here for the same reason. (test_scenario_harness.py is deliberately not listed: it
predates this guard and imports layer_a/report first, the same way.)
"""

collect_ignore = ["test_layer_a.py", "test_order_controls.py"]
