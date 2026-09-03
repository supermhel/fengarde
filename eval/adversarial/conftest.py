"""Keep pytest from collecting the standalone Layer A acceptance script.

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
"""

collect_ignore = ["test_layer_a.py"]
