import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_floor_lowering as C

base = {"rule_sets": {"r": {"fields": {"extra_seconds": {"better": "max", "value": 70.0},
                                       "forgery_evades": {"better": "min", "value": False}}}}}
def mk(sec, ev=False, lowered=0):
    return {"rule_sets": {"r": {"fields": {"extra_seconds": {"better": "max", "value": sec},
                                           "forgery_evades": {"better": "min", "value": ev}},
                                "lowered": [{"date": "x"}] * lowered}}}
assert C.violations(base, mk(70.0)) == [], "unchanged"
assert C.violations(base, mk(80.0)) == [], "improved (higher is better) is fine"
assert len(C.violations(base, mk(60.0))) == 1, "hand-lowered max field must be caught"
assert len(C.violations(base, mk(70.0, ev=True))) == 1, "min field worsened must be caught"
assert C.violations(base, mk(60.0, lowered=1)) == [], "lowered with a recorded entry passes"
print("[OK] check_floor_lowering: hand-lowered floors caught, improvements and recorded lowerings pass")
