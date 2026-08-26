"""Stock-defaults reproduction of gap-hunt findings #1/#2/#3 through the
real correlator: 1 recon alert + 400 brute-force alerts, member_cap=200
(DEFAULT_MEMBER_CAP -- the exact scenario the finding reproduced)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))

from shared.allowlist import Allowlist  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402
from correlator import Correlator, DEFAULT_MEMBER_CAP, _SIDES_SWEEP_EVERY  # noqa: E402


def alert(aid, tactic, actor):
    return {"alert_id": aid, "score": 5, "tenant_id": "default", "time": 0,
            "mitre": {"tactic": tactic}, "actor": {"user": {"name": actor}}}


c = Correlator(DequeWindowCounter(), allowlist=Allowlist([]))
c.ingest_alert(alert("recon1", "TA0043", "mallory"))
emitted = 0
first_id = None
tactics_bad = 0
for i in range(400):
    incs = c.ingest_alert(alert(f"bf-{i}", "TA0006", "mallory"))
    if incs:
        emitted += 1
        if first_id is None:
            first_id = incs[0]["incident_id"]
        if set(incs[0]["tactics"]) != {"TA0043", "TA0006"}:
            tactics_bad += 1
key = c._track_key("default", "actor", "mallory")
side = len(c._sides[key])
print(f"emitted={emitted}/400  side_entries={side} (cap={DEFAULT_MEMBER_CAP})  "
      f"tactics_dropped_on={tactics_bad}  id_stable_from={first_id}")
print("metrics:", c.metrics())
assert emitted == 400, "finding #1: incident must keep re-emitting (alerts #199-399 used to emit nothing)"
assert side <= DEFAULT_MEMBER_CAP, f"finding #2: side table must be bounded at cap, got {side}"
assert tactics_bad == 0, "tactics must keep both under a sustained flood"
print("REPRO OK")