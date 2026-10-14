# Q15/Q16 boundary measurements — owner decisions, not drive-by fixes (2026-10-14)

This document records the measurements available on follow-up head `7e7d5da`. It deliberately
does not change a production rule or regenerate an evasion floor. Both questions alter
published detection semantics and therefore belong after the Phase-2/3 code work, with their
negative twins and ratchets recut deliberately.

## Q15 — `common_beaconing`: six beats vs a 20-beat noise floor

### Shipped contract

`contracts/rules/common_beaconing.yml` declares:

- accepted outbound network activity (`class_uid: 4001`, `activity_id: 7`);
- `group_by: src_endpoint.ip`;
- `window_seconds: 3600`;
- `threshold: 6` accepted connections;
- coefficient of variation `max_cv: 0.25`.

The rule description itself calls this a coarse proxy and warns that regular legitimate
polling can look like a beacon.

### Executed measurements

`python3 eval/adversarial/test_evasion_axes.py` exited **0**. Relevant output:

- `B1 common_beaconing`: the reference burst fired; the T-1 burst did not fire; the reported
  declared threshold was `T=6`.
- `C2 common_beaconing`: the optimal regular schedule evaded, measured and predicted; the
  one-millisecond-faster schedule remained detected.
- `C4 beaconing`: `min_jitter_permille: 269`, `declared_max_cv_permille: 250`,
  `measured == predicted`.

The independent blind pass recorded a preferred minimum sample around 20. The handoff
quantifies the concern: at small samples the regularity statistic has a materially higher
chance of appearing regular under memoryless traffic, and six events can be inside the
false-positive floor for a large estate. That is an independent risk estimate, not a product
failure proven by a benign corpus.

### Q15 decision record

- **Current status:** OPEN.
- **Option A:** keep six beats and document the measured false-positive limitation.
- **Option B:** raise the threshold toward 20 beats, then recut positive/negative twins,
  `rule_probes.py`, evasion floors, oracle boundaries and the scorecard.
- **Do not:** silently edit `threshold` while doing storyline work. The existing tests prove
  the current rule as written, not that six is the correct operational threshold.

## Q16 — credential stuffing: 300-second burst vs sustained campaign tier

### Shipped contract

`contracts/rules/common_password_spray.yml` declares a credential-stuffing rule, not true
password spraying:

- one account (`group_by: actor.user.name`);
- failures (`class_uid: 3002`, `activity_id: 4`);
- `distinct_field: src_endpoint.ip`;
- `threshold: 8` distinct source IPs;
- `window_seconds: 300`;
- ATT&CK `T1110.004`.

The same file explicitly says one-source/many-account password spraying is not covered by
any shipped rule and must not be credited to this rule.

### Executed measurements

The focused evasion-axis run exited **0**. Relevant output:

- `B1 common_password_spray`: the reference burst fired; the T-1 burst did not fire;
  reported `T=8`.
- `B2`: the account setter moved the grouping field, producing three account keys as
  expected.
- `G4`: the shipped per-key counter remained detected under the noise experiment;
  `measured == predicted == immune`, with `backend: deque` and `sweep: per_key`.
- The probe fixture creates 16 failures for one account at 5-second spacing, while the
  declared production window remains 300 seconds.

The independent pass proposed a 24-hour campaign view with a one-hour fast tier. That is a
semantic extension, not a claim that the existing five-minute burst is invalid.

### Q16 decision record

- **Current status:** OPEN.
- **Option A:** keep the 300-second burst as the fast tier and add a separately named 24-hour
  companion rule for sustained one-account stuffing.
- **Option B:** redefine the existing rule's window, then recut every positive/negative twin,
  counter/noise measurement, evasion floor and oracle boundary.
- **Do not:** change the ATT&CK label to T1110.003. The repository's naming correction is
  deliberate: T1110.003 is the known one-source/many-account gap; this rule is T1110.004.

## Acceptance required after owner decisions

For either question, the implementation phase must rerun the focused rule probes, the relevant
negative controls, the evasion-axis suite, the floor/ratchet update deliberately, the affected
storyline oracles, and the final gate. Until then this file is a measurement register only.
