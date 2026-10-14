# P4 disagreement register — phishing/BEC blind pass (2026-10-14)

This is an analysis register, not a gate result. The independent YAML is archived under
`docs/handoff/blind-oracles/`, outside `eval/`, so `test_oracle_crosscheck.py` does not
silently consume it as a committed oracle.

## Mechanical comparison actually performed

Both files were loaded with PyYAML and compared by the eight common step names. The committed
oracle uses `gap.no_rule_exists` and `expected_rules`; the blind oracle uses `gap` plus
`detectable_in_principle`. The resulting gap-flag comparison is **6/8 equal**:

| step | committed oracle | blind oracle | register | owner decision |
|---|---|---|---|---|
| `phish_delivery` | gap | gap / not detectable from supplied telemetry | agree | none; mail parser remains a product gap |
| `user_execution` | gap (`T1204.002`) | detectable in principle; no rule id | **disagree** | treat as an unimplemented product gap, not as inherently undetectable; owner decides whether to add a process-launch rule |
| `c2_beacon` | rule `f6071829-…` | detectable in principle; no rule id | agree on detectability | **Q15**: decide whether 6 beats is acceptable or raise the threshold toward the independent 20-beat noise-floor estimate |
| `victim_session` | gap / context (`no_rule_exists`) | context; detectable telemetry but no attack alert expected | **schema disagreement** | split “must-not-fire context” from “attack step should fire but no rule exists” in a future schema change; do not count this as a product gap without that distinction |
| `proxy_pool_logins` | rule `4f8a2c61-…` | detectable in principle; no rule id | agree on shape | no immediate owner decision; counting key is the account plus distinct source addresses |
| `foreign_login` | rule `7081a2b3-…` | detectable in principle; no rule id | agree on detectability; blind version is stricter | owner may decide whether country-change alone is sufficient or requires stuffing correlation |
| `inbox_rule` | gap (`T1114.003`) | gap / not detectable from supplied telemetry | agree | M365 audit parser remains a product gap |
| `payment_redirect` | gap (`T1565.001`) | gap / not detectable from supplied telemetry | agree | database change-data-capture remains a product gap |

The `…` in rule IDs is only presentation in this table; the committed YAML is authoritative
for full UUIDs. The blind artifact intentionally carries no rule IDs.

## Boundary observations

These are observations, not automatic recommendations:

- **Beaconing:** `contracts/rules/common_beaconing.yml` declares `threshold: 6`,
  `window_seconds: 3600`, and `periodicity.max_cv: 0.25`. The executed evasion-axis test
  reported the regular schedule as detected, a 1 ms faster boundary as still detected, and
  `min_jitter_permille: 269` against `declared_max_cv_permille: 250`. The independent pass
  documented a preferred sample size around 20. This is the Q15 decision, not a drive-by rule
  edit.
- **Credential stuffing:** `common_password_spray.yml` declares one account, distinct
  `src_endpoint.ip`, `threshold: 8`, `window_seconds: 300`. The rule-probe test reported the
  positive burst firing and the T-1 (7) burst silent. The independent pass proposed a longer
  campaign tier (24 h, with a faster tier) rather than replacing the existing burst semantics.
  This is Q16, not permission to relabel the rule as T1110.003; the file explicitly says it is
  T1110.004 credential stuffing and that true one-source/many-account spray is uncovered.

## Scope verdict

The pass supplies an independent detectability comparison and records two schema/product
findings. It does **not** close P4: the blind YAML is not wired into `oracle_mutate.py` or the
normal oracle-consistency gate, and owner decisions for the two disagreements remain open.
The correct claim is “6/8 gap flags agree, with two recorded disagreements,” not “blind
validation passed.”
