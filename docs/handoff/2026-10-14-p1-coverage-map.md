# P1 coverage map — which rules the four remaining storylines must exercise (2026-10-14)

Measured on the current head (`7e7d5da`), statically: every rule id declared in any
`eval/twin/oracle*.yaml` `detection_points[].expected_rules` is "covered by an oracle"; every
rule file in `contracts/rules/` that no oracle names is "uncovered". This is the same
measurement `technique_matrix.py` gates on (a rule in no oracle is "unexercised" and the
matrix lane reports it).

## Measured now

- 35 rule files, **28 covered** by an oracle (the 5th storyline, `ot_opcua_sabotage`,
  removed six from the uncovered set).
- **7 uncovered** rule files:

| rule | id | designed storyline (from `design-specs/step2_storyline-coverage.json`) | evidence |
|---|---|---|---|
| `bank_db_priv_esc` | `2a9d7b41-5e6c-4f88-bb12-3c0a1e7d4f02` | **insider_exfil** | banking-DB privileged operation; insider_exfil's `grant_self_access` step |
| `bank_mass_card_read` | `d4e5f607-8192-4a31-8b4c-5d6e7f809104` | **insider_exfil** | mass cardholder read on one DB object; insider_exfil's `bulk_table_read` step |
| `common_after_hours_admin` | `9b5f2d18-3c7a-4e61-8f24-5a1d7c3e9b06` | **ransomware** | fires in ransomware at 23:46 UTC; must remain silent on insider_exfil (Tue 10:30 UTC) and its in-hours twin |
| `common_rapid_account_lifecycle` | `e5f60718-92a3-4b42-9c5d-6e7f80910415` | **cloud_iam_abuse** | account create-then-delete, the `backdoor_account` step |
| `common_bruteforce_sourceless` | `8c2f5a91-4d16-4e8b-9c3a-1f6b2e7d5a83` | **needs owner confirmation** | the spec places a one-source/many-account `cred_spray` step in ransomware; candidate is strong, but the sourceless AD 4625 semantics must be explicit |
| `agent_tool_call_burst` | `2b3c4d5e-6f70-4899-8a1b-2c3d4e5f6a7c` | **needs owner decision** | agent-family rule; no `mitre` block. Extend the agent steps in `supply_chain_ci` or retain a permanent no-technique waiver; do not invent a fifth storyline |
| `agent_destructive_command` | `5e6f7081-92a3-4bc4-ad2e-4f5a6b7c8d9e` | **needs owner decision** | agent-family rule; natural fit beside the supply-chain agent steps, but the mapping is not yet committed |

## What this means for Phase 6 (the four storylines)

- insider_exfil and ransomware together clear **3 of the 7** (bank_db_priv_esc, bank_mass_card_read,
  common_after_hours_admin) with the spec's own positive/negative design.
- cloud_iam_abuse should clear **1** (common_rapid_account_lifecycle).
- `common_bruteforce_sourceless` is placed by the spec in ransomware's `cred_spray` step, and
  `eval/adversarial/technique_waivers.yaml` already waits on exactly that step; the AD 4625
  sourceless semantics must be explicit in that oracle.
- The two agent_* rules are waived pending supply_chain_ci (`pipeline_sabotage`,
  `agent_runaway`) in the same waiver file; no fifth storyline is needed to absorb them.
- The storylines also add **technique coverage** beyond the rule catalog (their declared gaps): ransomware
  T1078/T1490/T1486, insider_exfil T1560.001/T1074.001/T1567/T1070, cloud_iam_abuse T1110.004/T1087.004/
  T1098.001/T1562.008, supply_chain_ci T1195.001. None of those invents a rule.

## Reproduction

```sh
# count + list uncovered rules (statics only, no pipeline run needed)
python3 - <<'PY'
import yaml, glob
rules = {str(yaml.safe_load(open(f)).get('id','')): f.split('/')[-1]
         for f in glob.glob('contracts/rules/*.yml')}
covered = set()
for f in glob.glob('eval/twin/oracle*.yaml'):
    for v in (yaml.safe_load(open(f)).get('detection_points') or {}).values():
        for er in (v.get('expected_rules') or []):
            rid = er.get('rule_id') if isinstance(er, dict) else er
            if rid: covered.add(str(rid))
print(len(rules), 'rules,', len(covered), 'covered,', len(rules)-len(covered), 'uncovered')
for rid in sorted(rules):
    if rid not in covered: print(' ', rid, rules[rid])
PY
```

The storyline-to-rule mapping above is read from the design spec, not guessed; the rows marked "needs owner
confirmation/decision" are the honest remainder.
