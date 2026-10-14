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
| `bank_db_priv_esc` | `2a9d7b41-…` | **insider_exfil** | banking-DB privileged operation; insider_exfil's in-hours banking steps (the spec's 2.2 design) |
| `bank_mass_card_read` | `d4e5f607-…` | **insider_exfil** | mass cardholder read on one DB object; same storyline |
| `common_after_hours_admin` | `9b5f2d18-…` | **ransomware** | the spec states the POSITIVE: fires in ransomware at 23:46 UTC, and the NEGATIVE: silent on insider_exfil (Tue 10:30 UTC, in hours) and on the in-hours twin |
| `common_rapid_account_lifecycle` | `e5f60718-…` | **cloud_iam_abuse** | account create-then-delete is IAM lifecycle abuse (T1098/T1078 family) |
| `common_bruteforce_sourceless` | `8c2f5a91-…` | **needs a decision** | the critic validated the shape ("sourceless via AD 4625"), but none of the four storylines names it unambiguously; candidate: cloud_iam_abuse (console/IDP stuffing) or a dedicated enterprise step |
| `agent_tool_call_burst` | `2b3c4d5e-…` | **needs a decision** | agent_* family; `ai_to_ot` already covers `agent_mcp_tool_call` but not burst/destructive. The critic noted `agent_tool_call_burst` is the only rule with no MITRE block. Candidate: extend ai_to_ot (its own oracle) rather than a new storyline |
| `agent_destructive_command` | `5e6f7081-…` | **needs a decision** | same family as above |

## What this means for Phase 6 (the four storylines)

- insider_exfil and ransomware together clear **3 of the 7** (bank_db_priv_esc, bank_mass_card_read,
  common_after_hours_admin) with the spec's own positive/negative design.
- cloud_iam_abuse should clear **1** (common_rapid_account_lifecycle) and is the natural home for
  `common_bruteforce_sourceless` if its IDP-stuffing steps are keyed on the account, not the source.
- **Two rules have no obvious home** among the four: the agent_* family. Phase 6 should either (a) extend
  `ai_to_ot`'s oracle with a burst/destructive step (it already owns the agent-tool domain), or (b) get an
  owner decision. This is recorded so the storyline author does not invent a fifth storyline to absorb them.
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

The storyline-to-rule mapping above is read from the design spec, not guessed; the three "needs a
decision" rows are the honest remainder.
