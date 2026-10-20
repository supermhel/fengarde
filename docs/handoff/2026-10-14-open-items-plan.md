# Open items after PR #93 — verified state and plan (2026-10-14)

Base: `fix/r3-injection-evasion-hardening` at `7e7d5da` (local only until pushed). Each item below was
checked against the tree, not taken from the earlier hand-off list.

## Verified state (start of the work -- superseded by the Status section at the end of this file)

| Item | State | Evidence |
|------|-------|----------|
| P0(b) external review | DONE in a separate session; findings OPEN | `engineering:code-review` run on `origin/main...7e7d5da` on 2026-10-14: 7 production + 12 eval-harness findings, 5 reproduced by script |
| P1 four storylines (ransomware, insider_exfil, cloud_iam_abuse, supply_chain_ci) | OPEN, not started | `scenario_registry.ALL` holds 5; `technique_waivers.yaml` has 7 `unexercised` rules waiting on exactly these storylines |
| P3 step 6 (ratchet) | OPEN, not started | no `eval/twin/ratchet.py`, no `baseline_scenarios.json`; `RATCHET_FLOOR_FILE` absent |
| P4 blind oracle grading | OPEN | `docs/handoff/blind-oracles/2026-10-14-phishing-bec-blind.yaml` declares no rule ids, so nothing grades it |
| P5 product decisions | OPEN, owner | WS-8 options A–D, F2, F4, mail/M365 parsers, OPC UA allowlist owner |
| §7 Q3 evasion tables | OPEN, owner | 10/10 rows `ratified: false`; 2 rows ASSUMED; the `linux_ssh.username` basis is stale (parser now takes the RIGHTMOST `from <ip>`) |
| §7 Q9/Q11/Q12 | OPEN, owner/data | need a real resolver log, the deployed Redis versions, a funding decision |
| §7 Q13 nightly corpus fetch | OPEN | `nightly-eval.yml` clones EVTX samples directly; no `fetch_corpora.py` / `blind_recall.py` step |
| Push `7e7d5da` | OPEN | `origin/fix/r3-injection-evasion-hardening` = `a56e5b8` |
| Stale worktree `storyline-ot-opcua-sabotage` | removable | every modified file equals `7e7d5da` except two older copies (`seed % 2` vs committed `seed % 3`; `oracle_strength.json` differs only by CRLF) |
| `heuristic-dhawan-8f7d20`, `.impeccable/`, `AGENTS.md`, `docs/cfp/` | not ours | left alone |
| 27 mypy errors in `eval/twin` | OPEN | gate mypy covers `services/` + `tools/` only |

## Plan

Work lands in two places so PR #93 does not grow by another 20k lines:

- **PR #93 branch** — fixes to code PR #93 introduced (review findings), mypy, cleanup, nightly.
- **Stacked follow-up branch `feat/eval-p1-p3-p4`** (based on the PR #93 head) — new storylines, ratchet, blind grading.

### Phase 1 — housekeeping
1. Push `7e7d5da` to the PR branch.
2. Remove the superseded `storyline-ot-opcua-sabotage` worktree.

### Phase 2 — review findings (PR #93 branch)
Production: mcp_agent decode gaps (unpadded/offset base64, base64url, zero-width/format chars, JSON-escaped
whitespace); companion suppression keyed on the same entity, not just "sibling matched"; `_SLD` under-pooling claim;
`/rules` default tenant from `default_tenant()`; `/rules` rule-file read robustness; dead-rule gauge tenant scan;
copy-pasted score-weight comments. Eval: list-valued oracle-consistency metrics; dormant-control detection scoped to
`main()`/`__main__`; comment-blind gate wiring; TPR cell numerator; register count; vacuous guards; lint at sentence
end; extractor errors not rendered as `null`; vacuous shape test; 5th-oracle test coverage; `tools/` freshness;
`--run` message; evasion storyline cross-check. Each fix gets a negative control.

### Phase 3 — mypy over `eval/twin`
Fix the 27 errors, then add `eval/twin` to the blocking mypy step.

### Phase 4 — nightly corpus lane (Q13)
`nightly-eval.yml`: `fetch_corpora.py` + `blind_recall.py --require-corpus`, git-lfs and python-evtx installed,
behind the existing `NIGHTLY_EVAL_MODE` switch so it can be turned off without a code change.

### Phase 5 — step 6 ratchet (follow-up branch)
Per `design-specs/step6_ratchet-ci.json` with its critic verdict applied: atom-level baseline, dated capped
waivers, `refresh` as the only way up, weakened-rule mutation proof, gate stanza. Retires scorecard limit #12.

### Phase 6 — P1 storylines (follow-up branch)
Per `design-specs/step2_storyline-coverage.json`: ransomware, insider_exfil, cloud_iam_abuse, supply_chain_ci —
oracle first from rule intent, builder second, waiver lines deleted as rules become exercised, gaps tagged with
ATT&CK ids, scorecard registry extended. No rule is invented.

### Phase 7 — P4 blind grading (follow-up branch)
A technique-level grader for oracles that carry no rule ids, run over the archived blind oracle, writing a
disagreement register with an owner-decision field per row. The rule authors' decisions on the rows stay owner
input (Q15/Q16 included).

### Phase 8 — owner decisions (answered 2026-10-14)

| Question | Decision | Work |
|---|---|---|
| Q3 evasion tables | ratify the 8 verified rows; the 2 ASSUMED rows stay `ratified: false` | flip 8 rows, fix the stale `linux_ssh.username` basis, make ratified findings gate |
| F2 identity | strip + casefold (ADR-009 as ratified) | canonicalise WS-4 group keys for account fields; `alert_key` churns once (CHANGELOG) |
| F4 record clock | flag only | stamp `siem.clock_skew_ms` + flag when record vs receipt time differ by > 5 min; detection unchanged |
| WS-8 | options A + B | A: document + contract-test `ts_ms`; B: read-side `timeline.py`, graded by the harness |
| Q15 beaconing | raise 6 -> 20 beats | rule threshold/window, negative twins re-cut, evasion floor refreshed deliberately |
| Q16 spray | add a 24 h tier | new companion rule beside the 300 s burst rule |
| Parsers | build mail_gateway + m365_audit | parsers + fixtures + contract tests; storyline gaps re-evaluated |
| Q11 Redis | unsure | Lua fallback for Redis < 6.2 instead of `ZADD ... GT`, chosen by server version |

Still needs data the repo cannot produce: Q9 (a real resolver log for `tools/dns_cardinality_report.py`), Q12
(funding the wall-clock window input), the OPC UA allowlist owner (Q8).

Every phase ends with `bash run_all_tests.sh` green before it is called done.

---

# Status — FENGARDE PR #93 open items (2026-10-14, end of session)

## Just done
- External review of PR #93 (`origin/main...7e7d5da`) run in a separate session; every production and
  eval-harness finding fixed with a negative control (`services/ws2-normalization/parsers/mcp_agent.py`,
  `services/ws4-detection/{engine,main}.py`, `dns_query.py`, `services/ws3-indexer/rules_view.py`,
  `tools/generate_scorecard.py`, `eval/scorecard_registry.py`).
- The other agent's phases 5-7 (adaptive evasion, atom ratchet, scorecard audit) replayed as a linear
  history on `integrate/pr93` (its local merge `150b737` committed conflict markers in
  `docs/handoff/2026-10-14-p1-coverage-map.md`; the replay resolves them).
- Owner decisions implemented: F2, F4, Q3, Q11, Q15, Q16, WS-8 A+B, both parsers (see the Phase 8 table).
- P1: four storylines + oracles (`eval/twin/storyline_{ransomware,insider_exfil,cloud_iam_abuse,supply_chain_ci}.py`);
  the seven technique-matrix waivers they cover deleted; first-run disagreements recorded, not tuned.
- P4: `eval/twin/blind_grader.py` + `docs/handoff/blind-oracles/owner_decisions.yaml`.
- Q13 nightly corpus lane, `eval/twin` in the blocking mypy step, ratchet/floor/scorecard refreshed with reasons.

## Reality Map
| Item | State | Evidence |
|------|-------|----------|
| External review findings (production + eval) | DONE | PROVEN: tests with negative controls; full gate `run_all_tests.sh` (see the last row) |
| Companion suppression: coverage, not "sibling matched" | DONE | PROVEN: `test_companion_rules.py` (7) resolver tunnel alerts twice, (8) pure tunnel once; it_intrusion back to its pre-fix alert count |
| F2 account group keys = ADR-009 canonical actor | DONE | PROVEN: `test_group_canonical.py` (fails with the fix stashed); evasion E1/E2 re-measured |
| F4 `siem.clock_skew_ms` flag | DONE | PROVEN: `test_mail_m365.py::TestClockSkewStamp` |
| Q3 ratify 8 verified evasion-table rows | DONE | PROVEN: `test_evasion_axes.py` E0/E6; 2 ASSUMED rows stay unratified |
| Q11 Redis < 6.2 Lua fallback | DONE (fake) / ASSUMED (real server) | PROVEN on the fake: `test_window_distinct.py`; the live parity test `test_window_redis_live.py` runs only in CI redis-integration (no local Redis this session) |
| Q15 beaconing 20 beats | DONE | PROVEN: `test_v05_beaconing.py` (19 silent, 20 fires); floor lowered with a recorded reason |
| Q16 24 h stuffing tier | DONE | PROVEN: `test_companion_rules.py` credential_stuffing_sustained + (9)/(9b); fire_check boundary held |
| mail_gateway + m365_audit parsers, OCSF 4009 | DONE | PROVEN: `test_mail_m365.py`, property fuzz, lane-coverage A2 |
| WS-8 A `ts_ms` contract | DONE | PROVEN: `test_incident_graph_v2.py::test_ts_ms_semantics_contract` |
| WS-8 B `timeline.py` | DONE | PROVEN: `test_timeline.py`, `eval/twin/test_timeline_order.py` (mirrored-clock control says no on all nine) |
| P1 four storylines | DONE | PROVEN: TPR 1.0 on each, every negative twin fires restored / stays silent; oracle_consistency clean |
| P4 blind grader | DONE | PROVEN: `test_blind_grader.py`; register 7/8 agree, `user_execution` OPEN for the owner |
| Q13 nightly corpus lane | DONE (wired) / ASSUMED (run) | workflow YAML valid and pins verified offline; the lane only runs on the nightly schedule |
| mypy over `eval/twin` | DONE | PROVEN: `mypy eval/twin` 0 errors; added to the blocking loop |
| Full gate `bash run_all_tests.sh` | DONE | PROVEN: exit 0 on the final tree (2026-10-15) |
| Push | DONE | fast-forward of `fix/r3-injection-evasion-hardening` |

## Open threads
- Owner: `user_execution` (blind oracle says detectable; the product has no process-launch rule).
- Owner: DOMAIN\ / UPN folding would amend ADR-009 (F2 residual stays an open BUG).
- Owner/data: Q9 resolver log, Q12 funding, Q8 OPC UA allowlist owner.
- Main checkout's local branch still carries the other agent's merge `150b737` (with conflict markers);
  reset it to the pushed head once the push lands.
- Alert ids of account-grouped rules change once on deploy (F2): a redelivered alert across the upgrade
  can index twice.

## Owner decisions 2026-10-20 (Q2, Q8, Q9, Q12)

| Q | Decision | State |
|---|---|---|
| Q2 ratchet authority | Any maintainer may lower an evasion floor, with the reason written in the PR/file. | DONE: `tools/check_floor_lowering.py` fails PR CI when a floor value is lowered without a new dated `lowered:` entry (unit-tested; runs in `ratchet-integrity`). |
| Q8 OPC UA allowlist | The deploying operator owns it. The rule stays default-off; no real values ship. | DONE (decision recorded; no code change needed). |
| Q9 DNS allowlist | Verify against a public sample dataset. | OPEN: no dataset chosen or run yet. Starter list stays labelled UNVERIFIED until a run is recorded. |
| Q12 wall-clock window | Fund it now. | DONE (opt-in): WS-2 stamps `siem.received_ms`; `FENGARDE_WINDOW_TIME_SOURCE=ingest` drives WS-4 stateful windows from receipt time. Default `event` is unchanged. Periodicity rules always use record time. Regression test `test_window_time_source.py`. NOT proven: live Docker run; Redis window backend with ingest source; flipping the default is a separate decision. |
