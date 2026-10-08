# Handoff — FENGARDE evaluation harness (2026-10-08)

Branch `fix/r3-injection-evasion-hardening`, PR #93 on supermhel/fengarde, head `7205945`.
Gate at that commit: `run_all_tests.sh` ALL TESTS PASS (1,984 s). The PR reported 32 of 32 checks passing when this
was written (read once, not polled). Docker stack is down; nothing is running in the background.

This document is the single place that says what was done, what is proven, what is not, what is left, and
what you should doubt. `SSOT.md` and `CHANGELOG.md` carry the dated ledger; this file is the map.

How to read the evidence column below: **PROVEN** means a command or test that I (or the gate) ran and whose output
I read. **AGENT-REPORTED** means a subagent wrote it in its report and I did not re-derive it. **ASSUMED** means
neither. Most of this work was written by AI subagents in isolated worktrees and merged by me; treat every number
that is not tied to the gate or to a command I ran as a claim.

---

## 0. The harness was not the whole PR — read this first

The title of PR #93 is *"fix: R3 injection-evasion hardening + 2 mutation-harness bugs (mutation_robustness
0.61->0.86)"*. The evaluation-harness build-out that fills the rest of this document came **after** that, in the same
branch, and it is now the larger part of the diff. Against `origin/main` the branch is 65 commits, 124 files,
+26,206/−290 lines, of which **40 files / +4,509 / −170 are product code and contracts** (`services/`, `contracts/`)
and 77 files / +21,520 are `eval/`, `tools/` and `docs/`.

What the PR was originally for (commits `4070939`, `ec80b10`, `a8fadec`, all before the harness work):
- Closing the prompt-injection encoding-evasion gap Phase 4 disclosed: a bounded, deterministic normalisation pass in
  `services/ws2-normalization/parsers/mcp_agent.py` (NFKC, Cyrillic/Greek homoglyph fold, percent-decoding, bounded
  base64, whitespace collapse) shared by R1/R3/R5, plus a second bug in the same path (`json.dumps` with
  `ensure_ascii=True` escaped homoglyphs before the fold saw them) and a broadened R1 credential-path pattern.
- Two real bugs in the mutation harness itself (`eval/adversarial/mutate.py`).
- Then, still in the PR: Layer A made to measure the right thing (`5fd8952`), the **core-stones hardening**
  (`759ee8c`: `entity_id` collision-safety enforced locally, dormant-test guard `a9b9313`), and the oracle reconciliation
  (`b43a3e0`). I did not re-verify any of those during this part of the session beyond the full gate passing.

What has crept into the PR since, none of it mentioned in the title or body, and **all of it changes detection or
runtime behaviour, not just measurement**: six new detection rules (five companion rules, one OPC UA rule that now
ships default-off), the default-off rule state with per-tenant opt-in (engine, tenants, `/rules` view, compose), the
WS-4 window-poisoning guard, the window counter rewrite (per-key deadlines, deadline-heap sweep, Redis `ZADD GT`
requiring Redis ≥ 6.2), the `linux_ssh` parser rewrite, `dns_query.parent_domain`, the memory-bus wire-parity and
tail-read rewrite, the WS-8 `campaigns.py` read view, and the impossible-travel `ZZ` fix.

Consequences you should weigh:
1. **The PR description is stale.** It still says mutation_robustness 0.6111→0.8611 (31/36) with five remaining
   failures; Layer A is now 34/37 (0.9189) and the body mentions none of the above. I have not edited it (that is
   public text under your control); a corrected summary should say what is product, what is measurement, and what
   is proposal.
2. **It is too big to review as one unit**, and it mixes low-risk measurement code with changes to the live detection
   path. A split would be: (a) R3 normalisation + `mutate.py` bugs + Layer A, (b) core-stones hardening,
   (c) detection/runtime changes (rules, window, parser, bus, tenants, compose), (d) eval build-out and docs. This is
   your call; the commits are mostly topical, so a stacked-branch split is feasible but not free.
3. **README distillation** (the other task in this conversation) is already on `main` (`d8d10be`, 541→334 lines); it
   is not outstanding on this branch.
4. I only know this session's objectives through a compacted summary plus the commit log. If there was another goal
   that is neither R3 hardening, the core-stones audit, the harness, nor the README distill, it is not in this
   document — tell me and I will add it.

## 1. Where things stand, in one paragraph

The harness is materially stronger than it was a week ago, but it is not yet "the best", and the honest reasons are
specific: the oracles are still written by us (the independent one derives from the same rule files and so shares
their blind spots), only four storylines exist (nine were designed), no third-party labelled data has ever been
scored in the blocking gate or measured on a real fetch, the causal-order metrics are co-reported but cannot gate,
the ratchet that freezes per-storyline and per-technique scores (step 6) and the generated scorecard (step 7) do
not exist yet, and the deep adversarial review of this code only completed three of its eight areas.

## 2. Reality map

| Item | State | Evidence |
|---|---|---|
| Three original storylines (`ai_to_ot`, `it_intrusion`, `infra_takeover`) + oracles reconciled with the pipeline | DONE | PROVEN: `oracle_consistency.py` 0 unaccepted disagreements, in the gate |
| Fourth storyline `phishing_bec` (oracle authored before the builder) | DONE | PROVEN in gate; per-storyline numbers AGENT-REPORTED |
| Five more storylines (ransomware, insider_exfil, cloud_iam_abuse, supply_chain_ci, ot_opcua_sabotage) | OPEN, designed | specs in `design-specs/step2_*.json`; registry auto-discovers `eval/twin/storyline_NAME.py` |
| Scenario matrix, per storyline, never pooled | DONE | pooled 61/81 = 0.7531 PROVEN in gate output; per storyline (seed 7) ai_to_ot 14/14, it_intrusion 17/23, infra_takeover 15/19, phishing_bec 15/25 AGENT-REPORTED |
| Layer A (36→37-variant AI→OT catalogue) | DONE | PROVEN: 34/37, mutation_robustness 0.9189, unchanged through all merges |
| ATT&CK technique matrix + gate (every rule exercised or dated-waived) | DONE | PROVEN: gate stanza passes with its controls; 22/35 rules and 15/20 techniques exercised, 13 rules waived — AGENT-REPORTED |
| Causal-order metrics (co-reported) | DONE | PROVEN: tests + reversed-order control; `order_concordance` is a timestamp invariant, 1.0 by construction |
| Causal order as a gate or headline | NOT DONE, owner decision: co-report only | decision recorded 2026-10-03 |
| Oracle mutation testing + rule-derived oracle + triangulation | DONE | PROVEN in gate (`test_oracle_crosscheck.py`); limit stated below |
| Adaptive evasion: fast probe, cost vector, ratcheted floor, findings register, noise dilution | DONE (priorities 1–4 of step 5) | PROVEN in gate; flood/triage metrics NOT built |
| Blind-recall lane (third-party labels) | PARTLY DONE | blocking test is synthetic controls only (49 tests, PROVEN). No real measurement: the one local run read 65 of 1,216 units from a 95%-empty clone (8 MISS, 0 hits) |
| Default-off rules with per-tenant opt-in (OPC UA write rule off by default) | DONE | PROVEN live on the Docker stack, both directions |
| DNS cardinality report tool (measures the unverified starter allowlist) | DONE | PROVEN: its tests are in the gate; never run on real resolver logs |
| Companion rules (split-attack evasion), `score_weight: 0`, sibling suppression | DONE | PROVEN live (`live_companion_e2e`) and in gate |
| F1 window-sweep defect | FIXED, twice (first fix was incomplete) | PROVEN: property test vs reference model; Redis 7.4 parity 3,600 ops AGENT-REPORTED |
| F3 `linux_ssh` attribution forgery | FIXED, twice (first fix regressed) | PROVEN: 43-row literal corpus × 4 tags, 31 hand mutants (30 killed, 1 equivalent) AGENT-REPORTED |
| F2 identity canonicalisation, F4 record-clock trust | OPEN | in `eval/adversarial/evasion_findings.yaml` |
| Live verification on the rebuilt Docker stack | DONE | PROVEN, table in §4 |
| Deep adversarial review of waves 1–2 | 3 of 8 areas done | see §5 |
| External code review of PR #93 | NOT DONE | see §7 |
| Step 6 (ratchet over all instruments) | NOT STARTED | spec in `design-specs/step6_*.json` |
| Step 7 (generated `eval/SCORECARD.md`) | NOT STARTED | spec in `design-specs/step7_*.json` |
| `nightly-eval.yml` switched to `fetch_corpora.py` | NOT DONE | edit text is in the step-1 agent report; not applied because it is untestable here |

## 3. What was done, in order

1. **Storyline harness (2026-10-01/02, `e18e3f2` and earlier).** Three storylines, a boundary-searching evasion
   instrument, scenario-agnostic mutations, honest grader metrics (the legacy `chain_fidelity`/FCR measure entity
   sharing, not causal order: `directional_discrimination = 0.0`). Found and fixed a real product bug
   (`impossible_travel` counted the RFC1918 sentinel `ZZ` as a country).
2. **Findings closed.** Five companion rules close the 2-address / 2-account evasions; an OPC UA authorised-node rule
   closes the in-hours write gap; window poisoning fixed; memory bus brought to Redis wire parity; WS-8 campaign
   read view written (read-side only, ADR-009/010 untouched). A retraction was made: an earlier claim of an
   OPC UA product gap was a grader artefact.
3. **First code review of PR #93 (same thread, so a claim set, not an independent review).** Nine findings; eight
   fixed, one not reachable. Includes: `companion_of` validation, noisy rules (`bruteforce_by_account` high→medium,
   DNS tunnel allowlist, OPC UA `score_weight` 0), stable campaign id, bus efficiency, live e2e that could pass
   vacuously.
4. **Wave 1** (worktree agents): blind-recall lane, causal-order co-report, oracle cross-check, adaptive evasion.
5. **Owner decisions implemented:** default-off rule state with opt-in; DNS cardinality tool; the global
   read-before-edit hook repaired (see §8, this is outside the repo).
6. **Product fixes found by the evasion lane:** F1 and F3 (both later corrected, §5).
7. **Wave 2 core:** scenario auto-discovery, negative twins, mutation adapters, technique matrix and gate,
   `phishing_bec`.
8. **Live verification** on a rebuilt Docker stack (§4). It found one real defect nothing else caught:
   `FENGARDE_OPT_IN_RULES` never reached `ws3-indexer`/`ws4-detection` in compose, so the documented opt-in did not
   work in the shipped deployment. Fixed.
9. **Review of the review.** The first review pass listed file names and found nothing; I rejected it as not
   credible. The second pass required experiments (differential tests against the old code, property tests,
   sabotage) in sandbox worktrees. It completed 3 of 8 areas (parser, window counters, bus + campaigns) before usage
   limits stopped it; the fixes were merged and gated.

## 4. Live verification (real Docker stack, images rebuilt from the code)

Container smoke; strict live companion e2e; 8 Redis integration tests including the real-Redis half of the bus
parity test and the session store (the session Redis half only runs with `SESSION_TEST_REDIS=1` and
`FENGARDE_SESSION_SECRET`); 4 OpenSearch tests; MFA e2e in the deployed image; OT new-device e2e (needs
`INVENTORY_BASELINE_SECONDS=0`); chaos test (7 services killed mid-replay, 40 scenarios, 0 lost, 0 duplicated —
note `distinct_alert_ids=0` counts *violations*, so 0 is the good value, the label is misleading); the default-off
rule does not alert while `ot_config_change` does; with the variable set it alerts; the F3 forged-username burst is
attributed to the real source. All passed. The scripts are `docs/handoff/live/run_live.sh` and `live_props.py`
(absolute scratch paths inside; adjust before reuse). They ran against the code *before* the second round of
parser/window/bus fixes — **the live lane has not been re-run on `7205945`**.

## 5. What the deep review found, and what is still open from it

Corrected claims (both are written into `SSOT.md`/`CHANGELOG.md`):
- The F3 `linux_ssh` fix depended on the tag `sshd[pid]:`; on OpenSSH 9.8+ (`sshd-session[pid]:`) a hostile
  username could again forge a logon; `pam_sss`/`pam_ldap`/`pam_systemd` lines the old parser read were dropped;
  the regexes backtracked super-linearly (1.2–3.4 s for 8 KB). Rewritten without regexes on client text.
- The F1 window fix still let a single old-timestamp hit shrink a key's deadline (the old code had this too); the
  Redis distinct counter let an old score overwrite a newer one (now `ZADD GT`, **needs Redis ≥ 6.2**).

Residuals that were decided *not* to be fixed, and why:
- The parser anchors to the leftmost `sshd[...]:` anywhere in the line, not to the syslog header position. A stream
  that mixes foreign text into a `linux_ssh` source can still carry a forged `sshd[1]: Accepted ...`.
- A client-influenced SSH certificate key id echoed after the real source could win as the rightmost `from <ip>`.
- The deque window backend loses state for a source that lags the sweeping traffic by more than its own window
  (Redis, which expires on wall-clock, does not). Fixing it needs a wall-clock input and breaks tests that drive
  synthetic timestamps.
- `hit()` redelivery with an older timestamp still lowers recency on both backends (deliberate, R3-#61).

**Review areas that never ran** (usage limits): tenant/default-off configuration matrix, harness validity by
sabotage, evasion-ratchet bypass attempts, blind-recall security (path traversal, git/LFS argument injection, XML),
and the documentation-versus-code audit. The experiment prompts for all eight areas are in `docs/handoff/review-areas.js` (a Claude Code Workflow
script; its `REMAINING` list names the five that did not run; edit `BASE` to the current head). They must run against
`7205945` or later.

## 6. Plan: making the harness the best

"Best" needs a definition that can fail. A harness is the best when a sceptical reviewer can answer **yes** to all
four, each with evidence a script produced:

1. **Independence** — does it catch attacks nobody on the team wrote or labelled?
2. **Coverage** — is the attack surface covered by technique, not by what was convenient to build?
3. **Validity** — does every metric measure what it claims, and does each have a control that can fail?
4. **Regression resistance** — does a weakened rule, parser or oracle turn CI red without anyone remembering to look?

Today: independence **no**, coverage **partly** (4 storylines, 22/35 rules), validity **mostly** (every instrument has a
positive and negative control, but causal order and several legacy metrics are known-weak), regression resistance
**partly** (floors ratchet for evasion cost and oracle strength; nothing freezes per-storyline or per-technique
scores).

Ordered plan. Effort figures are the design agents' estimates, not measurements.

**P0 — Close the review (days).**
(a) Re-run the five missing review areas on `7205945`+, fix what is confirmed, re-gate. (b) Commission an
*external* review of PR #93 (§7). (c) Re-run the live lane (`docs/handoff/live/`) on the final code. (d) Remove stale
worktrees (§8). Exit: confirmed findings 0, live lane green on the PR head.

**P1 — Finish coverage (≈45 h).** Author the five remaining storylines as `eval/twin/storyline_NAME.py` +
`oracle_NAME.yaml`, oracle first, from rule intent. For each: delete its rules' lines from
`eval/adversarial/technique_waivers.yaml` (a stale waiver fails), regenerate the missing-rule register, add negative
twins, tag every gap with an ATT&CK id. Do not invent rules; a missing rule becomes a declared gap. Exit: waiver list
empty or each remaining entry has a reason; matrix reported per storyline.

**P2 — Get a real independent number (≈20–30 h plus a networked machine).** Run `fetch_corpora.py` and
`blind_recall.py --require-corpus` on a machine with network and git-lfs; commit nothing from it. Add the deferred
adapters (CloudTrail, linux_secure, k8s, OTRF) *each with a fixture-backed control first*. Agree the regression rule
for a blind-recall baseline file (proposal: a technique that was HIT may not become MISS/NO_RULE; no absolute
threshold). Exit: a recorded funnel from a real fetch, with the NO_RULE list published rather than hidden. Expect a
small hit count: FENGARDE has no process-creation, registry, persistence-by-execution or credential-dumping rule.

**P3 — Freeze it (step 6, ≈32 h) and make it falsifiable (step 7, ≈15 h).** Frozen per-storyline and
per-technique baseline with a ratchet (drop = red unless a dated waiver; improvement needs an explicit refresh
command); a mutation proof that a deliberately weakened rule turns the gate red; the Layer C trend file; then a
generated `eval/SCORECARD.md` (per storyline and technique, each metric with its blind spot and control, plus a
"cannot prove" section), with a staleness check. Both must freeze from a *committed* tree and a green full gate.

**P4 — Break the self-authoring problem properly.** Have a second person (or an external agent with no access to the
rules) author at least one oracle from an ATT&CK description alone, then triangulate. Until then the honest claim is
"consistent with the rules and with itself". The derived oracle does not fix this; it shares the rule YAML.

**P5 — Decide the product questions the harness keeps surfacing** (§7): WS-8 edge time / campaign persistence,
identity canonicalisation (F2), record-clock trust (F4), mail and M365 parsers, process-launch and mailbox-rule
detections.

## 7. Questions that need an answer from you, or from someone who is not me

1. **External review is owed.** Your global rule is that code review is done by an external reviewer
   (`engineering:code-review` in a *new* session, Opus, max effort). I did not do that: the reviews so far were
   in-thread and subagent reviews, and one subagent's safety-classifier check was unavailable. Please run it on
   PR #93 before merge and treat my self-assessment accordingly.
2. **Ratchet authority.** Who may run `evasion_cost.py --update-floor --allow-lower --reason ...`? Today anyone can
   hand-edit `evasion_floor.yaml`; the tool does not detect a hand-lowered value, only diff review would.
3. **Ratify or reject `evasion_tables.yaml`.** All 10 rows are `ratified: false`, so findings that rest on them are
   warnings and cannot gate. Two rows (vCenter SSO respelling, `linux_ssh.username` escaping) are ASSUMED, not
   verified against a real product.
4. **F2 policy.** Canonicalise WS-4 group keys with strip + casefold (consistent with ADR-009, churns `alert_key`),
   or amend ADR-009 to allow `DOMAIN\` / UPN stripping?
5. **F4 policy.** Six sources take event time from the record's own timestamp and ignore receipt time. Add a
   source-clock/receipt skew guard? (Trust-model decision.)
6. **WS-8.** Persist/emit/index the campaign view (`docs/proposals/2026-10-01-ws8-campaign-view.md`)? Edge time
   options A–D (`docs/proposals/2026-10-02-ws8-edge-time.md`); C and D change a bus schema or supersede ADR-009/010.
   Until decided, causal order stays co-reported and `chain_fidelity`/FCR stay known-weak.
7. **Causal-order gating** (promote `causal_order_retained` into `pass`; later a headline switch): decided "co-report
   only" for now. Layer A shows 0 flips across 84 rows, so promotion is cheap if you want it.
8. **OPC UA rule posture.** Default-off is implemented. The allowlist `opcua_authorized_nodes.yml` ships empty, so
   enabling the rule before populating it alerts on every write. Who owns populating it?
9. **Starter DNS allowlist** (`dns_high_cardinality_parents.yml`, 12 entries) is unverified against real traffic. Run
   `tools/dns_cardinality_report.py` on a real resolver log before relying on it.
10. **Brute-force companion routing.** `common_bruteforce_by_account` is now `medium` (classifier, score 40), so a
    2-address brute force *alone* no longer goes to LLM triage. Accepted by you on 2026-10-03; recorded here so it is
    not forgotten.
11. **Redis ≥ 6.2** is now a hard requirement (`ZADD GT`). Compose and CI use `redis:7`; is there any deployment on
    something older?
12. **Deque window backend vs wall-clock** (§5): accept the residual, or fund the wall-clock input?
13. **`nightly-eval.yml`.** Apply the `fetch_corpora.py` change (needs git-lfs and python-evtx on the runner)? Not
    applied.
14. **Product backlog the gaps point at:** mail-gateway and M365 parsers; rules for phishing delivery, user execution,
    mailbox rules, data manipulation, process launch, banking-DB UPDATE; a true one-source-many-accounts spray rule
    (T1110.003 stays a documented gap; `common_password_spray` is deliberately T1110.004).

## 8. Things that changed outside the code, or that you should clean up

- **I edited a file outside this repository:** `~/.claude/hooks/read-before-edit-guard.js`. It now walks the whole
  `subagents/` tree (workflow subagents log under `subagents/workflows/<run>/`, which the flat scan missed, so the
  guard wrongly blocked their edits). Verified with a positive and a negative control. Review that diff yourself; it
  is your global config.
- **Worktrees:** `git worktree list` still shows nine under `.claude/worktrees/` (the merged `wf_7ac6aa77-*`, the
  empty `wf_ddc294a3-*`, and one corrupt `wf_1a41cd68-ee7-12` that needs `git worktree remove -f -f`). Branches
  `worktree-*` are merged. They are git-ignored and safe to delete.
- **`AGENTS.md`** at the repo root is untracked and is not mine; I never committed it.
- **Compose change:** `FENGARDE_OPT_IN_RULES=${FENGARDE_OPT_IN_RULES:-}` added to `ws3-indexer` and `ws4-detection`
  (keep the two values identical).
- The design specs (≈330 KB) in `design-specs/` were saved from a temp directory; they are AI-written plans with
  independent critic verdicts, not authoritative. `plan.json` holds the sequencer's merged order and its list of
  dropped or corrected spec claims.

## 9. Things I did not verify, and numbers to distrust

- Per-storyline matrix numbers, the 13-rule waiver count, 22/35 and 15/20, the 84-row/0-flip causal-order diff, the
  mutation kill counts, and the hot-path timings (+2…12 %, 4–8 µs/hit) come from agent reports. The gate confirms
  that the tests pass, not those figures.
- ATT&CK ids for the missing-rule register (T1566.001, T1204.002, T1114.003, T1565.001) are from the author's
  knowledge of v14; the repo vendors no ATT&CK dataset.
- How real OpenSSH escapes usernames in log lines was not checked against a real server.
- The Redis F1 property was read from code; the window counter's Redis parity was tested by an agent against a
  throwaway container (not re-run by me).
- The 295 h total effort is the sequencer agent's sum and has no calibration.
- Two review-verifier verdicts exist (both CONFIRMED); the other findings were reproduced by the fixing agent
  instead of by an independent one.
- CI is green on the PR as of writing, but the CodeQL/fuzz jobs run on pushes I did not individually watch.

## 10. How to resume

```sh
git switch fix/r3-injection-evasion-hardening && git pull
bash run_all_tests.sh                       # ~33 min; run alone (parallel load flaked an HTTP test once)
python eval/adversarial/layer_a.py --seed 7 # expect 34/37
python eval/adversarial/scenario_matrix.py --seed 7 && python eval/adversarial/technique_matrix.py
python eval/adversarial/evasion_cost.py --seed 7
python eval/twin/oracle_consistency.py && python eval/twin/test_oracle_crosscheck.py
```

Live lane: start Docker Desktop yourself, `docker compose -f infra/docker-compose.yml up -d --build`, then adapt
and run `docs/handoff/live/run_live.sh` (note the OT e2e needs `INVENTORY_BASELINE_SECONDS=0` on `ws6`, and the opt-in
check needs `FENGARDE_OPT_IN_RULES` on `ws3` and `ws4`).

Next three actions, in order: (1) re-run the five unrun review areas; (2) author the five storylines (P1);
(3) steps 6 and 7 (P3). Specs for 2 and 3 are in `docs/handoff/design-specs/`; read the critic verdict in each file
first, because it overrides the spec.
