# P4, first pass — a blind prediction triangulated against the committed oracles (2026-10-14)

Plan §P4: *"Have a second person (or an external agent with no access to the rules) author at least one oracle
from an ATT&CK description alone, then triangulate. Until then the honest claim is 'consistent with the rules and
with itself'."*

This is a first pass at that. It is **not** a full P4: no complete oracle YAML was authored blind and committed.
What was done is narrower and checkable — three isolated agents, none of which saw a single rule file, the
oracles, or the storylines, were asked to predict what the detection should look like; their predictions were
then compared, mechanically, with what is committed.

**Isolation.** The three agents ran with no terminal use and no file reads (each returned the attestation as its
first output line, and each declared the judgement calls it made so they can be graded). Two were given the same
eight-step chain in two different information regimes — one with the ATT&CK technique ids and the telemetry list,
one with **behavioural prose only and no technique ids** — precisely so that a lucky match is distinguishable
from a reproduced one. The third was asked only for numbers.

**What the agents were told.** The attacker's behaviour at each of the eight steps, and which telemetry the
system can parse (including that there is no mail-gateway parser and no Microsoft 365 / mail-audit parser). They
were not told which steps are gaps, and not told any rule id, threshold, window or title.

## Result 1 — the detectability map: 7 of 8 steps identical, from both agents

Committed in `eval/twin/oracle_phishing_bec.yaml`: 3 steps carry an expected rule
(`c2_beacon`, `proxy_pool_logins`, `foreign_login`), 5 are flagged `no_rule_exists: true`.

| step | committed oracle | agent A (technique ids) | agent B (prose only) |
|---|---|---|---|
| phish_delivery | GAP | GAP | GAP |
| **user_execution** | **GAP** | **detectable** | **detectable** |
| c2_beacon | rule | rule | rule |
| victim_session | GAP (declared: not an attack step) | GAP, *context only* | GAP, *not an attack step* |
| proxy_pool_logins | rule | rule | rule |
| foreign_login | rule | rule | rule |
| inbox_rule | GAP | GAP | GAP |
| payment_redirect | GAP | GAP | GAP |

Agent B reached the identical verdict **without ever seeing the technique ids**, which is the part that makes
this a triangulation rather than a restatement.

**The one disagreement is informative, not a contradiction.** Both agents called `user_execution` detectable —
Sysmon EventID 1 (and Windows 4688) exposes the full command line, so an encoded-command or
Office-spawns-interpreter rule is conceivable on the telemetry that already exists. The oracle declares it a gap
because **no such rule is implemented** ("process-launch anomaly detection is unbuilt; class 1002 activity 1 is
under-covered; only privilege use (4672) has a rule"). Both are right at their own level: the telemetry supports
the detection, the platform does not implement it. That is exactly the distinction the oracle's `gap` semantics
encodes, and two agents that never read the rules independently landed on the telemetry-side answer. It is a
useful reminder that a `no_rule_exists` gap is a **product** claim, not a claim that the step is undetectable.

Both agents also independently classified `victim_session` as context rather than a coverage failure — matching
the rationale the oracle writes out at length (declared so that a rule which starts firing on a lone
home-country login is reported as a stale gap).

**Caveat on independence.** The agents were given the telemetry list, and "there is no mail parser" is a strong
pointer at two of the five gaps (`phish_delivery`, `inbox_rule`). Those two are therefore partly given away. The
non-trivial part is `user_execution` (both pushed back), the `victim_session` classification, and the numbers
below.

## Result 2 — the numbers: the statistics reproduce, one boundary does not

The third agent derived, from first principles, the boundary each of three detections needs. Compared with the
shipped rules (thresholds read from `contracts/rules/`, 2026-10-14):

| problem | blind prediction | shipped rule | verdict |
|---|---|---|---|
| beaconing | coefficient of variation of inter-arrival times ≤ 0.20 (high-confidence tier 0.10); window at least 3× the key's median interval; **min 20 intervals (30 preferred)** | `common_beaconing.yml`: CV ≤ **0.25**, `window_seconds: 3600`, `threshold: **6**` beats | statistic identical; the threshold sits inside the agent's own stated defensible band (0.15–0.25); **the minimum sample size disagrees by 3×** |
| impossible travel | 2 distinct **resolvable, non-sentinel** countries; sentinel/private-space observations must never count as a country and never suppress a pair; operative bound a ≤6 h pairing window with a 5 min floor | `common_impossible_travel.yml`: 2+ **distinct countries within 60 minutes**, country from a coarse local CIDR→country map | country count exact; **the sentinel exclusion was independently derived** — it is the bug this PR fixed (`ZZ` counted as a country, commit `2db8650`); window 60 min actual vs the agent's 6 h ceiling |
| credential stuffing | key on the **target username**, count **distinct source IPs** (never total failures); ≥ 10 distinct IPs with ≥ 10 failures in a rolling 24 h, plus /24-or-ASN diversity and a distinct/total ratio ≥ 0.5 | the rule id lives in `common_password_spray.yml`: `distinct_field: src_endpoint.ip`, `threshold: **8**`, `window_seconds: **300**` | counting key, the *reason for it* ("a per-source threshold is defeated by the proxy pool") and the threshold agree almost exactly (8 vs 10); **the window disagrees by two orders of magnitude** |

Two of these disagreements deserve to be treated as findings rather than noise:

1. **`common_beaconing` fires from 6 beats; an independent estimate puts the noise floor at 20.** The agent's
   argument is quantified, not aesthetic: for memoryless traffic the sample CV has standard error ≈ 1/√n, so
   P(CV ≤ 0.20) is ≈ 6×10⁻³ at n = 10 but ≈ 1×10⁻⁴ at n = 20; across an estate with 10⁵–10⁶ distinct
   (host, destination, port) keys per day, a 6-beat trigger is inside the false-positive floor. The rule's own
   window (3600 s) and the scenario's beat count (7–9, negative twin at 5) show the shipped boundary is
   deliberately low. **This is a candidate for the boundary/ratchet work (step 6), not for a silent change now**:
   raising `threshold` moves a shipped detection rule, which is an owner decision and would need the storylines'
   negative twins re-cut.
2. **The stuffing window is 300 s where the independent derivation says 24 h (fast tier 1 h).** A five-minute
   window on a 10-minute-events-per-account phenomenon is narrow by construction; the scenario's own proxy pool
   has to bunch into 5 minutes to be caught. Recorded here as a boundary observation, not a defect: whether the
   window is too narrow is a question about the intended detection semantics (burst capture vs sustained
   campaign), and the answer changes the rule's meaning.

## What this does and does not establish

- **Does**: two agents with no access to the rules reproduced the committed detectability map on 7 of 8 steps,
  one of them without technique ids; and a third independently reproduced the *statistic*, the *counting key*
  and the *design rationale* of all three detection rules involved — including the sentinel exclusion that
  turned out to be a real bug fixed in this PR. That is evidence that the oracles encode something a
  knowledgeable outsider can recover, rather than only something consistent with themselves.
- **Does not**: constitute P4. No full oracle was authored blind from an ATT&CK description and committed; three
  of the five gaps were partly implied by the telemetry list handed to the agents; a single model family
  produced all three predictions; and the two boundary disagreements above are unresolved — they are recorded,
  not adjudicated. The honest claim is still "consistent with the rules and with itself", now with one
  independent check that mostly agrees and twice disagrees in a way worth acting on later.
- **Next**: the real P4 needs an oracle YAML written from the ATT&CK description alone and committed under
  `eval/twin/`, then run through the same triangulation the derived oracle goes through. The comparison
  machinery already exists (`oracle_consistency.py`, `oracle_mutate.py`, `test_oracle_crosscheck.py`); what is
  missing is a genuinely blind author and a place to record where the two oracles disagree.

## Reproduction

The three agents ran with no tools; their inputs are the eight-step chain, the ATT&CK ids (for one of them) and
the telemetry list. The comparison values above were read, in this session, from
`eval/twin/oracle_phishing_bec.yaml`, `contracts/rules/common_beaconing.yml`,
`contracts/rules/common_impossible_travel.yml` and `contracts/rules/common_password_spray.yml`.

---

# Pass 2, 2026-10-14 — a complete blind oracle, and the schema defect it exposed

Pass 1 asked three isolated agents for predictions. Pass 2 asked one isolated agent for the thing §P4 actually
names: **a whole oracle, authored from the ATT&CK description alone**. It was given the eight-step chain, the
techniques, and the telemetry inventory — no repository, no rules, no oracle, no technique-to-rule mapping — and
returned a full oracle in the harness's own schema. It is archived verbatim at
`docs/handoff/blind-oracles/2026-10-14-phishing-bec-blind.yaml`.

**It is deliberately NOT under `eval/`.** `eval/twin/test_oracle_crosscheck.py:86` globs `oracle*.yaml` in
`eval/twin/`; a blind oracle with no rule ids dropped in there would be loaded as a grading oracle and break the
crosscheck. Archived under `docs/handoff/` it is what it is meant to be: an analysis artifact, not a grading
input. (The glob was checked afterwards: still exactly the four real oracles.)

## The comparison (mechanical)

`python3 scratch/blind_oracle_diff.py` loads both YAMLs and prints this; the script is a scratch tool, not repo
surface.

```
step                 committed       blind                                    verdict
phish_delivery       GAP             GAP                                      same
user_execution       GAP             rule (T1204.002)                         DIFFERS
c2_beacon            rule (1)        rule (T1071.001)                         same
victim_session       GAP             context (no rule)                        DIFFERS
proxy_pool_logins    rule (1)        rule (T1110.003 / T1110.004)             same
foreign_login        rule (1)        rule (T1078)                             same
inbox_rule           GAP             GAP                                      same
payment_redirect     GAP             GAP                                      same
gap-flag agreement: 6/8    disagreements: ['user_execution', 'victim_session']
committed: rules=3 gaps=5      blind: rules=4 gaps=3 (+victim_session as 'context', counted in neither)
```

On the literal gap flag it is **6 of 8**. On substance it is **7 of 8**: at `victim_session` the two oracles
agree that no rule should fire there — they disagree only about which word to use, which turns out to matter.

## Disagreement 1 — `user_execution`: now three independent sources against one

Pass 1's two agents both called it detectable; the blind author makes it a **rule**, not a gap, and writes the
rule: a process-creation event whose parent is a document or mail client and whose child is a script interpreter,
carrying an encoded/obfuscated command line, joined on the parent process GUID plus host — a *categorical* test,
with the obfuscation marker doing the work a threshold would otherwise do.

The committed oracle flags it `no_rule_exists: true` because **no such rule is implemented** ("process-launch
anomaly detection is unbuilt; class 1002 activity 1 is under-covered; only privilege use (4672) has a rule").
There is no factual conflict: the telemetry supports the detection, the product does not implement it. Three
independent authors landing on the telemetry side is worth recording, because it means the `no_rule_exists` flag
at this step is a **product** statement — and any reader who takes a flag count as "steps we cannot detect"
overstates the limit by exactly this step.

## Disagreement 2 — `victim_session`: a real defect in the committed oracle's vocabulary

The committed oracle sets `no_rule_exists: true` on `victim_session` — and its own reason text says *"Not an
attack step: ordinary telemetry that the foreign login is judged against… Declared so a rule that starts firing
on a lone home-country login is reported as a stale gap."* The blind author reaches the same conclusion and then
refuses the label, in writing:

> *"I choose the word context rather than gap: a gap means something that should be detected and is not, whereas
> this step is deliberately excluded from alerting by design and its non-detection is the correct outcome, so it
> is not counted in `steps_expected_gap` either."*

That is a defect, not a preference. The same boolean is being used for two opposite things:

- an attack step that **should** be detected and is not (a coverage hole), and
- a benign step that **must not** be detected (a negative control).

Consequences that follow from the conflation:

1. Any count of flagged steps — `steps_expected_gap`, a "gaps" column, a coverage percentage — overstates the
   coverage hole by every context step that carries the flag. In `phishing_bec` that is one of five flags, so the
   count reads 5 where the number of true coverage holes is 4, or 3 once `user_execution` is recognised as a
   product gap rather than an impossibility.
2. The stale-gap mechanism the committed oracle describes is the control it also needs — a rule firing on a
   context step *should* be an error — so the two meanings are not merely conflated, they pull in the same
   direction and hide each other.

Recorded as a finding for the oracle schema and its naming, not fixed here: splitting `no_rule_exists` touches
all four committed oracles, the reconciler, the mutation instrument's inert-key table and the technique matrix,
which needs its own gate run and an owner decision.

## Boundaries, blind prediction against the shipped rules

| step | blind author | shipped rule | verdict |
|---|---|---|---|
| `c2_beacon` | **CV <= 0.25**, >= 10 connections, mean interval 30 s-30 min, destination unseen 30 days | `common_beaconing.yml`: **CV <= 0.25**, `window_seconds: 3600`, `threshold: 6` | **the statistic and its threshold match exactly**; the minimum sample count differs (10 vs 6) |
| `proxy_pool_logins` | >= 10 distinct public source addresses per target account in 15 min, failure ratio >= 0.8, >= 1 success within 60 min, RFC1918/shared-egress exempt | `common_password_spray.yml`: `distinct_field: src_endpoint.ip`, `threshold: 8`, `window_seconds: 300` | same counting key and same rationale (the transpose of spray); threshold 10 vs 8; window 15 min vs 5 min |
| `foreign_login` | 0 prior successes from the resolved country in the trailing 30 days for an account with >= 3 prior logons, **and require correlation to the stuffing burst before escalating** | `common_impossible_travel.yml`: 2+ distinct countries within 60 minutes | different shape, and the blind author's version is *stricter*: it argues the shipped "two distinct countries in an hour" must not stand alone at high severity, because a traveller or a new remote worker produces exactly that |

Worth noting: pass 1's boundary agent independently said CV <= 0.20 with a minimum of 20 intervals; the blind
author says CV <= 0.25 with a minimum of 10. Two independent derivations bracket the shipped 0.25 from both sides,
and both put the minimum sample count *above* the shipped 6.

## What pass 2 does and does not establish

- **Does**: a second party with no access to the rules authored a complete oracle from the attack semantics, and
  it reproduces the committed oracle's shape on 7 of 8 steps by substance — including the two structural
  telemetry gaps — while independently matching one threshold to the digit. That is the strongest independence
  evidence this harness has produced, and it came with two findings worth acting on (the
  product-versus-impossibility distinction, and the `no_rule_exists` conflation).
- **Does not**: close P4. The blind oracle declares no rule ids, so the harness cannot grade with it — the
  comparison above is computed by a scratch script but *interpreted by me*, which is not the same as the
  dedicated triangulation machinery (`oracle_consistency.py`, `oracle_mutate.py`) doing it. All four blind
  inputs came from one model family. The telemetry list handed to the author names the two missing feeds, so
  `phish_delivery` and `inbox_rule` are partly given away. And none of the disagreements has been adjudicated by
  the rule authors — they are recorded, not resolved.
