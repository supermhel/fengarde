# Contract D — Sigma Convention & Scoring

Detection rules are written in **Sigma**, directly against OCSF field paths (Contract A).
Because they target the normalized schema, one rule works across all sources of that class.

## Rule conventions

- File: `contracts/rules/<sector>_<short_name>.yml` where sector ∈ `common|bank|dc`.
- `logsource.product` is unused; instead use `logsource.category` = the OCSF class name
  (`authentication`, `network_activity`, `datastore_activity`, `api_activity`...).
- Detection field names are **OCSF dotted paths**, e.g. `class_uid`, `activity_id`,
  `src_endpoint.ip`, `actor.user.name`, `siem.sector`.
- Every rule MUST carry a `level` (`informational|low|medium|high|critical`) and a
  custom `score_weight` (0–100) under `siem.score_weight` → mapped by scoring.yaml.
- Stateful rules (counts over time) declare `siem.window_seconds` and `siem.threshold`.

## Required rule fields

```yaml
title: <human title>
id: <uuid>
status: stable
level: high
logsource:
  category: authentication
detection:
  sel:
    class_uid: 3002
    activity_id: 4          # failure
  condition: sel
siem:
  sector: common
  score_weight: 40
  window_seconds: 60        # optional, stateful
  threshold: 10             # optional, stateful
```

**Stateful rules require their fields present on the event (v0.4):** an event
where `group_by` (or `distinct_field`, when set) resolves to nothing is
*unattributable* — it is never counted, for any group. Fail-closed, same as
every other malformed-input path: pooling unattributable events under a shared
bucket (or counting a missing value as a distinct value) fabricates
correlations across unrelated actors.

## Selection operators (v0.3, A3)

A selection maps an OCSF path to either a **scalar** (equality) or an **operator
dict**. Operators are evaluated by a non-`eval()`, fail-closed evaluator
(`services/ws4-detection/engine.py`): any malformed argument makes the selection
*not match* rather than raise — rule files are contributor-supplied.

```yaml
detection:
  sel:
    class_uid: 1002                       # equality (scalar)
    score: {gt: 60}                       # gt|gte|lt|lte|ne — numeric, non-numeric operand => no match
    activity_id: {in: [1, 3]}             # list membership (bool != int; missing field => no match)
    api.operation: {contains: "credentials."} # bounded substring, both operands strings, NO regex
    process.file.name: {glob: "svchost*.exe"} # Sigma-style */?/[seq] wildcard (A-Sigma; shipped in v0.5.0; tags now go through v0.10.0, gap-hunt 2026-09-04 fixed this stale claim), NOT regex
    src_endpoint.ip: {not_in: corp_ranges} # suppress if value ∈ contracts/allowlists/corp_ranges.yml (CIDR + exact)
    time:                                  # time-of-day / day-of-week
      outside_hours:
        start: "08:00"                     # HH:MM, 24h
        end: "18:00"                       # start<end normal window; start>end wraps midnight
        days: [mon, tue, wed, thu, fri]    # optional, default Mon–Fri
        tz_offset_minutes: 0               # optional, applied to the event's epoch-ms `time`
  condition: sel
```

- `not_in`: a missing/malformed allowlist file fails **open on the rule** (keeps
  firing — a broken allowlist must not silently blind a SIEM) but **closed on
  suppression** (never suppresses). A non-string allowlist name is a malformed
  rule and fails fully closed.
- `outside_hours`: matches when the event time falls **outside** the business
  window. `start == end`, unknown keys, bad `HH:MM`, non-int/absurd tz, empty or
  unknown `days` all fail closed.
- `in` (v0.4): value must equal one member of the list. `bool` and `int` are kept
  distinct (`True` does not match `1`). A non-list arg or a missing field fails
  closed. Use it instead of widening a rule across activity ids.
- `contains` (v0.4): plain substring test — both operands must be strings and the
  needle is length-capped; it is **not** a regex (no ReDoS on contributor rules).
  A non-string operand or empty/oversized needle fails closed.
- `glob` (A-Sigma; shipped in v0.5.0; tags now go through v0.10.0, gap-hunt 2026-09-04 fixed this stale claim): Sigma-style wildcard match (`*`, `?`, `[seq]`, `[!seq]`)
  via Python's `fnmatch`, the first step toward mechanical Sigma-rule portability
  (design-review finding D, 2026-07-29 — the rule grammar had no wildcard support
  at all). **Still not a regex**: `fnmatch` translates these four metacharacters
  into bounded, non-overlapping-repetition patterns, so ADR-005's no-ReDoS
  constraint is unchanged — this closes the *wildcard* gap, not the *arbitrary
  regex* one; most of SigmaHQ's ~3,000 public rules still need a real translation
  layer, not just this operator. A non-string operand or empty/oversized
  (>200 char) pattern fails closed, same discipline as `contains`.

## Importing SigmaHQ rules (M7 follow-up)

`tools/import_sigma_rules.py` converts a real SigmaHQ rule YAML into the shape
this file describes: selection sanitization, dict/list/OR selection shapes,
`and`/`or`/`not` condition rewriting, and the `contains`/`startswith`/
`endswith`/`re` modifiers (`re` translates to a bounded `glob` above, or
rejects the rule if it can't). Run it with `python tools/import_sigma_rules.py
<sigma-rule.yml> [out.yml]`; anything it drops or defaults is printed as a
`[WARN]`, not silently discarded. **Honest scope**: this covers roughly the
basic detection/condition layer, an estimated 10-20% of real-world SigmaHQ
constructs — full regex fields, additional modifiers (`base64`, etc.),
timeframes, references, and more complex condition syntax are not yet
supported, so this does not make arbitrary SigmaHQ rules importable.

## Periodicity / beaconing (v0.5, A3)

An optional `siem.periodicity` block on a stateful rule additionally requires
the matching events to arrive at a REGULAR interval, not just frequently
enough:

```yaml
siem:
  window_seconds: 3600
  threshold: 6
  group_by: src_endpoint.ip
  periodicity:
    max_cv: 0.25     # required, (0, 1] -- lower = stricter regularity
```

The rule fires only when BOTH `count >= threshold` AND the coefficient of
variation (stdev / mean) of the in-window events' inter-arrival deltas is
`<= max_cv`. Fewer than 3 in-window events never fires (not enough data to
judge regularity — see `services/ws4-detection/window.py`'s design note and
`docs/superpowers/specs/2026-07-21-periodicity-primitive.md` for the full
rationale and stated limitations, chiefly: trivially evaded by jitter, and
`group_by` is single-field so it can't group by (src, dst) pairs).
`periodicity` cannot be combined with `distinct_field` — the two window
semantics don't compose.

## Scoring model (see scoring.yaml)

Each matching rule contributes `score_weight`. A single event's score is the
**capped sum** of all matching rule weights, clamped to 0–100. Severity floor is also
applied: a `critical` rule guarantees score ≥ 80.

## The funnel thresholds (drive the AI pipeline, Contract B)

| Score band | Action                                                |
|------------|-------------------------------------------------------|
| `< 20`     | store only (WS-3), no further processing              |
| `20–59`    | light classifier (WS-5 layer 2)                       |
| `>= 60`    | enqueue to `ai.requests` → LLM analysis (WS-5 layer 3)|

These two numbers (20, 60) are defined once in `scoring.yaml` and consumed by WS-4/WS-5.

### `siem.llm_gate: false` — decoupling funnel cost from displayed severity

Design-B (2026-07-29 audit): `high`/`critical` severity floors (70/80) are
both ≥ `llm_min` (60), so **every** `high`/`critical` rule always pays for an
LLM triage call the moment it fires — tuning `score_weight` down does
nothing, since the floor overrides it. That's the wrong rule set to make
un-tunable: several shipped rules document themselves as noisy *before* an
operator tunes an allowlist/threshold (`agent_credential_file_access.yml`,
`ot_config_change.yml`, `bank_mass_card_read.yml`,
`common_after_hours_admin.yml`).

Set `siem.llm_gate: false` on a rule to exclude **only its own severity
floor** from the funnel-routing decision (`Scorer.routing_score()`) — the
rule's `score_weight` still counts toward routing as always, and the
alert's stored/displayed `score` and `level` (`Scorer.score()`, still
floor-inclusive) are completely unaffected. This is a per-rule, explicit
opt-in: omitting it (the default) keeps today's exact behavior, byte for
byte. Nobody's existing rule routing changes unless a rule author adds this
field on purpose.

```yaml
siem:
  sector: common
  score_weight: 45
  llm_gate: false   # high severity for the analyst UI; don't force an LLM
                     # call until score_weight alone crosses llm_min
```
