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
  custom `score_weight` (0–100) under `tags` → mapped by scoring.yaml.
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
