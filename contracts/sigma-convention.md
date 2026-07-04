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
