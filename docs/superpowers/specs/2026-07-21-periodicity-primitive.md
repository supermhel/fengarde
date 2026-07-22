# Periodicity/beaconing primitive (v0.5 Track A3)

## Why

`contracts/detection-coverage.md` and the v0.3 improvement plan flagged
periodicity/beaconing as "design-first" since v0.3: a C2 beacon calls home
at a roughly regular interval, and none of the shipped rule grammar
(equality, comparison, distinct-count, time-of-day) can express "regular",
only "frequent." This closes that design item and ships a first primitive.

## Design

**Where the state lives.** Both window backends (`services/ws4-detection/
window.py`) already keep the exact in-window timestamps a plain `hit()`
needs to trim the window. `hit_periodic()` reuses that SAME state — no new
storage, no new redelivery-dedup semantics — and additionally computes the
**coefficient of variation** (stdev / mean) of the consecutive inter-arrival
deltas among the timestamps currently in-window, after adding this event.

- `DequeWindowCounter.hit_periodic`: calls `hit()` (member-dedup, trim, all
  unchanged), then reads back the same deque's timestamps.
- `RedisWindowCounter.hit_periodic`: calls `hit()` (ZADD/ZREMRANGEBYSCORE/
  ZCARD/EXPIRE, unchanged), then one extra `ZRANGE ... WITHSCORES` to read
  the surviving timestamps back for the CV calculation.

Both backends are proven to agree in `test_window_periodic.py` (same
inputs, same count, same CV, on both a regular and an irregular sequence).

**Why CV, not FFT/autocorrelation.** A real periodicity detector (FFT power
spectrum, autocorrelation) needs a much longer, denser sample and unbounded
memory to be worth it, and this repo's window primitives are deliberately
bounded-memory, O(window) structures (the same discipline `hit`/`hit_distinct`
already follow). CV over inter-arrival deltas is: (a) computable from the
window state that already exists, (b) O(n) in the window size, (c)
understandable and tunable by an operator (`max_cv` is just "how tight does
the spacing have to be"), and (d) a genuinely used first-pass heuristic in
real beacon-detection tooling (e.g. RITA's beacon score). It is explicitly
NOT claimed to be robust.

**Fewer than 3 events → `cv=None`, never a fabricated 0.** A single event or
a single delta can't say anything about regularity; treating that as
"perfectly regular" (cv=0) would let a rule fire on 2 coincidental events.
The engine (`services/ws4-detection/engine.py::Rule.evaluate`) treats
`cv=None` as fail-closed: never fires.

**Grammar**: `siem.periodicity: {max_cv: <float in (0,1]>}`, additive on top
of the existing `window_seconds`/`threshold`/`group_by` stateful fields.
Mutually exclusive with `distinct_field` (the two window semantics don't
compose — validated in `tools/validate_rules.py`). See
`contracts/sigma-convention.md` for the frozen grammar doc.

## Known limitation (stated up front, not discovered later)

**Trivially evaded by jitter.** An attacker adding random jitter to their
callback interval defeats a low `max_cv` threshold immediately — this is a
coarse first-pass signal, not a hardened C2-beacon detector. It also doesn't
group by destination: `common_beaconing.yml` groups by `src_endpoint.ip`
only (the grammar has no multi-field group_by), so a host regularly polling
several unrelated legitimate destinations at a similar cadence can
coincidentally look periodic. Both limitations are stated in the rule's own
`description:` field, not just here.

## What shipped

- `services/ws4-detection/window.py`: `hit_periodic()` on both backends,
  `_coefficient_of_variation()` helper.
- `services/ws4-detection/engine.py`: `Rule.periodicity`, wired into
  `evaluate()`'s stateful branch.
- `tools/validate_rules.py`: shape check (`max_cv` range, requires
  window_seconds/threshold, rejects combination with distinct_field) +
  adversarial tests in `tools/test_validate_rules.py`.
- `contracts/rules/common_beaconing.yml`: class 4001 (Network Activity),
  activity 7 (Accept), producer = `cisco_asa` (existing, no new parser
  needed). `test_v05_beaconing.py` proves it fires on a regular cadence and
  does NOT fire on an irregular cadence of the same event count, using real
  `cisco_asa` parser output.
- `test_window_periodic.py`: backend-parity tests (regular → low CV, bursty
  → high CV, <3 events → `cv=None`, stale events age out same as `hit()`).

All wired into `run_all_tests.sh` / `make test` (zero infra).
