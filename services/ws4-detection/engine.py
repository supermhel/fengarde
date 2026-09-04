"""WS-4 Sigma-style detection engine.

Loads rules from contracts/rules/*.yml (Contract D) and evaluates OCSF events
(Contract A) against them. Rules target OCSF dotted field paths, so one rule works
across every source of that class.

Supported rule shape (subset of Sigma, per sigma-convention.md):

    detection:
      <selection_name>:
        <ocsf.dotted.path>: <scalar>        # equality
        <ocsf.dotted.path>: {gt|gte|lt|lte|ne: <number>}   # comparison (fail closed)
        <ocsf.dotted.path>: {not_in: <allowlist-name>}     # suppression via contracts/allowlists/
        <ocsf.dotted.path>: {glob: "svchost*.exe"}         # Sigma-style *?[seq] wildcard, NOT regex
        <ocsf.dotted.path>: {exists: true|false}           # field presence/absence
        time: {outside_hours: {start: "08:00", end: "18:00",   # time-of-day / day-of-week
               days: [mon,tue,wed,thu,fri], tz_offset_minutes: 0}}
      condition: "<sel> [and|or|not] <sel> ..."  # boolean over selection names
    siem:
      score_weight: <int>
      window_seconds: <int>    # optional -> stateful
      threshold: <int>         # optional -> stateful
      group_by: <ocsf.path>    # optional, defaults to src_endpoint.ip
      distinct_field: <ocsf.path>  # optional -> distinct-count instead of count

Stateful rules only "fire" once the count of matching events for a group reaches
`threshold` within `window_seconds`. When `distinct_field` is set, the rule counts
DISTINCT values of that field per group (e.g. distinct dst ports for a port scan, or
distinct dst hosts for lateral movement) rather than the raw number of events.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import re
import sys
import time
from pathlib import Path

import yaml

# Make `shared` resolvable regardless of how engine.py is imported. The
# service entrypoint (main.py) already puts `services/` on sys.path, but
# tools that import engine.py directly (validate_rules.py, fire_check.py,
# the WS-4 rule-firing tests) only add `services/ws4-detection` -- without
# this, `from shared.log import get_logger` below raises ModuleNotFoundError
# in every one of those callers (found 2026-08-07: 14 failures, one root cause).
# window.py moved into shared/ 2026-08-18 (WS-8 correlation reuses the same
# primitive), so this sys.path setup must run BEFORE the window import too.
_SERVICES_DIR = Path(__file__).resolve().parent.parent
if str(_SERVICES_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVICES_DIR))

from shared.envelope import valid_tenant_id  # noqa: E402
from shared.log import get_logger  # noqa: E402
from shared.window import DequeWindowCounter  # noqa: E402

_log = get_logger("ws4-detection")
_DEFAULT_TENANT = "default"


def _event_tenant(event: dict) -> str:
    """``siem.tenant``, falling back to ``_DEFAULT_TENANT`` on absent OR
    invalid. `_namespaced_group()`'s length-prefix only defends `group`
    against a colon-collision, not `tenant` -- its own docstring justifies
    that by claiming tenant is "deployment-stamped, not per-event", but this
    is exactly where it's read straight off the per-event `siem.tenant`
    field, the same field every other tenant-trusting call site
    (`tenants.py::tenant_of`/`load_disabled_rules`, `ws3-indexer/router.py`,
    `ws3-indexer/rules_view.py`) validates via `valid_tenant_id()` before
    use. Rejecting (not merely ignoring) a malformed tenant here closes the
    same colon-collision class `_namespaced_group` was written to prevent,
    just on the other side of the join."""
    tenant = (event.get("siem") or {}).get("tenant") or _DEFAULT_TENANT
    return tenant if valid_tenant_id(tenant) else _DEFAULT_TENANT

# Sliding-window counters use the event's own ``time`` as "now" so historical
# replay works on event-time. But log time is attacker-influenced (most parsers
# read it straight off the record), and one event stamped far in the future would
# push the window horizon past every real entry, collapsing the group's count to 1
# -- an attacker could hold every brute-force/spray/scan threshold at bay with one
# spoofed-timestamp event per group. So an event whose time is implausibly ahead of
# wall-clock (beyond benign source clock-drift) is not allowed to drive a stateful
# window. Past timestamps are always fine (that IS replay), so this never impedes
# legitimate historical processing.
_MAX_CLOCK_SKEW_MS = 300_000  # 5 minutes of tolerated source clock drift


def _get_path_parts(doc: dict, parts: tuple):
    """Same walk as ``get_path``, over an already-split path tuple. Hot-path
    helper: ``Rule`` precomputes and reuses these tuples (perf #1, 2026-07-29
    audit) instead of calling ``str.split(".")`` on every lookup."""
    node = doc
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def get_path(doc: dict, dotted: str):
    return _get_path_parts(doc, tuple(dotted.split(".")))


# --- A3: allowlists -----------------------------------------------------------
# Moved to services/shared/allowlist.py 2026-08-18 so WS-8 correlation can
# reuse the same loader/matcher without a cross-workstream import (see that
# module's docstring). `Allowlist`/`load_allowlist` re-exported here so
# every existing caller of `engine.Allowlist`/`engine.load_allowlist` (this
# module's own `not_in` operator below, `tools/validate_rules.py`, tests)
# keeps working unchanged -- a pure relocation, not a behavior change. A
# missing/malformed allowlist makes the ALLOWLIST ITSELF fail closed
# (`Allowlist.matches()` always returns False -- it can never suppress
# anything), which makes a RULE using it in `not_in` fail OPEN (the
# selection keeps matching/firing -- see `_operator_matches`'s `not_in`
# branch and M2 in this file's history).
from shared.allowlist import Allowlist, invalidate_dir, load_allowlist  # noqa: E402,F401


_NUMERIC_OPS = {"gt", "gte", "lt", "lte", "ne"}
_CONTAINS_MAX = 200  # cap the needle length; contains is a plain (non-regex) match
# Every operator key `_operator_matches` recognizes. Kept in sync manually
# (gap-hunt 2026-09-04) so a rule-load-time check can warn on a typo'd key
# (`not: in`, `exist:`) instead of the rule silently fail-closing to no-match
# forever with zero signal -- same "shows active, never fires" blackout class
# the condition-parse warning above already exists to catch.
_KNOWN_OPS = _NUMERIC_OPS | {"not_in", "outside_hours", "in", "contains", "glob", "exists"}

# Single source for the T4 condition tokenizer. tools/validate_rules.py imports
# this (R3-#41, 2026-08-27): a hand-copied duplicate in the validator used to
# drift from what the runtime actually parses, so the gate could call a rule
# valid while the engine tokenizes it differently. Everything that tokenizes a
# condition must share THIS pattern and nothing else.
_CONDITION_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+")


def _in_list(actual, choices: list) -> bool:
    """True if ``actual`` equals a member of ``choices`` (bool-safe: a bool must
    not match a numeric member, since bool is an int subtype in Python)."""
    for c in choices:
        if isinstance(actual, bool) != isinstance(c, bool):
            continue
        if actual == c:
            return True
    return False


def _contains(actual, needle) -> bool:
    """Fail-closed substring test: both operands must be strings and the needle
    bounded. No regex -> no ReDoS on contributor-supplied rules."""
    if not isinstance(actual, str) or not isinstance(needle, str):
        return False
    if not needle or len(needle) > _CONTAINS_MAX:
        return False
    return needle in actual


_GLOB_MAX = 200  # same bound as _CONTAINS_MAX -- patterns are contributor-supplied


def _glob_match(actual, pattern) -> bool:
    """Fail-closed glob match (Sigma-style `*`/`?`/`[seq]` wildcards, M7
    2026-08-05: the cheap partial step toward Sigma-rule portability design-
    review finding D named -- ADR-005's no-regex constraint stays unchanged,
    this does NOT reopen that door).

    ``fnmatch`` translates these four glob metacharacters into a regex built
    from bounded, non-overlapping quantifiers -- there is no construction of
    ``*``/``?``/``[seq]`` alone that produces the nested/alternating
    repetition catastrophic backtracking needs, unlike arbitrary contributor
    regex (which is why ADR-005 excludes regex, not wildcards specifically).
    Both operands must be strings and the pattern length-capped, same
    contributor-safety discipline as ``_contains``."""
    if not isinstance(actual, str) or not isinstance(pattern, str):
        return False
    if not pattern or len(pattern) > _GLOB_MAX:
        return False
    return fnmatch.fnmatchcase(actual, pattern)

# --- A3: time-of-day / day-of-week predicate ----------------------------------
_DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
_WEEKDAYS = ["mon", "tue", "wed", "thu", "fri"]
_HHMM_RE = re.compile(r"([01]\d|2[0-3]):([0-5]\d)\Z")


def _parse_hhmm(s) -> int | None:
    """'HH:MM' -> minute-of-day, or None on any malformed input."""
    if not isinstance(s, str):
        return None
    m = _HHMM_RE.match(s)
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def _time_outside_hours(spec, actual) -> bool:
    """True when epoch-ms `actual` falls OUTSIDE the business-hours window in
    `spec` ({start: "HH:MM", end: "HH:MM", days: [mon..], tz_offset_minutes: N}).

    "Within business hours" = the local weekday is in `days` (default Mon-Fri)
    AND start <= minute-of-day < end; a start > end window wraps past midnight.
    Fail closed: a malformed spec or non-numeric event time returns False (the
    selection doesn't match), never raises -- untrusted contributor rules.
    """
    if not isinstance(spec, dict) or not spec:
        return False
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return False
    start = _parse_hhmm(spec.get("start"))
    end = _parse_hhmm(spec.get("end"))
    if start is None or end is None or start == end:
        return False
    tz = spec.get("tz_offset_minutes", 0)
    if isinstance(tz, bool) or not isinstance(tz, int) or not -14 * 60 <= tz <= 14 * 60:
        return False
    days_raw = spec.get("days", _WEEKDAYS)
    if not isinstance(days_raw, list) or not days_raw:
        return False
    days: set[int] = set()
    for d in days_raw:
        if not isinstance(d, str) or d.lower() not in _DAY_NAMES:
            return False
        days.add(_DAY_NAMES[d.lower()])
    for key in spec:
        if key not in ("start", "end", "days", "tz_offset_minutes"):
            return False  # unknown key -> malformed spec -> fail closed
    local_minutes = int(actual) // 60000 + tz
    # Epoch day 0 (1970-01-01) was a Thursday; Python floor-division keeps this
    # correct for pre-1970 (negative) timestamps too.
    weekday = (local_minutes // 1440 + 3) % 7
    minute_of_day = local_minutes % 1440
    if weekday not in days:
        return True
    if start < end:
        within = start <= minute_of_day < end
    else:  # window wraps midnight, e.g. 22:00-06:00
        within = minute_of_day >= start or minute_of_day < end
    return not within


def _numeric_compare(op: str, actual, expected) -> bool:
    """Fail-closed numeric comparison: any non-numeric operand -> False, never raise."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False  # bool is a numeric subtype in Python; exclude to avoid surprises
    if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
        return False
    try:
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "lt":
            return actual < expected
        if op == "lte":
            return actual <= expected
        if op == "ne":
            return actual != expected
    except TypeError:
        return False
    return False


def _event_fingerprint(event: dict) -> str:
    """Stable short hash of an event, for deduping non-stateful alerts that lack an
    ingest_id. Deterministic across processes (sorted-key JSON), so redelivery of the
    same event yields the same alert id."""
    try:
        blob = json.dumps(event, sort_keys=True, default=str)
    except (TypeError, ValueError):
        blob = repr(event)
    return hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:16]


def _valid_window_time(value) -> int | None:
    """Return event ``time`` as epoch-ms int if it can safely drive a stateful
    window, else None (fail closed). Rejects bool, non-numeric, NaN/inf, and
    timestamps implausibly far ahead of wall-clock (see _MAX_CLOCK_SKEW_MS).
    Past timestamps always pass -- that is legitimate historical replay."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    now = int(value)
    if now > int(time.time() * 1000) + _MAX_CLOCK_SKEW_MS:
        return None
    return now


class Rule:
    def __init__(self, raw: dict, allowlists_dir: Path | None = None):
        self.raw = raw
        self.id = raw.get("id")
        self.title = raw.get("title", "untitled")
        self.level = raw.get("level", "medium")
        det = raw.get("detection", {})
        self.condition = det.get("condition", "")
        self.selections = {k: v for k, v in det.items() if k != "condition"}
        self._allowlists_dir = allowlists_dir
        # Gap-hunt finding (2026-08-23): an unparseable condition (valid YAML,
        # bad boolean logic) used to fail closed to "no match" in
        # _eval_condition with ZERO logging -- unlike the future-timestamp
        # guard a few hundred lines below, which got an explicit warn
        # specifically because a silent fail-closed drop was judged
        # unacceptable. Net effect before this: a hot-reloaded rule with a
        # typo'd condition showed "active" via /rules and simply never fired
        # again, silently, forever. Warned ONCE per Rule instance (not once
        # per event -- a broken condition fails on every event, and reload()
        # builds a fresh Rule on every edit, so this naturally re-warns on
        # each reload attempt, same "warn once until state changes"
        # convention as ws1-collectors' ingest-silence watchdog).
        self._condition_error_warned = False
        # Perf #1 (2026-07-29 audit): self.condition/self.selections are fixed
        # at load time and never change for this Rule's lifetime (reload()
        # builds fresh Rule instances rather than mutating one), yet
        # _eval_condition used to re-tokenize the condition string and
        # get_path used to re-split every selection's dotted path on EVERY
        # event, for every candidate rule -- pure re-derivation of a value
        # that never changes, sitting in the one stage every event passes
        # through. Precompute both once here; no semantic change.
        self._condition_tokens = re.findall(
            r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+",
            self.condition.strip() or " and ".join(self.selections))
        self._compiled_selections = {
            name: [(tuple(path.split(".")), expected) for path, expected in sel.items()]
            for name, sel in self.selections.items()
        }
        # Load-time unknown-operator check (gap-hunt 2026-09-04): an
        # operator-shaped selection value (e.g. {gt: 60}) whose key
        # `_operator_matches` doesn't recognize fail-closes to no-match on
        # every event, silently, forever -- same class of blackout the
        # condition-parse warning above exists to catch, and for the same
        # reason done here rather than only in `_operator_matches`: a rule
        # bucketed under a class_uid that never sees a matching event would
        # never reach the runtime check at all.
        for sel in self.selections.values():
            for expected in sel.values():
                if isinstance(expected, dict):
                    bad = set(expected) - _KNOWN_OPS
                    if bad:
                        _log.warn(
                            f"rule {self.id}: selection uses unrecognized "
                            f"operator key(s) {sorted(bad)}; that predicate "
                            f"will fail closed to no-match on every event "
                            f"until this rule is fixed and reloaded -- it "
                            f"will show as 'active' via /rules but never fire"
                        )
        # B1: bucket this rule under class_uid X only when X is provably
        # NECESSARY for any match -- i.e. the condition is UNSATISFIABLE when
        # every selection carrying a plain equality class_uid==X is False and
        # every other selection is True (most permissive). Probed with the real
        # T4 parser, so and/or/not are handled exactly like runtime:
        #   "a and b"      (a=class X, b classless) -> bucketable under X
        #   "a or b"       (b classless or other class) -> catch-all
        #   "not a" / any negation that can match other classes -> catch-all
        # The previous first-selection-wins heuristic mis-bucketed a
        # multi-class OR rule under its first class, silently skipping events
        # of the other class -- a missed detection, found in review.
        # Catch-all (self.class_uid None) is always CORRECT, just unfiltered.
        self.class_uid = self._bucketable_class_uid()
        # Gap-hunt follow-up (2026-08-23): _eval_condition's warn-once only
        # fires when the rule is actually evaluated. A rule bucketed under a
        # class_uid that never produces events (or a rule whose condition has
        # unconsumed tokens that still "parses" without raising) would never
        # trigger _eval_condition at all, so the silent fail-closed went
        # undetected. Dry-run the parse here (at load time) so the warning
        # fires regardless of whether any event of the right class ever arrives.
        try:
            value, end = _parse_or(
                self._condition_tokens, 0,
                {name: True for name in self._compiled_selections})
            if end != len(self._condition_tokens):
                raise ValueError(
                    f"{end} unconsumed token(s) after parsing condition")
        except (ValueError, IndexError, RecursionError) as exc:
            self._condition_error_warned = True  # suppress duplicate runtime warn
            _log.warn(
                f"rule {self.id}: condition has a load-time parse problem "
                f"({type(exc).__name__}: {exc}); it will fail closed to "
                f"no-match on every event until this rule is fixed and "
                f"reloaded -- it will show as 'active' via /rules but "
                f"never fire"
            )
        siem = raw.get("siem", {})
        self.sector = siem.get("sector", "common")
        self.score_weight = int(siem.get("score_weight", 0))
        # Design-B (2026-07-29 audit): `severity_floor` (scoring.yaml) floors
        # a high/critical rule's score to 70/80, which is always >= llm_min
        # (60) -- so today EVERY high/critical rule always pays for an LLM
        # triage call the moment it fires, and tuning score_weight down does
        # nothing (the floor overrides it). Several shipped high-level rules
        # document themselves as noisy pre-tuning (agent_credential_file_
        # access.yml, ot_config_change.yml, bank_mass_card_read.yml,
        # common_after_hours_admin.yml) with no way to say "keep the
        # analyst-facing severity, but don't burn an LLM call until this is
        # tuned". `llm_gate: false` is that lever: it excludes ONLY this
        # rule's severity floor from the FUNNEL ROUTING decision (Scorer.
        # routing_score) -- the analyst-facing `score` (Scorer.score, still
        # floor-inclusive) and `level` are completely unaffected, so nothing
        # about how the alert LOOKS changes, only whether it queues for LLM
        # triage. Defaults to True (gate stays on): an unmodified rule's
        # routing is byte-for-byte unchanged by this feature existing --
        # opting out is a per-rule decision an operator must make explicitly,
        # never a silent global behavior change. `is not False` (rather than
        # `bool(...)`) so a typo'd non-bool value (e.g. a quoted "false"
        # string) fails closed to the safe side (gate stays ON, more triage
        # rather than less) instead of `bool("false") == True` silently
        # doing the wrong thing.
        self.llm_gate = siem.get("llm_gate", True) is not False
        self.window_seconds = siem.get("window_seconds")
        self.threshold = siem.get("threshold")
        # FIX 2(b) poison-pill guard (2026-08-06): validate the stateful
        # window/threshold TYPES at construction, so a poisoned rule like
        # `window_seconds: "60"` raises a clear ValueError HERE (bad
        # contributor rule spotted at load time) instead of a TypeError inside
        # event evaluation -- `"60" * 1000` or `count >= "10"` would otherwise
        # escape the condition-phase try/except and poison-pill the consumer.
        # Bool is rejected too: it is an int subtype whose arithmetic would be
        # silently nonsense (True * 1000 == 1000).
        for _f in ("window_seconds", "threshold"):
            _v = siem.get(_f)
            if _v is not None and (isinstance(_v, bool)
                                   or not isinstance(_v, (int, float))):
                raise ValueError(
                    f"rule {raw.get('id')}: siem.{_f} must be numeric, "
                    f"got {type(_v).__name__}")
        self.group_by = siem.get("group_by", "src_endpoint.ip")
        self._group_by_parts = tuple(self.group_by.split("."))
        # Optional: count DISTINCT values of this OCSF field per group instead of a
        # raw event count (port scan -> distinct dst ports; lateral movement ->
        # distinct dst hosts). None => plain count (brute-force, mass-delete).
        self.distinct_field = siem.get("distinct_field")
        self._distinct_field_parts = (
            tuple(self.distinct_field.split(".")) if self.distinct_field else None
        )
        # v0.5 A3: optional periodicity/beaconing check on top of the plain
        # count -- {"max_cv": <float>}. Mutually meaningful only alongside
        # window_seconds/threshold; validate_rules.py enforces the shape and
        # that it isn't combined with distinct_field (the two window
        # semantics don't compose). See window.py's design note.
        self.periodicity = siem.get("periodicity")
        self.stateful = self.window_seconds is not None and self.threshold is not None
        # Sliding-window counter (T6). Defaults to an in-process deque (correct for a
        # single replica / tests). main() swaps in a RedisWindowCounter when running
        # on Redis so the count is global across replicas. See window.py.
        self._counter = DequeWindowCounter()

    def _bucketable_class_uid(self):
        """Return the class_uid this rule can safely be bucketed under, or None
        for the catch-all. See the B1 comment in __init__ for the criterion."""
        candidates: list = []
        for sel in self.selections.values():
            if isinstance(sel, dict):
                val = sel.get("class_uid")
                if isinstance(val, (int, str)) and not isinstance(val, bool):
                    if val not in candidates:
                        candidates.append(val)
        if not candidates:
            return None
        expr = self.condition.strip() or " and ".join(self.selections)
        tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", expr)
        for cand in candidates:
            # Two probes bound satisfiability without `cand`'s own selections:
            # every OTHER selection forced True, and every OTHER selection
            # forced False. Forcing True alone (the original probe) is
            # unsound for a negated classless selection -- `not other_sel` is
            # naturally True at runtime for the common case of a legitimately
            # different-class event that simply doesn't match other_sel's
            # fields, which the True-only probe never tries. That let a rule
            # like `class_x_sel or not other_sel` get bucketed under
            # class_x_sel's class_uid and silently skipped for every other
            # class it can genuinely still match. (Names the condition
            # references but doesn't define stay absent -> the parser
            # resolves them to False in either probe, same as at runtime.)
            satisfiable_without = False
            for force_others in (True, False):
                probe = {}
                for name, sel in self.selections.items():
                    val = sel.get("class_uid") if isinstance(sel, dict) else None
                    is_cand = (val == cand and isinstance(val, (int, str))
                               and not isinstance(val, bool))
                    probe[name] = False if is_cand else force_others
                try:
                    value, end = _parse_or(tokens, 0, probe)
                    if end == len(tokens) and bool(value):
                        satisfiable_without = True
                        break
                except (ValueError, IndexError, RecursionError):
                    satisfiable_without = True  # can't prove safety -> catch-all
                    break
            if not satisfiable_without:
                return cand
        return None

    def set_counter(self, counter) -> None:
        """Swap the window backend (e.g. RedisWindowCounter for multi-replica)."""
        self._counter = counter

    @staticmethod
    def _namespaced_group(tenant: str, group: str) -> str:
        """``tenant:len(group):group`` -- the shared prefix for both the
        window-counter key and the stateful alert_id (security-medium #1,
        2026-07-29 audit).

        `group` comes straight from `group_by` (e.g. `actor.user.name`) and is
        attacker-controlled with no length cap or character filtering -- a raw
        `f"{tenant}:{group}"` join lets a crafted `group` containing ':'
        produce the SAME joined string as a different (tenant, group) pair,
        letting an attacker deliberately collide their alert_id/window-key
        with someone else's and overwrite it (idempotent-upsert storage keys
        on this exact id). Length-prefixing `group` makes the join unambiguous
        regardless of what characters `group` contains: the digits before the
        first ':' are never part of `group` itself, so they always disclose
        exactly how many of the following characters belong to `group` --
        two different `group` values can never encode to the same string.
        `tenant` and `self.id` don't need this treatment: tenant is
        deployment-stamped, not per-event, and rule id is fixed.
        """
        return f"{tenant}:{len(group)}:{group}"

    def _selection_matches(self, compiled_sel: list, event: dict) -> bool:
        for parts, expected in compiled_sel:
            actual = _get_path_parts(event, parts)
            if isinstance(expected, dict):
                if not self._operator_matches(expected, actual):
                    return False
                continue
            if actual != expected:
                return False
        return True

    def _operator_matches(self, expected: dict, actual) -> bool:
        """A3: evaluate an operator-shaped selection value, e.g. {gt: 60} or
        {not_in: "corp_ranges"}. Unknown/malformed operator dicts fail closed
        (return False), never raise -- this runs on untrusted contributor rules.
        """
        if not expected:
            return False
        for op, arg in expected.items():
            if op in _NUMERIC_OPS:
                if not _numeric_compare(op, actual, arg):
                    return False
            elif op == "not_in":
                if not isinstance(arg, str):
                    return False  # malformed allowlist reference -> fail closed
                allowlist = load_allowlist(self._allowlists_dir or _default_allowlists_dir(), arg)
                # FAIL-OPEN on a broken allowlist (2026-08-06, matches the
                # project's established intent in test_v03_rule_grammar /
                # test_v04_rule_tuning / test_v05_agent_rules -- see M2).
                # `not_in` is a SUPPRESSION allowlist ("fire when the field is
                # NOT in this known-good list"). If the list cannot be loaded,
                # over-alerting (keep firing = noise) is strictly safer than
                # silently disabling the rule (detection blackout). This is
                # deliberate and tested; do not flip to fail-closed.
                if allowlist.matches(actual):
                    return False  # value IS in the allowlist -> suppressed -> no match
            elif op == "outside_hours":
                if not _time_outside_hours(arg, actual):
                    return False
            elif op == "in":
                # list membership: actual must equal one of the listed scalars.
                if not isinstance(arg, list) or not _in_list(actual, arg):
                    return False
            elif op == "contains":
                # bounded substring match (attacker-safe: plain str.__contains__,
                # no regex, arg length capped). Both operands must be strings.
                if not _contains(actual, arg):
                    return False
            elif op == "glob":
                # M7 2026-08-05: Sigma-style */?/[seq] wildcard via fnmatch, NOT
                # regex (see _glob_match's docstring for why this doesn't reopen
                # ADR-005's no-regex/ReDoS-safety constraint).
                if not _glob_match(actual, arg):
                    return False
            elif op == "exists":
                # Presence predicate: {exists: true} matches when the field is
                # populated (not None); {exists: false} matches when it's
                # missing/None. Lets a rule discriminate on an out-of-band
                # context field a parser only sometimes sets (e.g.
                # unmapped.ot.change_ticket_id) without hard-coding every
                # possible value via equality. arg must be a real bool (not a
                # truthy int/string) -> fail closed on a typo'd non-bool value.
                if not isinstance(arg, bool):
                    return False
                if (actual is not None) != arg:
                    return False
            else:
                return False  # unknown operator -> fail closed
        return True

    def _eval_condition(self, event: dict) -> bool:
        matched = {name: self._selection_matches(compiled, event)
                   for name, compiled in self._compiled_selections.items()}
        tokens = self._condition_tokens
        # T4: explicit recursive-descent boolean evaluator over the tokens.
        # No eval(): rule files are contributor-supplied (open source), so executing
        # them as Python — even with __builtins__ stripped — is an RCE surface.
        # RecursionError is caught too: a rule with deeply nested parens would
        # otherwise blow the stack and escape as an uncaught error, poison-pilling
        # the consumer (message unacked -> redelivered forever). A malformed
        # condition must fail closed to "no match", never crash the worker.
        try:
            value, end = _parse_or(tokens, 0, matched)
            if end != len(tokens):
                # Trailing garbage tokens (e.g. "a b", no connective) parsed
                # without raising, but never consumed the full condition --
                # same silent-forever-no-match shape as the except below.
                raise ValueError(f"condition left {len(tokens) - end} "
                                 f"unconsumed token(s) after parsing")
            return bool(value)
        except (ValueError, IndexError, RecursionError) as exc:
            if not self._condition_error_warned:
                self._condition_error_warned = True
                _log.warn(
                    f"rule {self.id}: condition failed to parse/evaluate "
                    f"({type(exc).__name__}: {exc}); failing closed to "
                    f"no-match on every event until this rule is fixed and "
                    f"reloaded -- it will show as 'active' via /rules but "
                    f"never fire"
                )
            return False

    def alert_key(self, event: dict) -> str:
        """Deterministic alert identity (T7).

        Redelivery / duplicate processing of the same triggering event must yield the
        SAME alert id, never a fresh uuid4 — otherwise at-least-once delivery produces
        undeduplicatable duplicate alerts. Keyed by (rule, group, window-bucket) for
        stateful rules, (rule, ingest_id) otherwise.

        This is a PURE function of the event on purpose: a stateful "open incident"
        anchor would key the id on processing order, so a redelivery arriving after a
        later event could get a different id — the exact undeduplicatable-duplicate
        failure this key exists to prevent. We keep determinism and accept two known
        edge behaviors of the fixed epoch bucket instead:
          * two distinct bursts from one group that fall in the same `window`-aligned
            bucket share an id (deduped as one incident — acceptable for a burst rule);
          * a single burst straddling a bucket boundary yields two ids (a duplicate
            alert for one incident).
        Both are minor and self-healing; neither can drop or fabricate a *detection*.
        """
        if self.stateful:
            # evaluate() gates on group_by being present, so a fired stateful
            # alert always has a real group here -- str() of None can only
            # appear if alert_key is called for an event evaluate() rejected.
            group = str(_get_path_parts(event, self._group_by_parts))
            now = int(event.get("time", 0) or 0)
            window_ms = int(self.window_seconds) * 1000
            bucket = now // window_ms if window_ms else now
            # F1 follow-up (adversarial review of 6e3fbe4): the window COUNTER
            # key was namespaced by tenant in evaluate() above, but this id --
            # the actual alert_id stored in OpenSearch/MemoryStore and returned
            # to callers -- was not. Two tenants sharing a group_by value whose
            # bursts land in the same window bucket produced the SAME alert_id;
            # WS-3's find_alert()/find_report() search alerts-* indices by id
            # and return the first match, so one tenant's alert could shadow
            # (become unreachable behind) the other's under find_alert-by-id --
            # the same cross-tenant pooling class F1 fixed for the counter,
            # left open here. Tenant-scoped storage (F3's separate
            # alerts-{tenant}-* indices) does NOT save us: the collision is on
            # the id used to look a doc up, not on where it's physically stored.
            tenant = _event_tenant(event)
            return f"{self.id}:{self._namespaced_group(tenant, group)}:{bucket}"
        # Non-stateful: prefer ingest_id (one alert per source event). When absent,
        # fall back to a content hash rather than a shared "noingest" constant --
        # otherwise every ingest_id-less event of this rule collapses onto ONE alert
        # id and all but the first are silently deduped away downstream.
        #
        # P1-1 (2026-07-21 audit): this branch was missing the tenant namespacing
        # the stateful branch above already has (the F1 follow-up). Two tenants
        # whose ingest-less events hash to the same content fingerprint -- or,
        # simpler, two tenants who happen to reuse the same ingest_id value --
        # got the IDENTICAL alert_id; storage/opensearch.py's _search_alert()
        # queries alerts-* by _id and returns the first match, so one tenant's
        # alert could shadow (become unreachable behind) the other's. Same
        # class of bug F1 fixed for the counter and its own follow-up fixed for
        # the stateful id; this was the one spot it was missed. Always include
        # tenant, matching the stateful branch's unconditional format (no
        # special-casing "default" -- consistency matters more than a few
        # bytes for the common single-tenant case).
        tenant = _event_tenant(event)
        ingest = (event.get("siem") or {}).get("ingest_id")
        if not ingest:
            ingest = "sha:" + _event_fingerprint(event)
        return f"{self.id}:{tenant}:{ingest}"

    _MAX_CONTRIBUTING_IDS = 50

    def contributing_event_ids(self, event: dict) -> list:
        """Design-A (2026-07-29 audit): best-effort list of ingest_ids behind
        this alert, for the analyst/audit trail. Before this, a stateful
        alert's `event_ids` was always a single-element list -- just the one
        event that happened to cross the threshold -- even though the alert's
        own rule_title claims N events occurred (a `common_bruteforce` alert
        cites "10 failed logins" but referenced only 1 of the 10). That gap
        compounds with alert retention (365d) outliving common-sector event
        retention (30d): after 30 days the alert can no longer be
        substantiated even for the one id it does keep.

        Best-effort, not exhaustive: this reads whatever the window counter
        currently remembers (bounded by member-dedup + the window itself), so
        it can under-report if the caller checks long after the window aged
        entries out, but it can never fabricate an id that wasn't a real hit.
        Capped at _MAX_CONTRIBUTING_IDS so one very-high-threshold rule can't
        bloat every alert document.

        Returns the plain, clean list of ids only. Callers who need to know
        whether the cap actually bit should use
        :meth:`contributing_event_ids_with_omitted` -- review finding
        (2026-08-27): an earlier version of this method stamped an in-band
        `"<truncated: N omitted>"` STRING into the returned list itself, so
        any caller treating `event_ids` as "a list of ids" (a wire/UI
        consumer, a join against raw events) would treat that sentinel as a
        real id. This method is kept id-list-only; the count is a sibling.
        """
        ids, _omitted = self.contributing_event_ids_with_omitted(event)
        return ids

    def contributing_event_ids_with_omitted(self, event: dict) -> tuple[list, int]:
        """Same as :meth:`contributing_event_ids`, but returns
        ``(ids, omitted_count)`` -- ``omitted_count`` is 0 unless the
        ``_MAX_CONTRIBUTING_IDS`` cap actually bit, in which case it is the
        number of ids that were dropped (not embedded into ``ids`` itself)."""
        own_id = (event.get("siem") or {}).get("ingest_id")
        if not self.stateful:
            return ([own_id] if own_id else []), 0
        tenant = (event.get("siem") or {}).get("tenant") or "default"
        group_value = _get_path_parts(event, self._group_by_parts)
        if group_value is None:
            return ([own_id] if own_id else []), 0
        window_key = f"{self.id}:{self._namespaced_group(tenant, str(group_value))}"
        if self.distinct_field:
            # The tracked "member" for a distinct-field window IS the field
            # value (e.g. distinct dst ports), not an event id -- still real
            # evidence of what tripped the rule, just a different shape.
            ids = self._counter.distinct_members(window_key)
        else:
            ids = self._counter.members(window_key)
        ids = [str(i) for i in ids]
        # R4-29 (2026-08-27): the old `[: _MAX_CONTRIBUTING_IDS]` slice silently
        # dropped every id past the cap, so an analyst looking at an N-event
        # stateful alert could not tell whether the list was truncated or truly
        # only held those ids (the alert's own rule_title claims N events occurred
        # -- silent loss is exactly the gap Design-A was written to close). Cap
        # explicitly and report how many were omitted as a SEPARATE value
        # (review finding, 2026-08-27: not embedded into the ids list itself --
        # see contributing_event_ids's docstring for why). Un-truncated lists
        # are byte-identical to the pre-fix behavior.
        omitted = max(0, len(ids) - self._MAX_CONTRIBUTING_IDS)
        if omitted:
            ids = ids[: self._MAX_CONTRIBUTING_IDS]
        if not ids and own_id:
            ids = [own_id]
        return ids, omitted

    def evaluate(self, event: dict) -> bool:
        """Return True if this rule fires for the event (incl. stateful threshold)."""
        if not self._eval_condition(event):
            return False
        if not self.stateful:
            return True
        # FIX 2(a) poison-pill guard (2026-08-06): the stateful evaluation runs
        # window arithmetic (`window_seconds * 1000`, `count >= threshold`) that
        # is out of reach of the condition-phase try/except in _eval_condition.
        # A poisoned rule that slipped past load-time validation (Part B here +
        # validate_rules wiring in load_rules) must fail CLOSED to no-match,
        # never escape as an uncaught TypeError/ValueError that crashes the
        # consumer (message unacked -> redelivered forever).
        try:
            return self._evaluate_stateful(event)
        except (TypeError, ValueError):
            return False

    def _evaluate_stateful(self, event: dict) -> bool:
        """Stateful threshold path. Caller wraps this in a TypeError/ValueError
        guard (FIX 2(a)); f(n) must never let window arithmetic raise."""
        group_value = _get_path_parts(event, self._group_by_parts)
        if group_value is None:
            # An event without the group_by field cannot be attributed to any
            # group. Counting it anyway would pool ALL such events under one
            # shared "None" bucket -- two unrelated agent sessions missing
            # session_id would sum toward one burst threshold, fabricating a
            # correlation. Fail closed: no group, no count. (Same convention
            # as every other malformed-input path in this evaluator.)
            return False
        group = str(group_value)
        now = _valid_window_time(event.get("time", 0))
        if now is None:
            # Non-numeric/NaN/inf time would crash the counter arithmetic
            # (now_ms - window_ms) and poison-pill the consumer; a far-future
            # time would corrupt the window (see _MAX_CLOCK_SKEW_MS). Fail closed
            # -- same discipline as the time-of-day predicate (_time_outside_hours).
            raw = event.get("time", 0)
            if (isinstance(raw, (int, float)) and not isinstance(raw, bool)
                    and math.isfinite(raw)
                    and int(raw) > int(time.time() * 1000) + _MAX_CLOCK_SKEW_MS):
                # FIX L1 (2026-08-06): a future-dated event is dropped here by
                # the anti-window-poisoning guard -- surface it at WARN so these
                # silent fail-closed drops (source clock-skew / spoofed timestamps)
                # are visible to operators instead of vanishing without a trace.
                _log.warn(
                    f"rule {self.id}: dropping future-dated event (time={raw}); "
                    f"beyond {_MAX_CLOCK_SKEW_MS}ms clock-skew guard, not driving "
                    f"stateful window"
                )
            return False
        member = (event.get("siem") or {}).get("ingest_id") or str(now)
        # Namespace the window by rule id AND tenant so two rules (or two
        # tenants) grouping on the same field don't share a counter. Without
        # the tenant component, two tenants whose events share a group_by
        # value (e.g. overlapping RFC1918 source IPs -- the normal case for
        # an MSP) would pool their event counts into one window, letting one
        # tenant's traffic push another tenant's rule over threshold. This is
        # a real isolation gap the M4.1 gate test didn't catch because it
        # used distinct source IPs per tenant. The counter returns the
        # in-window count after add.
        tenant = _event_tenant(event)
        window_key = f"{self.id}:{self._namespaced_group(tenant, group)}"
        window_ms = self.window_seconds * 1000
        if self.distinct_field:
            assert self._distinct_field_parts is not None
            value = _get_path_parts(event, self._distinct_field_parts)
            if value is None:
                # A non-value must not count as a distinct value. The two
                # backends previously DISAGREED here: MemoryStore counted None
                # as one distinct value, RedisWindowCounter turned every
                # None-valued event into a FRESH member (str(now_ms)) -- so N
                # unenriched events alone could satisfy any distinct threshold
                # (e.g. impossible-travel firing on 2 logins with no geo
                # enrichment). Fail closed on both.
                return False
            count = self._counter.hit_distinct(window_key, now,
                                               window_ms, value, member)
        elif self.periodicity:
            count, cv = self._counter.hit_periodic(window_key, now,
                                                   window_ms, member)
            if cv is None:
                # Fewer than 3 events in-window yet -- not enough data to judge
                # regularity. Fail closed: never treat "can't tell" as "is
                # periodic" (that would fabricate a beacon signal from noise).
                return False
            return count >= self.threshold and cv <= self.periodicity.get("max_cv", 1.0)
        else:
            count = self._counter.hit(window_key, now, window_ms, member)
        return count >= self.threshold


# --- T4 boolean expression evaluator (replaces eval) -------------------------
# Grammar:  or_expr := and_expr ("or" and_expr)*
#           and_expr := not_expr ("and" not_expr)*
#           not_expr := "not" not_expr | atom
#           atom     := "(" or_expr ")" | <selection-name>
# Each function returns (value, next_index). Unknown selection names are False.

def _parse_or(tokens, i, values):
    val, i = _parse_and(tokens, i, values)
    while i < len(tokens) and tokens[i] == "or":
        rhs, i = _parse_and(tokens, i + 1, values)
        val = val or rhs
    return val, i


def _parse_and(tokens, i, values):
    val, i = _parse_not(tokens, i, values)
    while i < len(tokens) and tokens[i] == "and":
        rhs, i = _parse_not(tokens, i + 1, values)
        val = val and rhs
    return val, i


def _parse_not(tokens, i, values):
    if i < len(tokens) and tokens[i] == "not":
        val, i = _parse_not(tokens, i + 1, values)
        return (not val), i
    return _parse_atom(tokens, i, values)


def _parse_atom(tokens, i, values):
    if i >= len(tokens):
        raise ValueError("unexpected end of condition")
    t = tokens[i]
    if t == "(":
        val, i = _parse_or(tokens, i + 1, values)
        if i >= len(tokens) or tokens[i] != ")":
            raise ValueError("missing closing paren")
        return val, i + 1
    if t in ("and", "or", "not", ")"):
        raise ValueError(f"unexpected token {t!r}")
    return bool(values.get(t, False)), i + 1


def _default_allowlists_dir() -> Path:
    """contracts/allowlists sibling to contracts/rules, best-effort. If neither
    exists, callers fail closed via load_allowlist's missing-file handling."""
    return Path(__file__).resolve().parent.parent.parent / "contracts" / "allowlists"


def _validate_loaded_rule(raw: dict, path: Path) -> None:
    """FIX 2(c) poison-pill guard (2026-08-06): run the rule validator
    (tools/validate_rules.validate_rule) on each loaded YAML dict BEFORE
    constructing its ``Rule``, so a poisoned rule (e.g. ``window_seconds:
    "60"``) is rejected at load time with a clear error instead of raising
    inside event evaluation and poison-pilling the consumer. Only the
    poison-pill class (bad window_seconds/threshold types) blocks a load; the
    validator's other strict-gate findings are tolerated by the runtime (see
    the filter below).

    Loaded lazily and by ABSOLUTE FILE PATH on purpose:
      * deferred import -- tools/validate_rules.py imports engine at module
        scope, so a module-level import here would be circular;
      * file-path load -- the repo's ``tools/`` is a namespace package (no
        ``__init__.py``) and can be shadowed on ``sys.path`` by an unrelated
        regular ``tools`` package (e.g. the hermes-agent ``tools`` dir), so
        ``import tools.validate_rules`` is not reliable in every runtime.
        Loading by resolved path works regardless of what else sits on
        ``sys.path``. If the file is genuinely absent, we fall back to
        engine.Rule.__init__'s own type checks, which still guard the actual
        poison-pill case.
    """
    import importlib.util  # noqa: E402  (module-level would bloat hot imports)
    vrf = Path(__file__).resolve().parents[2] / "tools" / "validate_rules.py"
    if not vrf.exists():
        return  # tools/ not deployed; Rule.__init__ still guards
    spec = importlib.util.spec_from_file_location("_fengarde_validate_rules", vrf)
    if spec is None or spec.loader is None:
        return  # could not build a spec/loader; Rule.__init__ still guards
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_fengarde_validate_rules"] = mod
    spec.loader.exec_module(mod)
    errors = mod.validate_rule(raw)
    # The rule validator is a strict CONTRIBUTION gate (UUID id, title,
    # level, ... required for the open-source rule flywheel). The runtime,
    # by contrast, is deliberately tolerant: Rule defaults a missing `level`
    # to "medium", and a malformed rule fails CLOSED at evaluate -- it never
    # refuses to load. So applying the full gate here would reject rules that
    # are perfectly valid AT RUNTIME (e.g. a rule missing an optional `level`
    # field). The one error class that MUST stop a load is a poison-pill
    # window -- a non-numeric window_seconds/threshold that would crash the
    # stateful path (guarded anyway by FIX 2(a)/(b), but far better to reject
    # the rule here with a clear file+field message). Surface only that class.
    poison = [e for e in errors
              if "window_seconds" in e or "threshold" in e]
    if poison:
        raise ValueError(f"rule file {path.name} failed validation: "
                         f"{poison[0]}")


def load_rules(rules_dir: Path, allowlists_dir: Path | None = None) -> list[Rule]:
    rules = []
    resolved_allowlists = allowlists_dir or (Path(rules_dir).parent / "allowlists")
    # Drop this dir's cached allowlists before the pass. Without this, an
    # allowlist that failed to load once (ok=False, cached) stays cached for
    # the life of the process even after an operator fixes the file on disk
    # and a hot-reload picks up the new rules -- load_allowlist() would keep
    # returning the stale broken-allowlist object forever, so a `not_in`
    # suppression the operator just repaired would silently stay disabled
    # (fail-open noise) instead of resuming suppression.
    invalidate_dir(resolved_allowlists)
    for path in sorted(Path(rules_dir).glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not raw:
            # Gap-hunt (2026-08-26): an empty/zero-byte/truncated rule file
            # parses to None/{} and was silently SKIPPED by the old `if raw:`
            # guard -- the rule set just shrank with no error, and a
            # hot-reload logged SUCCESS with fewer rules live. Warn instead so
            # "rules hot-reloaded, N rules" is cross-checkable against disk.
            _log.warn(
                "rule file parsed to empty/None (zero-byte or truncated?); "
                "ignoring it -- the loaded rule set is smaller than the dir "
                "contains", file=path.name)
            continue
        _validate_loaded_rule(raw, path)  # FIX 2(c): reject bad rules at load time
        rules.append(Rule(raw, allowlists_dir=resolved_allowlists))
    return rules
