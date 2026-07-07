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

import ipaddress
import re
from pathlib import Path

import yaml

from window import DequeWindowCounter


def get_path(doc: dict, dotted: str):
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


# --- A3: allowlists -----------------------------------------------------------
# Loaded once per rule-load pass (see load_rules) and shared via a module-level
# cache keyed by directory, so repeated `not_in: <name>` references across rules
# don't re-read/re-parse the file. A missing/malformed allowlist fails CLOSED:
# the rule selection referencing it can never match (never raises), and a
# warning is printed once at load time so the misconfiguration is visible.
_ALLOWLIST_CACHE: dict[str, "Allowlist"] = {}


class Allowlist:
    """A loaded allowlist: exact-match strings plus optional CIDR ranges.

    `ok` is False when the file was missing/malformed; matches() then always
    returns False (fail closed) instead of raising.
    """

    def __init__(self, entries: list, ok: bool = True):
        self.ok = ok
        self.exact: set[str] = set()
        self.nets: list = []
        for entry in entries or []:
            if not isinstance(entry, str):
                continue
            self.exact.add(entry)
            try:
                self.nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass  # not CIDR-shaped; exact-match only

    def matches(self, value) -> bool:
        if not self.ok:
            return False
        if value is None:
            return False
        s = str(value)
        if s in self.exact:
            return True
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return False
        for net in self.nets:
            try:
                if addr in net:
                    return True
            except TypeError:
                continue  # mismatched IP version (v4 addr vs v6 net etc.)
        return False


def load_allowlist(allowlists_dir: Path, name: str) -> Allowlist:
    """Load (and cache) an allowlist by name from contracts/allowlists/<name>.yml."""
    cache_key = f"{Path(allowlists_dir).resolve()}::{name}"
    if cache_key in _ALLOWLIST_CACHE:
        return _ALLOWLIST_CACHE[cache_key]

    path = Path(allowlists_dir) / f"{name}.yml"
    allowlist: Allowlist
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        entries = raw.get("entries") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            raise ValueError("allowlist file missing a list 'entries:' key")
        allowlist = Allowlist(entries, ok=True)
    except Exception as exc:  # missing file, bad YAML, bad shape -> fail closed
        print(f"[engine] WARNING: allowlist '{name}' failed to load ({exc}); "
              f"rule selections using not_in:{name} will never match (fail closed).")
        allowlist = Allowlist([], ok=False)

    _ALLOWLIST_CACHE[cache_key] = allowlist
    return allowlist


_NUMERIC_OPS = {"gt", "gte", "lt", "lte", "ne"}

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
        siem = raw.get("siem", {})
        self.sector = siem.get("sector", "common")
        self.score_weight = int(siem.get("score_weight", 0))
        self.window_seconds = siem.get("window_seconds")
        self.threshold = siem.get("threshold")
        self.group_by = siem.get("group_by", "src_endpoint.ip")
        # Optional: count DISTINCT values of this OCSF field per group instead of a
        # raw event count (port scan -> distinct dst ports; lateral movement ->
        # distinct dst hosts). None => plain count (brute-force, mass-delete).
        self.distinct_field = siem.get("distinct_field")
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
            # Probe: class-cand selections False, every other selection True.
            # (Names the condition references but doesn't define stay absent ->
            # the parser resolves them to False, same as at runtime.)
            probe = {}
            for name, sel in self.selections.items():
                val = sel.get("class_uid") if isinstance(sel, dict) else None
                is_cand = (val == cand and isinstance(val, (int, str))
                           and not isinstance(val, bool))
                probe[name] = not is_cand
            try:
                value, end = _parse_or(tokens, 0, probe)
                satisfiable_without = bool(value) if end == len(tokens) else True
            except (ValueError, IndexError, RecursionError):
                satisfiable_without = True  # can't prove safety -> catch-all
            if not satisfiable_without:
                return cand
        return None

    def set_counter(self, counter) -> None:
        """Swap the window backend (e.g. RedisWindowCounter for multi-replica)."""
        self._counter = counter

    def _selection_matches(self, sel: dict, event: dict) -> bool:
        for path, expected in sel.items():
            actual = get_path(event, path)
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
                if allowlist.matches(actual):
                    return False  # value IS in the allowlist -> suppressed -> no match
            elif op == "outside_hours":
                if not _time_outside_hours(arg, actual):
                    return False
            else:
                return False  # unknown operator -> fail closed
        return True

    def _eval_condition(self, event: dict) -> bool:
        matched = {name: self._selection_matches(sel, event)
                   for name, sel in self.selections.items()}
        expr = self.condition.strip() or " and ".join(self.selections)
        # tokenize: selection names and and/or/not/parens
        tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.]+", expr)
        # T4: explicit recursive-descent boolean evaluator over the tokens.
        # No eval(): rule files are contributor-supplied (open source), so executing
        # them as Python — even with __builtins__ stripped — is an RCE surface.
        # RecursionError is caught too: a rule with deeply nested parens would
        # otherwise blow the stack and escape as an uncaught error, poison-pilling
        # the consumer (message unacked -> redelivered forever). A malformed
        # condition must fail closed to "no match", never crash the worker.
        try:
            value, end = _parse_or(tokens, 0, matched)
            return bool(value) if end == len(tokens) else False
        except (ValueError, IndexError, RecursionError):
            return False

    def alert_key(self, event: dict) -> str:
        """Deterministic alert identity (T7).

        Redelivery / duplicate processing of the same triggering event must yield the
        SAME alert id, never a fresh uuid4 — otherwise at-least-once delivery produces
        undeduplicatable duplicate alerts. Keyed by (rule, group, window-bucket) for
        stateful rules, (rule, ingest_id) otherwise.
        """
        if self.stateful:
            group = str(get_path(event, self.group_by))
            now = int(event.get("time", 0) or 0)
            window_ms = int(self.window_seconds) * 1000
            bucket = now // window_ms if window_ms else now
            return f"{self.id}:{group}:{bucket}"
        ingest = (event.get("siem") or {}).get("ingest_id") or "noingest"
        return f"{self.id}:{ingest}"

    def evaluate(self, event: dict) -> bool:
        """Return True if this rule fires for the event (incl. stateful threshold)."""
        if not self._eval_condition(event):
            return False
        if not self.stateful:
            return True
        group = str(get_path(event, self.group_by))
        now = event.get("time", 0)
        member = (event.get("siem") or {}).get("ingest_id") or str(now)
        # Namespace the window by rule id so two rules grouping on the same field
        # don't share a counter. The counter returns the in-window count after add.
        window_ms = self.window_seconds * 1000
        if self.distinct_field:
            value = get_path(event, self.distinct_field)
            count = self._counter.hit_distinct(f"{self.id}:{group}", now,
                                               window_ms, value, member)
        else:
            count = self._counter.hit(f"{self.id}:{group}", now, window_ms, member)
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


def load_rules(rules_dir: Path, allowlists_dir: Path | None = None) -> list[Rule]:
    rules = []
    resolved_allowlists = allowlists_dir or (Path(rules_dir).parent / "allowlists")
    for path in sorted(Path(rules_dir).glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw:
            rules.append(Rule(raw, allowlists_dir=resolved_allowlists))
    return rules
