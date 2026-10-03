"""mutate_generic -- scenario-AGNOSTIC mutation operators for the Phase-4 harness.

WHY THIS EXISTS (2026-10-01)
    ``mutate.py`` is a 36-variant catalogue written for ONE storyline: its
    operators find steps by hard-coded label (``agent_mcp_tool_call``,
    ``credential_use``, ``modbus_write``) and rewrite their raw fields. Pointed
    at any other chain they find nothing to mutate and -- the dangerous part --
    "mutate nothing" grades as "baseline == mutated", i.e. PASS. A mutation
    harness whose operators silently no-op on a new scenario reports robustness
    it never tested.

    These operators know nothing about a specific chain. They act on STRUCTURE
    that every storyline has -- events, steps, bursts, time, source address,
    account, workstation -- through small per-source-type FIELD ADAPTERS
    (below). Three properties keep them honest:

      * every variant returns ``(payloads, changed)`` where ``changed`` is the
        number of raw events it actually altered. ``changed == 0`` is reported
        ``applicable=False`` and EXCLUDED from pass rates -- never counted as
        a pass;
      * the evasion classes are the ones a volume/window rule is actually
        weak to (spread the burst over time, over source addresses, over
        accounts, over workstation names; thin it; lose a log source) --
        classes the AI-to-OT chain, whose detections are almost all
        single-shot, could not even express;
      * everything is a pure function of (payloads, seed): no wall clock, no
        randomness beyond ``Random(derived seed)``.

ADAPTERS (2026-10-03). Every source a registered storyline can emit has an adapter for the three
fields the operators need (time, source address, actor), and the sources that carry a workstation
name have one for it. ``test_mutation_adapters.py`` proves each adapter moves the PARSED field, not
only the raw one: an adapter that edits a raw key the parser ignores would make its variant a silent
no-op that still reports ``changed > 0``.

BURST = a step label with >= ``_BURST_MIN`` events (a port scan's 16 denied
connections, a brute force's 12 failures). Burst-only operators leave
single-event steps alone, by definition.

STDLIB ONLY.
"""
from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime, timedelta, timezone
from random import Random
from typing import Callable, Optional

_BURST_MIN = 3

_IP_RE = r"\d{1,3}(?:\.\d{1,3}){3}"
_ASA_SRC = re.compile(r"(src \w+:)(" + _IP_RE + r")")
_SSH_FROM = re.compile(r"(from )(" + _IP_RE + r")")
_SSH_USER = re.compile(r"(for (?:invalid user )?)(\S+)( from )")
_DNS_FROM = re.compile(r"(from )(" + _IP_RE + r")\s*$")
# CEF extension keys (``src=1.2.3.4 suser=bob``). The look-behind keeps ``src=`` from matching
# inside another key (``msrc=``); ``duser`` is the parser's fallback identity when no ``suser``.
_CEF_SRC = re.compile(r"((?<![\w])src=)(" + _IP_RE + r")")
_CEF_SUSER = re.compile(r"((?<![\w])suser=)(\S+)")
_CEF_DUSER = re.compile(r"((?<![\w])duser=)(\S+)")


# ---------------------------------------------------------------------------
# Field adapters: (get, set) per source_type for time / source address / actor /
# hostname. A source with no adapter for a field returns None / False and the
# variant that needed it is reported N/A -- never a silent pass.
# ---------------------------------------------------------------------------
def _meta(p: dict) -> dict:
    return p.setdefault("meta", {})


def get_time(p: dict) -> Optional[int]:
    return _meta(p).get("received_at")


#: raw-record keys that carry an epoch-ms event time (rewritten when present). ``timestamp`` is
#: db_audit's / opcua_audit's own clock and ``seen_at`` inventory_diff's: the parser reads those in
#: preference to ``meta.received_at``, so leaving them behind would silently keep the old time.
_EPOCH_KEYS = ("TimeCreated", "createdTime", "ts", "time", "timestamp", "seen_at")
#: raw-record keys that carry an ISO-8601 event time (rewritten when present). k8s audit records
#: carry ``requestReceivedTimestamp`` (microsecond precision) and the parser prefers it to
#: ``meta.received_at``.
_ISO_KEYS = ("eventTime", "requestReceivedTimestamp", "stageTimestamp")


def _iso(ts: int, template) -> str:
    """ISO form of ``ts`` in the same shape as ``template`` (fractional seconds preserved)."""
    dt = datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ" if "." in str(template) else "%Y-%m-%dT%H:%M:%SZ")


def set_time(p: dict, ts: int) -> bool:
    """Move an event to ``ts`` (epoch ms): the envelope clock AND the source's
    own timestamp field, so the parser cannot read the old time from either."""
    m = _meta(p)
    if m.get("received_at") is None:
        return False
    m["received_at"] = ts
    raw = p.get("raw")
    if isinstance(raw, dict):
        for key in _EPOCH_KEYS:
            if key in raw:
                raw[key] = ts
        for key in _ISO_KEYS:
            if key in raw:
                raw[key] = _iso(ts, raw[key])
    return True


# source_type -> the raw-record keys that can carry the source address / identity / workstation
# (first present key wins; the same key is written back).
_DICT_IP_KEYS = {
    "windows_eventlog": ("IpAddress",), "active_directory": ("IpAddress",),
    "cloudtrail": ("sourceIPAddress",), "vmware_vsphere": ("ipAddress",),
    "mcp_agent": ("client_ip",), "n8n_audit": ("ip",), "modbus_anomaly": ("sourceIp",),
    "web_access": ("src_ip",),
    "db_audit": ("ipAddress", "ip"), "opcua_audit": ("clientAddress", "clientIp"),
    "sysmon": ("SourceIp",), "inventory_diff": ("ip",),
}
_STR_IP_RX = {"cisco_asa": _ASA_SRC, "linux_ssh": _SSH_FROM, "dns_query": _DNS_FROM, "cef": _CEF_SRC}

_DICT_ACTOR_KEYS = {
    "vmware_vsphere": ("userName",), "mcp_agent": ("agent",), "n8n_audit": ("user",),
    "db_audit": ("user", "userName"), "opcua_audit": ("clientUserId", "userId"),
    "sysmon": ("User",),
}

_DICT_HOST_KEYS = {
    "windows_eventlog": ("WorkstationName",), "active_directory": ("WorkstationName",),
    "sysmon": ("SourceHostname", "Computer"), "inventory_diff": ("hostname",),
}
#: a Windows log writes a literal "-" for "no workstation recorded"; that is absence, not a name
_NO_HOST = ("", "-")


def _first_key(raw: dict, keys: tuple):
    for k in keys:
        if raw.get(k) is not None:
            return k
    return None


def get_src_ip(p: dict) -> Optional[str]:
    raw, st = p.get("raw"), p.get("source_type")
    if isinstance(raw, str):
        rx = _STR_IP_RX.get(st)
        mt = rx.search(raw) if rx else None
        return mt.group(2) if mt else None
    if isinstance(raw, dict):
        if st == "k8s_audit":
            ips = raw.get("sourceIPs")
            return ips[0] if isinstance(ips, list) and ips else None
        key = _first_key(raw, _DICT_IP_KEYS.get(st, ()))
        return raw.get(key) if key else None
    return None


def set_src_ip(p: dict, ip: str) -> bool:
    raw, st = p.get("raw"), p.get("source_type")
    old = get_src_ip(p)
    if old is None:
        return False
    if isinstance(raw, str):
        p["raw"] = _STR_IP_RX[st].sub(lambda mt: mt.group(1) + ip, raw, count=1)
    elif st == "k8s_audit":
        raw["sourceIPs"] = [ip] + list(raw["sourceIPs"][1:])
    else:
        raw[_first_key(raw, _DICT_IP_KEYS[st])] = ip
    if _meta(p).get("ip") == old:
        _meta(p)["ip"] = ip
    return True


def get_actor(p: dict) -> Optional[str]:
    raw, st = p.get("raw"), p.get("source_type")
    if isinstance(raw, str):
        if st == "linux_ssh":
            mt = _SSH_USER.search(raw)
            return mt.group(2) if mt else None
        if st == "cef":
            mt = _CEF_SUSER.search(raw) or _CEF_DUSER.search(raw)
            return mt.group(2) if mt else None
        return None
    if isinstance(raw, dict):
        if st in ("windows_eventlog", "active_directory"):
            return raw.get("SubjectUserName") if raw.get("EventID") == 4728 else raw.get("TargetUserName")
        if st == "k8s_audit":
            return (raw.get("user") or {}).get("username")
        if st == "cloudtrail":
            return (raw.get("userIdentity") or {}).get("arn")
        key = _first_key(raw, _DICT_ACTOR_KEYS.get(st, ()))
        return raw.get(key) if key else None
    return None


def set_actor(p: dict, name: str) -> bool:
    raw, st = p.get("raw"), p.get("source_type")
    if get_actor(p) is None:
        return False
    if isinstance(raw, str):
        if st == "cef":
            rx = _CEF_SUSER if _CEF_SUSER.search(raw) else _CEF_DUSER
            p["raw"] = rx.sub(lambda mt: mt.group(1) + name, raw, count=1)
        else:
            p["raw"] = _SSH_USER.sub(lambda mt: mt.group(1) + name + mt.group(3), raw, count=1)
    elif st in ("windows_eventlog", "active_directory"):
        raw["SubjectUserName" if raw.get("EventID") == 4728 else "TargetUserName"] = name
    elif st == "k8s_audit":
        raw["user"]["username"] = name
    elif st == "cloudtrail":
        raw["userIdentity"]["arn"] = name
    else:
        raw[_first_key(raw, _DICT_ACTOR_KEYS[st])] = name
    return True


def get_hostname(p: dict) -> Optional[str]:
    """The workstation / host name the parser reads as the event's SOURCE host (for Windows
    logons ``WorkstationName``). None when the source has no adapter or records none."""
    raw, st = p.get("raw"), p.get("source_type")
    if not isinstance(raw, dict):
        return None
    for k in _DICT_HOST_KEYS.get(st, ()):
        v = raw.get(k)
        if isinstance(v, str) and v.strip() not in _NO_HOST:
            return v
    return None


def set_hostname(p: dict, name: str) -> bool:
    raw, st = p.get("raw"), p.get("source_type")
    if get_hostname(p) is None:
        return False
    for k in _DICT_HOST_KEYS[st]:
        v = raw.get(k)
        if isinstance(v, str) and v.strip() not in _NO_HOST:
            raw[k] = name
            return True
    return False


# ---------------------------------------------------------------------------
# Structure helpers
# ---------------------------------------------------------------------------
def _by_step(payloads: list) -> dict:
    out: dict = {}
    for i, (spec, _p) in enumerate(payloads):
        out.setdefault(spec.label, []).append(i)
    return out


def _bursts(payloads: list, attack_steps: set) -> dict:
    return {lab: idxs for lab, idxs in _by_step(payloads).items()
            if lab in attack_steps and len(idxs) >= _BURST_MIN}


def _stable(*parts) -> int:
    h = hashlib.sha256("|".join(str(x) for x in parts).encode()).hexdigest()
    return int(h[:8], 16)


# ---------------------------------------------------------------------------
# Operators. Each: (payloads, ctx) -> (new_payloads, changed_event_count)
# ctx = {"seed", "attack_steps", "sdef"}
# ---------------------------------------------------------------------------
def _thin(keep: Callable[[int], bool]):
    def op(payloads, ctx):
        bursts = _bursts(payloads, ctx["attack_steps"])
        drop = set()
        for idxs in bursts.values():
            for rank, i in enumerate(idxs):
                if not keep(rank):
                    drop.add(i)
        return [x for i, x in enumerate(payloads) if i not in drop], len(drop)
    return op


def _stretch(factor: int):
    def op(payloads, ctx):
        out = copy.deepcopy(payloads)
        changed = 0
        for idxs in _bursts(out, ctx["attack_steps"]).values():
            t0 = min(get_time(out[i][1]) for i in idxs)
            for i in idxs:
                t = get_time(out[i][1])
                if set_time(out[i][1], t0 + (t - t0) * factor):
                    changed += 1
        return out, changed
    return op


def _rotate_ip(k: Optional[int]):
    """Spread each burst over ``k`` source addresses (None = one per event)."""
    def op(payloads, ctx):
        out = copy.deepcopy(payloads)
        changed = 0
        for n, idxs in enumerate(_bursts(out, ctx["attack_steps"]).values()):
            for rank, i in enumerate(idxs):
                j = rank if k is None else rank % k
                if set_src_ip(out[i][1], f"198.18.{n + 1}.{j + 10}"):
                    changed += 1
        return out, changed
    return op


def _split_actor(k: int):
    def op(payloads, ctx):
        out = copy.deepcopy(payloads)
        changed = 0
        for idxs in _bursts(out, ctx["attack_steps"]).values():
            for rank, i in enumerate(idxs):
                base = get_actor(out[i][1])
                if base is None:
                    continue
                if rank % k and set_actor(out[i][1], f"{base}-{rank % k + 1}"):
                    changed += 1
        return out, changed
    return op


def _rotate_hostname(payloads, ctx):
    """Give every event of every burst its OWN workstation name. A rule keyed on the source
    workstation (``common_bruteforce_sourceless`` pools failed logons by ``WorkstationName``) can
    be bypassed by a client that simply lies about its name; the one rule that is shaped that way
    is the question this variant asks. Sources that record no workstation name are untouched."""
    out = copy.deepcopy(payloads)
    changed = 0
    for n, idxs in enumerate(_bursts(out, ctx["attack_steps"]).values()):
        for rank, i in enumerate(idxs):
            if set_hostname(out[i][1], f"rot-{n + 1}-{rank:03d}"):
                changed += 1
    return out, changed


def _drop_step(label: str):
    def op(payloads, ctx):
        kept = [x for x in payloads if x[0].label != label]
        return kept, len(payloads) - len(kept)
    return op


def _shift(ms: int):
    def op(payloads, ctx):
        out = copy.deepcopy(payloads)
        changed = sum(1 for _s, p in out if get_time(p) is not None and set_time(p, get_time(p) + ms))
        return out, changed
    return op


def _to_clock(hour: int, minute: int, *, weekday_only: bool):
    """Move the WHOLE stream, rigidly, so its first event lands at ``hour:minute`` UTC on the next
    calendar day (the next WEEKDAY when ``weekday_only``). A pure shift: every gap, every ordering
    and every inter-step distance is preserved, so the only thing that changes is the wall-clock
    time of day a time-predicate rule sees. ``changed == 0`` (N/A) only if the stream already
    starts at exactly that instant."""
    def op(payloads, ctx):
        times = [get_time(p) for _s, p in payloads if get_time(p) is not None]
        if not times:
            return copy.deepcopy(payloads), 0
        t0 = min(times)
        day = datetime.fromtimestamp(t0 / 1000.0, tz=timezone.utc).replace(
            hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=1)
        while weekday_only and day.weekday() >= 5:
            day += timedelta(days=1)
        shift = int(day.timestamp() * 1000) - t0
        if shift == 0:
            return copy.deepcopy(payloads), 0
        return _shift(shift)(payloads, ctx)
    return op


def _jitter(max_ms: int):
    def op(payloads, ctx):
        out = copy.deepcopy(payloads)
        changed = 0
        for i, (_s, p) in enumerate(out):
            t = get_time(p)
            if t is None:
                continue
            d = (_stable(ctx["seed"], "jitter", i) % (2 * max_ms + 1)) - max_ms
            if set_time(p, t + d):
                changed += 1
        return out, changed
    return op


def _jitter_period(payloads, ctx):
    """Per-timestamp jitter of +/-100% of each burst's own PERIOD (its median inter-event gap).

    Each event of a burst step is displaced independently by a uniform draw in [-period, +period].
    This is the realistic evasion for a periodic (beacon) rule: the analytic shortcut 'uniform
    jitter j gives CV = j/sqrt(3), so the rule is evaded above j = 0.433' is WRONG for this engine,
    which evaluates the SAMPLE coefficient of variation on the prefixes of 6..n events and
    re-evaluates on every arrival, and a per-timestamp draw doubles the interval variance. At
    +/-50% the rule still fired in about 17% of draws; at +/-100% about 2%. Which side of the
    boundary one seed lands on is therefore a MEASUREMENT, reported per seed, not a prediction.
    Deterministic: the draw is a hash of (seed, event index), never a random source."""
    out = copy.deepcopy(payloads)
    changed = 0
    for idxs in _bursts(out, ctx["attack_steps"]).values():
        ts = sorted(get_time(out[i][1]) for i in idxs)
        gaps = sorted(b - a for a, b in zip(ts, ts[1:]) if b > a)
        if not gaps:
            continue
        period = gaps[len(gaps) // 2]
        for i in idxs:
            t = get_time(out[i][1])
            d = (_stable(ctx["seed"], "jitter100", i) % (2 * period + 1)) - period
            if d and set_time(out[i][1], t + d):
                changed += 1
    return out, changed


def _duplicate(payloads, ctx):
    out: list = []
    for spec, p in payloads:
        out.append((spec, p))
        out.append((spec, copy.deepcopy(p)))
    return out, len(payloads)


def _reverse_arrival(payloads, ctx):
    """The whole stream ARRIVES backwards. Every event keeps its true
    timestamp; only delivery order changes. The bus is at-least-once and does
    not order across partitions, so the detector must be keyed on EVENT time,
    not arrival order. (This replaces an earlier ``swap_first_two_steps``
    variant that rewrote timestamps: that changed what the logs say happened,
    so failing it said nothing about the product.)"""
    return list(reversed(copy.deepcopy(payloads))), len(payloads)


def _shuffle_arrival(payloads, ctx):
    """Seeded shuffle of delivery order; timestamps untouched."""
    out = copy.deepcopy(payloads)
    Random(_stable(ctx["seed"], "shuffle")).shuffle(out)
    return out, len(out)


def _decoy(payloads, ctx):
    sdef = ctx["sdef"]
    if sdef is None or sdef.decoy is None:
        return payloads, 0
    extra = sdef.decoy(ctx["seed"])
    merged = list(payloads) + list(extra)
    merged.sort(key=lambda x: (get_time(x[1]) or 0))
    return merged, len(extra)


# (axis, variant) -> operator.  `drop_step:<label>` variants are generated per
# scenario from its own step list (see variants_for).
_STATIC: dict = {
    ("volume", "thin_25pct"):        _thin(lambda r: r % 4 != 3),
    ("volume", "thin_60pct"):        _thin(lambda r: r % 5 in (0, 2)),
    ("pacing", "stretch_2x"):        _stretch(2),
    ("pacing", "stretch_6x"):        _stretch(6),
    ("distribution", "ip_rotate_2"): _rotate_ip(2),
    ("distribution", "ip_rotate_all"): _rotate_ip(None),
    ("identity", "account_split_2"): _split_actor(2),
    ("timing", "shift_1h"):          _shift(3_600_000),
    ("timing", "jitter_900ms"):      _jitter(900),
    ("delivery", "duplicate_all"):   _duplicate,
    ("delivery", "reverse_arrival"): _reverse_arrival,
    ("delivery", "shuffle_arrival"): _shuffle_arrival,
    ("noise", "benign_decoys"):      _decoy,
    # 2026-10-03 (wave 2): the variants the six new storylines need
    ("timing", "to_business_hours"): _to_clock(10, 30, weekday_only=True),
    ("timing", "to_night"):          _to_clock(3, 0, weekday_only=False),
    ("pacing", "jitter_100pct"):     _jitter_period,
    ("distribution", "hostname_rotate_all"): _rotate_hostname,
}


def variants_for(sdef) -> list:
    """The full deterministic variant list for one storyline: the static
    structure-level variants plus a ``loss/drop_<step>`` for every attack step
    (a log source going dark, one step at a time)."""
    out = [(ax, v) for (ax, v) in _STATIC]
    out += [("loss", f"drop_{s.label}") for s in sdef.steps]
    return out


def apply(payloads: list, axis: str, variant: str, *, seed: int, sdef) -> tuple:
    """Apply one variant. Returns ``(mutated_payloads, changed_event_count)``.
    Never mutates ``payloads`` in place."""
    ctx = {"seed": seed, "attack_steps": {s.label for s in sdef.steps}, "sdef": sdef}
    base = copy.deepcopy(payloads)
    if axis == "loss" and variant.startswith("drop_"):
        return _drop_step(variant[len("drop_"):])(base, ctx)
    return _STATIC[(axis, variant)](base, ctx)
