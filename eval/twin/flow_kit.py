"""flow_kit -- raw Suricata EVE / Zeek JSON record generators for the ``storyline_flow_*.py`` twins.

Not itself a storyline (its name does not match the registry's ``storyline_*.py`` glob). Pure functions of
their arguments plus a seeded ``random.Random``: no wall clock, no I/O.

WHY IT EXISTS (ADR-012 section 3, WP 7, basis ``network_flow``). The twin must know which steps share ONE network
flow BY CONSTRUCTION, independently of the code that will later extract the key. So this module:

  * writes the records in the sensors' own native shapes (an EVE JSON line, a Zeek JSON row) and mints the
    flow identifiers itself (``flow_id``: a 16-digit integer; ``uid``: ``C`` + 17 base62 characters, the shape in
    ``parsers/test_fixtures/zeek_json_real.json``);
  * remembers, per emitted record, ``(step, namespace, scope, key, time)`` in a ``FlowBook``: ``book.notes`` holds the
    TRIGGER records (the records the builder declares alert-raising: a severity-1 IDS alert, a 1 GiB+ flow record, the
    40th distinct name of a DNS burst) and ``book.context`` every other keyed record;
  * derives the oracle's ``causal_links`` from the trigger notes only (``derive_links``), never from the parsed events.
    ws4 builds an alert's causal keys from its trigger event ONLY, so a link between records that raise no alert is not
    gradable and is not truth. ``test_flow_storylines`` cross-checks every trigger declaration against the real
    detector's alerts.

It deliberately does NOT import ``services/shared/causal_keys.py`` or any WS-2/WS-4/WS-8 module, and it reads no
parsed event: truth (this file) and prediction (the future linker) share nothing but the raw record format, which
is the independence ADR-012 "Twin circularity" requires.

SCOPE (ADR-012 table). A Suricata ``flow_id`` is comparable only on ONE sensor; a Zeek ``uid`` only inside one
deployment. The book therefore records the scope with every key, ``derive_links`` never joins across scopes, and
each sensor ships under its own ``meta.shipper_ip`` (the authenticated-sender part of the future key hash).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from random import Random

from scenario_kit import meta

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASIS = "network_flow"


@dataclass(frozen=True)
class Sensor:
    """One network sensor. ``kind`` is ``suricata`` or ``zeek``; ``ip`` is its management address and becomes the
    envelope's ``meta.ip`` and ``meta.shipper_ip`` (distinct per sensor)."""

    name: str
    kind: str
    ip: str

    @property
    def source_type(self) -> str:
        return "suricata_eve" if self.kind == "suricata" else "zeek_json"

    @property
    def scope(self) -> str:
        # Suricata: tenant + sensor id. Zeek: one deployment (the sensor still ships under its own sender ip).
        return f"suricata:{self.name}" if self.kind == "suricata" else "zeek:deployment"


def _iso(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}+0000"


class FlowBook:
    """Collects payloads and the flow keys they carry for ONE storyline build."""

    def __init__(self, seed: int, tag: str, steps: tuple):
        self.seed, self.tag = seed, tag
        self._steps = {s.label: s for s in steps}
        self._rng = Random(seed * 104729 + sum(ord(c) * (i + 1) for i, c in enumerate(tag)))
        self._used: set = set()
        self._idx = 0
        self.payloads: list = []
        self.notes: list = []          # (step, namespace, scope, key, ts_ms): TRIGGER records only
        self.context: list = []        # same shape: keyed records the design says raise NO alert (context)

    # -- identifiers -------------------------------------------------------------------------------------------
    def flow_id(self) -> int:
        while True:
            v = self._rng.randrange(10 ** 15, 2 * 10 ** 15)
            if v not in self._used:
                self._used.add(v)
                return v

    def uid(self) -> str:
        while True:
            v = "C" + "".join(self._rng.choice(_B62) for _ in range(17))
            if v not in self._used:
                self._used.add(v)
                return v

    # -- emission ----------------------------------------------------------------------------------------------
    def _emit(self, step: str, source_type: str, raw, ts: int, ip: str, shipper: str | None = None) -> None:
        m = meta(self.seed, self.tag, self._idx, ts, ip)
        if shipper:
            m["shipper_ip"] = shipper
        self._idx += 1
        self.payloads.append((self._steps[step], {"source_type": source_type, "raw": raw, "meta": m}))

    def raw(self, step: str, source_type: str, raw, ts: int, ip: str) -> None:
        """A non-keyed record (an ASA line, an AD event, an sshd line) belonging to ``step``."""
        self._emit(step, source_type, raw, ts, ip)

    def _key(self, step: str, sensor: Sensor, key, ts: int, trigger: bool) -> None:
        """Record the key a raw record carries. ``trigger`` is the BUILDER's declaration that this record is an
        alert-raising (trigger) record of its step; only trigger records become truth endpoints (ADR-012: the alert
        carries the key of its trigger event ONLY). ``test_flow_storylines`` cross-checks every declaration against
        the alerts the real detector raises, so the flag is a claim under test, never an assumption."""
        (self.notes if trigger else self.context).append((step, BASIS, sensor.scope, str(key), ts))

    # -- Suricata EVE ------------------------------------------------------------------------------------------
    def eve_alert(self, step: str, sensor: Sensor, ts: int, flow_id: int, src: tuple, dst: tuple, *, signature: str,
                  sid: int, category: str, severity: int = 1, proto: str = "TCP", app_proto: str | None = None,
                  trigger: bool | None = None) -> None:
        """``trigger`` defaults to ``severity == 1``: ``common_ids_high_severity_alert`` passes exactly the signature
        severity-1 tier through (its own description), so a severity-1 alert record is a trigger record and a
        severity 2/3 one is context."""
        rec = {"timestamp": _iso(ts), "flow_id": flow_id, "in_iface": "eth1", "event_type": "alert",
               "src_ip": src[0], "src_port": src[1], "dest_ip": dst[0], "dest_port": dst[1], "proto": proto,
               "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 3, "signature": signature,
                         "category": category, "severity": severity}}
        if app_proto:
            rec["app_proto"] = app_proto
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), ts, sensor.ip, sensor.ip)
        self._key(step, sensor, flow_id, ts, severity == 1 if trigger is None else trigger)

    def eve_flow(self, step: str, sensor: Sensor, start_ms: int, end_ms: int, flow_id: int, src: tuple, dst: tuple,
                 *, proto: str = "TCP", app_proto: str | None = None, bytes_ts: int = 0, bytes_tc: int = 0,
                 alerted: bool = False, trigger: bool = False) -> None:
        """A flow record: Suricata writes it when the flow ENDS and the parser stamps it ``flow.end``."""
        age = max(0, (end_ms - start_ms) // 1000)
        rec = {"timestamp": _iso(end_ms + 1000), "flow_id": flow_id, "event_type": "flow",
               "src_ip": src[0], "src_port": src[1], "dest_ip": dst[0], "dest_port": dst[1], "proto": proto,
               "flow": {"pkts_toserver": 10 + bytes_ts // 1200, "pkts_toclient": 8 + bytes_tc // 1200,
                        "bytes_toserver": bytes_ts, "bytes_toclient": bytes_tc, "start": _iso(start_ms),
                        "end": _iso(end_ms), "age": age, "state": "closed", "reason": "timeout", "alerted": alerted}}
        if app_proto:
            rec["app_proto"] = app_proto
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), end_ms, sensor.ip, sensor.ip)
        self._key(step, sensor, flow_id, end_ms, trigger)

    def eve_dns(self, step: str, sensor: Sensor, ts: int, flow_id: int, src: tuple, dst: tuple, name: str, *,
                rrtype: str = "A", tx_id: int = 0, proto: str = "UDP", trigger: bool = False) -> None:
        rec = {"timestamp": _iso(ts), "flow_id": flow_id, "event_type": "dns", "src_ip": src[0], "src_port": src[1],
               "dest_ip": dst[0], "dest_port": dst[1], "proto": proto,
               "dns": {"version": 3, "type": "request", "tx_id": tx_id, "id": 1000 + tx_id, "rd": True,
                       "rrname": name, "rrtype": rrtype, "queries": [{"rrname": name, "rrtype": rrtype}]}}
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), ts, sensor.ip, sensor.ip)
        self._key(step, sensor, flow_id, ts, trigger)

    def eve_modbus(self, step: str, sensor: Sensor, ts: int, flow_id: int, src: tuple, dst: tuple, *, function_raw: int,
                   function_code: str, access_type: str, address: int, quantity: int | None = None,
                   unit_id: int = 1, tx: int = 1, trigger: bool = False) -> None:
        side: dict = {"transaction_id": tx, "protocol_id": 0, "unit_id": unit_id, "function_raw": function_raw,
                      "function_code": function_code, "access_type": access_type,
                      "write" if "WRITE" in access_type else "read":
                          ({"address": address, "data": 1} if "WRITE" in access_type
                           else {"address": address, "quantity": quantity or 1})}
        rec = {"timestamp": _iso(ts), "flow_id": flow_id, "event_type": "modbus", "src_ip": src[0],
               "src_port": src[1], "dest_ip": dst[0], "dest_port": dst[1], "proto": "TCP",
               "modbus": {"id": tx, "request": side}}
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), ts, sensor.ip, sensor.ip)
        self._key(step, sensor, flow_id, ts, trigger)

    # -- Zeek JSON ---------------------------------------------------------------------------------------------
    @staticmethod
    def _zeek_ids(uid: str, src: tuple, dst: tuple, proto: str) -> dict:
        return {"uid": uid, "id.orig_h": src[0], "id.orig_p": src[1], "id.resp_h": dst[0], "id.resp_p": dst[1],
                "proto": proto}

    def zeek_conn(self, step: str, sensor: Sensor, start_ms: int, duration_s: float, uid: str, src: tuple,
                  dst: tuple, *, proto: str = "tcp", service: str | None = None, state: str = "SF",
                  history: str = "ShADadFf", orig_bytes: int = 0, resp_bytes: int = 0, trigger: bool = False) -> None:
        """conn.log is written when the connection ENDS; the parser stamps it ``ts + duration``."""
        rec = {"ts": start_ms / 1000.0, **self._zeek_ids(uid, src, dst, proto), "duration": float(duration_s),
               "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, "conn_state": state, "history": history,
               "orig_pkts": 4 + orig_bytes // 1200, "resp_pkts": 3 + resp_bytes // 1200}
        if service:
            rec["service"] = service
        end_ms = start_ms + int(duration_s * 1000)
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), end_ms, sensor.ip, sensor.ip)
        self._key(step, sensor, uid, end_ms, trigger)

    def zeek_dns(self, step: str, sensor: Sensor, ts: int, uid: str, src: tuple, dst: tuple, name: str, *,
                 proto: str = "udp", qtype: str = "A", trans_id: int = 1, trigger: bool = False) -> None:
        rec = {"ts": ts / 1000.0, **self._zeek_ids(uid, src, dst, proto), "trans_id": trans_id, "query": name,
               "qclass": 1, "qclass_name": "C_INTERNET", "qtype": 1 if qtype == "A" else 16, "qtype_name": qtype,
               "rcode": 0, "rcode_name": "NOERROR", "answers": ["192.0.2.53"], "rejected": False}
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), ts, sensor.ip, sensor.ip)
        self._key(step, sensor, uid, ts, trigger)

    def zeek_modbus(self, step: str, sensor: Sensor, ts: int, uid: str, src: tuple, dst: tuple, *, func: str,
                    unit: int = 1, pdu_type: str = "REQ", tid: int = 1, address: int | None = None,
                    trigger: bool = False) -> None:
        rec = {"ts": ts / 1000.0, **self._zeek_ids(uid, src, dst, "tcp"), "tid": tid, "unit": unit, "func": func,
               "pdu_type": pdu_type}
        if address is not None:
            rec["address"] = address
        self._emit(step, sensor.source_type, json.dumps(rec, sort_keys=True), ts, sensor.ip, sensor.ip)
        self._key(step, sensor, uid, ts, trigger)


# ---------------------------------------------------------------------------------------------------------------
# Truth derivation (from the book only)
# ---------------------------------------------------------------------------------------------------------------
def derive_links(notes: list, step_order: list) -> list:
    """``[{from, to, basis}]`` from the keys the BUILDER minted.

    Records are grouped by ``(namespace, scope, key)``. Inside a group the distinct steps are ordered by the time
    of their first record in the group (ties by ``step_order``) and joined through their time-ordered
    neighbours: a group over n steps yields n-1 links, never a clique (ADR-012 rule 3). Two groups that happen to
    carry the SAME key value under DIFFERENT scopes are different groups and never link. Output is sorted and
    de-duplicated, so it is a pure function of ``(notes, step_order)``."""
    rank = {s: i for i, s in enumerate(step_order)}
    groups: dict = {}
    for step, ns, scope, key, ts in notes:
        first = groups.setdefault((ns, scope, key), {})
        first[step] = min(ts, first.get(step, ts))
    links: set = set()
    for (ns, _scope, _key), first in groups.items():
        ordered = sorted(first, key=lambda s: (first[s], rank.get(s, 10 ** 6)))
        for a, b in zip(ordered, ordered[1:]):
            links.add((a, b, ns))
    return [{"from": a, "to": b, "basis": ns} for a, b, ns in sorted(links, key=lambda t: (rank.get(t[0], 10 ** 6),
                                                                                           rank.get(t[1], 10 ** 6)))]


def key_groups(notes: list) -> dict:
    """``{(namespace, scope, key): {step, ...}}`` -- the candidate-link groups, for the measurement report."""
    out: dict = {}
    for step, ns, scope, key, _ts in notes:
        out.setdefault((ns, scope, key), set()).add(step)
    return out


def candidate_pairs(notes: list) -> int:
    """Event-level key-sharing record pairs on the neighbour chain: per group, (records - 1)."""
    counts: dict = {}
    for _step, ns, scope, key, _ts in notes:
        counts[(ns, scope, key)] = counts.get((ns, scope, key), 0) + 1
    return sum(n - 1 for n in counts.values() if n > 1)
