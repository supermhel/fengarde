"""Suricata EVE JSON -> OCSF (alert, flow, dns, modbus, dnp3).

FENGARDE does not capture packets. This parser normalises the log of a tool that does: Suricata's ``eve.json``
(one JSON object per line, ``event_type`` names the record kind). Fixture and field coverage:
``parsers/test_fixtures/suricata_eve_real.json`` (a real Suricata 8.0.8 run on a public pcap, provenance in its header)
and ``parsers/test_suricata_zeek.py`` (reports which EVE fields are mapped and which are dropped).

Mapping (class / activity; activity ids beyond ocsf-classes.md are project-local, like the other 4001/4002 producers):

    alert   -> 4001 / 99 (Other)   an IDS signature match is not a connection verdict, so it must NOT be a Deny (6) or
                                   Accept (7): common_port_scan* and common_beaconing key on those. unmapped.ids.*
    flow    -> 4001 / 2  (Close)   Suricata logs a flow record when the flow ends. unmapped.suricata.flow.*
    dns     -> 4002 / 1  (query)   a ``request``: feeds common_dns_exfil / common_dns_tunnel_by_domain through
                                   dst_endpoint.hostname and unmapped.dns.parent_domain, like dns_query.py
               4002 / 2  (response) a ``response`` (``answer`` in EVE DNS v2): no rule counts these, so a lookup is not counted twice
    modbus  -> 4001 / 99           unmapped.ot.{protocol, function_code, unit_id, address, ...}; sector datacenter
    dnp3    -> 4001 / 99           unmapped.ot.{protocol, function_code, ...}; sector datacenter

Modbus/DNP3 events deliberately never set ``unmapped.ot.anomaly_type``: that is modbus_anomaly.py's own classification
(ot_modbus_unauthorized_write keys on it) and this parser makes no judgement of its own. Every other EVE ``event_type``
(stats, anomaly, http, tls, ...) is dropped (returns None); its fields are not mapped.
"""
from __future__ import annotations

import time
from typing import Optional

from .base import Parser, SEV_HIGH, SEV_INFO, SEV_LOW, SEV_MEDIUM
from .dns_query import parent_domain
from .timeutil import to_epoch_ms
from ._netjson import drop_none, endpoint, envelope_meta, integer, load_record, sector, strings, text

_NET, _DNS = 4001, 4002
_CLOSE, _OTHER = 2, 99
_SEVERITY = {1: SEV_HIGH, 2: SEV_MEDIUM, 3: SEV_LOW}  # Suricata: 1 is the most severe


def _d(v) -> dict:
    return v if isinstance(v, dict) else {}


class SuricataEveParser(Parser):
    SOURCE_TYPE = "suricata_eve"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Suricata", "vendor_name": "OISF"}

    def parse(self, raw: dict) -> Optional[dict]:
        if not isinstance(raw, dict):
            return None
        rec = load_record(raw.get("raw"))
        if rec is None:
            return None
        et = rec.get("event_type")
        handler = {"alert": self._alert, "flow": self._flow, "dns": self._dns, "modbus": self._modbus,
                   "dnp3": self._dnp3}.get(et) if isinstance(et, str) else None
        if handler is None:
            return None
        built = handler(rec)
        if built is None:
            return None
        class_uid, activity, severity, message, extra, ot = built
        meta = envelope_meta(raw)
        event = self.base_event(
            class_uid=class_uid, activity_id=activity, severity_id=severity,
            time_ms=self._time_ms(rec, meta), ingest_id=meta.get("ingest_id"),
            message=message, meta=meta, sector=sector(meta, "datacenter" if ot else self.SECTOR))
        src = endpoint(rec.get("src_ip"), rec.get("src_port"))
        dst = endpoint(rec.get("dest_ip"), rec.get("dest_port"))
        if src:
            event["src_endpoint"] = src
        if "hostname" in extra:  # dns: the queried name is the destination, as in dns_query.py
            dst = dict(dst or {}, hostname=extra.pop("hostname"))
        if dst:
            event["dst_endpoint"] = dst
        event["unmapped"] = extra
        return event

    # Each record kind returns (class, activity, severity, message, unmapped, is_ot) or None.

    @staticmethod
    def _alert(rec: dict):
        a = _d(rec.get("alert"))
        sig = text(a.get("signature"))
        if sig is None:
            return None
        sev = integer(a.get("severity"))
        ids = drop_none({
            "engine": "suricata", "signature": sig, "signature_id": integer(a.get("signature_id")),
            "gid": integer(a.get("gid")), "rev": integer(a.get("rev")), "category": text(a.get("category")),
            "severity": sev, "action": text(a.get("action")), "app_proto": text(rec.get("app_proto")),
            "proto": text(rec.get("proto")), "flow_id": integer(rec.get("flow_id"))})
        return _NET, _OTHER, (SEV_INFO if sev is None else _SEVERITY.get(sev, SEV_INFO)), f"Suricata alert: {sig}", {"ids": ids}, False

    @staticmethod
    def _flow(rec: dict):
        f = _d(rec.get("flow"))
        flow = drop_none({
            "proto": text(rec.get("proto")), "app_proto": text(rec.get("app_proto")), "state": text(f.get("state")),
            "reason": text(f.get("reason")),
            "alerted": f.get("alerted") if isinstance(f.get("alerted"), bool) else None,
            "pkts_toserver": integer(f.get("pkts_toserver")), "pkts_toclient": integer(f.get("pkts_toclient")),
            "bytes_toserver": integer(f.get("bytes_toserver")), "bytes_toclient": integer(f.get("bytes_toclient")),
            "age_seconds": integer(f.get("age")), "flow_id": integer(rec.get("flow_id"))})
        msg = f"Suricata flow {flow.get('proto', '?')} closed"
        return _NET, _CLOSE, SEV_INFO, msg, {"suricata": {"flow": flow}}, False

    @staticmethod
    def _dns(rec: dict):
        d = _d(rec.get("dns"))
        kind = d.get("type")
        if kind not in ("request", "response", "answer"):  # v3 says "response"; v2 said "answer"
            return None
        # EVE DNS v3: queries[]; v1/v2 (flat): rrname/rrtype on the dns object itself.
        raw_q = d.get("queries")
        queries = raw_q if isinstance(raw_q, list) else []
        q = _d(queries[0]) if queries else d
        name = (text(q.get("rrname")) or "").rstrip(".")
        if not name:
            return None
        raw_a = d.get("answers")
        answers = raw_a if isinstance(raw_a, list) else []
        dns = drop_none({
            "qtype": text(q.get("rrtype"), 16), "rcode": text(d.get("rcode"), 32), "query_count": len(queries) or None,
            "answers": [s for s in (text(_d(x).get("rdata")) for x in answers[:16]) if s],
            "parent_domain": parent_domain(name), "tx_id": integer(d.get("tx_id"))})
        activity = 1 if kind == "request" else 2
        return (_DNS, activity, SEV_INFO, f"DNS {kind} {dns.get('qtype', '?')} {name}",
                {"hostname": name, "dns": dns}, False)

    @staticmethod
    def _modbus(rec: dict):
        m = _d(rec.get("modbus"))
        req, resp = _d(m.get("request")), _d(m.get("response"))
        side = req or resp
        if not side:
            return None
        code = integer(side.get("function_raw"))
        if code is not None and not req:
            code &= 0x7F  # a lone exception response carries function | 0x80
        body = next((_d(side.get(k)) for k in ("read", "write")
                     if integer(_d(side.get(k)).get("address")) is not None), {})
        exc = _d(resp.get("exception"))
        ot = drop_none({
            "protocol": "modbus_tcp", "function_code": code, "function_name": text(side.get("function_code"), 64),
            "unit_id": integer(side.get("unit_id")), "transaction_id": integer(side.get("transaction_id")),
            "access_type": text(side.get("access_type"), 64), "address": integer(body.get("address")),
            "quantity": integer(body.get("quantity")), "exception_code": integer(exc.get("raw")),
            "exception_name": text(exc.get("code"), 64)})
        return (_NET, _OTHER, SEV_INFO,
                f"Modbus/TCP {ot.get('function_name', 'function ' + str(code))} unit {ot.get('unit_id', '?')}",
                {"ot": ot}, True)

    @staticmethod
    def _dnp3(rec: dict):
        n = _d(rec.get("dnp3"))
        app = _d(n.get("application"))
        objects = app.get("objects")
        ot = drop_none({
            "protocol": "dnp3", "message_type": text(n.get("type"), 32),
            "function_code": integer(app.get("function_code")),
            "link_function_code": integer(_d(n.get("control")).get("function_code")),
            "source_address": integer(n.get("src")), "dest_address": integer(n.get("dst")),
            "iin": strings(_d(n.get("iin")).get("indicators")),
            "object_count": len(objects) if isinstance(objects, list) else None})
        if "function_code" not in ot and "message_type" not in ot:
            return None
        return (_NET, _OTHER, SEV_INFO,
                f"DNP3 {ot.get('message_type', 'message')} function {ot.get('function_code', '?')}", {"ot": ot}, True)

    @staticmethod
    def _time_ms(rec: dict, meta: dict) -> int:
        return (to_epoch_ms(rec.get("timestamp")) or to_epoch_ms(meta.get("received_at"))
                or int(time.time() * 1000))
