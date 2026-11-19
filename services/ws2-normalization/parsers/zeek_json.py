"""Zeek JSON logs -> OCSF (conn, dns, notice, modbus / ICSNPP modbus_detailed).

FENGARDE does not capture packets. This parser normalises the logs of a tool that does: Zeek with
``LogAscii::use_json=T`` (one JSON object per line per log stream). Fixture and field coverage:
``parsers/test_fixtures/zeek_json_real.json`` (a real Zeek 9.0.1 run on public pcaps, provenance in its header) and
``parsers/test_suricata_zeek.py`` (reports which Zeek fields are mapped and which are dropped).

A Zeek JSON line does not name its log stream, so the stream is recognised by field shape (all four are disjoint):

    notice.log           has ``note``                              -> 4001 / 99 (Other), severity Low
    dns.log              has ``query`` / ``trans_id`` / ``qtype_name`` -> 4002 / 1 (query; carries the answers too)
    modbus.log           has ``func`` + ``unit`` + ``pdu_type``    -> 4001 / 99, unmapped.ot.* (sector datacenter)
    modbus_detailed.log  has ``func`` + ``unit``, no ``pdu_type``  -> same (CISA ICSNPP ``icsnpp-modbus`` package)
    conn.log             has ``conn_state`` / ``history``          -> 4001 / 2 (Close; conn.log is written at end)

conn_state is NEVER mapped to Deny (activity 6), by owner decision 2026-11-13 on real evidence (Zeek 9.0.1 in Docker, 26 conn rows):
REJ means only "the target answered with an RST" (a closed port and a firewall REJECT-with-tcp-reset give byte-identical rows) and
S0 means only "no reply was seen" (a firewall DROP, an ICMP-reject, a closed UDP port and a dead host look the same). The raw state
stays in ``unmapped.zeek.conn.conn_state``. The deny-counting rules (common_port_scan, common_port_scan_by_target, common_port_sweep)
therefore do not fire on Zeek-only data; a rule on conn_state REJ/S0 would be the honest way to get that signal.

Event time: ``ts`` is the time of the connection's FIRST packet, but conn.log is written at the end, so the Close event is
stamped ``ts + duration`` (a 7200 s connection is no longer placed two hours early; with no ``duration`` it stays ``ts``).
dns/notice/modbus rows keep ``ts``, the time of that message.

Minimum Zeek: the ``unit`` and ``pdu_type`` columns that Modbus recognition relies on arrived in Zeek 5.1.0 (NEWS under
5.1.0, zeek/zeek PR 2281, July 2022); older releases write modbus.log lines with no ``unit``, which are dropped. One Modbus
transaction yields up to three events: modbus.log writes a REQ row and a RESP row and, with the ICSNPP package,
modbus_detailed.log adds a row of its own; each is a separate log line, hence a separate event.

Activity ids beyond ocsf-classes.md are project-local. 99 (Other) is used where no Deny (6) / Accept (7) verdict exists,
because common_port_scan* and common_beaconing key on those; a Modbus transaction or a notice is neither. This parser
never sets ``unmapped.ot.anomaly_type`` (modbus_anomaly.py's own classification, which ot_modbus_unauthorized_write
keys on) -- it makes no judgement of its own. Every other Zeek stream (http, ssl, files, weird, ...) is dropped
(returns None); its fields are not mapped.
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .base import Parser, SEV_INFO, SEV_LOW
from .dns_query import parent_domain
from .timeutil import to_epoch_ms
from ._netjson import (drop_none, endpoint, envelope_meta, integer, load_record, number, sector, strings,
                       text)

_NET, _DNS = 4001, 4002
_CLOSE, _OTHER = 2, 99
_MAX_DURATION_S = 10 * 366 * 86400  # a longer "connection" is not trusted to move the event time

# Zeek's Modbus::function_codes (scripts/base/protocols/modbus/consts.zeek, master): the 20 standard codes (incl. 0x5B
# OBJECT_MESSAGING) and the 12 machine/vendor ones. The log name is that table's value; for an exception response Zeek
# appends ``_EXCEPTION`` (stripped first). A code outside the table is logged as ``unknown-N`` (N may include the 0x80
# exception bit), handled in _function_code().
_MODBUS_CODES = {
    "READ_COILS": 0x01, "READ_DISCRETE_INPUTS": 0x02, "READ_HOLDING_REGISTERS": 0x03, "READ_INPUT_REGISTERS": 0x04,
    "WRITE_SINGLE_COIL": 0x05, "WRITE_SINGLE_REGISTER": 0x06, "READ_EXCEPTION_STATUS": 0x07, "DIAGNOSTICS": 0x08,
    "GET_COMM_EVENT_COUNTER": 0x0B, "GET_COMM_EVENT_LOG": 0x0C, "WRITE_MULTIPLE_COILS": 0x0F,
    "WRITE_MULTIPLE_REGISTERS": 0x10, "REPORT_SLAVE_ID": 0x11, "READ_FILE_RECORD": 0x14, "WRITE_FILE_RECORD": 0x15,
    "MASK_WRITE_REGISTER": 0x16, "READ_WRITE_MULTIPLE_REGISTERS": 0x17, "READ_FIFO_QUEUE": 0x18,
    "ENCAP_INTERFACE_TRANSPORT": 0x2B, "OBJECT_MESSAGING": 0x5B,
    "PROGRAM_484": 0x09, "POLL_484": 0x0A, "PROGRAM_584_984": 0x0D, "POLL_584_984": 0x0E, "PROGRAM_884_U84": 0x12,
    "RESET_COMM_LINK_884_U84": 0x13, "PROGRAM_CONCEPT": 0x28, "MULTIPLE_FUNCTION_CODES": 0x29, "PROGRAM_UNITY": 0x5A,
    "FIRMWARE_REPLACEMENT": 0x7D, "PROGRAM_584_984_2": 0x7E, "REPORT_LOCAL_ADDRESS": 0x7F,
}
_UNKNOWN_FUNC = re.compile(r"unknown-(\d{1,3})")


def _function_code(func: str) -> Optional[int]:
    base = func[:-len("_EXCEPTION")] if func.endswith("_EXCEPTION") else func
    if base in _MODBUS_CODES:
        return _MODBUS_CODES[base]
    m = _UNKNOWN_FUNC.fullmatch(func)
    return int(m.group(1)) & 0x7F if m and int(m.group(1)) <= 0xFF else None  # 0x80 is the exception flag, not a code


class ZeekJsonParser(Parser):
    SOURCE_TYPE = "zeek_json"
    SECTOR = "common"
    ORIGINAL_FORMAT = "json"
    PRODUCT = {"name": "Zeek", "vendor_name": "The Zeek Project"}

    def parse(self, raw: dict) -> Optional[dict]:
        if not isinstance(raw, dict):
            return None
        rec = load_record(raw.get("raw"))
        if rec is None:
            return None
        if "note" in rec:
            built = self._notice(rec)
        elif "query" in rec or "trans_id" in rec or "qtype_name" in rec:
            built = self._dns_log(rec)
        elif "func" in rec and "unit" in rec:
            built = self._modbus(rec)
        elif "conn_state" in rec or "history" in rec:
            built = self._conn(rec)
        else:
            return None
        if built is None:
            return None
        class_uid, activity, severity, message, extra, ot, src, dst = built
        meta = envelope_meta(raw)
        event = self.base_event(
            class_uid=class_uid, activity_id=activity, severity_id=severity,
            time_ms=self._time_ms(rec, meta, activity == _CLOSE), ingest_id=meta.get("ingest_id"),
            message=message, meta=meta, sector=sector(meta, "datacenter" if ot else self.SECTOR))
        if src:
            event["src_endpoint"] = src
        if "hostname" in extra:  # dns: the queried name is the destination, as in dns_query.py
            dst = dict(dst or {}, hostname=extra.pop("hostname"))
        if dst:
            event["dst_endpoint"] = dst
        event["unmapped"] = extra
        return event

    # Each record kind returns (class, activity, severity, message, unmapped, is_ot, src_endpoint, dst_endpoint) or None.

    @staticmethod
    def _conn_endpoints(rec: dict):
        return (endpoint(rec.get("id.orig_h"), rec.get("id.orig_p")),
                endpoint(rec.get("id.resp_h"), rec.get("id.resp_p")))

    @classmethod
    def _conn(cls, rec: dict):
        conn = drop_none({
            "uid": text(rec.get("uid"), 64), "proto": text(rec.get("proto"), 16), "service": text(rec.get("service"), 64),
            "conn_state": text(rec.get("conn_state"), 16), "history": text(rec.get("history"), 64),
            "duration_seconds": number(rec.get("duration")),
            "orig_bytes": integer(rec.get("orig_bytes")), "resp_bytes": integer(rec.get("resp_bytes")),
            "orig_pkts": integer(rec.get("orig_pkts")), "resp_pkts": integer(rec.get("resp_pkts")),
            "missed_bytes": integer(rec.get("missed_bytes")), "local_orig": _bool(rec.get("local_orig")),
            "local_resp": _bool(rec.get("local_resp"))})
        src, dst = cls._conn_endpoints(rec)
        msg = f"Zeek conn {conn.get('proto', '?')} {conn.get('service', '')} {conn.get('conn_state', '')}".strip()
        return _NET, _CLOSE, SEV_INFO, msg, {"zeek": {"conn": conn}}, False, src, dst

    @classmethod
    def _dns_log(cls, rec: dict):
        name = (text(rec.get("query")) or "").rstrip(".")
        if not name:
            return None
        dns = drop_none({
            "qtype": text(rec.get("qtype_name"), 16), "rcode": text(rec.get("rcode_name"), 32),
            "answers": strings(rec.get("answers")), "parent_domain": parent_domain(name),
            "tx_id": integer(rec.get("trans_id")), "uid": text(rec.get("uid"), 64)})
        src, dst = cls._conn_endpoints(rec)
        return (_DNS, 1, SEV_INFO, f"DNS query {dns.get('qtype', '?')} {name}",
                {"hostname": name, "dns": dns}, False, src, dst)

    @classmethod
    def _notice(cls, rec: dict):
        note = text(rec.get("note"), 128)
        if note is None:
            return None
        src, dst = cls._conn_endpoints(rec)
        if src is None and dst is None:  # notices may carry bare src/dst/p instead of a connection id
            src = endpoint(rec.get("src"), None)
            dst = endpoint(rec.get("dst"), rec.get("p"))
        zeek = drop_none({"note": note, "sub": text(rec.get("sub")), "uid": text(rec.get("uid"), 64),
                          "suppress_for_seconds": number(rec.get("suppress_for"))})
        msg = f"Zeek notice {note}" + (f": {text(rec.get('msg'))}" if text(rec.get("msg")) else "")
        return _NET, _OTHER, SEV_LOW, msg, {"zeek": {"notice": zeek}}, False, src, dst

    @classmethod
    def _modbus(cls, rec: dict):
        func = text(rec.get("func"), 64)
        if func is None:
            return None
        # modbus_detailed.log names the failure ``exception_code``; modbus.log names it ``exception``.
        exc = text(rec.get("exception")) or text(rec.get("exception_code"))
        ot = drop_none({
            "protocol": "modbus_tcp", "function_code": _function_code(func), "function_name": func,
            "unit_id": integer(rec.get("unit")), "transaction_id": integer(rec.get("tid")),
            "pdu_type": text(rec.get("pdu_type"), 8), "address": integer(rec.get("address")),
            "quantity": integer(rec.get("quantity")), "exception_name": exc,
            "subfunction": text(rec.get("request_subfunction_code"), 64)})
        src, dst = cls._conn_endpoints(rec)
        return (_NET, _OTHER, SEV_INFO, f"Modbus/TCP {func} unit {ot.get('unit_id', '?')}", {"ot": ot}, True, src, dst)

    @staticmethod
    def _time_ms(rec: dict, meta: dict, closing: bool) -> int:
        start = to_epoch_ms(rec.get("ts"))
        d = number(rec.get("duration")) if closing else None
        if start and d is not None and 0 <= d <= _MAX_DURATION_S:  # a hostile 1e300 duration keeps the start time
            start += int(d * 1000)
        return start or to_epoch_ms(meta.get("received_at")) or int(time.time() * 1000)


def _bool(v) -> Optional[bool]:
    return v if isinstance(v, bool) else None
