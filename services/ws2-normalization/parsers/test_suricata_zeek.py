"""Tests for the suricata_eve and zeek_json parsers (WP-1.5).

The fixtures are REAL sensor output: ``test_fixtures/suricata_eve_real.json`` (Suricata 8.0.8) and
``test_fixtures/zeek_json_real.json`` (Zeek 9.0.1 + ICSNPP modbus), each run on a public pcap; the provenance block at the
top of each file records pcap source, licence, image digest and command. Nothing in them is hand-written.

Besides the mapping assertions this prints a FIELD COVERAGE report: every leaf field of every fixture record is mutated
in turn and the parser output compared -- a field whose mutation changes nothing is not read by the parser (dropped).

Run with:
    python services/ws2-normalization/parsers/test_suricata_zeek.py
"""
from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers import get_parser, resolve  # noqa: E402
from parsers.timeutil import to_epoch_ms  # noqa: E402

FIX = HERE / "test_fixtures"
SURI = json.loads((FIX / "suricata_eve_real.json").read_text(encoding="utf-8"))
ZEEK = json.loads((FIX / "zeek_json_real.json").read_text(encoding="utf-8"))
META = {"ingest_id": "fixture", "trace_id": "t-fixed", "tenant_id": "default", "received_at": 1_700_000_000}
SURICATA, ZEEKP = get_parser("suricata_eve"), get_parser("zeek_json")


def _raw(source_type, rec, as_line=False):
    return {"source_type": source_type, "raw": json.dumps(rec) if as_line else rec, "meta": dict(META)}


def _find(fix, pred):
    return next(r["record"] for r in fix["records"] if pred(r))


def _suri(rec_or_pred):
    return SURICATA.parse(_raw("suricata_eve", _find(SURI, rec_or_pred)))


def _zeek(pred):
    return ZEEKP.parse(_raw("zeek_json", _find(ZEEK, pred)))


class TestProvenance(unittest.TestCase):
    def test_fixture_headers_name_pcap_licence_and_image(self):
        for fix in (SURI, ZEEK):
            p = fix["provenance"]
            self.assertIn("REAL", p["kind"])
            self.assertIn("MIT", p["pcap_source_and_licence"])
            self.assertTrue(p["image"].split("@sha256:")[1])
            for name, pc in p["pcaps"].items():
                self.assertEqual(len(pc["sha256"]), 64, name)
                self.assertTrue(pc["url"].startswith("https://"), name)


class TestFixtureRecords(unittest.TestCase):
    """Every fixture record: valid OCSF, derived type_uid, same result from a dict and from a JSON line."""

    def _each(self, source_type, parser, fix):
        mapped = dropped = 0
        for item in fix["records"]:
            ev = parser.parse(_raw(source_type, item["record"]))
            line_ev = parser.parse(_raw(source_type, item["record"], as_line=True))
            self.assertEqual(ev, line_ev)
            if ev is None:
                dropped += 1
                continue
            mapped += 1
            self.assertEqual(validate(ev), [], item["record"])
            self.assertEqual(ev["type_uid"], ev["class_uid"] * 100 + ev["activity_id"])
            self.assertEqual(ev["category_uid"], ev["class_uid"] // 1000)
            self.assertEqual(ev["siem"]["source_type"], source_type)
            self.assertNotEqual(ev["time"], META["received_at"] * 1000, "event time must come from the record")
            # No existing rule may consume these as a connection verdict/auth/OT-anomaly event.
            self.assertNotIn((ev["class_uid"], ev["activity_id"]), {(4001, 6), (4001, 7), (4001, 1)})
            self.assertNotIn("anomaly_type", (ev.get("unmapped") or {}).get("ot", {}))
        self.assertGreater(mapped, 8)
        self.assertGreaterEqual(dropped, 1, "fixture must include a record the parser drops")

    def test_suricata_records(self):
        self._each("suricata_eve", SURICATA, SURI)

    def test_zeek_records(self):
        self._each("zeek_json", ZEEKP, ZEEK)


class TestSuricataMapping(unittest.TestCase):
    def test_alert(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "alert" and r["record"].get("app_proto") == "dns")
        self.assertEqual((ev["class_uid"], ev["activity_id"], ev["type_uid"]), (4001, 99, 400199))
        self.assertEqual(ev["severity_id"], 2)  # Suricata severity 3 -> Low
        self.assertEqual(ev["unmapped"]["ids"]["signature_id"], 9900001)
        self.assertEqual(ev["src_endpoint"]["ip"], "10.16.1.11")
        self.assertEqual(ev["dst_endpoint"]["port"], 53)
        self.assertEqual(ev["siem"]["sector"], "common")

    def test_dns_request_feeds_dns_rules(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "dns" and r["record"]["dns"]["type"] == "request")
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4002, 1))
        self.assertIn("hostname", ev["dst_endpoint"])
        self.assertEqual(ev["unmapped"]["dns"]["parent_domain"], ".".join(ev["dst_endpoint"]["hostname"].split(".")[-2:]))

    def test_dns_response_is_not_a_second_query(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "dns" and r["record"]["dns"]["type"] == "response")
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4002, 2))
        self.assertTrue(ev["unmapped"]["dns"]["answers"])

    def test_flow_is_close(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "flow")
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4001, 2))
        self.assertIn("pkts_toserver", ev["unmapped"]["suricata"]["flow"])

    def test_modbus_write_and_exception(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "modbus"
                   and r["record"]["modbus"]["request"]["function_code"] == "WrSingleCoil")
        ot = ev["unmapped"]["ot"]
        self.assertEqual((ot["protocol"], ot["function_code"], ot["unit_id"], ot["address"]), ("modbus_tcp", 5, 10, 2))
        self.assertEqual(ev["siem"]["sector"], "datacenter")
        exc = _suri(lambda r: r["record"]["event_type"] == "modbus" and "exception" in r["record"]["modbus"]["response"])
        self.assertEqual(exc["unmapped"]["ot"]["exception_code"], 11)
        self.assertEqual(exc["unmapped"]["ot"]["function_code"], 8)

    def test_dnp3(self):
        ev = _suri(lambda r: r["record"]["event_type"] == "dnp3" and r["record"]["dnp3"]["type"] == "request")
        ot = ev["unmapped"]["ot"]
        self.assertEqual((ot["protocol"], ot["function_code"], ot["message_type"]), ("dnp3", 21, "request"))
        self.assertEqual(ev["siem"]["sector"], "datacenter")
        self.assertEqual(ev["dst_endpoint"]["port"], 20000)

    def test_meta_sector_override_and_junk_override(self):
        rec = _find(SURI, lambda r: r["record"]["event_type"] == "dnp3")
        ok = SURICATA.parse({"source_type": "suricata_eve", "raw": rec, "meta": {"sector": "bank"}})
        bad = SURICATA.parse({"source_type": "suricata_eve", "raw": rec, "meta": {"sector": "nonsense"}})
        self.assertEqual((ok["siem"]["sector"], bad["siem"]["sector"]), ("bank", "datacenter"))


class TestZeekMapping(unittest.TestCase):
    def test_conn(self):
        ev = _zeek(lambda r: r["log"] == "conn.log" and r["record"].get("service") == "modbus")
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4001, 2))
        self.assertEqual(ev["dst_endpoint"], {"ip": "10.0.0.8", "port": 502})
        self.assertEqual(ev["unmapped"]["zeek"]["conn"]["conn_state"], "SF")

    def test_dns(self):
        ev = _zeek(lambda r: r["log"] == "dns.log")
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4002, 1))
        self.assertEqual(ev["dst_endpoint"]["hostname"], "client-cf.dropbox.com")
        self.assertEqual(ev["unmapped"]["dns"]["parent_domain"], "dropbox.com")
        self.assertEqual(ev["src_endpoint"]["ip"], "10.16.1.11")

    def test_notice(self):
        ev = _zeek(lambda r: r["log"] == "notice.log")
        self.assertEqual((ev["class_uid"], ev["activity_id"], ev["severity_id"]), (4001, 99, 2))
        self.assertEqual(ev["unmapped"]["zeek"]["notice"]["note"], "CaptureLoss::Too_Little_Traffic")
        self.assertIn("Too_Little_Traffic", ev["message"])

    def test_modbus_and_icsnpp_detailed(self):
        w = _zeek(lambda r: r["log"] == "modbus.log" and r["record"]["func"] == "WRITE_SINGLE_COIL")
        self.assertEqual(w["unmapped"]["ot"]["function_code"], 5)
        self.assertEqual(w["unmapped"]["ot"]["pdu_type"], "REQ")
        d = _zeek(lambda r: r["log"] == "modbus_detailed.log" and r["record"]["func"] == "WRITE_SINGLE_COIL")
        self.assertEqual((d["unmapped"]["ot"]["address"], d["unmapped"]["ot"]["quantity"]), (2, 1))
        exc = _zeek(lambda r: r["log"] == "modbus.log" and "exception" in r["record"])
        self.assertTrue(exc["unmapped"]["ot"]["exception_name"])
        self.assertEqual(exc["unmapped"]["ot"]["function_code"], 8)  # DIAGNOSTICS_EXCEPTION -> 8
        self.assertEqual(d["siem"]["sector"], "datacenter")


class TestRouting(unittest.TestCase):
    def test_source_type_is_authoritative_and_content_sniff_finds_them(self):
        s = _find(SURI, lambda r: r["record"]["event_type"] == "flow")
        z = _find(ZEEK, lambda r: r["log"] == "conn.log")
        self.assertIs(resolve({"source_type": "suricata_eve", "raw": s}), SURICATA)
        self.assertIs(resolve({"source_type": "zeek_json", "raw": z}), ZEEKP)
        # no source_type: Suricata's event_type key must not route to n8n_audit
        self.assertIs(resolve({"source_type": "", "raw": s}), SURICATA)
        self.assertIs(resolve({"source_type": "", "raw": json.dumps(z)}), ZEEKP)


class TestHostileInput(unittest.TestCase):
    JUNK: list[object] = [None, 0, 1.5, True, [], {}, "", "   ", "not json", "{", "[1,2]", '{"event_type": 5}', '{"uid":1}',
            {"event_type": "alert"}, {"event_type": "alert", "alert": "x"}, {"event_type": "dns", "dns": []},
            {"event_type": "modbus", "modbus": {"request": 3}}, {"event_type": "dnp3", "dnp3": {"application": 1}},
            {"event_type": "flow", "src_ip": ["1.1.1.1"], "src_port": 99999, "flow": {"pkts_toserver": 10 ** 400}},
            {"note": 5}, {"note": "x", "src": 1, "dst": [], "p": -1}, {"query": 5}, {"query": "."},
            {"func": 5, "unit": 5}, {"conn_state": "S0", "ts": 10 ** 400, "id.orig_h": {"a": 1}},
            "{" * 100_000, "[" * 100_000]

    def test_total(self):
        for parser, st in ((SURICATA, "suricata_eve"), (ZEEKP, "zeek_json")):
            for junk in self.JUNK:
                for meta in ({}, None, "x", {"sector": 5}):
                    ev = parser.parse({"source_type": st, "raw": junk, "meta": meta})
                    if ev is not None:
                        self.assertEqual(validate(ev), [], (st, junk))
            self.assertIsNone(parser.parse(None))
            self.assertIsNone(parser.parse({}))


class TestSuricataDnsV2(unittest.TestCase):
    """EVE DNS v1/v2 (every Suricata 7.x sensor): type query/answer, flat rrname/rrtype. Shapes from the Suricata 8.0
    upgrade notes (doc/userguide/upgrade/8.0-dns-logging-changes.rst, '7.0' column)."""
    BASE = {"timestamp": "2026-01-01T00:00:00.000000+0000", "flow_id": 1, "event_type": "dns", "src_ip": "10.0.0.5",
            "src_port": 5353, "dest_ip": "10.0.0.1", "dest_port": 53, "proto": "UDP"}

    def _dns(self, **dns):
        return SURICATA.parse(_raw("suricata_eve", dict(self.BASE, dns=dns)))

    def test_v2_query_is_a_dns_query_event(self):
        ev = self._dns(type="query", id=0, rrname="www.suricata.io", rrtype="A", tx_id=0, opcode=0)
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4002, 1))
        self.assertEqual(ev["dst_endpoint"]["hostname"], "www.suricata.io")
        self.assertEqual(ev["unmapped"]["dns"]["parent_domain"], "suricata.io")
        self.assertEqual(ev["unmapped"]["dns"]["qtype"], "A")

    def test_v2_answer_is_a_response(self):
        ev = self._dns(version=2, type="answer", id=0, flags="8180", qr=True, rd=True, ra=True, opcode=0,
                       rrname="www.suricata.io", rrtype="A", rcode="NOERROR",
                       answers=[{"rrname": "suricata.io", "rrtype": "A", "ttl": 597, "rdata": "35.212.0.44"}])
        self.assertEqual((ev["class_uid"], ev["activity_id"]), (4002, 2))
        self.assertEqual(ev["unmapped"]["dns"]["answers"], ["35.212.0.44"])
        self.assertEqual(ev["unmapped"]["dns"]["rcode"], "NOERROR")

    def test_v3_unchanged_and_unknown_type_dropped(self):
        req = self._dns(version=3, type="request", queries=[{"rrname": "a.example.org", "rrtype": "A"}])
        resp = self._dns(version=3, type="response", queries=[{"rrname": "a.example.org", "rrtype": "A"}])
        self.assertEqual((req["activity_id"], resp["activity_id"]), (1, 2))
        self.assertIsNone(self._dns(type="bogus", rrname="a.example.org"))


class TestRoutingNegatives(unittest.TestCase):
    """The content sniff must not steal records that merely have an event_type string and a flow_id."""

    def _name(self, rec):
        p = resolve({"source_type": "", "raw": rec})
        return p.SOURCE_TYPE if p else None

    def test_n8n_with_flow_id_stays_n8n(self):
        self.assertEqual(self._name({"event_type": "workflow.executed", "flow_id": "f1"}), "n8n_audit")
        self.assertEqual(self._name({"event_type": "workflow.executed", "flow_id": 7}), "n8n_audit")
        self.assertEqual(self._name({"event_type": "login", "flow_id": 7, "workflowId": "w"}), "n8n_audit")

    def test_other_event_type_sources_untouched(self):
        self.assertEqual(self._name({"eventType": "AuditWriteUpdateEventType", "nodeId": "ns=2;i=1"}), "opcua_audit")
        self.assertEqual(self._name({"event_type": "AuditFoo", "flow_id": 1}), "opcua_audit")
        self.assertEqual(self._name({"event_type": "workflow.started"}), "n8n_audit")

    def test_eve_needs_known_type_int_flow_id_and_an_address(self):
        ok = {"event_type": "flow", "flow_id": 1, "src_ip": "10.0.0.1"}
        self.assertEqual(self._name(ok), "suricata_eve")
        self.assertEqual(self._name({"event_type": "alert", "flow_id": 1, "pcap_cnt": 4}), "suricata_eve")
        for bad in (dict(ok, event_type="nonsense"), dict(ok, flow_id="1"), dict(ok, flow_id=True),
                    {"event_type": "flow", "flow_id": 1}, dict(ok, event_type=["flow"])):
            self.assertNotEqual(self._name(bad), "suricata_eve", bad)

    def test_every_fixture_record_with_a_flow_id_still_routes_to_suricata(self):
        n = 0
        for item in SURI["records"]:
            if "flow_id" in item["record"]:
                n += 1
                self.assertEqual(self._name(item["record"]), "suricata_eve", item["record"])
        self.assertGreater(n, 8)


class TestEventTime(unittest.TestCase):
    """Close events carry the END of the flow/connection; other events keep their own record time."""

    def test_suricata_flow_uses_flow_end_not_log_time(self):
        rec = _find(SURI, lambda r: r["record"]["event_type"] == "flow" and r["record"]["flow"]["age"] == 23)
        ev = SURICATA.parse(_raw("suricata_eve", rec))
        # flow.end 12:06:16.747072 (last packet); `timestamp` 12:01:18.945 is the engine clock when it was logged.
        self.assertEqual(ev["time"], to_epoch_ms(rec["flow"]["end"]))
        self.assertEqual(ev["time"], 1093521976747)
        self.assertNotEqual(ev["time"], to_epoch_ms(rec["timestamp"]))

    def test_suricata_flow_falls_back_to_timestamp(self):
        rec = copy.deepcopy(_find(SURI, lambda r: r["record"]["event_type"] == "flow"))
        for end in (None, "not a time", 7.5e300):
            rec["flow"]["end"] = end
            ev = SURICATA.parse(_raw("suricata_eve", rec))
            self.assertEqual((ev["activity_id"], ev["time"]), (2, to_epoch_ms(rec["timestamp"])), end)
        del rec["flow"]["end"]
        self.assertEqual(SURICATA.parse(_raw("suricata_eve", rec))["time"], to_epoch_ms(rec["timestamp"]))

    def test_suricata_non_flow_time_is_unchanged(self):
        for kind in ("alert", "dns", "modbus", "dnp3"):
            rec = _find(SURI, lambda r, k=kind: r["record"]["event_type"] == k)
            self.assertEqual(SURICATA.parse(_raw("suricata_eve", rec))["time"], to_epoch_ms(rec["timestamp"]), kind)

    def test_zeek_conn_is_start_plus_duration(self):
        long_conn = {"ts": 1_700_000_000.0, "uid": "C1", "id.orig_h": "10.0.0.1", "id.orig_p": 1000,
                     "id.resp_h": "10.0.0.2", "id.resp_p": 22, "proto": "tcp", "duration": 7200.0, "conn_state": "SF"}
        self.assertEqual(ZEEKP.parse(_raw("zeek_json", long_conn))["time"], 1_700_007_200_000)
        for bad in (None, -5, 1e300, "x", True):
            ev = ZEEKP.parse(_raw("zeek_json", dict(long_conn, duration=bad)))
            self.assertEqual(ev["time"], 1_700_000_000_000, bad)
        no_dur = {k: v for k, v in long_conn.items() if k != "duration"}
        self.assertEqual(ZEEKP.parse(_raw("zeek_json", no_dur))["time"], 1_700_000_000_000)

    def test_zeek_real_conn_and_non_conn_times(self):
        rec = _find(ZEEK, lambda r: r["log"] == "conn.log" and r["record"]["duration"] > 20)
        ev = ZEEKP.parse(_raw("zeek_json", rec))
        self.assertEqual(ev["time"], int(rec["ts"] * 1000) + int(rec["duration"] * 1000))
        for log in ("dns.log", "notice.log", "modbus.log"):
            rec = _find(ZEEK, lambda r, lg=log: r["log"] == lg)
            self.assertEqual(ZEEKP.parse(_raw("zeek_json", rec))["time"], int(rec["ts"] * 1000), log)


class TestZeekModbusFunctionCodes(unittest.TestCase):
    # name -> code, copied from zeek/zeek scripts/base/protocols/modbus/consts.zeek (master, fetched 2026-11-06).
    UPSTREAM = {
        "READ_COILS": 0x01, "READ_DISCRETE_INPUTS": 0x02, "READ_HOLDING_REGISTERS": 0x03, "READ_INPUT_REGISTERS": 0x04,
        "WRITE_SINGLE_COIL": 0x05, "WRITE_SINGLE_REGISTER": 0x06, "READ_EXCEPTION_STATUS": 0x07, "DIAGNOSTICS": 0x08,
        "GET_COMM_EVENT_COUNTER": 0x0B, "GET_COMM_EVENT_LOG": 0x0C, "WRITE_MULTIPLE_COILS": 0x0F,
        "WRITE_MULTIPLE_REGISTERS": 0x10, "REPORT_SLAVE_ID": 0x11, "READ_FILE_RECORD": 0x14,
        "WRITE_FILE_RECORD": 0x15, "MASK_WRITE_REGISTER": 0x16, "READ_WRITE_MULTIPLE_REGISTERS": 0x17,
        "READ_FIFO_QUEUE": 0x18, "ENCAP_INTERFACE_TRANSPORT": 0x2B, "OBJECT_MESSAGING": 0x5B,
        "PROGRAM_484": 0x09, "POLL_484": 0x0A, "PROGRAM_584_984": 0x0D, "POLL_584_984": 0x0E,
        "PROGRAM_884_U84": 0x12, "RESET_COMM_LINK_884_U84": 0x13, "PROGRAM_CONCEPT": 0x28,
        "MULTIPLE_FUNCTION_CODES": 0x29, "PROGRAM_UNITY": 0x5A, "FIRMWARE_REPLACEMENT": 0x7D,
        "PROGRAM_584_984_2": 0x7E, "REPORT_LOCAL_ADDRESS": 0x7F}

    def _code(self, func):
        rec = {"ts": 1_700_000_000.0, "uid": "C1", "id.orig_h": "10.0.0.1", "id.orig_p": 1000, "id.resp_h": "10.0.0.2",
               "id.resp_p": 502, "tid": 1, "unit": 1, "func": func, "pdu_type": "RESP"}
        return ZEEKP.parse(_raw("zeek_json", rec))["unmapped"]["ot"].get("function_code")

    def test_every_upstream_name_and_its_exception_form(self):
        self.assertEqual(len(self.UPSTREAM), 32)
        for name, code in self.UPSTREAM.items():
            self.assertEqual(self._code(name), code, name)
            self.assertEqual(self._code(name + "_EXCEPTION"), code, name)

    def test_unknown_n(self):
        self.assertEqual(self._code("unknown-100"), 100)
        self.assertEqual(self._code("unknown-200"), 200 & 0x7F)  # exception bit set, no table entry
        self.assertEqual(self._code("unknown-0"), 0)
        for bad in ("unknown-256", "unknown-", "unknown-1x", "unknown--1", "UNKNOWN-5", "unknown-0000", "NOT_A_FUNC"):
            self.assertIsNone(self._code(bad), bad)


class TestProvenanceAgainstContent(unittest.TestCase):
    """The headers are checked against what the fixture records actually contain, not just their shape."""

    def test_header_fields_match_fixture_content(self):
        for fix in (SURI, ZEEK):
            p = fix["provenance"]
            self.assertRegex(p["image"], r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
            self.assertRegex(p["generated"], r"^\d{4}-\d{2}-\d{2}$")
            commits = set()
            for name, pc in p["pcaps"].items():
                self.assertRegex(pc["sha256"], r"^[0-9a-f]{64}$", name)
                m = re.fullmatch(r"https://raw\.githubusercontent\.com/OISF/suricata-verify/([0-9a-f]{40})/tests/.+\.pcap",
                                 pc["url"])
                self.assertTrue(m, pc["url"])
                commits.add(m.group(1))
            self.assertEqual(len(commits), 1, "all pcaps come from one pinned suricata-verify commit")
            # every record names a declared pcap. Suricata: all three contributed records. Zeek: the header also lists
            # dnp3-eve.pcap but no selected Zeek record comes from it (Zeek's dnp3 analyzer has no log in this fixture),
            # so only the subset direction is asserted for Zeek.
            used = {r["pcap"] for r in fix["records"]}
            self.assertLessEqual(used, set(p["pcaps"]))
            if fix is SURI:
                self.assertEqual(used, set(p["pcaps"]))
        # Suricata: the command enables the protocols the records show; the local rules named in the header ARE the alerts
        self.assertTrue({"alert", "flow", "dns", "modbus", "dnp3"} <= {r["record"]["event_type"] for r in SURI["records"]})
        self.assertIn("Suricata 8.0.8", SURI["provenance"]["tool"])
        for proto in ("modbus", "dnp3"):
            self.assertIn(proto, SURI["provenance"]["command"])
        alerts = [r["record"]["alert"] for r in SURI["records"] if r["record"]["event_type"] == "alert"]
        self.assertTrue({a["signature_id"] for a in alerts} <= {9900001, 9900002, 9900003} and alerts)
        self.assertIn("9900001-9900003", SURI["provenance"]["local_rules"])
        self.assertTrue(all(a["signature"].startswith("FENGARDE-FIXTURE") for a in alerts))
        # Zeek: the ICSNPP log is present exactly when the header says the package was installed
        logs = {r["log"] for r in ZEEK["records"]}
        self.assertEqual("modbus_detailed.log" in logs, "icsnpp-modbus" in ZEEK["provenance"]["tool"])
        self.assertTrue({"conn.log", "dns.log", "notice.log", "modbus.log"} <= logs)
        self.assertIn("Zeek 9.0.1", ZEEK["provenance"]["tool"])


def _leaf_paths(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _leaf_paths(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _leaf_paths(v, path + (i,))
    else:
        yield path


def _mutate(rec, path):
    out = copy.deepcopy(rec)
    node = out
    for k in path[:-1]:
        node = node[k]
    v = node[path[-1]]
    node[path[-1]] = (not v if isinstance(v, bool) else v + 7 if isinstance(v, (int, float)) else
                      "zz-probe-" + v if isinstance(v, str) else "zz-probe")
    return out


def coverage(parser, source_type, fix):
    """(mapped, dropped) field-path sets, '*' standing for a list index. A field is mapped if mutating it changes
    the parser output for at least one record that carries it."""
    mapped: set = set()
    seen: set = set()
    for item in fix["records"]:
        rec = item["record"]
        base = parser.parse(_raw(source_type, rec))
        if base is None:
            continue
        for path in _leaf_paths(rec):
            name = ".".join("*" if isinstance(p, int) else p for p in path)
            seen.add(name)
            if parser.parse(_raw(source_type, _mutate(rec, path))) != base:
                mapped.add(name)
    return mapped, seen - mapped


class TestFieldCoverage(unittest.TestCase):
    def test_report_and_floor(self):
        for label, parser, st, fix, must in (
                ("Suricata EVE", SURICATA, "suricata_eve", SURI,
                 {"timestamp", "src_ip", "dest_ip", "alert.signature", "alert.signature_id", "alert.severity",
                  "dns.queries.*.rrname", "modbus.request.unit_id", "dnp3.application.function_code",
                  "flow.pkts_toserver"}),
                ("Zeek JSON", ZEEKP, "zeek_json", ZEEK,
                 {"ts", "id.orig_h", "id.resp_p", "query", "answers.*", "note", "func", "unit", "conn_state"})):
            mapped, dropped = coverage(parser, st, fix)
            print(f"\n[COVERAGE] {label}: {len(mapped)} fixture field paths mapped, {len(dropped)} dropped")
            print(f"  mapped : {', '.join(sorted(mapped))}")
            print(f"  dropped: {', '.join(sorted(dropped))}")
            self.assertTrue(must <= mapped, f"{label} no longer reads: {sorted(must - mapped)}")


if __name__ == "__main__":
    unittest.main(verbosity=1)
