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
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(SERVICES))

from shared.ocsf import validate  # noqa: E402
from parsers import get_parser, resolve  # noqa: E402

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
