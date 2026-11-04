"""WP-1.3 adapter contract tests: real shipper shapes -> parser-expected input.

Covers, per adapter in services/ws2-normalization/adapters/:
- the real-sample fixture maps to the EXACT dict the target parser expects
  (asserted field-by-field for the fields the parser reads);
- the adapted payload then resolves + parses to valid OCSF through the WS-2
  normalize path (windows_eventlog / sysmon / linux_ssh / generic_syslog);
- adapt() is TOTAL: every extreme leaf value is swept (same approach as
  parsers/test_extreme_values.py) and must never raise;
- sniffs() negative controls: a record from one family never trips another
  family's sniffer;
- meta.shipper selection wins over shape sniff; unknown shipper + unknown
  shape -> payload returned unchanged.

Run: python services/ws2-normalization/test_adapters.py
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
ROOT = SERVICES.parent
sys.path.insert(0, str(SERVICES))
sys.path.insert(0, str(HERE))

from adapters import ADAPTERS, adapt_record  # noqa: E402
from adapters import fluentbit_winevtlog, winlogbeat, fluentbit_journald, docker_json  # noqa: E402
from parsers.test_extreme_values import EXTREMES  # noqa: E402
from main import normalize_one  # noqa: E402

FAILS: list[str] = []


def check(cond, label):
    if not cond:
        FAILS.append(label)


# --- helper: run one record through the FULL ws2 path (adapt -> resolve/parse -> OCSF) --


def full_path(source_type: str, record: dict, meta: dict | None = None):
    payload = {"source_type": source_type, "raw": record,
               "meta": dict(meta) if meta else {"received_at": 1673963483}}
    adapted = adapt_record(payload)
    event, errors = normalize_one(adapted)
    return adapted, event, errors


def _show(payload, event, errors, want_st):
    adapted_st = payload["source_type"]
    raw = payload["raw"]
    ok = (event is not None and not errors and adapted_st == want_st)
    return (ok, f"source_type={adapted_st!r} want={want_st!r} event={'OK' if event else 'None'} "
                f"errors={errors[:1]} raw_keys={sorted(raw)[:6] if isinstance(raw, dict) else type(raw).__name__}")


def test_fluentbit_winevtlog_sysmon_fixture():
    # The REAL capture (fluent-bit 2.0.6, 2023-01-17): must route to sysmon and
    # parse as a process-launch Kernel/Process event with the parser's fields.
    if not fluentbit_winevtlog.sniffs(fluentbit_winevtlog.FIXTURE):
        FAILS.append("fluentbit-winevtlog: sniffs() rejects the real Sysmon capture")
    p, event, errors = full_path("windows_eventlog", fluentbit_winevtlog.FIXTURE,
                                 {"received_at": 1673963483})
    ok, msg = _show(p, event, errors, "sysmon")
    check(ok, f"fluentbit-winevtlog Sysmon fixture: {msg}")
    if event:
        check(event.get("class_uid") == 1002 and event.get("activity_id") == 1,
              "fluentbit-winevtlog Sysmon fixture: expected 1002/1 process launch")
        check(isinstance(p["raw"].get("TimeCreated"), int) and p["raw"]["TimeCreated"] > 0,
              "fluentbit-winevtlog: TimeCreated not converted to epoch ms")
        check(p["raw"].get("EventID") == 1 and "Computer" in p["raw"],
              "fluentbit-winevtlog: EventID/Computer lost")


def test_fluentbit_winevtlog_security_fixture():
    # Security-channel record: routes to windows_eventlog; 4624 maps to
    # Authentication 3002 (the Ad parser does NOT own 4624 in the windows path).
    if not fluentbit_winevtlog.sniffs(fluentbit_winevtlog.SECURITY_FIXTURE):
        FAILS.append("fluentbit-winevtlog: sniffs() rejects Security fixture")
    p, event, errors = full_path("windows_eventlog", fluentbit_winevtlog.SECURITY_FIXTURE)
    ok, msg = _show(p, event, errors, "windows_eventlog")
    check(ok, f"fluentbit-winevtlog Security fixture: {msg}")
    if event:
        check(event.get("class_uid") == 3002 and event.get("activity_id") == 1,
              "fluentbit-winevtlog Security fixture: expected 3002/1 logon")


def test_winlogbeat_process_fixture():
    # ECS-shaped winlogbeat record (field catalog, 4688): -> windows_eventlog,
    # 4688 maps to 1002/1; event_data flattened into the parser's keys.
    if not winlogbeat.sniffs(winlogbeat.FIXTURE):
        FAILS.append("winlogbeat: sniffs() rejects the 4688 fixture")
    p, event, errors = full_path("windows_eventlog", winlogbeat.FIXTURE)
    ok, msg = _show(p, event, errors, "windows_eventlog")
    check(ok, f"winlogbeat 4688 fixture: {msg}")
    raw = p["raw"]
    check(raw.get("EventID") == 4688 and raw.get("Computer") == "wks-jdoe",
          f"winlogbeat: EventID/Computer not flattened: {raw}")
    check(raw.get("NewProcessName") == "C:\\Program Files\\WindowsApps\\n8n.exe",
          "winlogbeat: winlog.event_data.NewProcessName not flattened")
    check(raw.get("SubjectUserName") == "WKS-JDOE$",
          "winlogbeat: winlog.event_data.SubjectUserName not flattened")
    check(isinstance(raw.get("TimeCreated"), int),
          "winlogbeat: winlog.time_created not converted to epoch ms")
    if event:
        check(event.get("class_uid") == 1002 and event.get("activity_id") == 1,
              "winlogbeat 4688 fixture: expected 1002/1 process launch")


def test_winlogbeat_logon_fixture():
    # 4624 logon -> Authentication 3002/1; IpAddress drives src_endpoint so the
    # brute-force/common rules can light up from real winlogbeat data.
    p, event, errors = full_path("windows_eventlog", winlogbeat.SECURITY_LOGON_FIXTURE)
    ok, msg = _show(p, event, errors, "windows_eventlog")
    check(ok, f"winlogbeat 4624 fixture: {msg}")
    if event:
        check(event.get("class_uid") == 3002,
              "winlogbeat 4624 fixture: expected class 3002")
        se = event.get("src_endpoint") or {}
        check(se.get("ip") == "203.0.113.9",
              f"winlogbeat 4624 fixture: src_endpoint.ip wrong: {se}")


def test_journald_sshd_fixture():
    # journald sshd failure -> reconstructed RFC3164 line -> linux_ssh parser
    # (Authentication 3002, activity 3/4 family). The text-sniff must hit.
    if not fluentbit_journald.sniffs(fluentbit_journald.FIXTURE):
        FAILS.append("fluentbit-journald: sniffs() rejects the sshd fixture")
    p, event, errors = full_path("generic_syslog", fluentbit_journald.FIXTURE)
    ok, msg = _show(p, event, errors, "generic_syslog")
    check(ok, f"fluentbit-journald sshd fixture: {msg}")
    check(isinstance(p["raw"], str) and "sshd[2154]:" in p["raw"],
          f"fluentbit-journald: RFC3164 line not rebuilt: {p['raw']!r}")
    if event:
        check(event.get("class_uid") == 3002,
              f"fluentbit-journald sshd fixture: expected class 3002, got "
              f"{event.get('class_uid')} (sniff missed sshd?)")
        check((event.get("actor") or {}).get("user", {}).get("name") == "admin",
              "fluentbit-journald: actor user not parsed from the sshd line")


def test_journald_non_ssh_fixture():
    # Accepted-publickey line (still sshd) and a generic line fallback.
    p, event, errors = full_path("generic_syslog", fluentbit_journald.NON_SSH_FIXTURE)
    ok, msg = _show(p, event, errors, "generic_syslog")
    check(ok, f"fluentbit-journald accept fixture: {msg}")
    # A journald record with no MESSAGE is not adapter material: unchanged.
    junk = {"source_type": "generic_syslog", "raw": {"_HOSTNAME": "h"}, "meta": {}}
    check(adapt_record(junk) is junk,
          "fluentbit-journald: record without MESSAGE must be untouched")


def test_docker_json_fixture():
    if not docker_json.sniffs(docker_json.FIXTURE):
        FAILS.append("docker-json: sniffs() rejects the json-file fixture")
    # With the docker filter's ids the adapter rebuilds the RFC 3164 header
    # from record fields only -> generic_syslog parses it.
    p, event, errors = full_path("generic_syslog", docker_json.FIXTURE)
    ok, msg = _show(p, event, errors, "generic_syslog")
    check(ok, f"docker-json fixture: {msg}")
    check(p["raw"].startswith("<14>Jan  1 11:11:11 1d8f02f0f8a9 n8n_bankcorp: User info: admin@bankcorp.example"),
          f"docker-json: RFC3164 header not rebuilt honestly: {p['raw']!r}")
    check(p["meta"].get("docker_id") == "1d8f02f0f8a9d0c1"
          and p["meta"].get("docker_name") == "n8n_bankcorp",
          "docker-json: docker_id/docker_name not carried into meta")
    # sshd line through docker logs: rebuilt header -> text sniff -> linux_ssh.
    p2, event2, errors2 = full_path("generic_syslog", docker_json.SSH_FIXTURE)
    ok2, msg2 = _show(p2, event2, errors2, "generic_syslog")
    check(ok2, f"docker-json sshd fixture: {msg2}")
    check(event2 is not None and event2.get("class_uid") == 3002,
          "docker-json sshd fixture: expected class 3002 via text sniff")
    # Naked json-file record (no docker filter ids): NOTHING honest to build
    # a header from -> adapter no-op, dead-letter carries the normal hint.
    naked = {"source_type": "generic_syslog", "raw": dict(docker_json.NO_CONTAINER_FIXTURE),
             "meta": {"received_at": 1673963483}}
    check(adapt_record(naked) is naked,
          "docker-json: id-less json-file record must be a no-op (same object)")


def test_shipper_label_beats_sniff_and_unknown_is_noop():
    # Explicit meta.shipper wins even when the shape is ambiguous...
    winlog_like = {"Channel": "Security", "EventID": 4624, "Computer": "c",
                   "TimeCreated": "2023-01-17 12:50:59 +0000"}
    payload = {"source_type": "generic_syslog", "raw": winlog_like,
               "meta": {"shipper": "fluentbit-winevtlog"}}
    out = adapt_record(payload)
    check(out["source_type"] == "windows_eventlog",
          f"shipper label must select the adapter: {out}")
    # ...and an unknown shipper with an unknown shape passes through untouched.
    mystery = {"source_type": "generic_syslog", "raw": {"foo": "bar"}, "meta": {"shipper": "bogus-product"}}
    check(adapt_record(mystery) is mystery,
          "unknown shipper + unknown shape must be a no-op (same object)")
    unlabelled = {"source_type": "generic_syslog", "raw": {"foo": "bar"}, "meta": {}}
    check(adapt_record(unlabelled) is unlabelled,
          "no shipper + no shape must be a no-op (same object)")
    # Invalid-input totality: adapt_record never raises, whatever it gets.
    for junk in (None, "x", 7, [], ["a"], {"raw": "text"}, {"raw": {}}):
        try:
            adapt_record(junk)
        except Exception as exc:  # noqa: BLE001
            FAILS.append(f"adapt_record({junk!r}) raised {type(exc).__name__}: {exc}")


def test_sniff_negative_controls():
    # A record from one family must not trip another family's sniffer.
    winlogbeat_rec = {"winlog": {"event_id": 1, "channel": "x", "computer_name": "c"}}
    check(not fluentbit_winevtlog.sniffs(winlogbeat_rec),
          "fluentbit-winevtlog sniffs() accepts a winlogbeat record")
    check(not docker_json.sniffs(winlogbeat_rec),
          "docker-json sniffs() accepts a winlogbeat record")
    journald_rec = {"MESSAGE": "hi", "_HOSTNAME": "h"}
    check(not winlogbeat.sniffs(journald_rec) and not fluentbit_winevtlog.sniffs(journald_rec)
          and not docker_json.sniffs(journald_rec),
          "journald record tripped a windows/docker sniffer")
    docker_rec = {"log": "x", "stream": "stdout", "time": "t"}
    check(not winlogbeat.sniffs(docker_rec) and not fluentbit_winevtlog.sniffs(docker_rec)
          and not fluentbit_journald.sniffs(docker_rec),
          "docker record tripped another family's sniffer")


def test_extreme_value_sweep_adapters():
    # The parsers' extreme-value guarantee, extended to adapters per WP-1.3:
    # every leaf of every real fixture replaced by every extreme must never
    # raise and must return a dict payload (totality is the contract).
    fixtures = [
        ("fluentbit-winevtlog", fluentbit_winevtlog.FIXTURE),
        ("fluentbit-winevtlog", fluentbit_winevtlog.SECURITY_FIXTURE),
        ("winlogbeat", winlogbeat.FIXTURE),
        ("winlogbeat", winlogbeat.SECURITY_LOGON_FIXTURE),
        ("fluentbit-journald", fluentbit_journald.FIXTURE),
        ("docker-json", docker_json.FIXTURE),
    ]
    total = 0

    def leaf_paths(node, path=()):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from leaf_paths(v, path + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from leaf_paths(v, path + (i,))
        else:
            yield path

    def set_path(node, path, value):
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    for adapter_id, fixture in fixtures:
        module = ADAPTERS[adapter_id]
        for path in leaf_paths(fixture):
            if not path:
                continue
            for ev in EXTREMES:
                mutated = copy.deepcopy(fixture)
                set_path(mutated, path, ev)
                total += 1
                try:
                    out = module.adapt({"source_type": "x", "raw": mutated, "meta": {}})
                except Exception as exc:  # the crash IS the finding
                    FAILS.append(f"{adapter_id} {'.'.join(map(str, path))}={ev!r}: "
                                 f"{type(exc).__name__}: {str(exc)[:80]}")
                    continue
                if not isinstance(out, dict):
                    FAILS.append(f"{adapter_id} {'.'.join(map(str, path))}: "
                                 f"adapt returned {type(out).__name__}")
    if not FAILS:
        print(f"  adapter sweep: {total} mutations, none raised")


def main():
    tests = [test_fluentbit_winevtlog_sysmon_fixture,
             test_fluentbit_winevtlog_security_fixture,
             test_winlogbeat_process_fixture,
             test_winlogbeat_logon_fixture,
             test_journald_sshd_fixture,
             test_journald_non_ssh_fixture,
             test_docker_json_fixture,
             test_shipper_label_beats_sniff_and_unknown_is_noop,
             test_sniff_negative_controls,
             test_extreme_value_sweep_adapters]
    for t in tests:
        t()
    if FAILS:
        print(f"[FAIL] adapters: {len(FAILS)} problem(s)")
        for f in FAILS[:40]:
            print("  -", f)
        return 1
    print(f"[OK] adapters: {len(tests)} test groups over {len(ADAPTERS)} adapters, "
          "real fixtures -> parser input, totality sweep clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())