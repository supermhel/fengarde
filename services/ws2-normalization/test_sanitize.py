"""M1 correctness gate: log-injection defense (ANSI + control-char stripping).

Proves services/shared/sanitize.py's regexes actually work, AND that
normalize_one() (services/ws2-normalization/main.py) applies them to every
free-text field a real parser populates from attacker-controlled log content --
not just that the helper function works in isolation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVICES = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SERVICES))
os.environ["BUS_BACKEND"] = "memory"

from shared.sanitize import strip_ansi_and_control  # noqa: E402
import main as ws2  # noqa: E402

FAILS: list[str] = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)


def test_strips_csi_ansi():
    out = strip_ansi_and_control("hello\x1b[31mRED\x1b[0mworld")
    check(out == "helloREDworld", f"CSI ansi not stripped: {out!r}")


def test_strips_osc_ansi_terminated_by_bel():
    # OSC 52 clipboard-injection shape: ESC ] 52 ; c ; <base64> BEL
    out = strip_ansi_and_control("before\x1b]52;c;ZXZpbA==\x07after")
    check(out == "beforeafter", f"OSC(BEL) ansi not stripped: {out!r}")


def test_strips_osc_ansi_terminated_by_st():
    out = strip_ansi_and_control("before\x1b]0;title\x1b\\after")
    check(out == "beforeafter", f"OSC(ST) ansi not stripped: {out!r}")


def test_strips_control_chars_but_keeps_tab():
    out = strip_ansi_and_control("a\rb\nc\x00d\te")
    check(out == "abcd\te", f"control chars not stripped (tab must survive): {out!r}")


def test_log_forging_newline_removed():
    """The concrete log-injection scenario: an attacker-controlled username
    containing a fake newline + fabricated log line must not survive as two
    lines once it reaches a terminal/log sink."""
    hostile = "admin\n2026-01-01 CRITICAL fake alert: system compromised"
    out = strip_ansi_and_control(hostile)
    check("\n" not in out, f"embedded newline (log forging) not stripped: {out!r}")


def test_non_string_passthrough():
    check(strip_ansi_and_control(None) is None, "None must pass through unchanged")
    check(strip_ansi_and_control(42) == 42, "non-str must pass through unchanged")


def test_normalize_one_sanitizes_message_from_real_parser():
    """End-to-end: a hostile ANSI/control payload in a linux_ssh raw line
    must NOT survive into the normalized event's message field."""
    hostile_user = "admin\x1b[31m\x07"
    raw = {
        "source_type": "linux_ssh",
        "raw": f"Jun 10 13:55:36 db01 sshd[2154]: Failed password for invalid user "
               f"{hostile_user} from 203.0.113.5 port 51000 ssh2",
        "meta": {"received_at": 1700000000, "ingest_id": "sanitize-test-1"},
    }
    event, errors = ws2.normalize_one(raw)
    check(event is not None, "parser must still produce an event for this input")
    check(not errors, f"sanitized event must still validate: {errors}")
    message = event.get("message", "")
    check("\x1b" not in message, f"ESC byte survived into message: {message!r}")
    check("\x07" not in message, f"BEL byte survived into message: {message!r}")


def test_sanitizes_unmapped_wildcard_any_prefix_any_depth():
    """M1 gap fix: attacker-controlled content under unmapped.* (ANY prefix,
    at ANY depth) and api.request.data must be stripped. Before the fix these
    two shapes were not in _FREE_TEXT_PATHS, so a hostile value riding in
    unmapped.mcp.* / unmapped.ot.* / unmapped.db.* reached downstream sinks
    untouched. Now the ("unmapped", "*") wildcard strips every string leaf in
    the whole subtree, and api.request.data is an explicit nested path."""
    hostile = "\x1b[31m\x1b]52;c;ZXZpbA==\x07\x00\r\n"
    event = {
        "unmapped": {
            "foo": {"bar": f"evil{hostile}red"},          # deep dict
            "ot": {"node_id": "n\x1b]52;c;ZXZpbA==\x07x"},  # OSC clipboard-injection
            "db": {"object": "a\r\nb"},                    # log-forging CRLF
            "deep": {"a": {"b": {"c": "y\x00z"}}},         # arbitrarily deep
            "flat_list": ["x\x1b[31m", "plain"],           # list of strings
            "count": 7,                                     # non-string leaf
        },
        "api": {"request": {"data": f"body{hostile}inject"}},
    }
    ws2._sanitize_free_text(event)
    check(event["unmapped"]["foo"]["bar"] == "evilred",
          f"unmapped.foo.bar not stripped: {event['unmapped']['foo']['bar']!r}")
    check(event["unmapped"]["ot"]["node_id"] == "nx",
          f"unmapped.ot.node_id OSC not stripped: {event['unmapped']['ot']['node_id']!r}")
    check(event["unmapped"]["db"]["object"] == "ab",
          f"unmapped.db.object CRLF not stripped: {event['unmapped']['db']['object']!r}")
    check(event["unmapped"]["deep"]["a"]["b"]["c"] == "yz",
          "unmapped arbitrarily-deep content not stripped: "
          f"{event['unmapped']['deep']['a']['b']['c']!r}")
    check(event["unmapped"]["flat_list"] == ["x", "plain"],
          f"unmapped list-of-strings not stripped: {event['unmapped']['flat_list']!r}")
    check(event["api"]["request"]["data"] == "bodyinject",
          f"api.request.data not stripped: {event['api']['request']['data']!r}")
    # Non-string leaves must survive untouched (same contract as strip_ansi_and_control).
    check(event["unmapped"]["count"] == 7,
          f"non-string leaf got mutated: {event['unmapped']['count']!r}")


def test_unmapped_wildcard_missing_subtree_is_noop():
    """A payload with no unmapped/api.request.data must pass through cleanly --
    the wildcard must not KeyError or corrupt a normal event."""
    event = {"message": "hello\x1b[31m", "src_endpoint": {"hostname": "h\x00st"}}
    out = ws2._sanitize_free_text(event)
    check(out["message"] == "hello", f"message not stripped: {out['message']!r}")
    check(out["src_endpoint"]["hostname"] == "hst",
          f"hostname not stripped: {out['src_endpoint']['hostname']!r}")


def test_explicit_path_with_nested_value_recurses_instead_of_passthrough():
    """api.request.data is documented as a string, but strip_ansi_and_control()
    silently no-ops on non-str input -- so if a producer ever puts a dict/list
    there instead (malformed shape, or a future producer), the OLD code path
    (`cursor[leaf] = strip_ansi_and_control(cursor[leaf])`) would leave hostile
    content in a nested dict/list completely unsanitized. Any explicit path
    whose value is a dict/list must recurse the same as the "*" wildcard."""
    hostile = "\x1b[31mx\x07"
    event = {"api": {"request": {"data": {"body": f"evil{hostile}", "n": 3}}}}
    ws2._sanitize_free_text(event)
    check(event["api"]["request"]["data"]["body"] == "evilx",
          f"nested dict at an explicit path not sanitized: {event['api']['request']['data']!r}")
    check(event["api"]["request"]["data"]["n"] == 3,
          f"non-string leaf under a nested explicit-path value got mutated: "
          f"{event['api']['request']['data']!r}")


def test_sanitizes_api_operation_and_actor_user_domain_uid():
    """WP-2-G re-derived gap fix: api.operation (carries the raw tool name /
    event_type copied verbatim from attacker-controlled content by mcp_agent
    str(tool), n8n_audit str(event_type), opcua_audit event_type) and
    actor.user.domain / actor.user.uid (raw Windows eventlog domain + SID set
    by active_directory + windows_eventlog) were NOT in _FREE_TEXT_PATHS and
    NOT under unmapped.*, so hostile strings in those mapped fields reached
    downstream sinks unsanitized. Each must now be stripped."""
    hostile = "\x1b[31m\x1b]52;c;ZXZpbA==\x07\x00\r\n"
    event = {
        "api": {"operation": f"read_{hostile}file", "request": {"data": "ok"}},
        "actor": {"user": {
            "name": "alice",
            "domain": f"BANK{hostile}CORP",
            "uid": f"S-1-5-21{hostile}",
        }},
    }
    ws2._sanitize_free_text(event)
    # unchanged fields must stay intact (surgical fix, no collateral churn)
    check(event["actor"]["user"]["name"] == "alice",
          f"already-covered actor.user.name got clobbered: {event['actor']['user']['name']!r}")
    check(event["api"]["request"]["data"] == "ok",
          f"already-covered api.request.data got clobbered: {event['api']['request']['data']!r}")
    # new coverage must be stripped
    check(event["api"]["operation"] == "read_file",
          f"api.operation not stripped: {event['api']['operation']!r}")
    check(event["actor"]["user"]["domain"] == "BANKCORP",
          f"actor.user.domain not stripped: {event['actor']['user']['domain']!r}")
    check(event["actor"]["user"]["uid"] == "S-1-5-21",
          f"actor.user.uid not stripped: {event['actor']['user']['uid']!r}")


def test_api_operation_stripped_end_to_end_through_real_parser():
    """End-to-end through normalize_one: an MCP agent record with a hostile
    (ANSI + control) tool name must NOT survive into api.operation -- proof the
    new explicit path is wired into the real parse->sanitize pipeline, not just
    a direct-call unit test."""
    hostile = "\x1b]52;c;ZXZpbA==\x07read\x00"
    raw = {
        "source_type": "mcp_agent",
        "raw": {"ts": 1700000000, "tool": hostile, "agent": "a",
                "arguments": {"path": "/tmp/x"}, "outcome": "success"},
        "meta": {"received_at": 1700000000, "ingest_id": "wp2g-mcp-1"},
    }
    event, errors = ws2.normalize_one(raw)
    check(event is not None, "mcp_agent parser must still produce an event")
    check(not errors, f"sanitized event must still validate: {errors}")
    op = event.get("api", {}).get("operation", "")
    check("\x1b" not in op and "\x07" not in op and "\x00" not in op,
          f"hostile control bytes survived into api.operation: {op!r}")


def test_unmapped_nested_list_of_dicts_stripped():
    """The ("unmapped", "*") wildcard must recurse into a nested LIST OF DICTS
    under unmapped.*, stripping string cells inside each dict -- not just the
    top-level dict and a flat list-of-strings. A producer putting an array of
    records under unmapped (e.g. unmapped.k8s.items: [{...raw...}]) must not
    let control chars in a cell escape to downstream sinks."""
    hostile = "\x1b[31m\x0b"
    event = {"unmapped": {
        "k8s": {
            "items": [
                {"name": f"pod{hostile}x", "ns": "prod"},
                {"name": "clean", "ns": "n\x07s"},
                {"labels": [f"a{hostile}b", "plain"]},   # list inside a dict cell
            ],
            "count": 3,                                   # non-string leaf survives
        },
    }}
    ws2._sanitize_free_text(event)
    items = event["unmapped"]["k8s"]["items"]
    check(items[0]["name"] == "podx",
          f"nested list-of-dicts cell not stripped: {items[0]['name']!r}")
    check(items[1]["ns"] == "ns",
          f"nested list-of-dicts cell (ns) not stripped: {items[1]['ns']!r}")
    check(items[2]["labels"] == ["ab", "plain"],
          f"list-inside-dict-cell not stripped: {items[2]['labels']!r}")
    check(event["unmapped"]["k8s"]["count"] == 3,
          f"non-string leaf under nested list got mutated: "
          f"{event['unmapped']['k8s']['count']!r}")


def main():
    test_strips_csi_ansi()
    test_strips_osc_ansi_terminated_by_bel()
    test_strips_osc_ansi_terminated_by_st()
    test_strips_control_chars_but_keeps_tab()
    test_log_forging_newline_removed()
    test_non_string_passthrough()
    test_normalize_one_sanitizes_message_from_real_parser()
    test_sanitizes_unmapped_wildcard_any_prefix_any_depth()
    test_unmapped_wildcard_missing_subtree_is_noop()
    test_explicit_path_with_nested_value_recurses_instead_of_passthrough()
    test_sanitizes_api_operation_and_actor_user_domain_uid()
    test_api_operation_stripped_end_to_end_through_real_parser()
    test_unmapped_nested_list_of_dicts_stripped()

    if FAILS:
        print(f"\n[FAIL] sanitize: {len(FAILS)} problem(s)")
        for f in FAILS:
            print("   -", f)
        sys.exit(1)
    print("[OK] log-injection defense (ANSI/control-char sanitize) unit tests PASS")


if __name__ == "__main__":
    main()
