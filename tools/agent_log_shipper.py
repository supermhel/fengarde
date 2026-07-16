"""Ship agent/MCP JSONL logs into FENGARDE's raw.events (M3, PLAN_A P3 3.5).

WS-1's real live collectors only handle syslog (UDP) and mock SNMP/NetFlow --
there is no "point an arbitrary JSON log file at FENGARDE" ingestion path for
the structured-record parsers (mcp_agent, opcua_audit, n8n_audit, db_audit,
windows_eventlog, active_directory, vmware_vsphere). Until v0.5 M3, the ONLY
way to get an mcp_agent event into a live stack was to write directly to the
bus yourself (as tools/demo_e2e.py / services/devkit-feeder/feed.py do) --
not a turnkey "5-minute" experience for an operator with a real log file.

This is that missing piece: reads one JSON object per line (JSONL -- the
shape Claude Code hooks and most MCP server/gateway logs already emit) and
produces each line to raw.events with a configurable source_type (default
mcp_agent), via the same shared.bus.Bus() abstraction every workstream uses
-- so it works against BUS_BACKEND=memory (zero-infra, for trying this out)
and BUS_BACKEND=redis (the live stack) identically.

Usage:
    # one-shot: ship every line currently in the file, then exit
    python tools/agent_log_shipper.py --file /var/log/claude-code/hooks.jsonl

    # continuous: keep tailing (like `tail -f`) as the log grows -- point a
    # running MCP server/gateway's log file here and leave it running
    python tools/agent_log_shipper.py --file /path/to/mcp-server.jsonl --follow

    # stdin: pipe from anything that emits one JSON object per line
    tail -f /path/to/log.jsonl | python tools/agent_log_shipper.py --stdin

Each line must be a JSON object; malformed lines are skipped (counted,
logged to stderr) rather than aborting the whole file -- one bad line in an
otherwise-good log must not block the rest, matching this project's
parser-isolation discipline (services/ws2-normalization/main.py).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
sys.path.insert(0, str(SERVICES))

from shared.bus import Bus  # noqa: E402
from shared.envelope import stamp_meta  # noqa: E402


def _partition_key(rec: dict) -> str:
    """Bus partition key: prefer a session/agent identity (keeps one agent's
    events on one partition, matching how raw.events is normally keyed by
    src_endpoint.ip for network sources -- an agent session is this source's
    analog of "one host")."""
    for k in ("session_id", "session", "sessionId", "agent", "agent_id", "agentId"):
        v = rec.get(k)
        if v:
            return str(v)
    return "agent-log-shipper"


def ship_line(bus, line: str, source_type: str) -> bool:
    """Parse one JSONL line and produce it to raw.events. Returns False (and
    prints to stderr) on a malformed line, without raising -- the caller
    keeps going."""
    line = line.strip()
    if not line:
        return True
    try:
        rec = json.loads(line)
    except (ValueError, TypeError) as exc:
        print(f"[agent-log-shipper] skipping malformed line: {exc}", file=sys.stderr)
        return False
    if not isinstance(rec, dict):
        print("[agent-log-shipper] skipping non-object JSON line", file=sys.stderr)
        return False

    meta = stamp_meta({})
    payload = {"source_type": source_type, "raw": rec, "meta": meta}
    bus.produce("raw.events", key=_partition_key(rec), payload=payload)
    return True


def ship_file(bus, path: Path, source_type: str, follow: bool) -> int:
    shipped = 0
    with path.open("r", encoding="utf-8") as fh:
        while True:
            line = fh.readline()
            if line:
                if ship_line(bus, line, source_type):
                    shipped += 1
                continue
            if not follow:
                break
            time.sleep(1.0)  # matches `tail -f`'s poll cadence closely enough for a log shipper
    return shipped


def ship_stdin(bus, source_type: str) -> int:
    shipped = 0
    for line in sys.stdin:
        if ship_line(bus, line, source_type):
            shipped += 1
    return shipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="path to a JSONL log file")
    src.add_argument("--stdin", action="store_true", help="read JSONL from stdin")
    ap.add_argument("--follow", action="store_true",
                     help="keep tailing --file as it grows (like tail -f); ignored with --stdin")
    ap.add_argument("--source-type", default="mcp_agent",
                     help="raw.events source_type to stamp (default: mcp_agent). "
                          "Use opcua_audit/n8n_audit/db_audit/etc. for other structured-record "
                          "sources -- this shipper's JSONL-line mechanism is source-agnostic.")
    args = ap.parse_args()

    bus = Bus()
    if args.stdin:
        shipped = ship_stdin(bus, args.source_type)
    else:
        if not args.file.exists():
            print(f"[agent-log-shipper] file not found: {args.file}", file=sys.stderr)
            return 1
        shipped = ship_file(bus, args.file, args.source_type, args.follow)

    print(f"[agent-log-shipper] shipped {shipped} event(s) to raw.events "
          f"(source_type={args.source_type})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
