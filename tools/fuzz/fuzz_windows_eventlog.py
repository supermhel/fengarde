"""atheris fuzz harness: services/ws2-normalization/parsers/windows_eventlog.py.

Unlike linux_ssh/cisco_asa (plain syslog lines), this parser's raw.raw is
JSON -- it accepts either a dict or a JSON string and json.loads()s the
latter, so feeding it a fuzzed string exercises BOTH the JSON decoder path
and the field-extraction logic (EventID/TimeCreated/FILETIME parsing, the
exact area P1.6 (625f4f8) fixed a real bug in) once the fuzzer stumbles onto
valid-ish JSON.

Run:  python tools/fuzz/fuzz_windows_eventlog.py -atheris_runs=200000
      python tools/fuzz/fuzz_windows_eventlog.py -max_total_time=600   # nightly CI (10 min)
"""
from __future__ import annotations

from _common import run
from parsers.windows_eventlog import WindowsEventLogParser

if __name__ == "__main__":
    run(WindowsEventLogParser(), "windows_eventlog")
