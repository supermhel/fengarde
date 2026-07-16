"""Log-injection defense (M1 correctness gate, PLAN_C Tier 1.2).

Attacker-controlled log content lands in OCSF free-text fields (``message``,
usernames/hostnames pulled out of a raw line by a parser's regex) and from
there reaches two places that are NOT covered by the dashboard's HTML-escaping
(``esc()`` in ``services/ws7-dashboard/index.html``, which only handles
browser DOM XSS):

  1. A terminal — ``tools/dlq_peek.py``, ``docker logs``, an analyst's shell
     piping a report through ``cat``. ANSI escape sequences here aren't a
     cosmetic problem: OSC 52 can inject the analyst's clipboard, CSI cursor
     tricks can overwrite what a previous line printed to hide/spoof output.
  2. Any newline-delimited log sink. A raw ``\\r``/``\\n`` inside a field
     lets one malicious event's field forge what looks like a second,
     independent log line -- classic log injection.

``strip_ansi_and_control`` is the fix: applied once, at the single choke point
every parser already funnels through (``Parser.base_event()``'s ``message``
param), so no per-parser change is needed.
"""
from __future__ import annotations

import re
from typing import Optional

# ESC (\x1b) starting a CSI (Control Sequence Introducer, `\x1b[...<final-byte>`),
# an OSC (Operating System Command, `\x1b]...BEL-or-ST`), or any other two-byte
# escape (`\x1b` + one more char, the common case for e.g. `\x1bc` reset).
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_ANSI_OTHER = re.compile(r"\x1b.")

# C0 control chars (0x00-0x1F) and DEL (0x7F), EXCEPT plain tab -- stripping
# tab too would mangle otherwise-legitimate tabular log content for no
# security benefit (tab can't forge a new line or move the cursor).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def strip_ansi_and_control(value: Optional[str]) -> Optional[str]:
    """Remove ANSI escape sequences and C0/DEL control chars (tab excepted)
    from a string. ``None`` and non-str input pass through unchanged (the
    caller's own type contract, not this function's problem to enforce).
    Bounded, no backtracking risk (fixed-class regexes, no nested quantifiers)
    -- safe to run on attacker-controlled input, no ReDoS."""
    if not isinstance(value, str):
        return value
    value = _ANSI_OSC.sub("", value)
    value = _ANSI_CSI.sub("", value)
    value = _ANSI_OTHER.sub("", value)
    value = _CONTROL_CHARS.sub("", value)
    return value
