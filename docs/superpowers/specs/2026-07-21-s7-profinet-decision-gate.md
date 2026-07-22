# S7/PROFINET parser: decision gate (2026-07-21)

## Question

`services/ws2-normalization/parsers/opcua_audit.py`'s docstring (v0.4 Track P2)
deferred S7/PROFINET with the reasoning: "S7/PROFINET telemetry is
proprietary-shaped and needs hardware access to fixture honestly." Track X
carried this forward unexamined. This pass re-checks that reasoning before
accepting it again for v0.5.

## What was found

The premise is **partly wrong**. Siemens S7-1200/S7-1500 CPUs (and
SCALANCE/RUGGEDCOM network gear) have a real, publicly documented,
**structured** security-event feed: standard syslog (RFC 5424 framing —
timestamp, hostname, app-name, MSGID, structured-data, message body),
configurable to ship straight to a syslog collector. This is not
proprietary-shaped in the way raw S7comm/PROFINET wire protocol traffic is —
it is exactly the same class of source as `linux_ssh.py` or `cisco_asa.py`
(a vendor's own syslog export), and the general syslog *framing* is
unambiguous public spec (RFC 5424), same as any other syslog-based parser
in this repo.

Sources (public, unauthenticated web search; the primary vendor PDF found
during this pass required a Siemens support login and returned HTTP 403
when fetched — see "What's still missing" below):
- Siemens Industry Online Support: "Sending SIMATIC S7-1200/S7-1500 CPU
  Security Messages via Syslog to SINEC INS" (support.industry.siemens.com,
  doc ID 51929235).
- Siemens Industry Online Support: "Syslog Security Events SCALANCE &
  RUGGEDCOM Network components" (doc ID 109805218).
- TIA Portal online documentation, "Structure of the Syslog messages" /
  "Syslog messages" sections (docs.tia.siemens.cloud), confirming RFC 5424
  framing and a worked PRI-value example (facility 20 "local use 4",
  severity 5 "Notice" → priority 165).

## What's still missing (why no parser ships this pass)

The framing (RFC 5424 syslog) is confirmed public. The actual **content
vocabulary this repo would need to classify events honestly** — the specific
MSGID values or message-body patterns Siemens uses for "unauthorized access
attempt", "configuration changed", "firmware update", etc. (the OT-relevant
distinctions `ot_config_change.yml`/`ot_write_outside_maintenance.yml`
already key on for OPC UA) — lives inside the two vendor PDFs above, both of
which sit behind a Siemens Industry Online Support login (confirmed: a
direct fetch of doc 109805218 during this pass returned HTTP 403, not a
public 200). Writing a parser that guesses plausible-looking MSGID values
from a search-result summary, without ever having read the real enum, would
be fabricating a fixture and calling it "spec-derived" when it isn't —
exactly the failure mode the opcua_audit.py precedent's honesty discipline
exists to prevent. TIA Portal's own audit-trail export (a second candidate
source, engineering-workstation-side rather than CPU-side) is real but its
field-level export schema wasn't findable in public documentation either
during this pass (only high-level "how to export" guidance, no field list).

## Decision

**Still deferred, but for a narrower and now-evidenced reason**: not
"proprietary-shaped, needs hardware" (that was too broad — the framing is
public) but "the specific event-classification vocabulary is
access-gated, not genuinely undocumented." PROFINET's own wire protocol
remains out of scope regardless (that IS proprietary/binary and would need
either hardware or a licensed protocol dissector, unchanged from the
original reasoning).

## Unblock path (for whoever picks this up next)

1. A Siemens Industry Online Support account (free registration) can likely
   retrieve doc 51929235 and 109805218 directly — re-run this gate with
   read access to the actual MSGID table before writing
   `s7_security_syslog.py`.
2. Once the vocabulary is in hand, the parser is a straightforward RFC 5424
   syslog parser (Python's `email.utils`/manual PRI-byte parsing, no new
   library) mapping MSGID → OCSF class 6003 (API Activity, config-change-
   shaped events, mirroring `ot_config_change.yml`'s pattern) or 3002
   (Authentication, for access-attempt-shaped events), same structure as
   `opcua_audit.py`.
3. A 1-2 rule pack (`ot_s7_unauthorized_access.yml` style) would follow the
   same `siem.source_type` cross-source-scoping discipline every other v0.5
   OT/6003-sharing rule already uses.

## SSOT update

`SSOT.md`'s Track X row for "S7/PROFINET (after OPC UA)" now points at this
file: investigated 2026-07-21, reasoning narrowed and evidenced, still
deferred — not a silent carry-forward of the original (partially incorrect)
justification.
