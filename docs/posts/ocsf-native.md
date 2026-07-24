# OCSF-native SIEM: normalize once, stay portable

![FENGARDE architecture: AI-agent/MCP tool-call logs and OT protocol data normalize into OCSF, then flow through the detection engine into AI-abuse, Modbus-anomaly, and OCSF-normalization rule sets, each independently verified against the CI gate.](fengarde-architecture.png)

*Draft technical write-up — v0.4. Facts checked against the codebase as of this
commit; update if the pipeline changes before publishing.*

Most self-hosted SIEMs retrofit a common schema onto whatever their parsers
already produce — a per-vendor field name here, an ECS-flavored mapping there,
a "normalized" event that's really just the least-common-denominator of
whatever sources happened to exist when the schema was bolted on.

FENGARDE does it the other way: [OCSF](https://schema.ocsf.io/) (the Open
Cybersecurity Schema Framework) is the *only* shape a normalized event is
allowed to have, from the very first parser. Every one of FENGARDE's parsers —
Cisco ASA, Active Directory, VMware vSphere, Linux SSH, generic syslog,
Windows Event Log, DB audit, and as of v0.4 an MCP/AI-agent tool-call parser,
an OPC UA industrial-control parser, and an n8n automation-platform parser —
turns its source-specific input into the same `class_uid`/`activity_id`/
`type_uid` structure, validated in CI against a frozen JSON schema
(`contracts/ocsf-event.schema.json`).

## Why this matters more than it sounds

A brute-force detection rule written against OCSF's Authentication class
(3002) works identically whether the failed login came from `sshd`, Active
Directory, or — new in v0.4 — an OPC UA engineering session. The rule doesn't
know or care which parser produced the event. That's the actual payoff of
schema-first design: **instrument once, detect everywhere.** Add a tenth
parser next month and every existing authentication rule already covers it.

## What "OCSF-native" costs

Discipline, mostly. Every parser derives `type_uid` from `class_uid` +
`activity_id` (never hand-set — `services/ws2-normalization/parsers/base.py`
enforces this in one shared helper) so a copy-paste bug can't silently produce
an inconsistent id. A CI gate (`tools/validate_contract.py`) rejects any event
that doesn't validate. And an anti-dormancy check
(`tools/check_rule_producers.py`) proves every rule's field references are
actually satisfiable by some parser's real output — catching the class of bug
where a rule references a field nothing emits, which has shipped (and been
caught) three times in this repo's history.

## The v0.4 proof point

Adding OPC UA (industrial control-system audit events) and MCP (AI-agent
tool-call logs) — two sources with *nothing* in common at the wire-format
level — took one parser module each, following the exact same pattern as the
very first parser (`linux_ssh.py`). No detection-engine change. No dashboard
change. That's what "OCSF-native, not retrofitted" is supposed to buy you.

*Feedback and corrections welcome — this is a working system, not a spec
document. Read the actual parsers at
[`services/ws2-normalization/parsers/`](../../services/ws2-normalization/parsers/).*
