---
name: Parser request
about: Request (or volunteer to add) a parser for a new log source
title: "[parser] "
labels: parser, good first issue
assignees: ''
---

<!--
Adding a parser is the best first contribution to FENGARDE — and needs NO Docker.
The whole loop is: copy services/ws2-normalization/parsers/linux_ssh.py, make 3
edits, run `python test_contract.py`. See docs/adding-a-parser.md.

17 parsers already ship (see README's "What's real" table for the full list).
Still genuinely deferred: SNMP, NetFlow, custom JSON, a proxy/web-gateway
parser, S7/PROFINET (see README's Planned table) — check there before filing
a duplicate for one of these five.
-->

## Source / product

<!-- e.g. "pfSense firewall syslog", "Okta system log", "AWS CloudTrail" -->

## `source_type` string

<!-- The value that will arrive in raw["source_type"], e.g. "pf_sense" -->

## Sample raw log line(s)

```
paste 1-3 representative raw lines or JSON payloads (REDACT any real IPs, users, secrets)
```

## Proposed OCSF mapping

- OCSF class (`class_uid`): <!-- e.g. 3002 Authentication, 4001 Network Activity -->
- activity_id(s): <!-- per contracts/ocsf-classes.md -->
- sector: <!-- bank | datacenter | common -->
- Fields to populate: <!-- e.g. src_endpoint.ip, actor.user.name, dst_endpoint.ip -->

## Are you volunteering to implement it?

- [ ] Yes — I'll open a PR (see docs/adding-a-parser.md)
- [ ] No — requesting someone else pick it up
