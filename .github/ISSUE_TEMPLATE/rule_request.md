---
name: New detection rule
about: Propose (or volunteer to add) a new detection rule
title: "[rule] "
labels: rule, good first issue
assignees: ''
---

<!--
A rule is a YAML file in contracts/rules/ evaluated by the WS-4 engine
(services/ws4-detection/engine.py). SECURITY.md sec3: the engine EXECUTES rule
files, so a maintainer will review the condition like code before merging --
budget for that, it's not a rubber stamp.

Every rule needs an anti-dormancy fixture: a real (parser, raw payload) pair
that produces an event matching the rule's selections, added to
tools/check_rule_producers.py's FIXTURES dict. `python tools/check_rule_producers.py`
must pass -- a rule whose fields no parser ever emits is a rule that looks
tested but never fires on real data (this has shipped 3 times before this
gate existed; see the tool's own docstring).

Grammar reference: contracts/sigma-convention.md (equality, gt/gte/lt/lte/ne,
not_in allowlists, outside_hours, in, contains -- no eval(), no regex in
contains, by design).
-->

## What does this rule detect?

<!-- The specific behavior/technique, in plain language. e.g. "a single
account failing auth from >=8 distinct source IPs (inverse of brute-force)" -->

## Which OCSF class/parser produces the events this rule needs?

<!-- e.g. "class_uid 3002 (Authentication), from linux_ssh / active_directory /
windows_eventlog" -- if no shipped parser produces this, a parser needs to
land first (see the parser-request template) -->

## Proposed detection logic

```yaml
# sketch of the detection: block -- doesn't need to be final YAML, just the
# selections/condition/threshold you have in mind
```

- Single-shot or stateful (threshold + window)?
- If stateful: `group_by` field, `threshold`, `window_seconds`
- Proposed `level` (informational/low/medium/high/critical) and reasoning

## False-positive scenario(s)

<!-- What legitimate activity could also match this? Every shipped rule's
YAML description states this explicitly -- see contracts/rules/*.yml for the
convention. A rule with no plausible FP story either isn't specific enough
or hasn't been thought through yet. -->

## Anti-dormancy fixture

<!-- The real (parser, raw payload) pair that will prove this rule is
reachable -- see tools/check_rule_producers.py's FIXTURES dict for the
format each parser uses. -->

```json
{"raw": "paste a representative raw line or JSON payload here (REDACT any real IPs, users, secrets)"}
```

## Are you volunteering to implement it?

- [ ] Yes — I'll open a PR (rule YAML + anti-dormancy fixture + `python tools/validate_rules.py` and `python tools/check_rule_producers.py` both green)
- [ ] No — requesting someone else pick it up
