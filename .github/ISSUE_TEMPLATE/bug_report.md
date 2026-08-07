---
name: Bug report
about: Something in the FENGARDE pipeline isn't working as documented
title: "[bug] "
labels: bug
assignees: ''
---

<!--
Before filing: check the "What's real" table in the README (or SSOT.md for the
full authoritative status) — most of the pipeline is real and working, so a
mismatch there is usually a genuine bug, not an unimplemented feature. The
only parsers still genuinely deferred are SNMP, NetFlow, custom JSON, a
proxy/web-gateway parser, and S7/PROFINET (see README's Planned table) — a
report about any of these five is a feature request, not a bug. WS-5 AI
triage is real (local Ollama by default, with a documented stub fallback when
OLLAMA_URL is unset/unreachable) — a wrong/missing verdict when Ollama is
actually configured and reachable IS a bug.
-->

## What happened

A clear description of the bug.

## What you expected

What should have happened instead.

## Steps to reproduce

1.
2.
3.

## Which workstream / service

<!-- e.g. ws2-normalization, ws4-detection, the dashboard, infra/docker-compose -->

## Logs / output

```
paste relevant logs, stack traces, or test output here
```

## Environment

- OS: <!-- Linux / macOS / Windows+WSL2 -->
- Ran via: <!-- make demo / make test / docker compose / python test_contract.py -->
- Docker version (if relevant): <!-- docker --version -->
- Did `make preflight` pass? <!-- yes / no -->
- Commit / version:

## Anything else

<!-- If this is a security vulnerability, do NOT file it here — see SECURITY.md. -->
