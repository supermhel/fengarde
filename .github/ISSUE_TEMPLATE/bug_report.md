---
name: Bug report
about: Something in the ARGIEM pipeline isn't working as documented
title: "[bug] "
labels: bug
assignees: ''
---

<!--
Before filing: ARGIEM v0.1 is the detection PIPELINE. The AI service (WS-5) is a
documented passthrough stub and the 5 deferred parsers (generic syslog, SNMP,
NetFlow, Windows Event Log, custom JSON) are NOT implemented in v0.1 — those are
feature requests, not bugs. See the "What's real in v0.1" table in the README.
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
