# Launch Post Drafts

> **Historical (v0.1.0 era) — facts below are stale** (4 parsers, no AI triage yet).
> Current architecture write-ups: [`ocsf-native.md`](ocsf-native.md),
> [`opensearch-not-elastic.md`](opensearch-not-elastic.md),
> [`local-ai-triage.md`](local-ai-triage.md). Launch sequencing:
> [`launch-checklist.md`](launch-checklist.md). Keep this file as a draft-style
> reference for tone/structure, not current facts.

---

## Show HN

**Title:** Show HN: ARGIEM – open-source SIEM with OCSF normalization and brute-force detection

**Body:**

I built ARGIEM because I wanted a self-hosted security monitor for my homelab that didn't require a Splunk license or a Zabbix instance bolted onto an ELK stack. Everything runs offline; there is no call-home and no cloud dependency.

**What it does today (v0.1.0)**

- Parses logs from four sources: Linux SSH auth.log, Cisco ASA syslog, Windows AD EventID 4625, and VMware vSphere.
- Normalizes every event to OCSF (Open Cybersecurity Schema Framework) before anything touches the detection layer. Schema contracts are committed to the repo and validated in CI.
- Runs a brute-force detection rule: 10 failed authentications from one IP within 60 seconds fires an alert. Threshold and window are YAML — no code change to tune.
- Indexes alerts in OpenSearch and shows them in a browser dashboard. nginx handles the reverse proxy so there is no CORS wrestling.
- Ships with a devkit-feeder container that injects a synthetic attack sequence on `docker compose up`. You see a real alert in the dashboard in under a minute with no manual setup.

**Honest about what is not there yet**

- Only 4 parsers. Adding a new source means writing a small Python class, but it is still manual work.
- The AI triage feature (local LLM classifying alert severity) is a planned v0.2 item. The stub is in the codebase but it does nothing useful in v0.1.
- No RBAC, no multi-tenancy, no alerting integrations (PagerDuty, Slack, etc.) yet.

**Architecture decisions that might interest HN**

The message bus is abstracted behind a single interface. Tests use an in-memory backend (zero infrastructure, `make e2e` passes in CI with no Docker). Production uses Redis Streams. Services never import a concrete backend, so swapping transports is a one-line config change.

Alert IDs are deterministic hashes of the triggering evidence. Re-processing the same log stream produces identical alert IDs, which makes the pipeline idempotent under at-least-once delivery without a deduplication table.

Apache-2.0. Repo: https://github.com/supermhel/argiem

Happy to answer questions about the OCSF normalization layer or the detection architecture.

---

## Reddit Posts

### r/netsec

**Title:** ARGIEM – open-source SIEM with OCSF normalization, brute-force detection, and a full CI-gated detection pipeline

**Body:**

I've been working on an open-source SIEM called ARGIEM and just tagged v0.1.0. Sharing here because the design decisions might be interesting to people who think about detection pipelines.

**What it does**

ARGIEM is a self-hosted, offline-capable SIEM. The pipeline is: collect logs → normalize to OCSF → run detection rules → index in OpenSearch → browser dashboard.

Current detection: brute-force rule (10 failed auth / 60 s / per source IP). Threshold and window are YAML-configurable.

Current parsers: Linux SSH auth.log, Cisco ASA syslog, Windows AD EventID 4625 (failed logon), VMware vSphere.

**Design choices worth noting**

- All events are normalized to OCSF before detection. The contracts (OCSF schemas, OpenAPI, Sigma) are committed and validated in CI. Detection rules never see raw log strings.
- The message bus is abstracted. Tests use in-memory; production uses Redis Streams. `make e2e` runs the full pipeline with zero infrastructure.
- Alert IDs are deterministic hashes of evidence. Idempotent under at-least-once delivery.
- Global sliding-window counters live in Redis sorted sets so multi-replica deployments share state correctly.
- gitleaks runs in CI on every push.

**What it is not (yet)**

- 4 parsers only. More coverage is the next priority.
- Local AI triage is v0.2 (stub exists, does nothing in v0.1).
- No alerting integrations, no RBAC.

**Try it**

```
git clone https://github.com/supermhel/argiem
cd argiem
docker compose up
```

The devkit-feeder fires a synthetic brute-force sequence automatically. Open the dashboard and you should see an alert within ~60 seconds.

Asciinema demo: https://github.com/supermhel/argiem/blob/main/argiem-demo.cast

Apache-2.0. Feedback welcome, especially on the detection architecture and parser coverage gaps.

---

### r/homelab

**Title:** ARGIEM – self-hosted, offline SIEM for your homelab: brute-force detection, OpenSearch dashboard, one `docker compose up`

**Body:**

I've been working on an open-source SIEM called ARGIEM and just tagged v0.1.0. Sharing here because the homelab community cares about self-hosted, privacy-respecting tools and I think this fits that ethos.

**What it does**

ARGIEM monitors your homelab for security events without sending anything to the cloud. The pipeline is: collect logs → normalize to OCSF → run detection rules → index in OpenSearch → browser dashboard.

Right now it detects brute-force login attempts (10 failed auths from one IP in 60 seconds) and parses logs from: Linux SSH, Cisco ASA, Windows Active Directory, VMware vSphere.

**Getting started**

```
git clone https://github.com/supermhel/argiem
cd argiem
docker compose up
```

That's it. A feeder container automatically replays a sample brute-force attack so you can see an alert in the dashboard without configuring any log sources first. Useful for getting a feel for the system before pointing it at real infrastructure.

**Honest about scope**

This is early-stage. Only 4 log parsers today. A local-AI triage feature (classify alert severity with a local LLM, no cloud) is planned for v0.2 but is not in v0.1. No Slack/Discord/PagerDuty alerting yet.

If you're running pfSense, OPNsense, or other common homelab gear and want to contribute a parser, contributions are very welcome.

Asciinema demo: https://github.com/supermhel/argiem/blob/main/argiem-demo.cast

Repo: https://github.com/supermhel/argiem — Apache-2.0.
