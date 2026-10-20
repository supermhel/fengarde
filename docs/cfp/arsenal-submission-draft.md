# Black Hat Asia 2027 Arsenal: submission draft (FENGARDE)

Draft for the owner to edit and submit. It is not committed to the public repo. Every claim
below is checked against the repo (`origin/main` at 46d690f (v0.11.0; re-check claims before submitting)) or the demo fixtures. The
"Claims check" table at the end lists the source for each number. Fill in the presenter bio
and the form's own field names yourself; check the current CFP page for word limits.

---

## Title

FENGARDE: One Open-Source Pipeline for IT, OT and AI-Agent Security Telemetry

(Alternatives: "From Prompt Injection to PLC Write: Correlating AI-Agent and OT Telemetry in an
Open-Source SIEM" · "FENGARDE: An OCSF-Native, Self-Hosted SIEM That Shows Its Evidence")

## Short description (~80 words)

FENGARDE is an open-source (Apache-2.0), self-hosted SIEM pipeline. It normalizes IT, OT and
AI-agent logs into one OCSF schema, runs sliding-window detection rules, correlates alerts into
multi-stage incidents, and shows the evidence behind every conclusion. The same engine covers
SSH brute-force, a prompt-injected AI agent reaching for credentials, and an out-of-range Modbus
write on a PLC. AI triage stays on your network, and a deterministic NIS2 notification draft is
one click away.

## Full description (~350 words)

Security teams at small manufacturers face three telemetry worlds with three toolchains: office
IT, the plant floor (OT), and now AI agents that call tools on their behalf. FENGARDE puts all
three through one pipeline.

Nineteen parsers (SSH, Windows Event Log, Sysmon, Active Directory, Cisco ASA, CloudTrail,
Kubernetes audit, CEF, n8n, MCP/AI-agent tool-call audit, OPC UA, a Modbus/TCP protocol-anomaly
detector and more) normalize into the open OCSF schema. One rule therefore covers every source
that emits the same event. Thirty-six detection rules run over sliding windows with
deterministic alert IDs, so replays and at-least-once redelivery never duplicate an alert. A
correlation service promotes a track (an actor, an IP or a device) to an incident once its alerts
span at least two distinct tactics. It emits an entity graph, and on request it builds a
hash-chained evidence package for the whole incident.

The Arsenal demo walks through a scripted attack run through the real pipeline code:
- An n8n automation exposes a webhook out of hours.
- An AI agent's tool call carries a prompt-injection indicator, reaches a non-allowlisted domain
  and reads credential material.
- A Modbus/TCP write lands outside the PLC's expected address range.

FENGARDE correlates those seven alerts across MITRE ATT&CK, ATLAS and ATT&CK for ICS into one
incident. It then drafts a German or English NIS2 incident notification (Art. 23 NIS2, §32 BSIG)
deterministically, with no LLM involved.

Two design choices matter to us:
- **Honesty is a feature.** Every empty state says why it is empty, AI verdicts name the backend
  that produced them (local Ollama or a documented stub), and our detection numbers ship with
  their limits: macro-F1 0.875 on our own labelled fixtures, and 43.2% parser coverage of public
  external corpora.
- **Nothing leaves your network.** AI triage runs locally, storage is OpenSearch, and every
  service talks to the others only through a message bus with frozen contracts.

Attendees can run the full detection pipeline in seconds with no Docker
(`python tools/demo_e2e.py`). They can bring the whole stack up with `make demo`, or click
through the hosted demo.

## What attendees will see at the station

1. **Live console:** the scripted IT and AI → OT attack, alert by alert, with each rule's "Why"
   (rule, MITRE mapping, AI verdict and its backend).
2. **Incident view:** the correlated incident, its causal entity graph, and the evidence package
   being built and verified.
3. **NIS2 draft:** generated live in German and English, plus the fields an analyst still has to
   fill in.
4. **Detection coverage:** which techniques the 36 rules cover and which they do not.
5. **Bring your own logs:** adding a parser takes about 30 minutes (`docs/adding-a-parser.md`).

## Suggested tracks / categories

ICS/IoT · Threat Detection / Blue Team · AI, ML & Data Science (pick what the CFP offers)

## Links for the form

- Code: https://github.com/supermhel/fengarde
- Live demo (the real console on a recording of a lab run, embedded in the
  project page): https://supermhel.github.io/fengarde/demo/
- Project page with recorded walkthroughs (four chapters, real console, real
  UDP attack): https://supermhel.github.io/fengarde/
- One-pager: `docs/demo/fengarde-onepager.pdf`

## Claims check

| Claim | Source |
|---|---|
| 19 parsers | README.md "Parsers (17)" table row; `services/ws2-normalization/parsers/` |
| 36 rules | `contracts/rules/` (36 files); the dashboard shows "36 rules loaded" |
| macro-F1 0.875, parser coverage 43.2% | latest `eval/trend.jsonl` row |
| 7 alerts, 6 tactics, 1 incident | `docs/demo/fixtures.json` (`/api/incidents`, incident `acme:ip:10.20.0.50:20271`) |
| NIS2 draft DE/EN, deterministic | `services/ws3-indexer/nis2_template.py`; demo fixture reports |
| Local AI triage + stub, verdict names backend | README; the demo "Why" panel shows "AI triage (high, stub)" |
| Correlation rule (≥ 2 distinct tactics) | dashboard Incidents view copy; `services/ws8-correlation/correlator.py` |

**Do not claim** (not true today): IT → OT correlation across *different* hosts (the SSH
brute-force in the demo is a separate source, not part of the incident); customers, design
partners or production installs; Kafka support; an independent benchmark result.

## Presenter bio

_(owner to write)_
