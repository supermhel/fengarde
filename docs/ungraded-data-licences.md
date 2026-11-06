# Public labelled data for the ungraded rules — licence record (WP-4.5)

Status: **licence survey recorded 2026-11-06.** Every dataset below was
checked AT its source (licence text/README read on the linked page, not from
a secondary citation) before a verdict was recorded. The verdicts decide
which public data MAY legally be used to grade FENGARDE's currently ungraded
rule families. **Nothing in this WP downloads, ingests, or commits any of
this data** — it is the licence record the brief asked for.

## Governing statement (the bar)

**Ungraded rules stay ungraded until real data exists.** A rule whose grade
today rests only on synthetic fixtures (the repo's own attack fixtures,
twin/oracle scenarios) is reported as ungraded — scorecard and benchmark
already keep fixture-only rules out of the graded columns
(`untested_rules`, fixture lanes never folded into corpus confusion; see
`eval/detection_accuracy/attack_fixtures.py`). Adding a dataset to this
record does NOT grade anything; a follow-up WP must fetch it, replay it
through the real WS-2→WS-4→WS-8 path into OCSF, and grade it before any rule
leaves the ungraded column.

The repo is **Apache-2.0**. CC BY / CC BY-SA data are compatible to *use*
with attribution (metrics/report output is not an adaptation of the data; a
derived dataset committed to the repo would carry the dataset's own licence
+ attribution). NC (non-commercial) and ND (no-derivatives) data are NOT
usable in a public open-source project's pipeline and are rejected below.

## Verified datasets per family

| Family (rules) | Dataset | URL (checked 2026-11-06) | Licence (verbatim source clause) | Verdict |
|---|---|---|---|---|
| OT `ot_*` (7: config_change, modbus_unauthorized_write[_ticketed], new_device_on_segment, new_engineering_connection, opcua_write_unauthorized_node, write_outside_maintenance) | **HAI 23.05 + HAIEnd 23.05** (HIL-based Augmented ICS; 52 labelled attack scenarios, OPC-UA gateway data collection) | https://github.com/icsdataset/hai | README "License" section: *"This work is licensed under a Creative Commons Attribution-ShareAlike License (CC BY-SA 4.0)"*; the repo's own dataset-metadata table states *"CC BY 4.0"* (discrepancy recorded — both are BY-family with attribution; SA additionally constrains derivatives, not evaluation results) | **CLEARED to use** (attribution; cite Shin et al., CSET '21; keep the BY-SA-vs-BY discrepancy on record) |
| OT | SWaT (Secure Water Treatment) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | SUTD iTrust request-based download under a research licence agreement | **NOT cleared** (request + agreement; not a public OSS-downloadable licence) |
| OT | WADI (Water Distribution) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | same iTrust agreement regime | **NOT cleared** |
| OT | EPIC (Electric Power and Intelligent Control) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | same iTrust agreement regime | **NOT cleared** |
| OT | Real-world ICS network attack dataset (Nature Scientific Data, 2026) | https://www.nature.com/articles/s41597-026-06738-x | *"CC BY-NC-ND 4.0"* (non-commercial, no derivatives) | **NOT cleared** (NC+ND bar rejection) |
| OT | Morris/UAH ICS Cyber Attack Datasets (gas pipeline, power system) | https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets | cite-the-paper request only; **no explicit licence text** on the page | **NOT cleared** (no licence grant; cite-only is not a redistribution licence) |
| M365 `m365_inbox_rule_external_forward` | **Office 365 Unified Audit Log Dataset (BEC) — invictus-ir** (9,608 real UAL records: inbox-rule manipulation, mailbox-permission abuse, sign-ins) | https://github.com/invictus-ir/o365_dataset | README + LICENSE: *"CC BY 4.0"* — *"reuse freely, just credit Invictus IR"* | **CLEARED to use** (strongest fit in the survey: `New-InboxRule`/`Set-InboxRule` with Forward operations are exactly the rule's trigger) |
| Mail `email_macro_attachment_delivered` | SpamAssassin public mail corpus (6,047 msgs, spam/ham labels) | https://spamassassin.apache.org/old/publiccorpus/ | readme states *"Copyright for the text in the messages remains with the original senders"* (no blanket licence grant; labels are spam/ham, no macro-attachment label) | **NOT fitting** (no macro labels; per-message copyright — not cleared for bundling) |
| Mail | Enron Email Dataset | https://www.cs.cmu.edu/~enron/ | released by FERC/CMU; research tradition, no labelled macro-attachment instances | **NOT fitting** (no macro labels; historical corpus, not mail-gateway attack traffic) |
| Agent `agent_*` (5) + `n8n_*` (2) | — (surveyed: MITRE ATLAS `atlas-data` is technique/case-study knowledge, not tool-call traffic; no established public labelled MCP/agent-security log dataset exists as of 2026-11-06) | https://github.com/mitre-atlas/atlas-data | ATLAS corpus licence governs the knowledge base, not traffic data | **NO suitable dataset exists → rules stay ungraded** (existing evidence remains the repo's synthetic ATLAS-mapped fixtures) |

## What "cleared" means and what it does NOT mean

- **Cleared-to-use** rows are licence-usable for a future grading WP, not yet
  graded. HAI covers the OT *anomaly-scale* semantics (process/config/write
  anomalies during attack windows); its labels are attack-window labels, not
  per-record "unauthorized node write" semantics, so even with HAI the
  authorization-semantics rules (`opcua_write_unauthorized_node`,
  `modbus_unauthorized_write`) will likely need fixture+real-data hybrid
  grading — the real data exercises the family, the fixtures pin the
  authorization semantics. That decision is the follow-up WP's, not this
  record's.
- **NOT cleared / NOT fitting** rows are final for this project as-is: a
  request-based academic licence or an NC/ND licence would put the public
  repo in violation; a missing licence is a red light, not a grey light.
- Nothing here changes any scorecard row today. The next WP that wants a
  rule graded first shows: dataset downloaded → licence re-verified at fetch
  time → replayed end-to-end → graded → scorecard row updated → and only
  then does the "ungraded until real data exists" marker leave.