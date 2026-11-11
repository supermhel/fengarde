# Public labelled data for the ungraded rules — licence record (WP-4.5)

Status: **licence survey recorded 2026-11-06.** Each dataset listed below (the ones
the survey looked at; it is not an exhaustive search of all public data) was
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
| OT `ot_*` (7: config_change, modbus_unauthorized_write[_ticketed], new_device_on_segment, new_engineering_connection, opcua_write_unauthorized_node, write_outside_maintenance) | **HAI 23.05 + HAIEnd 23.05** (HIL-based Augmented ICS; 52 labelled attack scenarios, OPC-UA gateway data collection) | https://github.com/icsdataset/hai | README "License" section: *"This work is licensed under a Creative Commons Attribution-ShareAlike License (CC BY-SA 4.0)"*; the repo's own dataset-metadata table states *"CC BY 4.0"* (discrepancy recorded — both are BY-family with attribution; SA additionally constrains derivatives, not evaluation results) | **Licence cleared; no known fit to any of the 7 `ot_*` rules** (attribution; cite Shin et al., CSET '21; keep the BY-SA-vs-BY discrepancy on record). HAI is process-sensor time-series CSV; the OPC-UA gateway was only the collection path. The 7 rules consume other inputs: `ot_config_change`, `ot_opcua_write_unauthorized_node`, `ot_write_outside_maintenance` need OPC-UA write audit events (OCSF class 6003); `ot_new_engineering_connection` needs OPC-UA audit authentication events (class 3002); `ot_modbus_unauthorized_write` and `_ticketed` need network events (class 4001) tagged `unauthorized_write` with a change ticket id; `ot_new_device_on_segment` needs a new-device network event (class 4001). No HAI file carries any of these, so HAI could not produce an input event for any of the 7 as they stand. Using it would need a sensor-to-OCSF mapping and a different (anomaly-style) rule, not these |
| OT | SWaT (Secure Water Treatment) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | SUTD iTrust dataset page (per the independent PR review's web check on 2026-11-11; not re-fetched when this was edited): free click-through terms and conditions with no named licence; the request form is open to academia **or non-academia**; the terms forbid sharing the data with others, require credit, and the requester's name, organisation and date are published on the site | **NOT cleared for bundling or redistribution** (the no-sharing clause bars committing or shipping the data; it does not by itself bar a local, unredistributed grading run, so "not cleared" for grading is a stricter project choice than the terms require) |
| OT | WADI (Water Distribution) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | same iTrust terms | **NOT cleared** (same reason) |
| OT | EPIC (Electric Power and Intelligent Control) | https://www.sutd.edu.sg/itrust/itrust-labs/datasets/ | same iTrust terms | **NOT cleared** (same reason) |
| OT | Real-world ICS network attack dataset (Nature Scientific Data, 2026) | https://www.nature.com/articles/s41597-026-06738-x | *"CC BY-NC-ND 4.0"* (non-commercial, no derivatives) | **NOT cleared** (NC+ND bar rejection) |
| OT | Morris/UAH ICS Cyber Attack Datasets (gas pipeline, power system) | https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets | cite-the-paper request only; **no explicit licence text** on the page | **NOT cleared** (no licence grant; cite-only is not a redistribution licence) |
| M365 `m365_inbox_rule_external_forward` | **Office 365 Unified Audit Log Dataset (BEC) — invictus-ir** (9,608 real UAL records: inbox-rule manipulation, mailbox-permission abuse, sign-ins) | https://github.com/invictus-ir/o365_dataset | README + LICENSE: *"CC BY 4.0"* — *"reuse freely, just credit Invictus IR"* | **CLEARED to use** (strongest fit in the survey by its README: `New-InboxRule`/`Set-InboxRule` with Forward operations look like the rule's trigger; not checked whether the data exposes the user's own domain, which the rule's external-forward test needs). **Personal data:** these are real victims' audit logs (user principal names, client IPs, mailbox paths). CC BY does not address privacy law. Process locally, never commit the raw data or samples to the repo, and run a data-protection check before any follow-up WP |
| Mail `email_macro_attachment_delivered` | SpamAssassin public mail corpus (6,047 msgs, spam/ham labels) | https://spamassassin.apache.org/old/publiccorpus/ | readme states *"Copyright for the text in the messages remains with the original senders"* (no blanket licence grant; labels are spam/ham, no macro-attachment label) | **NOT fitting** (no macro labels; per-message copyright — not cleared for bundling) |
| Mail | Enron Email Dataset | https://www.cs.cmu.edu/~enron/ | released by FERC/CMU; research tradition, no labelled macro-attachment instances | **NOT fitting** (no macro labels; historical corpus, not mail-gateway attack traffic) |
| Agent `agent_*` (5) + `n8n_*` (2) | — (surveyed: MITRE ATLAS `atlas-data` is technique/case-study knowledge, not tool-call traffic; no public labelled MCP/agent-security log dataset was found in this survey. No exhaustive search was run, so this is "none found", not "none exists") | https://github.com/mitre-atlas/atlas-data | ATLAS corpus licence governs the knowledge base, not traffic data | **No suitable dataset found in this survey → rules stay ungraded** (existing evidence remains the repo's synthetic ATLAS-mapped fixtures) |

## What "cleared" means and what it does NOT mean

- **Cleared-to-use** rows are licence-usable for a future grading WP, not yet
  graded, and licence is all that "cleared" says. HAI has attack-window labels
  on process-sensor time series. It carries none of the event types the 7
  `ot_*` rules read (see the HAI row), so it is not a grading source for those
  rules. Whether HAI is useful for anything else in this project is the
  follow-up WP's decision, not this record's.
- **NOT cleared / NOT fitting** rows are final for this project as-is: terms
  that forbid sharing (SUTD) or an NC/ND licence would put the public
  repo in violation if the data were bundled; a missing licence is a red light, not a grey light.
- Nothing here changes any scorecard row today. The next WP that wants a
  rule graded first shows: dataset downloaded → licence re-verified at fetch
  time → replayed end-to-end → graded → scorecard row updated → and only
  then does the "ungraded until real data exists" marker leave.
