# OCSF Version Assessment (WP-4.2)

**Date:** 2026-11-04
**Branch:** `wp/4.2-ocsf-version-assessment` (base `origin/main` `921d75b`)
**Type:** READ-ONLY assessment. **No schema, parser, or code change was made anywhere in this repo.** Recommendation only; the owner decides.

**Premise under test:** the roadmap claims FENGARDE's parsers emit `metadata.version` `1.1.0` at
`services/ws2-normalization/parsers/base.py:193`, and that current OCSF is `1.8.0`, released 2026-03-16.

**Evidence labels used in this document:**

- **VERIFIED** — read directly in this repo (file:line cited).
- **READ** — read from a web source (URL cited).
- **ASSUMED** — reasoned inference not backed by a direct read.

---

## 0. Premise verification

**VERIFIED.** `services/ws2-normalization/parsers/base.py` builds the OCSF `metadata` block in
`Parser.base_event()`:

```python
# base.py:189-201
category_uid = class_uid // 1000  # floored, per Contract A
meta = meta or {}
event = {
    "metadata": {
        "version": "1.1.0",                  # <-- base.py:193
        "schema_version": SCHEMA_VERSION,
        "product": dict(self.PRODUCT),
        "original_format": self.ORIGINAL_FORMAT,
    },
    "class_uid": class_uid,
    "category_uid": category_uid,
    "activity_id": activity_id,
    "type_uid": make_type_uid(class_uid, activity_id),  # derived, never hand-set
    "severity_id": severity_id,
    "time": time_ms,
    "siem": { ... },
}
```

- The version string is **hardcoded once** and shared by every parser: no parser module constructs
  `metadata` itself (repo-wide grep for `"metadata"` under `services/ws2-normalization/parsers/*.py`
  outside `base.py` returns zero hits) — **VERIFIED**.
- Every parser output therefore carries `metadata.version = "1.1.0"`: all 19 built-in parsers
  subclass `Parser` and build events through `base_event()` (each `parse()` calls
  `self.base_event(class_uid=..., ...)`, e.g. `linux_ssh.py:135`, `sysmon.py:219`,
  `windows_eventlog.py:272`), and plugin parsers (`parsers/plugins.py`) must also subclass `Parser`
  and get the same envelope — **VERIFIED**.
- `make_type_uid` is `class_uid * 100 + activity_id` (`services/shared/ocsf.py:42-44`) — the
  `type_uid == class_uid*100 + activity_id` invariant is enforced by `tools/validate_contract.py`
  (module docstring, lines 3-5) — **VERIFIED**.
- **Premise: CONFIRMED as stated.** The roadmap's line reference (base.py:193) is exact.

---

## (a) What FENGARDE emits today (verified inventory)

### (a.1) The shared envelope (every normalized event)

Every event emitted on `normalized.events` (Contract A) carries — **VERIFIED** (`base.py:189-218`,
`contracts/ocsf-event.schema.json`):

| Field | Source | Notes |
|---|---|---|
| `metadata.version` | `base.py:193` | Hardcoded `"1.1.0"`. Schema: `type: string`, description "OCSF schema version, e.g. 1.1.0" (`contracts/ocsf-event.schema.json:23`). No enum, no pattern — any string validates. |
| `metadata.schema_version` | `base.py:194` + `services/shared/envelope.py:23` | Envelope-v1 contract version (`"1.0"`) — **not** the OCSF version; see `contracts/bus-topics.md` "Envelope v1" and the schema's own field description (`ocsf-event.schema.json:35`). Do not conflate (this doc does not). |
| `metadata.product` | `base.py:195` | Per-parser `PRODUCT` class attr (`{"name": ...}` minimal, `base.py:150`). |
| `metadata.original_format` | `base.py:196` | Per-parser `ORIGINAL_FORMAT` attr; schema enum `["syslog","snmp","netflow","winevent","cef","leef","json","api"]` (`ocsf-event.schema.json:34`). |
| `metadata.logged_time` | `base.py:212-213` | Optional; ingest time (Envelope v1), distinct from `time`. |
| `class_uid` | `base.py:198` | Schema enum (9 classes) `[3002, 3003, 4001, 4002, 4009, 6003, 6005, 1001, 1002]` (`ocsf-event.schema.json:41`). |
| `category_uid` | `base.py:199` | Derived `class_uid // 1000`; schema enum `[1, 3, 4, 6]`. |
| `activity_id` | `base.py:200` | Per-parser, int 0-99 (schema `ocsf-event.schema.json:48-53`). FENGARDE sets `activity_id`; it does **not** emit `activity_uid` (not part of the schema). |
| `type_uid` | `base.py:201` | Derived via `make_type_uid`; contract test enforces the invariant. |
| `severity_id` | `base.py:202` | Schema enum `[0..6]` (`ocsf-event.schema.json:58-62`). FENGARDE does **not** emit `severity` string sibling. |
| `time` | `base.py:203` | Event time, epoch ms. |
| `siem.*` | `base.py:204-210` | `sector`, `source_type`, `ingest_id`, `trace_id`, `tenant` (schema `ocsf-event.schema.json:88-103`, required `sector/source_type/ingest_id`). |
| `status` | `base.py:214-215` | Optional; **string** enum `["Success","Failure","Unknown"]` (`ocsf-event.schema.json:65`). FENGARDE does **not** emit `status_id` (see (c.6)). |
| `message` | `base.py:216-217` | Optional human-readable summary. |
| `src_endpoint`/`dst_endpoint` | parsers | Schema `$defs/endpoint` (`ocsf-event.schema.json:106-120`): `ip` (pattern), `mac` (pattern), `hostname`, `port`. |

`additionalProperties: true` at the top level (`ocsf-event.schema.json:17`) is why FENGARDE's
`unmapped.*` extension blocks and `siem.*` additions validate — **VERIFIED**.

### (a.2) OCSF classes produced, and which parsers produce them (all VERIFIED: constant definition file:line)

| class_uid | Class (per `contracts/ocsf-classes.md`) | Produced by (parser:line of the constant) |
|---|---|---|
| 1001 | File System Activity (System) | `sysmon.py:110` (`_CLS_FILE`) |
| 1002 | Kernel / Process Activity (System) | `generic_syslog.py:37`, `sysmon.py:108` (`_CLS_PROC`), `windows_eventlog.py:68` (`_CLS_PROC`) |
| 3002 | Authentication (IAM) | `active_directory.py:26`, `cef.py:32`, `cloudtrail.py:30`, `linux_ssh.py:35`, `m365_audit.py:37`, `n8n_audit.py:32`, `opcua_audit.py:46`, `windows_eventlog.py:67` (`_CLS_AUTH`) |
| 3003 | Account Change (IAM) | `windows_eventlog.py:69` (`_CLS_ACCT`) |
| 4001 | Network Activity (Network) | `cef.py:33`, `cisco_asa.py:59`, `inventory_diff.py:25`, `modbus_anomaly.py:77`, `sysmon.py:109` (`_CLS_NET`) |
| 4002 | DNS / HTTP Activity (Network) | `dns_query.py:31` |
| 4009 | Email Activity (Network) | `mail_gateway.py:33` (`_CLASS_EMAIL`) |
| 6003 | API Activity (Application) | `cloudtrail.py:31`, `k8s_audit.py:35`, `m365_audit.py:38`, `mcp_agent.py:67`, `n8n_audit.py:31`, `opcua_audit.py:47`, `vmware_vsphere.py:23` |
| 6005 | Datastore Activity (Application) | `db_audit.py:32` |

Registrations: `parsers/__init__.py` `_REGISTRY` + plugin discovery (`parsers/plugins.py`).
Activity sets per class are documented in `contracts/ocsf-classes.md` ("Common activity_id values");
several are deliberately project-local (see (a.3)).

### (a.3) Documented divergences from upstream OCSF semantics (pre-existing design, VERIFIED)

- Class 1002 uses **project-local activity ids**: "Project-local ids, not OCSF's Process Activity
  ids; `3` is shared by two meanings" (`contracts/ocsf-classes.md`); `windows_eventlog.py`'s module
  docstring: "class_uid enum does not include a dedicated Process Activity class (1007)"
  (`windows_eventlog.py:39` — upstream 1007 `process_activity` exists but is deliberately not used).
- Authentication (3002) is restricted to ids 1/2/3/4; Account Change (3003) to 1-6 (incl. project
  extension "6 Directory Object Modified (5136)"); Network (4001) to 1/2/6/7; Email (4009) to
  1 Send / 2 Receive / 3 Scan; API (6003) to 1-4; Datastore (6005) to 1-5 (`contracts/ocsf-classes.md`).
  Upstream enums are supersets; FENGARDE uses a restricted profile — by design (Contract A).
- `status` string instead of `status_id` integer; no `severity` sibling; no `activity_uid`; no
  `metadata.class_uid/class_name` (upstream OCSF events also carry class_uid at top level, so this is
  not a divergence) — **VERIFIED** against the schema.

### (a.4) Where the OCSF event schema lives and who consumes it

- **Schema source of truth:** `contracts/ocsf-event.schema.json` (Contract A). Validated by
  `tools/validate_contract.py` (`SCHEMA_PATH = ROOT / "contracts" / "ocsf-event.schema.json"`,
  `validate_contract.py:15`), imported by every parser via `services/shared/ocsf.py::validate`
  (`shared/ocsf.py:37-49`). Also referenced from `contracts/ocsf-classes.md` and
  `contracts/bus-topics.md` ("Contract A").
- **ws3-indexer:** no code reads `metadata.version` or `metadata` at all. The only mention of the
  OCSF schema is a comment in `services/ws3-indexer/router.py:81` ("contrast
  contracts/ocsf-event.schema.json's class_uid/type_uid, used elsewhere in this codebase") —
  **VERIFIED** via repo-wide grep of `ws3-indexer` for `metadata`/`ocsf`/`version`.
- **OpenSearch mappings:** `contracts/opensearch-mappings/events-common.json:20-22` (and the
  bank/dc twins) map `metadata.version` as `"type": "keyword"` — any string value is indexable,
  nothing pins `1.1.0` — **VERIFIED**.
- **Search consumers:** WS-4/WS-8/WS-9 rules and correlation key on `class_uid`, `activity_id`,
  `src_endpoint`, `actor`, `siem.*` — not on the version string — **VERIFIED** (rule files in
  `contracts/rules/*.yml`; no rule references `metadata.version`).

---

## (b) What changed between OCSF 1.1.0 and 1.8.0 (READ — release notes)

Source: the official releases page https://github.com/ocsf/ocsf-schema/releases (fetched 2026-11-04),
per-tag notes for 1.4.0/1.5.0/1.8.0. Secondary corroboration: Synqly "OCSF Explained" 
(https://www.synqly.com/ocsf-explained-cybersecurity-integration-standards/, "Version 1.8.0, released
March 16, 2026") and Bidda's OCSF 1.8.0 write-up (https://bidda.com/intelligence/ocsf-open-cybersecurity-schema-framework-1-8-0).

### (b.1) Premise check: 1.8.0 release date

**READ — CONFIRMED.** The 1.8.0 release notes are titled `[v1.8.0] - Mar 16th, 2026`
(https://github.com/ocsf/ocsf-schema/releases/tag/1.8.0). GitHub's "released this" timestamp on the
same page is Mar 18, 2026 (commit `6fa6499`, tag signed/verified); the Bidda article says "released
on 18 March 2026" while Synqly says March 16, 2026. The note-title date (2026-03-16) matches the
roadmap claim; the GitHub publish date is two days later. **Claim substantially verified** — the
discrepancy is the difference between the notes' stated date and the tag-publish timestamp.

### (b.2) Release list 1.1.0 → 1.8.0 (dates from the releases page, READ)

| Release | Stated date (notes) | GitHub publish |
|---|---|---|
| **1.1.0** (FENGARDE's emitted version) | 2024-01-25 | Jan 25, 2024 |
| 1.2.0 | 2024-04-23 | Apr 23, 2024 |
| 1.3.0 | 2024-08-01 | Aug 1, 2024 |
| 1.4.0 | 2025-01-31 | Feb 5, 2025 |
| 1.5.0 | 2025-04-28 | Apr 28, 2025 |
| 1.6.0 | 2025-08-01 | Aug 1, 2025 |
| 1.7.0 | 2025-11-14 | Nov 14, 2025 |
| **1.8.0** | **2026-03-16** | Mar 18, 2026 |
| 1.9.0 (already out at assessment time; post-dates the roadmap claim) | 2026-08-03 | Aug 3, 2026 |

Between 1.1.0 and 1.8.0: **seven minor releases** (1.2.0 … 1.8.0). No 2.x. There are no other
releases between 1.1.0 and 1.8.0 on the page (1.0.0 predates; 1.9.0 follows).

### (b.3) Per-release summary — with focus on the 9 classes FENGARDE uses (READ)

**1.2.0 (2024-04-23).** Added: Data Security Finding; 16 Query event classes (File/Folder/Group/Job/
Kernel Object/Module/Network Connection/Networks/Peripheral Device/Prefetch/Process/Registry Key/
Registry Value/Service/Session/User Query); Tunnel Activity; `data_classification` profile;
`auth_factor` object; `autonomous_system`; `agent`. Improved: **Authentication gets `auth_factors`
array** and a **`Preauth` activity_id**; **Datastore Activity gets List/Encrypt/Decrypt activities**
and the **`security_control` profile**; "Modified all classes such that primary attributes are at
least recommended"; IAM categories get `src_endpoint`/`http_request`. Deprecated: `coordinates`,
`invoked_by`. Breaking changes: **n/a** (explicitly).

**1.3.0 (2024-08-01).** Added: Remediation category; Event Log Activity; Windows Service Activity
(Windows ext.); Software Inventory Info; `osint` profile; JA4 fingerprint; whois; timespan. Improved:
**Network Activity gets a new `Listen` activity and `src_endpoint` requirement relaxed**; application
lifecycle activities; entity-management activities. Deprecated: `resource` in Vulnerability/
Compliance Finding → `resources`. Breaking changes: **n/a** (explicitly).

**1.4.0 (2025-01-31).** Added: Unmanned Systems category; Script Activity; Application Error;
`incident` profile; SCIM/SSO objects; SBOM objects; `process_entity`. Improved: **Email Activity gets
a `Trace` activity_id and `message_trace_uid`**; **Account Change gets `policies` and an `Unlock`
activity**; **Network Activity's `dst_endpoint` requirement relaxed with an `at_least_one`
(src_endpoint, dst_endpoint) constraint**; `actor` added to the IAM base event; base_event host/
security_control profile relocation. No "Breaking changes" section in these notes.

**1.5.0 (2025-04-28).** Added: Application Security Posture Finding; Live Evidence Info;
`authentication_token` object (and **`authentication_token` attribute on Authentication**);
`ldap` added to the `auth_protocol_id` enum; `raw_data_size` on base_event; graph/node/edge objects.
Deprecated: 16 Query classes (including `file_query`, `process_query`) in favor of
`live_evidence_info` (none used by FENGARDE); `user_access.resource` → `resources`. No Breaking
changes section.

**1.6.0 (2025-08-01).** Added: IAM Analysis Finding. Improved: **Authentication gets `Account
Switch` activity_id plus `account_switch_type`/`account_switch_type_id`**; **Email Activity gets an
`MTA Relay` activity and `to`/`from` attributes**; **Network Activity gets
`is_src_dst_assignment_known`**; `process.ptid` added (deprecates `tid`); `metadata.is_truncated`/
`untruncated_size`. Deprecated: `databucket.group` → `groups`; `credential_uid` →
`programmatic_credentials`; `account.type_id` enum items 3/4 (FENGARDE does not use `account.type_id`
— **VERIFIED**: not in the schema, not emitted). No Breaking changes section.

**1.7.0 (2025-11-14).** Added: Peripheral Activity class. Improved: **Account Change gets
`auth_factors` and updated activity names**; **Network base event gets `cumulative_traffic`**;
metadata gains `reporter`, `source`, `type`, `log_source`, `original_event_uid`, `log_format`,
`transmit_time`; Process Activity descriptions. No Breaking changes section, no Deprecated section.

**1.8.0 (2026-03-16).** Added: `ai_operation` profile; `ai_model`/`message_context`/`token`/`gpu_info`/
privilege-analysis objects; **`token` attribute on the `api` object**; `macos` extension; Network
gets `app_protocol_name`, **`packet`/`packet_list`**, `network_observation_point`; **metadata gets
`total_queued_duration`**; `file.signatures`; account `is_disabled`/`is_locked`. **Breaking changes:
exactly one** — the regex constraint on the `file_hash_t` dictionary type was REMOVED
(`#1564`), flagged upstream as "can create a breaking change for some kinds of tooling that process
OCSF events". **FENGARDE impact: none** — no parser emits a file hash (repo grep for `hash` in
parser modules: zero hits — **VERIFIED**). Deprecated: `file.signature` → `file.signatures`.
Also note (from the repo README, READ, https://github.com/ocsf/ocsf-schema): "Passing a version
number to ocsf-lib does not work for 1.8.0 and newer, because schema.ocsf.io rejects the legacy
export/schema API for those releases" — a **tooling** incompatibility for consumers that pull the
upstream schema programmatically; FENGARDE vendors its own restricted schema, so it is not affected.

**1.9.0 (2026-08-03, post-claim context).** Added `user_management`/`role_management`/
`clipboard_activity`/`device_power_state_activity` classes, `record_integrity` profile, IAM-role
objects, and a **DNS Activity restructuring** (`dns_resource_record`, `dns_section`, `tsig` objects;
`transaction_id`, `query_additional`, `response_additional`, `authority`, `key_name` attributes,
`#1634`). The DNS restructuring is the first release in this window that reworks a class FENGARDE
uses (4002, `dns_query.py`) — additively (new objects/attributes, no renumbering), and it landed
*after* the roadmap's 1.8.0 target.

### (b.4) Net change map for the classes FENGARDE uses (READ + ASSUMED)

- **New classes 1.1.0 → 1.8.0:** none of FENGARDE's nine classes were removed, deprecated, renamed,
  or renumbered; all upstream additions were *new* classes in other categories (Findings, Discovery,
  Remediation, Unmanned Systems, Query classes, Peripheral Activity).
- **activity_id enums:** the only 1.1.0→1.8.0 changes in classes FENGARDE uses were **additions**
  (`Preauth` on 3002 in 1.2.0; `Listen` on 4001 in 1.3.0; `Trace` on 4009 and `Unlock` on 3003 in
  1.4.0; `Account Switch` on 3002 and `MTA Relay` on 4009 in 1.6.0). No enum value used by FENGARDE
  (3002: 1-4; 3003: 1-6; 4001: 1/2/6/7; 4002; 4009: 1-3; 6003: 1-4; 6005: 1-5; 1001/1002 project
  local) was renumbered or removed — READ (release notes show only additions) and ASSUMED (not a
  byte-level dictionary diff; renumbering of an enum that FENGARDE uses would have appeared in the
  notes' Breaking-changes sections, which list only 1.8.0's `file_hash_t` change).
- **Breaking changes 1.1.0 → 1.8.0:** exactly one, upstream-wide: 1.8.0's `file_hash_t` regex
  removal — READ. Irrelevant to FENGARDE (no file hashes emitted) — VERIFIED.
- **Requirement relaxations on classes FENGARDE uses (all reader-friendly, READ):** 1.3.0 relaxed
  `src_endpoint` on 4001; 1.4.0 relaxed `dst_endpoint` on 4001 and added `at_least_one`; 1.2.0 made
  primary attributes "at least recommended". A restricted emitter like FENGARDE remains valid under
  these relaxations.
- **Deprecations touching FENGARDE's emitted fields:** none. Deprecated upstream items (`resource`,
  `group`, `credential_uid`, `account.type_id` 3/4, the Query classes, `file.signature`, TLS
  `extension_list`) are all fields/classes FENGARDE does not emit — VERIFIED (not in
  `contracts/ocsf-event.schema.json`, not set by any parser).

---

## (c) What a bump of `metadata.version` to 1.8.0 would break

Repo-wide grep for the literal string `1.1.0` under `services/`, `eval/`, `tools/`, `contracts/`
(single command, counts per file) — **VERIFIED**:

| Hit | Count | Nature |
|---|---|---|
| `services/ws2-normalization/parsers/base.py:193` | 1 | The emitter (the line itself) |
| `contracts/ocsf-event.schema.json:23` | 1 | Schema description text "e.g. 1.1.0" |
| `eval/llm_triage/labelled_cases.json` | 54 lines | Labelled LLM-triage fixtures (embedded OCSF events) |
| `services/ws7-dashboard/app/src/demo/fixtures.json` | 1 line | Dashboard demo fixture (embedded OCSF events) |
| `services/ws7-dashboard/app/src/demo/fixtures-ai-ot.json` | 1 line | Dashboard demo fixture (embedded OCSF events) |
| `services/ws7-dashboard/app/package-lock.json` | 3 | **Unrelated**: npm dep `loose-envify: ^1.1.0` (not OCSF) |
| `tools/` | 0 | — |

Concrete break analysis:

1. **Parser output:** zero parsers would break — the version is one hardcoded string in the shared
   envelope (`base.py:193`). No parser reads it back, no parser logic depends on it. A bump is a
   one-line edit — but it changes *every* emitted event's claim.
2. **Contract validation:** nothing breaks. `contracts/ocsf-event.schema.json:23` types
   `metadata.version` as a plain string; `tools/validate_contract.py` enforces `required/type/enum/
   pattern/$ref` plus the `type_uid` invariant — no check on the version's value (VERIFIED, module
   docstring `validate_contract.py:3-5`). Fixtures under `fixtures/` would also still validate.
3. **ws3-indexer / OpenSearch:** nothing breaks. No code path in `ws3-indexer` reads
   `metadata.version` (VERIFIED); the index mappings (`events-*.json`) map it as `keyword` — any
   string indexes (VERIFIED).
4. **Tests asserting the version string:** none exist. Zero hits for `1.1.0` in any test file under
   `services/`, `eval/`, `tools/` (VERIFIED). The contract tests assert class/sector/`type_uid`
   invariants, not the version.
5. **Stale fixtures:** a bump without regeneration leaves `eval/llm_triage/labelled_cases.json`
   (54 lines), `services/ws7-dashboard/app/src/demo/fixtures.json` and `fixtures-ai-ot.json` carrying
   events that claim `1.1.0` inside a pipe that claims 1.8.0. These are fixture *data* (nothing
   asserts them), so this is inconsistency, not breakage — but it is exactly the kind of
   claim-vs-data drift this repo's §2 (SSOT) honesty convention exists to prevent.
6. **Honesty/compliance (the real cost, not mechanical):** FENGARDE's profile is a *restricted,
   partly project-local* reading of OCSF 1.1.0: class 1002 uses project-local activity ids
   (`contracts/ocsf-classes.md`; `windows_eventlog.py:39` notes upstream 1007 is deliberately
   absent), 3003 carries a project extension activity (5136), `status` is a string instead of the
   upstream `status_id` integer, and the activity sets are strict subsets of upstream enums
   (VERIFIED, (a.3)). Labeling these events `1.8.0` would claim conformance with a schema version
   whose dictionaries/enums the project does not actually follow — misleading to any consumer that
   validates or routes on the version string (mappers, SIEM/DataBricks-style normalization, OCSF
   validators, Splunk CIM-style pipelines).
7. **Version sincerity aside:** the roadmap's target (1.8.0, 2026-03-16) is already *two* releases
   behind at assessment time — 1.9.0 shipped 2026-08-03 (READ). Any bump conversation should target
   "current OCSF (1.9.x)" rather than 1.8.0, or the work is stale on arrival.

**What a bump would *not* break (explicitly negative results, all VERIFIED):** the schema, the
validator, the indexer, the OpenSearch mappings, any rule, any test, `tools/`, `services/ws4/5/8/9`.

---

## (d) Recommendation — keep 1.1.0 for now; owner decides (no change made)

**Recommendation: do NOT bump the emitted `metadata.version` at this time.** Rationale:

1. The version string is currently **declarative and harmless**: nothing reads it, nothing validates
   against it, and `1.1.0` is an *accurate* statement of the OCSF semantics FENGARDE actually
   implements (restricted 1.1.0-era profile, Contract A).
2. A bump buys nothing mechanical (no consumer reads the field — VERIFIED) and costs honesty:
   `1.1.0`→`1.8.0` with unchanged class/activity semantics and a `status` string would be a
   false-conformance claim (c.6).
3. Real conformance work, if ever wanted, is a **mapping pass, not a string edit**: adopt upstream
   activity_id semantics per class (or accept 1002's documented project-local ids as a permanent
   deviation), add `status_id`, decide on 4002's 1.9.0 DNS restructuring, then bump the string in the
   *same* change that updates `contracts/ocsf-classes.md` and regenerates the `eval/llm_triage` and
   `ws7-dashboard` demo fixtures.
4. If the owner still wants the bump for marketing/interop reasons, the mechanical cost is tiny
   (base.py:193 + schema description + fixtures) — but it should target the *current* release (1.9.x),
   not the already-superseded 1.8.0, and the decision should be recorded in
   `contracts/ocsf-event.schema.json`'s description so the schema itself stops saying "e.g. 1.1.0".

**This document makes no change.** The single writable line (`base.py:193`), the schema, all parsers
and all fixtures are untouched; the branch adds only this assessment plus the CHANGELOG/SSOT
bookkeeping rows.

---

## Method / reproducibility

- Repo reads: `services/ws2-normalization/parsers/base.py` (full), all parser modules (constant
  definitions + `base_event` call sites), `contracts/ocsf-event.schema.json` (full),
  `contracts/ocsf-classes.md` (head), `tools/validate_contract.py` (head),
  `services/shared/ocsf.py`, `services/shared/envelope.py`, `services/ws3-indexer` (grep for
  `ocsf`/`metadata`), `contracts/opensearch-mappings/events-*.json` (grep for `version`/`metadata`).
- Greps: `grep -rn "1\.1\.0" services/ eval/ tools/ contracts/` (counts per file),
  `grep -rn "class_uid" services/ws2-normalization/parsers/*.py`,
  `grep -rn "metadata" parsers/*.py`, `grep -rn '\["version"\]\|\.get("version")' services/ --include="*.py"`.
- Web: https://github.com/ocsf/ocsf-schema/releases (+ per-tag pages 1.4.0, 1.5.0, 1.8.0),
  https://github.com/ocsf/ocsf-schema, https://www.synqly.com/ocsf-explained-cybersecurity-integration-standards/,
  https://bidda.com/intelligence/ocsf-open-cybersecurity-schema-framework-1-8-0 (all fetched 2026-11-04).
