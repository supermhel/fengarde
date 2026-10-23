# Live proof: F4 window clamp and F2 alias map on the real Redis pipeline (2026-10-22)

**What ran.** An isolated Docker compose project (`f2f4proof`, own network, no host ports except an ephemeral
`127.0.0.1` Redis port; the pre-existing `infra-*` stack was not touched) with `redis:7-alpine`, WS-2, WS-4, WS-8 and
WS-9 built from this branch, `BUS_BACKEND=redis` everywhere, so WS-4 used the **Redis window counter**. A host script
injected Windows 4624 logons into the `raw.events` stream (WS-1 skipped: it only stamps `meta.received_at`, which the script
sets to the real injection time), then read the `alerts` and `entity.updates` streams. All containers, volumes and
images were removed afterwards. Rule under test: `common_lateral_movement` (5 distinct hosts / 300 s per account, effective
skew = min(600 s, 300 s / 2) = 150 s). Not covered: WS-1 itself, WS-3/OpenSearch, WS-8 incident output.

## Phase 1 - WS-4 `FENGARDE_WINDOW_TIME_SOURCE=event` (the old behaviour), no alias map
```
##### PHASE 1: WS-4 FENGARDE_WINDOW_TIME_SOURCE=event (old behaviour), no alias map
[forged] tenant=live-a account='mallory' clamp-metric before: {"detection_time_clamped_total": 0}
[forged] alerts produced for tenant live-a: 0
[forged] WS-9 actor entities for tenant live-a: []
[forged] clamp-metric after: {"detection_time_clamped_total": 0}
[spelled] tenant=live-b account='jdoe1' clamp-metric before: {"detection_time_clamped_total": 0}
[spelled] alerts produced for tenant live-b: 2
   ALERT {"alert_id": "90561d27-ace4-4138-8cc4-c74569a439c6:live-b:10:10.50.0.46:5975407", "rule_id": "90561d27-ace4-4138-8cc4-c74569a439c6", "score": 70} actor= CORP\jdoe1
   ALERT {"alert_id": "90561d27-ace4-4138-8cc4-c74569a439c6:live-b:10:10.50.0.46:5975407", "rule_id": "90561d27-ace4-4138-8cc4-c74569a439c6", "score": 70} actor= jdoe1@corp.example
[spelled] WS-9 actor entities for tenant live-b: ['15511a67c272..=jdoe1@corp.example', '4f5e0edfd808..=corp\\jdoe1']
[spelled] clamp-metric after: {"detection_time_clamped_total": 0}
##### PHASE 1 (rerun, 5 hosts, lateral-movement alerts only)
[spelled] tenant=live-b account='jdoe2' clamp-metric before: {"detection_time_clamped_total": 0}
[spelled] common_lateral_movement alerts for tenant live-b: 0  (other rules fired: 5)
[spelled] WS-9 actor entities for tenant live-b: ['7fed5fb17eeb..=corp\\jdoe2', 'ece28a4c6f5b..=jdoe2@corp.example']
[spelled] clamp-metric after: {"detection_time_clamped_total": 0}
[lagged] tenant=live-c account='builder1' clamp-metric before: {"detection_time_clamped_total": 0}
[lagged] common_lateral_movement alerts for tenant live-c: 1  (other rules fired: 0)
   ALERT {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-c:8:builder1:5975407", "rule_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", "score": 70} actor= builder1
[lagged] WS-9 actor entities for tenant live-c: ['c1b29d2726b4..=builder1']
[lagged] clamp-metric after: {"detection_time_clamped_total": 0}
```
- `forged` (5 hosts, record clock forged 100 s apart, 400 s span, receipt true): **0 alerts**. The evasion works.
- `spelled` (`CORP\jdoe2` / `jdoe2@corp.example` alternating, no map): **0 lateral-movement alerts**, and WS-9 holds
  **two** actor entities for one person.
- The first `spelled` attempt used 6 hosts, which also tripped an unrelated per-source rule; it was re-run with 5 hosts and
  the output is filtered to the lateral-movement rule id.

## Phase 2 - WS-4 default (no env set -> `clamp`), alias map for tenant `live-b` mounted into WS-4/8/9
```
##### PHASE 2: WS-4 default (clamp, no env set) + alias map for tenant live-b mounted in ws4/ws8/ws9
[forged] tenant=live-a account='mallory' clamp-metric before: {"detection_time_clamped_total": 0}
[forged] common_lateral_movement alerts for tenant live-a: 1  (other rules fired: 0)
   ALERT {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:7:mallory:5975408", "rule_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", "score": 70} actor= mallory
[forged] WS-9 actor entities for tenant live-a: ['869790d869c3..=mallory']
[forged] clamp-metric after: {"detection_time_clamped_total": 3}
[spelled] tenant=live-b account='jdoe2' clamp-metric before: {"detection_time_clamped_total": 3}
[spelled] common_lateral_movement alerts for tenant live-b: 1  (other rules fired: 0)
   ALERT {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-b:10:jdoe2@corp:5975408", "rule_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", "score": 70} actor= CORP\jdoe2
[spelled] WS-9 actor entities for tenant live-b: ['02d13b8fc8be..=jdoe2@corp']
[spelled] clamp-metric after: {"detection_time_clamped_total": 3}
[lagged] tenant=live-c account='builder1' clamp-metric before: {"detection_time_clamped_total": 3}
[lagged] common_lateral_movement alerts for tenant live-c: 1  (other rules fired: 0)
   ALERT {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-c:8:builder1:5975407", "rule_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061", "score": 70} actor= builder1
[lagged] WS-9 actor entities for tenant live-c: ['c1b29d2726b4..=builder1']
[lagged] clamp-metric after: {"detection_time_clamped_total": 3}
```
- (a) the **same forged burst now fires** (1 alert) and `detection_time_clamped_total` went 0 -> **3** (the three records
  more than 150 s from receipt were clamped; the two within 150 s kept their record time).
- (b) the two spellings give **one alert** (group key `jdoe2@corp`) and **one** WS-9 actor entity.
- (c) five records each **60 s behind receipt** (a legitimate shipper lag inside the 150 s limit): **1 alert, clamp metric
  unchanged at 3**, so honest delay is counted on its record time and not touched.

## Two things the live run found
1. **WS-9 crash-looped on first start**: `shared/identity_aliases.py` imports PyYAML and `ws9-resolver/requirements.txt` did
   not list it. Every zero-infra test was green because the local Python has PyYAML. Fixed (hash-pinned PyYAML added to the
   WS-9 requirements) and the image rebuilt before the numbers above.
2. **Fail closed, observed**: a first attempt mounted the map at a path the shell had mangled; WS-4, WS-8 and WS-9 refused to
   start with `IdentityAliasError: cannot read identity alias map ...: No such file or directory` instead of running without
   the map.

---

# Part 2: real collectors, real OpenSearch, WS-8 incidents, vCenter/AD spellings (2026-10-22)

**What ran.** A second isolated compose project (`f2f4proof2`, removed afterwards; the pre-existing 13-container `infra-*`
stack was not touched; preflight: Docker 29.6.1, 8 GB RAM, `vm.max_map_count` = 1048576): `redis:7-alpine`,
`opensearchproject/opensearch:2.13.0` (single node, 512 MB heap, as in `infra/docker-compose.yml`), the repo's own
`infra/provision.sh` (ISM policies + index templates), WS-1, WS-2, WS-3 (`STORAGE_BACKEND=opensearch`), WS-4, WS-8, WS-9, all built
from this branch, `BUS_BACKEND=redis` (Redis window counter in WS-4). Records entered through the **real collector code**:
`tools/agent_log_shipper.py` (the JSONL shipper, the only WS-1-side path for structured Windows/vSphere records, run against
the stack's Redis with `TENANT_ID` per scenario) and the **WS-1 UDP syslog listener** (10 SSH failures sent to its published
port). Results were read back from OpenSearch's REST API (`alerts-<tenant>-*`, `incidents-<tenant>-*`: `_id`, `_version`,
`_count`) from inside the compose network. Phase 1 = WS-4 `FENGARDE_WINDOW_TIME_SOURCE=event`, no map; phase 2 = default
(clamp) with `contracts`-style map mounted into WS-4/8/9; phase 3 = default, map removed.

## Bugs the live run exposed (both fixed, both with regression tests)
1. **The JSONL shipper never stamped `meta.received_at`.** WS-2 turns that field into `siem.received_ms`; without it the
   clamp has no trusted clock and silently falls back to the record time, so F4 was NOT closed for records that arrive through
   `tools/agent_log_shipper.py`. Found while building the scenario (reading the shipper, not from a failing run); the live
   runs below all used the fixed shipper. Fix: the shipper stamps `received_at`; regression assertion in
   `tools/test_agent_log_shipper.py`. (Records produced straight onto the bus by other tools must set `received_at`
   themselves; WS-1's syslog/NetFlow/SNMP collectors already do.)
2. **A byte-identical redelivery of a forged burst created a second alert document.** The alert id's time bucket came from
   the triggering event's raw record time. On redelivery the window already holds the hosts, so the rule fires on an EARLIER
   event whose forged record time sits in an earlier 300 s bucket. Observed live before the fix, same bus messages re-XADDed:
   `...:mallory3:5975531` (_version 4) and a NEW `...:mallory3:5975530` (_version 2) -> two docs for one burst. Fix:
   `Rule.alert_key` buckets on the same clock that drives the window (`_window_time_of(..., stamp=False)`); honest,
   unclamped events and `event` mode produce exactly the ids they did before. Regression:
   `test_window_time_source.py` (fails on the previous code with two ids, passes now). Proven live below (mallory4).

## Phase 1 - `event` mode, no alias map
```
##### PHASE 1: WS-4 FENGARDE_WINDOW_TIME_SOURCE=event, NO alias map; data via tools/agent_log_shipper.py / WS-1 UDP; read back from OpenSearch
[forged] tenant=live-a: 5 logons by 'mallory', record times now-400s..now (receipt = now)
  shipper: [agent-log-shipper] shipped 5 event(s) to raw.events (source_type=windows_eventlog)
[forged] OpenSearch alerts-live-a-*: 0 doc(s) for rule 2e3d4c5b
[forged] OpenSearch incidents-live-a-*: 0 doc(s)
[forged] alerts-live-a-* _count = 0   ws4 clamp metric: {'detection_time_clamped_total': 0}
[incident] tenant=live-b: 5 logons as CORP\jdoe1 (TA0008) + log clear as jdoe1@corp.example (TA0005)
  shipper: [agent-log-shipper] shipped 6 event(s) to raw.events (source_type=windows_eventlog)
[incident] OpenSearch alerts-live-b-*: 2 doc(s)
   alerts-live-b-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-b:10:corp\jdoe1:5975530 _version=? rule=2e3d4c5b actor='CORP\\jdoe1' tactic=TA0008
   alerts-live-b-2026.10.22 _id=17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-b:a76ea359-cfcb-436d-9c46-dc1f19a76ea5 _version=? rule=17dcc2b9 actor='jdoe1@corp.example' tactic=TA0005
[incident] OpenSearch incidents-live-b-*: 0 doc(s)
[incident] alerts-live-b-* _count = 2   ws4 clamp metric: {'detection_time_clamped_total': 0}
[vsphere] tenant=live-v: 6 deletes over 3 SSO spellings + 6 deletes over 2 AD spellings (3+3), clock honest
  shipper: [agent-log-shipper] shipped 12 event(s) to raw.events (source_type=vmware_vsphere)
[vsphere] OpenSearch alerts-live-v-*: 0 doc(s) for rule 8c4e1f90
[vsphere] OpenSearch incidents-live-v-*: 0 doc(s)
[vsphere] alerts-live-v-* _count = 2   ws4 clamp metric: {'detection_time_clamped_total': 0}
[syslog] 10 SSH failures sent over UDP to the WS-1 listener (127.0.0.1:54075), WS-1 tenant live-syslog
[syslog] OpenSearch alerts-live-syslog-*: 1 doc(s)
   alerts-live-syslog-2026.10.22 _id=6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01:live-syslog:11:203.0.113.5:29877653 _version=? rule=6f1c8a2e actor='root' tactic=TA0006
[syslog] OpenSearch incidents-live-syslog-*: 0 doc(s)
[syslog] alerts-live-syslog-* _count = 1   ws4 clamp metric: {'detection_time_clamped_total': 0}
```
- Forged burst: **0 alerts** in OpenSearch (the evasion works with the clamp opted out).
- `incident` run without a map: the two alerts exist (TA0008 under `CORP\jdoe1`, TA0005 under `jdoe1@corp.example`) and
  there are **0 incident documents**: two actor tracks, one tactic each.
- `vsphere` run without a map: **0 `dc_mass_vm_delete` alerts** (the burst is split 2+2+2 over three SSO spellings and 3+3
  over two AD spellings). A different per-source-IP rule (`9c86195a`) fired on the shared source address; it is not the rule
  under test.
- WS-1 syslog path: the SSH brute-force alert landed in `alerts-live-syslog-*`.

## Phase 2 - default clamp, alias map mounted
```
##### PHASE 2: WS-4 default (clamp), alias map mounted into WS-4/8/9 (tenants live-b, live-v)
[forged] tenant=live-a: 5 logons by 'mallory2', record times now-400s..now (receipt = now)
  shipper: [agent-log-shipper] shipped 5 event(s) to raw.events (source_type=windows_eventlog)
[forged] OpenSearch alerts-live-a-*: 1 doc(s) for rule 2e3d4c5b
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975530 _version=? rule=2e3d4c5b actor='mallory2' tactic=TA0008
[forged] OpenSearch incidents-live-a-*: 0 doc(s)
[forged] alerts-live-a-* _count = 2   ws4 clamp metric: {'detection_time_clamped_total': 3}
[replay] tenant=live-a: shipping the identical file again (f2f4_forged_live-a.jsonl)
  shipper: [agent-log-shipper] shipped 5 event(s) to raw.events (source_type=windows_eventlog)
[replay] OpenSearch alerts-live-a-*: 2 doc(s) for rule 2e3d4c5b
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975529 _version=? rule=2e3d4c5b actor='mallory2' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975530 _version=? rule=2e3d4c5b actor='mallory2' tactic=TA0008
[replay] OpenSearch incidents-live-a-*: 0 doc(s)
[replay] alerts-live-a-* _count = 3   ws4 clamp metric: {'detection_time_clamped_total': 6}
[incident] tenant=live-b: 5 logons as CORP\jdoe2 (TA0008) + log clear as jdoe2@corp.example (TA0005)
  shipper: [agent-log-shipper] shipped 6 event(s) to raw.events (source_type=windows_eventlog)
[incident] OpenSearch alerts-live-b-*: 5 doc(s)
   alerts-live-b-2026.10.22 _id=90561d27-ace4-4138-8cc4-c74569a439c6:live-b:10:10.50.0.46:5975531 _version=? rule=90561d27 actor='CORP\\jdoe2' tactic=TA0008
   alerts-live-b-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-b:10:jdoe2@corp:5975531 _version=? rule=2e3d4c5b actor='CORP\\jdoe2' tactic=TA0008
   alerts-live-b-2026.10.22 _id=17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-b:493f675a-c416-4cd5-92c5-e73fb53247d3 _version=? rule=17dcc2b9 actor='jdoe2@corp.example' tactic=TA0005
[incident] OpenSearch incidents-live-b-*: 1 doc(s)
   INCIDENT {"incident_id": "live-b:actor:jdoe2@corp:20748", "entity_type": "actor", "entity_value": "jdoe2@corp", "tactics": ["TA0005", "TA0008"], "member_alert_ids": ["17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-b:493f675a-c416-4cd5-92c5-e73fb53247d3
[incident] alerts-live-b-* _count = 5   ws4 clamp metric: {'detection_time_clamped_total': 6}
[vsphere] tenant=live-v: 6 deletes over 3 SSO spellings + 6 deletes over 2 AD spellings (3+3), clock honest
  shipper: [agent-log-shipper] shipped 12 event(s) to raw.events (source_type=vmware_vsphere)
[vsphere] OpenSearch alerts-live-v-*: 2 doc(s) for rule 8c4e1f90
   alerts-live-v-2026.10.22 _id=8c4e1f90-7a2b-4d33-9e55-6f1b2c3a4d03:live-v:27:administrator@vsphere.local:14938828 _version=? rule=8c4e1f90 actor='administrator@VSPHERE.LOCAL' tactic=TA0040
   alerts-live-v-2026.10.22 _id=8c4e1f90-7a2b-4d33-9e55-6f1b2c3a4d03:live-v:9:jdoe@corp:14938828 _version=? rule=8c4e1f90 actor='jdoe@corp.example' tactic=TA0040
[vsphere] OpenSearch incidents-live-v-*: 0 doc(s)
[vsphere] alerts-live-v-* _count = 4   ws4 clamp metric: {'detection_time_clamped_total': 6}
```
- **Forged burst now fires**: `alerts-live-a-*` holds the lateral-movement alert, WS-4 clamp metric 0 -> 3.
- **Replay by re-running the shipper** (new receipt times, same record times) produced a SECOND doc
  (`...:mallory2:5975529`): that is the documented bucket-boundary behaviour (a 400 s forged spread necessarily crosses a
  300 s bucket and the second pass fires one event earlier because the window state persisted); it is not byte-identical
  redelivery. The byte-identical case is below.
- **Incident with the map**: ONE incident per person holding both spellings' alerts (quoted next); without it (phase 1) none.
- **vCenter, with the map**: `dc_mass_vm_delete` fired for the SSO burst (`administrator@vsphere.local` group) AND for the AD
  burst (`jdoe@corp` group), 2 alerts, vs 0 in phase 1.

Incident document from `incidents-live-b-2026.10.22` (`GET` via search; trimmed to the relevant fields):
```
_index incidents-live-b-2026.10.22 _id live-b:actor:jdoe4@corp:20748
{
 "incident_id": "live-b:actor:jdoe4@corp:20748",
 "tenant_id": "live-b",
 "entity_type": "actor",
 "entity_value": "jdoe4@corp",
 "tactics": [
  "TA0005",
  "TA0008"
 ],
 "member_alert_ids": [
  "17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-b:b9083799-b8c9-4139-97e7-79aed23a79ab",
  "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-b:10:jdoe4@corp:5975531",
  "90561d27-ace4-4138-8cc4-c74569a439c6:live-b:10:10.50.0.46:5975531"
 ],
 "score": null,
 "severity": 215
}
```
The member alerts are the lateral-movement alert (actor spelled `CORP\jdoe4`), the log-clear alert (actor spelled
`jdoe4@corp.example`) and an unrelated per-IP rule's alert: one track `live-b:actor:jdoe4@corp`, tactics TA0005 + TA0008.

## Phase 2b - byte-identical redelivery after the alert-id fix (default clamp)
```
##### PHASE 2b (after the alert-id fix): byte-identical bus redelivery of a forged burst, default clamp
[redeliver] round 1: XADDed 5 byte-identical raw.events messages (same ingest_id/received_at)
[redeliver-1] OpenSearch alerts-live-a-*: 5 doc(s) for rule 2e3d4c5b
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975529 _version=2 rule=2e3d4c5b actor='mallory2' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975530 _version=4 rule=2e3d4c5b actor='mallory2' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory3:5975530 _version=2 rule=2e3d4c5b actor='mallory3' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory3:5975531 _version=4 rule=2e3d4c5b actor='mallory3' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory4:5975532 _version=1 rule=2e3d4c5b actor='mallory4' tactic=TA0008
[redeliver-1] OpenSearch incidents-live-a-*: 0 doc(s)
[redeliver-1] alerts-live-a-* _count = 8   ws4 clamp metric: {'detection_time_clamped_total': 3}
[redeliver] round 2: XADDed 5 byte-identical raw.events messages (same ingest_id/received_at)
[redeliver-2] OpenSearch alerts-live-a-*: 5 doc(s) for rule 2e3d4c5b
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975529 _version=2 rule=2e3d4c5b actor='mallory2' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory2:5975530 _version=4 rule=2e3d4c5b actor='mallory2' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory3:5975530 _version=2 rule=2e3d4c5b actor='mallory3' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory3:5975531 _version=4 rule=2e3d4c5b actor='mallory3' tactic=TA0008
   alerts-live-a-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:8:mallory4:5975532 _version=6 rule=2e3d4c5b actor='mallory4' tactic=TA0008
[redeliver-2] OpenSearch incidents-live-a-*: 0 doc(s)
[redeliver-2] alerts-live-a-* _count = 8   ws4 clamp metric: {'detection_time_clamped_total': 6}
```
Both rounds put the same five `raw.events` messages (same `ingest_id`, same `meta.received_at`) on the bus. For `mallory4`
there is **one** document `...:mallory4:5975532`; `_version` goes 1 -> 6 (re-indexed in place by `_id`), `_count` for the
tenant stays at 8 and the number of docs for the rule stays at 5 across the two rounds: **idempotent**. The `mallory2` and
`mallory3` docs above it are the pre-fix leftovers described in bug 2.

## Phase 3 - default clamp, map removed (the unmapped incident case, WS-9 entities)
```
##### PHASE 3: default clamp, alias map REMOVED (same tenant live-b, new account): the unmapped incident case
[incident] tenant=live-b: 5 logons as CORP\jdoe5 (TA0008) + log clear as jdoe5@corp.example (TA0005)
  shipper: [agent-log-shipper] shipped 6 event(s) to raw.events (source_type=windows_eventlog)
[incident] OpenSearch alerts-live-b-*: 10 doc(s)
   alerts-live-b-2026.10.22 _id=90561d27-ace4-4138-8cc4-c74569a439c6:live-b:10:10.50.0.46:5975532 _version=4 rule=90561d27 actor='CORP\\jdoe5' tactic=TA0008
   alerts-live-b-2026.10.22 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-b:10:corp\jdoe5:5975532 _version=1 rule=2e3d4c5b actor='CORP\\jdoe5' tactic=TA0008
   alerts-live-b-2026.10.22 _id=17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-b:f79107b0-0532-4316-a0ab-c68cc63041ea _version=1 rule=17dcc2b9 actor='jdoe5@corp.example' tactic=TA0005
[incident] OpenSearch incidents-live-b-*: 2 doc(s)
[incident] alerts-live-b-* _count = 10   ws4 clamp metric: {'detection_time_clamped_total': 0}
[incident] WS-9 actor entities seen on entity.updates for tenant live-b: {"f30fb9ac40fc": "corp\\jdoe5", "d8f85edcb905": "jdoe5@corp.example"}
```
- No new incident for `jdoe5` (the incident count stays at the two mapped ones from phase 2) and WS-9 holds **two** actor
  entities for one person (`corp\jdoe5`, `jdoe5@corp.example`). In phase 2 the same shape gave one entity (`jdoe4@corp`).

## What the alias map does to the spellings (the rule, executed)
Rule: the WHOLE identifier is `strip().casefold()`-ed first (ADR-009), so **both the realm and the local part are
case-insensitive**; then, only for a tenant that lists the realm, `realm\name` and `name@realm` become `name@<first listed
spelling, casefolded>`. An unlisted realm, an unlisted tenant, or a bare name without `default_realm` stays as it was.
The consequence to know: a source whose local parts are case-SENSITIVE would be merged wrongly (`Admin` vs `admin`);
that is the ADR-009 decision, not something the map adds.
```
'VSPHERE.LOCAL\\Administrator'     -> 'administrator@vsphere.local'   (other tenant: 'vsphere.local\\administrator')
'Administrator@vsphere.local'      -> 'administrator@vsphere.local'   (other tenant: 'administrator@vsphere.local')
'administrator@VSPHERE.LOCAL'      -> 'administrator@vsphere.local'   (other tenant: 'administrator@vsphere.local')
' ADMINISTRATOR@Vsphere.Local '    -> 'administrator@vsphere.local'   (other tenant: 'administrator@vsphere.local')
'CORP\\jdoe'                       -> 'jdoe@corp'   (other tenant: 'corp\\jdoe')
'jdoe@corp.example'                -> 'jdoe@corp'   (other tenant: 'jdoe@corp.example')
'OTHER\\Administrator'             -> 'other\\administrator'   (other tenant: 'other\\administrator')
'Administrator@other.local'        -> 'administrator@other.local'   (other tenant: 'administrator@other.local')
'Administrator'                    -> 'administrator'   (other tenant: 'administrator')
```

## Where each vCenter / AD spelling comes from (provenance)
- **Record format** (backed by the repo): `services/ws2-normalization/parsers/vmware_vsphere.py` docstring
  (`operation`, `vm`, `userName`, `host`, `ipAddress`, `createdTime`), `services/ws2-normalization/mocks/raw_samples.json`,
  `eval/twin/scenarios_extra.py` (mass VM delete) and `services/ws4-detection/test_companion_rules.py`.
- **The spellings are NOT backed by any repo fixture.** `grep -ri vsphere.local` over the repo finds nothing; every vSphere
  fixture uses a plain name (`svc_orchestrator`, `svc_x`, `u`). `VSPHERE.LOCAL\Administrator` (domain-qualified, upper realm)
  and `Administrator@vsphere.local` (UPN / SSO login name) are the identity forms VMware's SSO documentation describes
  (the default SSO domain is `vsphere.local`), `administrator@VSPHERE.LOCAL` is my case variant, and `CORP\jdoe` /
  `jdoe@corp.example` are the usual AD-joined forms. I did not check them against a live vCenter or a vendor sample in this
  repo, so they are a **synthetic assumption**; `eval/adversarial/evasion_tables.yaml` keeps `vmware_vsphere.account` marked
  ASSUMED / `ratified: false` for the same reason, and I left it that way.
- `windows_eventlog` normally carries the domain in a separate `TargetDomainName`; the `CORP\jdoe` spelling in the Windows
  scenario is shipped inside `TargetUserName` (a shape the parser accepts and that other sources, e.g. SSH usernames, do
  produce), so it exercises the map, not a claim about what Windows logs.

## What is proven now, what is not
Proven live (Docker, Redis bus + Redis window backend, WS-1 UDP + JSONL shipper in, WS-2/3/4/8/9, real OpenSearch out):
the forged burst is missed under `event` and alerted under the default clamp; byte-identical redelivery keeps one alert
document; the two-spelling case gives one incident / one entity with the map and none / two without; a dc_mass_vm_delete-style
burst split over SSO and AD spellings is missed without the map and detected with it; WS-1's syslog listener path reaches an
indexed alert. **Still not proven:** a real vCenter or Windows log sample carrying these spellings; ADR-009 case-folding of a
case-sensitive local part; the HA (Sentinel) window backend; WS-5 (AI triage) and the dashboard in the loop.

---

# Part 3: HA (Sentinel) window backend, WS-5 triage, the dashboard, shipper re-run across a bucket (2026-10-23)

**What ran.** A third isolated compose project (`f2f4proof3`, removed afterwards; no container, volume, image or network left;
the pre-existing stack was not touched): Redis primary + 2 replicas + 3 Sentinels built as in `infra/docker-compose.ha.yml`
(static IPs, `--min-replicas-to-write 1`, the repo's `redis-sentinel-entrypoint.sh`), a single OpenSearch node provisioned
with `infra/provision.sh`, and WS-2, WS-3, WS-4, WS-5 (`StubLLM`, no Ollama), WS-8, WS-9 and the **real WS-7 dashboard**
(its nginx config, published on an ephemeral loopback port), every service on `BUS_BACKEND=redis-sentinel`. Default clamp, no
alias map. The Redis password is a random test value generated for the run. Not included: WS-1, WS-6.

## HA / Sentinel window backend
```
##### HA: Redis primary+2 replicas+3 Sentinels, all services via Sentinel, default clamp, no alias map
[ha] sentinel master address: 172.28.0.11 6379
[ha] sentinel replicas: 2 known replica record(s)
[ha] redis-1 replication: role:master | connected_slaves:2 | slave0:ip=172.28.0.12,port=6379,state=online,offset=42486,lag=1 | slave1:ip=172.28.0.13,port=6379,state=online,offset=42349,lag=1
[ha] window keys on the primary matching 'mallory': 0
[ha] sentinel master address: 172.28.0.11 6379
[ha] sentinel replicas: 2 known replica record(s)
[ha] redis-1 replication: role:master | connected_slaves:2 | slave0:ip=172.28.0.12,port=6379,state=online,offset=79176,lag=0 | slave1:ip=172.28.0.13,port=6379,state=online,offset=79039,lag=1
[ha] window keys on the primary matching 'mallory': 1
    ws4:win:d:2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:7:mallory ZCARD(primary) = 5  ZCARD(redis-2 replica) = 5  ZCARD(redis-3 replica) = 5
```
- Sentinel reports the primary `172.28.0.11` with 2 replicas, both `state=online`.
- After the forged burst the WS-4 window key `ws4:win:d:<rule>:live-a:7:mallory` exists on the primary with 5 members and the
  **same 5 members on both replicas**: the `RedisWindowCounter` runs on the Sentinel-managed topology and replicates.
- The forged burst alerted (1 doc) with the clamp metric at 3.

### Failover in the middle of a burst
```
##### HA FAILOVER: 3 of 5 forged events, kill the Redis primary, Sentinel promotes, last 2 events, alert must still fire
master before: 172.28.0.11 6379 
produced via Sentinel: fo1 fs00
produced via Sentinel: fo1 fs01
produced via Sentinel: fo1 fs02
window ZCARD on primary before the kill: ws4:win:d:2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-f:3:fo1
 Container f2f4proof3-redis-1-1 Stopping 
 Container f2f4proof3-redis-1-1 Stopped 
master after failover: 172.28.0.12 6379 
produced via Sentinel: fo1 fs03
produced via Sentinel: fo1 fs04
##### after failover
alerts-live-f-* docs: 1
   2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-f:3:fo1:5975872 _version 1 rule 2e3d4c5b
role:master connected_slaves:1 
window key on NEW primary: ws4:win:d:2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-f:3:fo1 ZCARD=5
```
Three of five forged events were produced, the primary (`redis-1`) was stopped, Sentinel promoted `redis-2`
(`172.28.0.12`), the last two events were produced through the Sentinel-aware bus client, and the alert fired: the new
primary holds the window key with all 5 members and `alerts-live-f-*` has the alert (`_version` 1). (The `AUTH failed` lines in
the raw output are my status helper calling a password-less Sentinel with `-a`; they do not affect the run.) This is one
failover with a small window; it shows state survives a promotion, not a soak test, and `min-replicas-to-write` means the
primary refuses writes while no replica is connected.

## WS-5 triage and the dashboard
```
##### HA: Redis primary+2 replicas+3 Sentinels, all services via Sentinel, default clamp, no alias map
[dash] GET / -> 200 (789 bytes of the real dashboard page)
[dash] POST /api/alerts -> 200: 1 alert(s), 1 for tenant live-a
    {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-a:7:mallory:5975871", "rule_title": "Lateral movement (one account auth success to many distinct hosts)", "score": 70, "level": "high"} | ai block: False
[dash] POST /api/ai-triage -> 200: 1 triage doc(s), 0 for tenant live-a
[dash] GET /api/incidents -> 200: {"incidents": [], "count": 0}
```
- **WS-5 ran**: an `ai-...` triage document landed in `alerts-2026.10.23` with `ai.verdict = "suspicious"`, `engine = "stub"`,
  summary "common event scored 70; triggered: Lateral movement ...". The engine is `StubLLM` (no Ollama in this stack), so this
  proves WS-5 is wired into the loop, not the quality of a real LLM verdict.
- **The dashboard served the real data**: its nginx returned the page (200) and `POST /api/alerts` returned the indexed
  lateral-movement alert (`rule_title`, score 70, level high); `GET /api/incidents` returned the incident below once one existed.
- **A finding, not caused by this change**: the triage document's `event_ids` is the triggering event's `ingest_id`
  (`22cca0f3-...`), but the distinct-count alert's own `event_ids` are the distinct VALUES it counted
  (`['fs03','fs04','fs00','fs01','fs02']`), so the dashboard's join "triage doc -> alert by `event_ids`" cannot attach the AI
  verdict to a distinct-count alert (`/api/ai-triage` returned the triage doc, 0 for the tenant). I only looked at this one
  rule; I did not check other rules or fix it (out of scope for F2/F4).

## Dashboard incident, single spelling
```
##### HA stack: shipper RE-RUN over the same file (new receipt time), then a single-spelling incident for the dashboard
[incident] tenant=live-d: 5 logons as CORP\jdoe9 (TA0008) + log clear as jdoe9@corp.example (TA0005)
[incident] OpenSearch alerts-live-d-*: 2 doc(s)
   alerts-live-d-2026.10.23 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-d:10:corp\jdoe9:5975871 _version=1 rule=2e3d4c5b actor='CORP\\jdoe9' tactic=TA0008
   alerts-live-d-2026.10.23 _id=17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-d:80daa88c-0ecb-4b38-94e4-2e077d5d1f7a _version=1 rule=17dcc2b9 actor='CORP\\jdoe9' tactic=TA0005
[incident] OpenSearch incidents-live-d-*: 1 doc(s)
   INCIDENT {"incident_id": "live-d:actor:CORP\\jdoe9:20749", "entity_type": "actor", "entity_value": "CORP\\jdoe9", "tactics": ["TA0005", "TA0008"], "member_alert_ids": ["17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-d:80daa88c-0ecb-4b38-94e4-2e077d5d1f
[incident] alerts-live-d-* _count = 2   ws4 clamp metric: {'detection_time_clamped_total': 7}
[incident] WS-9 actor entities seen on entity.updates for tenant live-d: {"31a0147b1568": "corp\\jdoe9"}
[dash] GET / -> 200 (789 bytes of the real dashboard page)
[dash] POST /api/alerts -> 200: 3 alert(s), 2 for tenant live-d
    {"alert_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-d:10:corp\\jdoe9:5975871", "rule_title": "Lateral movement (one account auth success to many distinct hosts)", "score": 70, "level": "high"} | ai block: False
    {"alert_id": "17dcc2b9-4d62-4fc2-9833-83954bf1b902:live-d:80daa88c-0ecb-4b38-94e4-2e077d5d1f7a", "rule_title": "Windows audit log cleared", "score": 75, "level": "high"} | ai block: False
[dash] POST /api/ai-triage -> 200: 3 triage doc(s), 0 for tenant live-d
[dash] GET /api/incidents -> 200: {"incidents": [{"incident_id": "live-d:actor:CORP\\jdoe9:20749", "tenant_id": "live-d", "entity_type": "actor", "entity_value": "CORP\\jdoe9", "first_seen": 1792761492955, "last_seen": 1792761492955, "tactics": ["TA0
```
`GET /api/incidents` through the dashboard returned the WS-8 incident `live-d:actor:CORP\\jdoe9:20749` (tactics TA0005 +
TA0008, both alerts as members). This stack had no alias map and the two logs used the same spelling (the unmapped
two-spelling case is in Part 2).

## Shipper re-run idempotency across a 300 s bucket boundary
```
##### HA stack: shipper re-run ACROSS a 300 s alert bucket boundary
[forged] tenant=live-e: 5 logons by 'm5', record times now-400s..now (receipt = now)
  shipper: [agent-log-shipper] shipped 5 event(s) to raw.events (source_type=windows_eventlog)
[forged] OpenSearch alerts-live-e-*: 1 doc(s) for rule 2e3d4c5b
   alerts-live-e-2026.10.23 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-e:2:m5:5975871 _version=1 rule=2e3d4c5b actor='m5' tactic=TA0008
[forged] OpenSearch incidents-live-e-*: 0 doc(s)
[forged] alerts-live-e-* _count = 1   ws4 clamp metric: {'detection_time_clamped_total': 10}
[bucket] sleeping 40s to cross the 300 s boundary
[replay] tenant=live-e: shipping the identical file again (f2f4_forged_live-e.jsonl)
  shipper: [agent-log-shipper] shipped 5 event(s) to raw.events (source_type=windows_eventlog)
[replay] OpenSearch alerts-live-e-*: 2 doc(s) for rule 2e3d4c5b
   alerts-live-e-2026.10.23 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-e:2:m5:5975872 _version=4 rule=2e3d4c5b actor='m5' tactic=TA0008
   alerts-live-e-2026.10.23 _id=2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061:live-e:2:m5:5975871 _version=2 rule=2e3d4c5b actor='m5' tactic=TA0008
[replay] OpenSearch incidents-live-e-*: 0 doc(s)
[replay] alerts-live-e-* _count = 2   ws4 clamp metric: {'detection_time_clamped_total': 14}
```
Same records, the shipper run twice. **Inside one 300 s alert bucket** (earlier run in this stack, `mallory`): the re-run
re-indexed the existing document (`...:mallory:5975871`, `_version` 1 -> 6), `_count` stayed 1. **Across a bucket boundary**
(`m5`, re-run 40 s later, after the boundary): a second document `...:m5:5975872` appeared next to `...:m5:5975871`
(`_count` 1 -> 2). That is the documented residual: the alert id of a clamped event buckets on its receipt time, and a
re-ship is a new ingestion with a new receipt time. Byte-identical redelivery of the same bus message stays idempotent (Part
2). The unit test `test_window_time_source.py` now pins both halves (same bucket = same id, next bucket = new id).

## Status after Part 3
Proven live: Sentinel-managed window backend incl. a primary failover mid-burst; WS-5 (stub engine) and the real dashboard in the
loop; the bucket-boundary behaviour. **Still unproven:** a real LLM (Ollama) verdict; the dashboard's AI-verdict join for
distinct-count alerts (looks broken, not investigated); OpenSearch 3-node HA; WS-6 inventory in the loop; a soak of repeated
failovers.
