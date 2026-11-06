# ADR 012: Causal evidence keys (process tree, logon session, network flow, agent session) for the incident graph

**Status:** Proposed. **Not Accepted: owner sign-off pending.** Nothing in
`services/`, `contracts/` or `eval/` changes until the owner ticks the checklist
at the end. **Date:** 2026-11-06. **Builds on:** ADR-011 (event-time ordering of
graph evidence; also Proposed, so this ADR is conditional on it). **Amends, if
accepted:** the no-transitive-inference rule of ADR-009 / ADR-010 by adding ONE
narrowly defined exception (cross-alert link on an equal causal key), and the
`incident.graph` v2 payload (additive optional field `links[]`; `version` stays
2). Everything else in ADR-009 / ADR-010 / ADR-011 is kept: per-entity tracks
never merge, the `incidents` payload is untouched, partition key
`incident_id`, determinism under redelivery.

**How to read the claims below.** Code facts cite `file:line` in the worktree
at `origin/docs/ws8-edge-time-adr` (ADR-011 tip, `27b54a3`, on top of
`origin/main` `182a4ab`). Numbers marked **[MEASURED]** come from throwaway
scripts kept OUTSIDE the repo
(`.../scratchpad/adr012/m1_fixture.py`, `m2_twin_keys.py`, plus a fixture count
over `git show origin/wp/1.5-zeek-suricata:...`); each states what was run.
Anything I could not run or open is **[UNVERIFIED]**. I changed no service,
contract or eval code and ran no test tier.

## Context

### The owner goal

Bring the incident graph to a genuinely **causal** level, not only time-ordered.
ADR-011 adds event-time evidence intervals to edges, which gives *order*. Order
is necessary and nowhere near sufficient for causation. What can make a link
causal in a log pipeline is a **shared identifier that the producing system
itself assigned to a single process, session or conversation** (a Sysmon
`ProcessGuid`, a Windows `LogonId`, a Zeek `uid`), plus an order that does not
contradict it. This ADR defines that, and what must be built to earn the word.

### Owner's measured-facts list, verified (corrections first)

| # | Owner's statement | Verdict | Evidence |
|---|---|---|---|
| 1 | No parser reads Sysmon `ProcessGuid`/`ParentProcessGuid` or any `LogonId`/`TargetLogonId`/`SubjectLogonId` | **Confirmed** | `grep -ri` for the six names over the worktree hits only: the two adapters' fixture text (`adapters/fluentbit_winevtlog.py:50,55,57`, `adapters/winlogbeat.py:69,72,106`), and `docs/handoff/blind-oracles/2026-10-14-phishing-bec-blind.yaml:237,241`. No file under `parsers/` reads any of them. |
| 2 | "Sysmon reads `ParentImage`/`ParentProcessId` only" | **Wrong in one name.** Sysmon reads `ParentImage` (`sysmon.py:286`), `ProcessId` (`:200`), `SourceProcessId` (`:203`), `Image`, `User`. `ParentProcessId` is NOT read; it appears only in the docstring example (`sysmon.py:85`) and test fixtures. Windows 4688 reads `NewProcessId` (`windows_eventlog.py:319`) and `ParentProcessName` (`:341`), not the creator `ProcessId`, not `ParentProcessId`, not any LogonId. |
| 3 | `flow_id` is read only by `n8n_audit` | **Wrong.** `grep -rnw flow_id` over `*.py/*.md/*.json/*.yml/*.yaml` on this tree: **0 hits**. `n8n_audit.py:115` reads `workflowId`/`workflow_id` (an n8n workflow id, not a network flow id; the earlier grep matched the substring). On PR #152's branch (`origin/wp/1.5-zeek-suricata`, `34048eb`) `suricata_eve.py` reads `flow_id` for `alert` (`:92`) and `flow` (`:104`) records only, and `zeek_json.py` reads `uid` for conn (`:97`), dns (`:116`), notice (`:130`). The `unmapped.*` home means none of this is a top-level field. |
| 4 | The OCSF contract has no process-parent/session fields | **Confirmed.** `contracts/ocsf-event.schema.json:68-92` has `actor.user{name,uid,domain}` and `actor.process{name,pid}` only; no `uid` on process, no `parent_process`, no `session`. (The schema root has `additionalProperties: true`, line 17, so extra keys validate today, which is exactly why they would be silently unversioned.) |
| 5 | ws8 edges come from ONE alert's entity pairs (actor, ip, device); typed kinds come from MITRE tactic labels; `caused_by` has no shipped evidence | **Confirmed, with a nuance.** Edges: `_EDGE_KINDS` (`correlator.py:166-172`), one alert per edge. Typed kinds read `mitre.tactic`, `mitre.technique` and one scalar `unmapped.ot.anomaly_type` (`correlator.py:275-304`); `caused_by` needs that scalar on the *alert*, but `make_alert` forwards a fixed field list with no `unmapped` (`ws4-detection/main.py:660-700`), and the code itself says "`caused_by` is not evidenced by any shipped alert" (`correlator.py:285-290`). Nuance: `make_alert` DOES copy `actor` wholesale (`main.py:689`), so any `actor.process.*` / `actor.session.*` field a parser sets would ride on the alert with no ws4 change. |

Two more corrections to the briefing:

- **The "Windows 11 Fluent Bit record" is not Windows 11 and not a byte-exact
  capture.** `adapters/fluentbit_winevtlog.py:22-31` says it is the output of
  fluent-bit 2.0.6 on a Windows host (2023-01-17, computer name `EC2AMAZ-...`, an
  AWS Windows Server) transcribed from a ClickHouse blog post; no capture file is
  stored. The owner has no Windows 11 Sysmon capture yet (owner's own statement).
- **That record carries its causal keys only inside the `Message` text**
  (`ProcessGuid: {f51ddac1-...}`, `LogonId: 0xCE96D`, `ParentProcessId: 7720`,
  `adapters/fluentbit_winevtlog.py:47-58`); it has no flat `Image`, `ProcessId`
  or `ParentImage` keys. **[MEASURED]** (`m1_fixture.py`): adapted and parsed by
  the real `SysmonParser`, the event is class 1002 with `actor = None` and
  `unmapped.process_launch = {"suspicious": false}`. So on the one real Windows
  record in the repo the pipeline extracts **no process identity at all**, not
  merely no GUID. The adapter docstring says `event_data_as_map: true` is required
  and "the recipe sets it", but the transcribed record is evidently not map-mode
  output. **[UNVERIFIED]** whether real map-mode output carries flat
  `ProcessGuid` etc.: I cannot capture one here. This is the first thing the
  Windows 11 lab capture must settle.

### What is in the real or captured data (inventory)

Fixtures available locally: the Fluent Bit record above (Sysmon EID 1, 1 record);
`winlogbeat.py` fixtures (template-derived, not captured: 4688 with
`NewProcessId`, `ParentProcessId`, `SubjectLogonId`; 4624 with `TargetLogonId`);
Suricata/Zeek fixtures on the unmerged PR #152 branch (REAL capture-derived, from
public OISF pcaps, Suricata 8.0.8 and Zeek 9.0.1 per their provenance blocks).
**The Sysmon/EVTX corpus is absent locally**: `eval/detection_accuracy/evtx-samples`
does not exist (GPL-3.0 corpus, fetched on demand per its README). `SSOT.md` row
"0.12.0 prep" records one CI full-corpus run (EVTX 278 files / 2,082 records) but
those bytes are not on this machine; I did not fetch them. `benchmark/` holds
results and raw timing files only, no event corpus.

Per source, causal keys that exist in the real log format versus what the parser
keeps today. "Real format" claims about Microsoft/Sysmon event layouts are from my
knowledge of the documented schemas, not from a capture in this repo, so they are
**[UNVERIFIED]** until the lab capture.

| Source (parser) | Causal keys in the real format | Kept today | Dropped today | Strength |
|---|---|---|---|---|
| Sysmon EID 1 (`sysmon.py`) | `ProcessGuid`, `ParentProcessGuid`, `LogonGuid`, `LogonId`, `ProcessId`, `ParentProcessId` | `ProcessId`->`actor.process.pid` (`:200`), `ParentImage` name only (`:286`) | **all GUIDs, LogonId, ParentProcessId** | GUID: strong (globally unique per process start). PID alone: weak (reused). |
| Sysmon EID 3 / 10 / 11 | `ProcessGuid` (EID 10: `SourceProcessGUID`, `TargetProcessGUID`), `ProcessId` | pid (EID 10 `SourceProcessId`, `:203`) | GUIDs | strong (GUID) |
| Windows 4688 (`windows_eventlog.py`) | `NewProcessId` (new), creator `ProcessId`, `SubjectLogonId`, `TargetLogonId` (new process token), `NewProcessName`, `ParentProcessName` | `NewProcessId`->pid (`:319`), `NewProcessName`, `ParentProcessName` name only | creator pid, both LogonIds | pid is host-local and reused: **weak** unless paired with start time (4688 has none) |
| Windows 4624 / 4672 / 4648 | 4624 `TargetLogonId` (+ `LinkedLogonId`); 4672/4648 `SubjectLogonId` | none | all | LogonId: strong **within one host between reboots**; not unique globally |
| Active Directory (`active_directory.py`) | same 4624/4768-9 family; `TargetLogonId` on 4624 | `TargetUserSid` only (`:141`) | LogonId | as above |
| Suricata (`suricata_eve.py`, PR #152) | `flow_id` on every record kind; `community_id` only if enabled | `flow_id` on alert, flow | **`flow_id` on dns, modbus, dnp3** (fixtures: 3/3, 4/4, 2/2 carry it) | strong within one sensor; `flow_id` is NOT comparable across Suricata instances or to Zeek `uid` |
| Zeek (`zeek_json.py`, PR #152) | `uid` on conn, dns, modbus, modbus_detailed; `community_id` only with a package | `uid` on conn, dns | **`uid` on modbus / modbus_detailed** (fixtures: 4/4 and 3/3 carry it); notice fixture has no `uid` | strong within one Zeek deployment |
| `mcp_agent` | `session_id`, agent id | `unmapped.mcp.session_id` (`:383`); `actor.user.name = agent or session` | not on the alert (`make_alert` drops `unmapped`) | medium: a self-declared id from the agent runtime, forgeable by the agent |
| `n8n_audit` | `workflowId` (workflow, not execution) | `unmapped.n8n.workflow_id` (`:138`) | execution id (not in the parser) | weak: a workflow definition id groups runs, it does not identify one |
| `linux_ssh`, `cisco_asa`, generic syslog, `dns_query` | none that name a process, session or flow (syslog `sshd[pid]` is a PID only) | n/a | n/a | **never causal-grade** |
| `cloudtrail`, `k8s_audit`, `m365_audit` | request/session ids exist in the real formats (e.g. CloudTrail `requestID`, `sessionContext`) | not examined in this ADR | **[UNVERIFIED]** | out of scope for the first pass |

### What the twin can show today [MEASURED]

`m2_twin_keys.py`, seed 7, every storyline in `scenario_registry.ALL` run through
the real WS-2 path (11 storylines, **494 events**), counting raw records that
carry any key from five families and which of them survive normalization:

| Family authored in raw twin events | Events | Pairs sharing a key value | Survives normalization |
|---|---|---|---|
| `ProcessGuid` / `ParentProcessGuid` | **0** | 0 | n/a |
| `LogonId` family | **0** | 0 | n/a |
| `flow_id` / `uid` | **0** | 0 | n/a |
| PID-like (`SourceProcessId` on one Sysmon EID 10 in each of 5 storylines) | **5** | **0** | yes, `actor.process.pid` |
| session-like: `mcp_agent` `session_id` (65 events: 2 in `ai_to_ot`, 63 in `supply_chain_ci`), `n8n` `workflowId` (1) | 66 | 1774 (1 + 1773) | `unmapped.mcp.session_id` on 65 events; **not on the alert, not read by ws8** |

Reading: **ground-truth parent/child and logon-session links authored in the twin
by construction: 0.** The twin builders author *steps*, and the oracle's
`allowed_relationships` are step-level (`causal_kind: execution`,
`credential_reuse`, e.g. `oracle_it_intrusion.yaml:42-44`), not event-level
process or session links. So the number the task asked for ("how many true links
exist per storyline and how many are recoverable from the current normalized
events") is: **true key-level links 0 (none authored); recoverable from current
normalized events 0 for process/logon/flow, and 1,774 `session_id` pairs on
normalized events that are then lost at the alert.** Nothing is recoverable at
the graph level today. A causal-edge precision/recall metric therefore cannot be
computed on the present twin; building the keyed storylines is a work package
(WP-7), not a measurement I could run. Seeds other than 7 were not measured
(a second run produced log lines on stdout that broke my JSON pipe; not
re-run). **[UNVERIFIED]** for other seeds.

## Decision (proposed)

### 1. What "causal" will mean, per edge basis

A **causal link** is a record between two member alerts of ONE incident, stored
beside (not instead of) the entity edges. The entity edges (`used_ip`,
`authenticated_as`, `caused_by` typed by MITRE, ...) **stay "entity-linked"
forever**: their typed kinds come from tactic labels, so renaming them "causal"
would repeat the mistake ADR-011 documents. The word "causal" is allowed in the
product ONLY for a link that satisfies all three conditions:

1. **A key condition.** Both alerts carry a causal evidence key with the same
   *namespace* and the same *canonical value within the same scope*, where the
   namespace's semantics says "this identifier names one process / session / flow
   / conversation". The accepted namespaces:

   | basis | key (self role -> related role) | scope the value is unique in | direction rule |
   |---|---|---|---|
   | `process_tree` | child `ParentProcessGuid` == parent `ProcessGuid` (Sysmon); or (4688) creator `ProcessId` == earlier `NewProcessId` on the SAME host **and** the child event time falls inside the parent's lifetime window known from logged events; PID-only matches without a start time are **not** causal-grade | tenant + host (Sysmon GUID embeds a machine part, still scope it) | parent -> child |
   | `logon_session` | 4624 `TargetLogonId` == 4688/4672/4648 `SubjectLogonId` (or 4688 `TargetLogonId`) | tenant + **host** + boot epoch (LogonId is unique per host until reboot) | logon -> activity under it |
   | `network_flow` | same Suricata `flow_id` on one sensor, or same Zeek `uid` in one deployment, across conn/dns/modbus/alert | tenant + sensor id (not comparable across sensors) | none: **symmetric**, order from ADR-011 only |
   | `agent_session` | same MCP `session_id` (and optionally agent id) | tenant + agent runtime | none: symmetric; **self-declared**, so a link carries `trust: "declared"` and the UI must say so |

   Not in scope until grounded in a real capture: CloudTrail/Kubernetes request
   ids, n8n execution ids, CI run ids (listed in the inventory as unexamined).
   A key outside this table, or a PID without a start time, makes a link at most
   `entity-linked`.

2. **An order condition (ADR-011).** For a directed basis the parent/logon
   event must not be *strictly later* than the child by ADR-011's rule
   (`parent.last_ts_ms < child.first_ts_ms` is `before`; overlap or tie is
   `concurrent` and still allowed, since process creation and its first event can
   share a millisecond). A link whose logged order is *reversed* is emitted as
   `order: "conflict"`, **never labelled causal**: it is evidence of clock skew
   or forged time and is counted, not hidden. Symmetric bases take their order
   straight from ADR-011.

3. **A hop condition.** A path of links is causal only if **every hop** is a
   key link satisfying (1) and (2). No hop may be an entity edge or a tactic
   label. Maximum path length 8 (a design parameter; the ADR does not claim 8 is
   tuned).

Everything else, including all edges built today, is `entity-linked`. The
vocabulary is fixed so the product text can be checked: `entity-linked`
(shared actor/ip/device in one alert), `time-ordered` (ADR-011 intervals ordered,
no key), `key-linked` (condition 1 only, order concurrent or missing), `causal`
(1 + 2 + 3).

### 2. Contract changes

**2a. OCSF event (Contract A, WS-2 output).** Use OCSF 1.1.0's own attribute
names. I checked the 1.1.0 schema pages (via `schema.ocsf.io`, a fetch tool
summarised them; confirm against the schema before coding **[UNVERIFIED]**
beyond the names):

| Field | In OCSF 1.1.0? | Use here |
|---|---|---|
| `process.uid` (string, "unique identifier for the process, assigned by the producing tool, used to correlate events") and `process.pid` | yes (`pid` or `uid` required) | `actor.process.uid` = Sysmon `ProcessGuid`; for 4688, `actor.process.uid` stays absent unless a start-time-qualified key is built (see PID rule) |
| `process.parent_process` (process object) | yes | `actor.process.parent_process.{uid,pid,name}` from `ParentProcessGuid` / `ParentProcessId` / `ParentImage` |
| `process.session` and `actor.session` (session object with `uid`) | yes (session object is embedded by Actor, Process, Authentication, Network Connection Info) | `actor.session.uid` = canonical LogonId; on 4624 the **new** session is `Authentication.session.uid` = `TargetLogonId` |
| `network_connection_info.uid` (string, "unique identifier of the connection") | yes; the 1.1.0 object has `uid`, `direction`, `protocol_name` but I did not find `community_uid` there | `connection_info.uid` = Suricata `flow_id` / Zeek `uid` |
| a per-sensor scope for the flow key | no OCSF equivalent found | **extension**: `siem.key_scope` (see below) |
| `siem.key_scope` (object `{sensor, boot}` or host-boot token) | **FENGARDE extension**, in the existing `siem` namespace ("never collides with OCSF fields", schema comment) | carries the uniqueness scope so a LogonId on host A can never match one on host B |

The restricted profile in `contracts/ocsf-event.schema.json` is hand-written, so
these are additive optional properties on `actor.process` / `actor.session` /
`connection_info`; nothing already required changes; old events remain valid.
Raw values are canonicalised in WS-2: GUID lowercase without braces, LogonId as
lowercase hex without leading zeros, Suricata `flow_id` as a decimal string, all
capped at 128 chars; an empty, `0x0`, `-` or `{00000000-...}` value is dropped
(Windows uses `0x0` and `-` as "none"; treating them as keys would join every
unrelated event, so they are explicit negative tests).

**2b. Alert payload (WS-4 `make_alert`).** Add one optional field:

```
"causal_keys": [ {"ns": "proc"|"logon"|"flow"|"agent",
                  "role": "self"|"parent"|"issuer"|"member",
                  "h": "<first 16 hex of sha256(tenant|ns|scope|canonical_value)>"} , ... ]
```

- Computed from the **trigger event only**, by one shared helper (a pure function
  in `services/shared/`, so ws4 and the tests use the same code; ws8 never
  imports ws4). A stateful rule's alert still has one trigger event; keys of the
  other contributing events are NOT carried. This is a stated limit: a link can
  be missed (recall), never invented (precision). `event_ids` remains the drill
  down.
- **Size.** At most 6 entries, 16-hex digest each: about 70 bytes per key, under
  500 bytes per alert worst case, constant regardless of rule or event size. Hash
  not raw value: bounded, no PII/host path in the field, and equality is all ws8
  needs. The raw `actor.process.uid` etc. still ride on the alert through the
  existing `actor` passthrough (`main.py:689`) for display; `causal_keys` is
  what ws8 trusts. Alternative of passing raw values: Rejected (below, G).
- Absent field means "no key", never "no link possible".

**2c. ws8 linking (incident.graph v2, additive).** For each incident ws8 already
rebuilds the graph from live member entries (`_build_incident_graph_v2`,
`correlator.py`). Add `links[]` computed in the same pass:

```
"links": [ {"from_event_id": "...", "to_event_id": "...", "basis": "process_tree"|"logon_session"|"network_flow"|"agent_session",
            "order": "forward"|"concurrent"|"conflict"|"unordered",
            "from_ts_ms": int|null, "to_ts_ms": int|null, "trust": "observed"|"declared"} ]
```

Rules, all inherited from ADR-010 and made explicit:

1. **Scope: members of ONE incident only.** Keys never move an alert into an
   incident, never merge two incidents, never merge two per-entity tracks (ADR-010
   "tracks never merge" is untouched). A key shared by members of two different
   incidents produces no link and increments a counter (open question 2).
2. **The one exception to no-transitive-inference.** ADR-010 forbids joining two
   alerts "that merely share an entity". A causal key is not an entity: it names
   one process/session/flow instance. The amendment is exactly: *two alerts may be
   linked iff they carry an equal `(ns, h)` pair with compatible roles*, and a
   multi-hop path is allowed *iff every hop is such a link*. Shared actor/ip/device
   never links.
3. **Union by key, deterministically.** Members are grouped by `(ns, h)` into
   link groups (union-find over sorted member ids); within a directed group, a
   `self`/`parent` match yields parent -> child; within a symmetric group every
   pair is linked through its time-ordered neighbour chain, not a clique (a group
   of n members emits at most n-1 links, bounded by the 200-member cap and
   therefore <= 199 links per group, <= 600 per incident by the existing 3 x
   members bound for edges; links get their own cap of 1,000 with a
   `links_truncated` flag, **sizes unmeasured [UNVERIFIED]**).
4. **Determinism and idempotency.** Links are a pure function of the live member
   side table (keys captured at store time as `entry["causal_keys"]`, same pattern
   as `cooccur`/`typed_signal`), sorted by `(basis, from_event_id, to_event_id)`.
   Redelivery overwrites the member's own entry; a fresh instance must emit
   byte-identical payloads; `_graph_signature` must include the keys (a test must
   prove a changed key invalidates the cache). Eviction can drop a link
   (non-monotone, as ADR-011 documents for intervals).
5. **No fabrication.** A key with no counterpart emits nothing; an
   un-canonicalisable value is dropped at WS-2, not guessed.
6. **Dashboard/WS-3** treat `links` as unknown optional data: absent/ignored is
   safe. The consumer-strictness check ADR-011 requires covers this field too.

`caused_by` as a typed MITRE-derived entity-edge kind is left as is (no behaviour
change) but this ADR records that it is a **label, not evidence**, and the docs
must not describe entity edges as causal after this ADR.

### 3. Evaluation: causal-link precision/recall, with controls

Ground truth. The twin knows parent/child and session links *by construction*
only after its builders author the keys (the measured result above: they do not
today). WP-7 extends selected storylines so each builder emits, for every step
pair it intends to be linked, the same key on both raw events, and the oracle
YAML gains `causal_links: [{from, to, basis}]` derived from the builder, not
typed by hand. Truth is therefore independent of ws4/ws8 behaviour, which is the
property `oracle_derive.py`/`oracle_provenance.py` already guard for steps.
**[UNVERIFIED]** how much of that tooling can be reused; WP-7's first task is to
read those files.

Metric (names provisional), computed from the **emitted `incident.graph.links`**
(pipeline output, not the harness's event list), mapping alerts to steps through
`event_ids`/`trigger_event_id`:

- `causal_link_precision` = |predicted key links that are in truth| / |predicted|
- `causal_link_recall` = |truth links recovered| / |gradable truth links|, where
  *gradable* = both endpoint steps produced an alert inside one incident
  (unalerted endpoints are counted and reported as `unalerted`, never silently
  removed or scored as misses)
- `causal_direction_accuracy` = among matched directed links, fraction with
  `order: forward`; `conflict` counts against it
- `causal_coverage` = alerts in incidents carrying >= 1 key / all alerts in
  incidents (headline honesty number; **0.0 today** by the measurement above)

Controls (each must collapse the metric it targets, or the metric is rejected;
the existing `eval/adversarial/order_controls.py` pattern):

| Control | What it does | Must happen |
|---|---|---|
| `mirror` | reverse event times (existing control) | key links unchanged (recall stays), `causal_direction_accuracy` collapses; shows keys and order are separate evidence |
| `swap` | swap timestamps of two linked steps | direction accuracy drops, `conflict` count rises |
| `shift_1h` | shift all times | no change in links (keys are time-free) |
| **`key_shuffle` (NEW)** | permute key values among events **within each namespace and scope**, preserving the multiset of values | `causal_link_precision` and `causal_link_recall` each fall to <= 0.25 x baseline (and toward the analytic chance rate p0 = truth links / candidate same-namespace pairs); if they do not, the linker is matching on something other than the key and the gate fails |
| `key_drop` (NEW) | delete all causal keys | recall -> 0, `causal_coverage` -> 0, every link reverts to `entity-linked`; no link may remain labelled causal |
| `key_collide` (NEW) | give two unrelated events the same bare PID (no start time) or `0x0` LogonId | zero causal links produced (the weak-key and null-value rules hold) |

Minimum n (owner to ratify, same style as ADR-011): at least **40 gradable truth
links**, over at least **4 keyed storylines**, covering at least **2 bases**,
no storyline contributing more than 40 %, and at least **15 links per basis**
for a per-basis claim; Wilson 95 % intervals reported. With 0 false links in 40
the Wilson lower bound on precision is about 0.91; at 15 it is about 0.80, which is
why per-basis claims need their own n. Below the minimum the harness prints
`insufficient_n`, not a score. Storylines whose logs have no keys (all syslog,
ASA, DNS, CloudTrail, k8s, OPC UA at present) are listed as `no_keys`, excluded
from the link denominators, and counted in `causal_coverage`, so a high link score
cannot hide a low coverage.

Claim wording by outcome (to be used verbatim in README/SSOT/dashboard):

| Outcome | Allowed wording |
|---|---|
| WP-7 not built, or n below minimum | "typed entity graph with event-time evidence" (ADR-011 wording). No "causal". |
| Precision gate passes on a basis, controls collapse, coverage reported | "key-linked causal links for <basis> on sources that emit <key> (coverage X %)". Per basis, per source. |
| Precision passes but `causal_direction_accuracy` below threshold or `conflict` common | "key-linked", not "ordered causal"; investigate clocks |
| `key_shuffle` does not collapse | no causal claim; defect in the linker |
| Gate passes on process_tree and logon_session only | "causal on Windows endpoint telemetry" and nothing about network or cloud |
| Any basis with `trust: declared` (agent_session) | always shown as "declared by the agent", never "observed" |

### 4. Honest scope

Can honestly claim causal links **once built**: Sysmon-sourced process trees
(GUID), Windows logon-session to activity on one host (LogonId), Suricata/Zeek
flows within one sensor. **Conditional**: Windows 4688-only process trees (PID
reuse), `agent_session` (self-declared).
**Never**, from the current formats: syslog text (`sshd[pid]` is a PID with no
start time), Cisco ASA messages, DNS query logs, any source with no id the system
itself assigned. A `src_ip` match, a shared username or a MITRE tactic order is
`entity-linked` or `time-ordered` and is not upgraded.

What the owner has: no Windows Security/Sysmon capture yet. A Windows 11 lab with
Sysmon installed would produce EID 1/3/10/11 with GUIDs and Security 4624/4688
with LogonIds; that capture is the missing real-data input, and it also settles
the Fluent Bit mode question above. The EVTX corpus is available only through the
CI lane (not local).

### 5. Work packages (order and size)

| WP | Work | Size | Depends on |
|---|---|---|---|
| 0 | Owner decisions on this ADR and ADR-011 acceptance | S | ADR-011 accepted (order condition) |
| 1 | Windows 11 + Sysmon lab capture (owner): EID 1/3/10, 4624/4688/4672, via Fluent Bit and Winlogbeat; commit as labelled fixtures | S (owner) / M (integrate) | none |
| 2 | OCSF restricted-profile additions + `siem.key_scope`; canonicaliser + negative tests (`0x0`, `-`, null GUID); `bus-topics.md` | S | 0 |
| 3 | WS-2: Sysmon + Windows 4688/4624/4672/4648 + AD parsers read the keys; Fluent Bit `Message` handling decided from WP 1 | M | 1, 2 |
| 4 | After PR #152 merges: read `flow_id` / `uid` on **all** record kinds (dns/modbus/dnp3, modbus.log); decide cross-tool `community_id` (not claimed) | S | #152 merged |
| 5 | WS-4: shared key helper + `causal_keys` on alerts | S | 2 |
| 6 | WS-8: key capture at store time, links, ordering with ADR-011 intervals, `INTERFACE.md`, tests (redelivery, fresh-instance, cache invalidation, no cross-incident link, null-key, PID-collision) | L | 5, ADR-011 implemented |
| 7 | Twin: keyed storylines (start with `win_credential_theft`, `ransomware`, `phishing_bec`, `supply_chain_ci`), oracle `causal_links`, metric, the six controls, minimum-n guard, scorecard rows | L | 3, 6 |
| 8 | PR #153 [UNVERIFIED: not opened; I do not know its content] merge ordering with WP 3/5 | S | #153 |
| 9 | Product wording and dashboard rendering of `links` | M | 7 passes |

## Consequences

- The graph gains a second, separate layer. Entity edges are unchanged and still
  honest; the causal claim lives only on `links`.
- The cost is real: GUID/LogonId extraction in WS-2, one alert field, one ws8
  pass, and keyed twin storylines (the large item). Nothing here helps a source
  that emits no ids.
- `causal_coverage` will be low for a long time (0.0 today). The ADR forces that
  number next to any precision figure.
- The no-transitive rule gets one named exception; reviewers must check that no
  other join sneaks in through it.

## Risks

- **Key forgery.** `agent_session` and any logged id are attacker-influenced;
  Sysmon GUIDs are only as trustworthy as the host. `trust` marks this; the
  `key_collide` control covers accidental, not malicious, collisions.
- **Scope bugs** (LogonId reused after reboot, Suricata `flow_id` reused across
  sensors) would create false causal links; `siem.key_scope` and the collide tests
  exist for this and must be treated as release blockers.
- **Missed links** from trigger-event-only keys.
- **Twin circularity.** If the builder and the parser share the key-extraction
  helper, truth and prediction are not independent. The builder must emit raw
  source-shaped records and use its own key generation. **[UNVERIFIED]** until
  WP 7.
- Fixture realism: the only real Windows record in the repo is a transcribed,
  Message-only record from a Windows Server host; the winlogbeat fixtures are
  template-derived.

## Alternatives considered and rejected

- **A. Infer causality from MITRE tactic order alone.** Rejected: it is the
  `caused_by` situation today (a label, no evidence); two unrelated actors doing
  tactics in kill-chain order would be "causal". The twin's own
  `false_correlation_rate` 1.0 (ADR-011 fact 1) shows what join-without-evidence
  looks like.
- **B. ML-based linking.** Rejected: not deterministic under redelivery, not
  explainable per link, and no labelled real data exists to train or validate it
  honestly. May be revisited only as a *suggestion* layer clearly marked
  `inferred`, never as `causal`.
- **C. Merge tracks / incidents by key.** Rejected: violates "tracks never merge"
  and makes incident membership depend on key presence.
- **D. Treat bare PID as a key.** Rejected: PIDs are reused; only a PID plus a
  verified start-time window can be a weak key, and it is `trust`-labelled.
- **E. Cross-sensor flow join (Suricata `flow_id` to Zeek `uid`).** Rejected: the
  ids are unrelated; the only portable key is Community ID, which is not present
  in either fixture set and is not claimed here.
- **F. Change entity edge kinds to "causal" when a key exists.** Rejected: mixes
  two evidence classes in one field the harness pins.
- **G. Put raw key values on the alert.** Rejected as the ws8 input: unbounded
  size and a PII/path-leak surface; the raw values stay on `actor.*` for display.
- **H. Do nothing; change wording only.** Remains the fallback and is already
  ADR-011's alternative I.
- **I. New topic for links.** Rejected: ADR-011 already puts evidence on
  `incident.graph`; a second topic adds a consistency problem for no gain.
- **J. Carry every contributing event's keys on a stateful alert.** Rejected for
  now: unbounded; revisit if recall is the binding constraint.

## Open questions

1. Should `links` also appear on the `incidents` payload? Proposed no (that
   payload stays byte-for-byte untouched).
2. Cross-incident key hits: count only, or emit a `related_incidents` hint later?
3. Boot epoch for LogonId scope: no event carries boot time reliably;
   **[UNVERIFIED]** which field (Sysmon `Event 4` start, Security 4608) is usable.
4. Does the dashboard need to draw `links` at all before WP 7 passes?
5. What is in PR #153? **[UNVERIFIED]**.

## Owner sign-off checklist

Tick each line (or edit it) before any code starts.

- [ ] 1. Confirm the corrected fact list in the Context table (notably: `flow_id`
  is read by nobody on `main`; Sysmon does not read `ParentProcessId`; the
  "Windows 11" Fluent Bit record is a transcribed Windows Server specimen with its
  keys only inside `Message`).
- [ ] 2. Approve the vocabulary: `entity-linked`, `time-ordered`, `key-linked`,
  `causal`, and that entity edges are never called causal.
- [ ] 3. Approve the three conditions (key, order via ADR-011, every hop keyed)
  and the namespace table, including that PID-only and `declared` keys are weak.
- [ ] 4. Approve the amendment to no-transitive-inference (equal-key links within
  one incident only; tracks and incidents still never merge).
- [ ] 5. Approve the contract additions: OCSF `actor.process.uid`,
  `parent_process`, `actor.session.uid`, `connection_info.uid`; extension
  `siem.key_scope`; alert `causal_keys` (hashed, <= 6, trigger event only);
  incident.graph optional `links[]` (`version` stays 2).
- [ ] 6. Ratify the evaluation: metrics, six controls (incl. NEW `key_shuffle`,
  `key_drop`, `key_collide`), minimum n (>= 40 links, >= 4 storylines, >= 2 bases,
  <= 40 % per storyline, >= 15 per basis), Wilson intervals, `no_keys` handling.
- [ ] 7. Ratify the claim-wording table.
- [ ] 8. Commission the Windows 11 + Sysmon capture (WP 1) and confirm it comes
  before parser work.
- [ ] 9. Confirm sequencing against ADR-011 acceptance and PRs #152 / #153.
- [ ] 10. Confirm A, B, C, D, E, F, G, I, J stay rejected and H is the fallback.

## Status

Proposed 2026-11-06. Awaiting owner sign-off. No code, contract, schema or eval
file is changed by this document.
