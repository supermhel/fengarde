# Detection coverage matrix (A1, v0.3 plan)

Ground truth: OCSF classes actually emitted by shipped parsers, cross-referenced against
detection rules. Update this file in the same PR as any parser or rule change.

## Classes emitted by parsers today

| class_uid | Class | Emitted by | Rules covering it |
|---|---|---|---|
| 1001 | File System Activity | sysmon (P0-3, 2026-07-21 audit fix plan — first producer, closes the long-standing gap below; EventID 11 FileCreate) | none yet — see "under-covered" below |
| 1002 | Kernel/Process | generic_syslog, windows_eventlog (4688/4672), sysmon (P0-3, EventID 1 ProcessCreate) | common_after_hours_admin (4672 activity 2) |
| 3002 | Authentication | linux_ssh, active_directory, windows_eventlog (4624/4634/4647), opcua_audit (v0.4 P2, session events), n8n_audit (v0.4 P3, login/logout — no dedicated rule yet), cef (v0.5, auth-shaped extension keys), cloudtrail (v0.5, ConsoleLogin) | common_bruteforce, common_bruteforce_sourceless (P0-2, 2026-07-21 audit fix plan), common_lateral_movement, common_password_spray, common_impossible_travel (v0.4 P4), ot_new_engineering_connection, cloud_root_console_login (v0.5) |
| 3003 | Account Change | windows_eventlog (4720/4722/4726/4728/4732, added v0.3) | common_priv_grant, common_rapid_account_lifecycle (v0.5) |
| 4001 | Network Activity | cisco_asa, cef (v0.5, non-auth-shaped extension keys), sysmon (P0-3, EventID 3 NetworkConnect, always activity 7/Accept), modbus_anomaly (M7, 2026-07-22 — protocol-anomaly detector, NOT a vendor-log parser, see its module docstring) | common_port_scan, common_beaconing (v0.5, periodicity primitive), ot_modbus_unauthorized_write (M7) |
| 4002 | DNS/HTTP Activity | dns_query (v0.5, first producer — closes the long-standing gap below) | common_dns_exfil (v0.5) |
| 6003 | API Activity | vmware_vsphere, mcp_agent (v0.4 P1), opcua_audit (v0.4 P2, write/method events), n8n_audit (v0.4 P3), k8s_audit (v0.5, first k8s producer), cloudtrail (v0.5, non-ConsoleLogin management events) | dc_mass_vm_delete, agent_credential_file_access, agent_tool_call_burst, agent_prompt_injection_indicator, ot_write_outside_maintenance, ot_config_change, n8n_new_webhook_exposed, n8n_workflow_modified_after_hours, dc_privileged_container (v0.5) |
| 6005 | Datastore Activity | db_audit (v0.3 — fixed the dormancy below) | bank_db_priv_esc, bank_mass_card_read (v0.5) |

## Gaps — classes with NO parser producer at all

**~~4002 DNS/HTTP Activity~~ FIXED (v0.5):** `services/ws2-normalization/parsers/
dns_query.py` (dnsmasq/BIND query-log lines) is the first class-4002 producer,
un-dormanting `common_dns_exfil.yml`.

**~~1001 File System Activity~~ FIXED (P0-3, 2026-07-21 audit fix plan):**
`services/ws2-normalization/parsers/sysmon.py` (EventID 11 FileCreate) is the
first class-1001 producer. No rule consumes it yet — see "under-covered" below,
this is now a rule gap, not a parser gap.

(No remaining classes in Contract A's restricted profile have zero producers.)

## Gaps — classes WITH a producer but under-covered by rules

- **1001 (File System Activity, NEW, P0-3):** zero rules yet — the parser just
  landed. Natural next rule: suspicious file-drop path (e.g. a process writing an
  executable to a temp/startup directory) or distinct-file-write burst per host.
- **1002 (Kernel/Process):** process-launch (4688/sysmon EventID 1, activity 1)
  anomaly detection (suspicious binary path, unexpected parent) is unbuilt; only
  privilege-use (4672) has a rule (after-hours admin, added v0.3).
- **4001 (Network Activity, sysmon slice):** sysmon's EventID 3 producer feeds
  `common_port_scan`/`common_beaconing` structurally (same class/activity shape
  as cisco_asa), but neither rule has a dedicated fixture proving it fires on
  sysmon-shaped events specifically — same class, unverified producer pairing,
  tracked here rather than assumed.
- **6005 (Datastore Activity):** ~~`bank_db_priv_esc.yml` referenced class 6005 with
  no producer — dormant on real data~~ **FIXED (v0.3):** `services/ws2-normalization/
  parsers/db_audit.py` added, a vendor-agnostic DB-audit parser emitting
  activity_id 5 for GRANT/REVOKE/ALTER. `tools/check_rule_producers.py` now passes.

## Rule-by-rule producer status

| Rule | Fields required | Producer exists? | MITRE |
|---|---|---|---|
| common_bruteforce | class 3002, activity 4 (Failure) | yes (linux_ssh, active_directory) | ATT&CK T1110 / TA0006 |
| common_password_spray | class 3002, activity 4, distinct src_endpoint.ip | yes (linux_ssh, active_directory) | ATT&CK T1110.003 / TA0006 |
| common_bruteforce_sourceless | class 3002, activity 4, distinct actor.user.name per src_endpoint.hostname | yes (active_directory, added P0-2, 2026-07-21 audit fix plan) | ATT&CK T1110 / TA0006 |
| common_lateral_movement | class 3002, activity 1, status Success, dst_endpoint.hostname | yes (windows_eventlog 4624) | ATT&CK T1021 / TA0008 |
| common_port_scan | class 4001, activity 6 (Deny), dst_endpoint.port | yes (cisco_asa) | ATT&CK T1046 / TA0007 |
| common_priv_grant | class 3003, activity 5 | yes (windows_eventlog 4728/4732) | ATT&CK T1098 / TA0003 |
| common_after_hours_admin | class 1002, activity 2, outside_hours | yes (windows_eventlog 4672) | ATT&CK T1078 / TA0004 |
| common_impossible_travel | class 3002, activity 1, distinct src_endpoint.location.country | yes (linux_ssh + A5 geo enrichment, added v0.4 -- see A5's note below: `check_rule_producers.py` now runs the real enrich() step too, not just parsers) | ATT&CK T1078 / TA0001 |
| dc_mass_vm_delete | class 6003, activity 4, siem.sector=datacenter | yes (vmware_vsphere) | ATT&CK T1485 / TA0040 |
| bank_db_priv_esc | class 6005, activity 5, siem.sector=bank | yes (db_audit, added v0.3) | ATT&CK T1548 / TA0004 |
| agent_credential_file_access | class 6003, unmapped.mcp.credential_path_access=true | yes (mcp_agent, added v0.4) | ATT&CK T1552 / TA0006 |
| agent_destructive_command | class 6003, unmapped.mcp.destructive_command_indicator=true | yes (mcp_agent, added v0.4) | ATT&CK T1485 / TA0040 |
| agent_egress_non_allowlisted_domain | class 6003, unmapped.mcp.is_egress_call=true | yes (mcp_agent, added v0.4) | ATT&CK T1071 / TA0011 |
| agent_tool_call_burst | class 6003, unmapped.mcp.session_id | yes (mcp_agent, added v0.4) | *(none -- no solid single ATT&CK mapping for a generic tool-call-volume burst; omitted rather than forced, see the C3 rule below)* |
| agent_prompt_injection_indicator | class 6003, unmapped.mcp.injection_indicator=true | yes (mcp_agent, added v0.4) | ATLAS AML.T0051 / AML.TA0004 |
| ot_write_outside_maintenance | class 6003, activity 3, time outside_hours | yes (opcua_audit, added v0.4) | ATT&CK-ICS T0836 / TA0106 |
| ot_new_engineering_connection | class 3002, activity 1, distinct src_endpoint.ip per unmapped.ot.server_id | yes (opcua_audit, added v0.4) | ATT&CK-ICS T0864 / TA0108 |
| ot_config_change | class 6003, unmapped.ot.is_config_node=true | yes (opcua_audit, added v0.4) | ATT&CK-ICS T0836 / TA0106 |
| n8n_new_webhook_exposed | class 6003, activity 1, api.operation=webhook.created | yes (n8n_audit, added v0.4) | ATT&CK T1133 / TA0003 |
| n8n_workflow_modified_after_hours | class 6003, siem.source_type=n8n_audit, time outside_hours | yes (n8n_audit, added v0.4) | ATT&CK T1078 / TA0004 |
| common_dns_exfil | class 4002, activity 1, distinct dst_endpoint.hostname | yes (dns_query, added v0.5) | ATT&CK T1071.004 / TA0011 |
| dc_privileged_container | class 6003, activity 1, siem.source_type=k8s_audit, unmapped.k8s.is_privileged=true | yes (k8s_audit, added v0.5) | ATT&CK T1610 / TA0002 |
| cloud_root_console_login | class 3002, activity 1, siem.source_type=cloudtrail, unmapped.cloud.identity_type=Root, unmapped.cloud.mfa_used=No | yes (cloudtrail, added v0.5) | ATT&CK T1078.004 / TA0001 |
| bank_mass_card_read | class 6005, activity 1, siem.sector=bank, distinct unmapped.db.object | yes (db_audit, object field added v0.5) | ATT&CK T1005 / TA0009 |
| common_rapid_account_lifecycle | class 3003, activity in [1,4], group unmapped.target_user.name | yes (windows_eventlog 4720/4726) | ATT&CK T1136 / TA0003 |
| common_beaconing | class 4001, activity 7, periodicity max_cv<=0.25 | yes (cisco_asa, existing producer; A3 periodicity primitive added v0.5) | ATT&CK T1071 / TA0011 |

**C3 rule (v0.5):** MITRE tagging is a SHAPE-checked, honest-effort mapping
(`tools/validate_rules.py`'s `mitre` block), not a claim of MITRE endorsement --
each id above was individually verified against MITRE's published corpus at the
time it was added. A rule with no defensible single-technique mapping (only
`agent_tool_call_burst` today) omits the field entirely rather than forcing one;
`tools/validate_rules.py` treats `mitre` as fully optional for exactly this
reason. The dashboard's coverage heatmap (`services/ws7-dashboard/`) renders
straight from this passthrough field on real alerts (`GET /api/v1/rules` +
alert data), so an omitted mapping shows as a real gap, not a hidden one.

## A6 guardrail (implemented)

`tools/check_rule_producers.py`, wired into `run_all_tests.sh`, runs every registered
parser against a real fixture and checks every rule's equality selections / group_by /
distinct_field are satisfiable by at least one parser's actual output — not just field
*paths* (every event has a `class_uid` key) but the specific *values* rules match on
(`class_uid: 6005` needs some parser to actually emit 6005). This is what caught the
bank_db_priv_esc dormancy above; it will catch the next one before it ships.

**v0.4 update:** the tool now runs each fixture's parsed event through the real A5
`enrich()` step too (`services/ws2-normalization/enrichment/`), mirroring
`normalize_one`'s actual parse → enrich pipeline. Without this, `common_impossible_travel`
(keyed on `src_endpoint.location.country`, an enrichment-added field no parser emits
directly) would have looked dormant by this tool's own standard — a false alarm, not a
real gap. Fields enrichment adds are just as "real" as parser fields once wired into
the pipeline.

## Cross-source rule scoping (v0.4 lesson)

v0.4 added three new `class_uid: 6003` producers (mcp_agent, opcua_audit, n8n_audit)
sharing the class with the existing vmware_vsphere. A rule keying only on
`class_uid`/`activity_id` (or grouping/distinct-counting on a field only ONE source
sets, e.g. `unmapped.mcp.session_id`) can silently mis-fire or pool unrelated sources
into one counter once a second producer of that class exists — `agent_tool_call_burst`,
`ot_write_outside_maintenance`, and `ot_new_engineering_connection` all needed an
explicit `siem.source_type: <parser>` selection added to stay scoped once n8n_audit
landed alongside them. `check_rule_producers.py`'s satisfiability check does NOT catch
this class of bug (it only proves a rule CAN fire, not that it fires on the RIGHT
source) — a new rule sharing a class_uid with an existing producer should always ask
"could another source's event also match this selection?" and add `siem.source_type`
or a source-distinctive field if so.

## Next-highest-value additions (from the v0.3 plan, Track A)

1. ~~Extend `windows_eventlog.py` to 4720/4722/4726/4728/4732~~ **DONE (v0.3)** — unlocked
   class 3003, and v0.5's `common_rapid_account_lifecycle.yml` now uses it.
2. ~~A DB-audit parser to un-dormant `bank_db_priv_esc.yml`~~ **DONE (v0.3)**; v0.5 also
   added `unmapped.db.object` to the same parser to un-dormant `bank_mass_card_read.yml`.
3. ~~A DNS/proxy parser for class 4002~~ **DONE (v0.5)** — `dns_query.py`, see above.

**v0.5 (Track A4) additions**: `k8s_audit.py` (first k8s producer, class 6003) and
`cloudtrail.py` (first cloud-control-plane producer, classes 3002/6003) — both new
producers, both follow the same `siem.source_type` scoping discipline the previous
paragraph describes (`dc_privileged_container.yml` scopes to `k8s_audit`,
`cloud_root_console_login.yml` scopes to `cloudtrail`) since both share a class_uid
with existing producers. `cef.py` deliberately ships with NO new rule of its own —
its value is feeding the existing `common_bruteforce`/`common_port_scan` rules from
any CEF-emitting appliance, a real but rule-count-invisible contribution.

Remaining open items, not v0.5 scope: SNMP, NetFlow (binary format), and a
class-1001 (File System Activity) auditd/FIM producer.
