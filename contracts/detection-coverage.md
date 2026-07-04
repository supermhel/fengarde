# Detection coverage matrix (A1, v0.3 plan)

Ground truth: OCSF classes actually emitted by shipped parsers, cross-referenced against
detection rules. Update this file in the same PR as any parser or rule change.

## Classes emitted by parsers today

| class_uid | Class | Emitted by | Rules covering it |
|---|---|---|---|
| 1002 | Kernel/Process | generic_syslog, windows_eventlog (4688/4672) | common_after_hours_admin (4672 activity 2) |
| 3002 | Authentication | linux_ssh, active_directory, windows_eventlog (4624/4634/4647) | common_bruteforce, common_lateral_movement, common_password_spray |
| 3003 | Account Change | windows_eventlog (4720/4722/4726/4728/4732, added v0.3) | common_priv_grant |
| 4001 | Network Activity | cisco_asa | common_port_scan |
| 6003 | API Activity | vmware_vsphere | dc_mass_vm_delete |
| 6005 | Datastore Activity | db_audit (v0.3 — fixed the dormancy below) | bank_db_priv_esc |

## Gaps — classes with NO parser producer at all

| class_uid | Class | Would unlock |
|---|---|---|
| 4002 | DNS/HTTP Activity | DNS-exfil, beaconing rules — needs a DNS/proxy parser |
| 1001 | File System Activity | file-integrity rules — needs an auditd/FIM parser |

## Gaps — classes WITH a producer but under-covered by rules

- **1002 (Kernel/Process):** process-launch (4688, activity 1) anomaly detection
  (suspicious binary path, unexpected parent) is unbuilt; only privilege-use (4672)
  has a rule (after-hours admin, added v0.3).
- **6005 (Datastore Activity):** ~~`bank_db_priv_esc.yml` referenced class 6005 with
  no producer — dormant on real data~~ **FIXED (v0.3):** `services/ws2-normalization/
  parsers/db_audit.py` added, a vendor-agnostic DB-audit parser emitting
  activity_id 5 for GRANT/REVOKE/ALTER. `tools/check_rule_producers.py` now passes.

## Rule-by-rule producer status

| Rule | Fields required | Producer exists? |
|---|---|---|
| common_bruteforce | class 3002, activity 4 (Failure) | yes (linux_ssh, active_directory) |
| common_lateral_movement | class 3002, activity 1, status Success, dst_endpoint.hostname | yes (windows_eventlog 4624) |
| common_port_scan | class 4001, activity 6 (Deny), dst_endpoint.port | yes (cisco_asa) |
| dc_mass_vm_delete | class 6003, activity 4, siem.sector=datacenter | yes (vmware_vsphere) |
| bank_db_priv_esc | class 6005, activity 5, siem.sector=bank | yes (db_audit, added v0.3) |

## A6 guardrail (implemented)

`tools/check_rule_producers.py`, wired into `run_all_tests.sh`, runs every registered
parser against a real fixture and checks every rule's equality selections / group_by /
distinct_field are satisfiable by at least one parser's actual output — not just field
*paths* (every event has a `class_uid` key) but the specific *values* rules match on
(`class_uid: 6005` needs some parser to actually emit 6005). This is what caught the
bank_db_priv_esc dormancy above; it will catch the next one before it ships.

## Next-highest-value additions (from the v0.3 plan, Track A)

1. Extend `windows_eventlog.py` to 4720/4722/4726/4728/4732 → unlocks class 3003 → unlocks
   password-spray-adjacent and account-lifecycle rules cheaply (parser already exists).
2. A DB-audit parser to un-dormant `bank_db_priv_esc.yml` — currently the only shipped rule
   with zero real producer.
3. A DNS/proxy parser for class 4002.
