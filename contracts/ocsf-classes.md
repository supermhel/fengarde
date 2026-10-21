# Contract A — OCSF Class Reference

Restricted OCSF profile for the SIEM (Banking + Data Center). Every parser maps its
source events to one of these classes. The `type_uid` is **derived, not free**:

```
type_uid = class_uid * 100 + activity_id
```

The contract validator rejects any event where this does not hold.

| category_uid | class_uid | Class name              | Used for                                   |
|--------------|-----------|-------------------------|--------------------------------------------|
| 1 (System)   | 1001      | File System Activity    | auditd file access, config changes         |
| 1 (System)   | 1002      | Kernel / Process        | process exec, privilege use                |
| 3 (IAM)      | 3002      | Authentication          | login success/failure, AD/LDAP/RADIUS      |
| 3 (IAM)      | 3003      | Account Change          | role/permission change, user create/delete |
| 4 (Network)  | 4001      | Network Activity        | NetFlow/IPFIX flows, firewall accept/deny  |
| 4 (Network)  | 4002      | DNS / HTTP Activity     | proxy, WAF, DNS logs                        |
| 4 (Network)  | 4009      | Email Activity          | secure-email-gateway message log (2026-10-14) |
| 6 (App)      | 6003      | API Activity            | hypervisor API, k8s API, REST              |
| 6 (App)      | 6005      | Datastore Activity      | DB query/audit (Oracle, DB2, Postgres)     |

## Common activity_id values

Kernel / Process (1002): `1` Launch, `2` Privilege Use, `3` Service Install (windows_eventlog) / Terminate (sysmon EID 5),
`4` Log Cleared, `5` Process Access, `6` Script (PowerShell 4104/4103/800). Project-local ids, not OCSF's Process Activity ids;
`3` is shared by two meanings, so a rule on activity 3 must also select a field only one of them sets (as
win_service_installed_suspicious_path does with `unmapped.service.suspicious_path`).
Authentication (3002): `1` Logon, `2` Logoff, `3` Auth Ticket, `4` Failure
Account Change (3003): `1` Create, `2` Enable, `3` Password Change, `4` Delete, `5` Privilege Grant, `6` Directory Object Modified (5136, 2026-10-20)
Network Activity (4001): `1` Open, `2` Close, `6` Deny, `7` Accept
Email Activity (4009): `1` Send, `2` Receive, `3` Scan
API Activity (6003): `1` Create, `2` Read, `3` Update, `4` Delete
Datastore (6005): `1` Query, `2` Write, `3` Update, `4` Delete, `5` Privileged Op

## Worked examples

- Failed login → class 3002, activity 4 → `type_uid = 300204`
- Firewall deny → class 4001, activity 6 → `type_uid = 400106`
- DB privileged op → class 6005, activity 5 → `type_uid = 600505`
- VM delete via API → class 6003, activity 4 → `type_uid = 600304`

## siem.* routing namespace

OCSF describes *what* happened; the `siem.*` block describes *how we route it*.
It never overlaps OCSF field names. `sector` and `source_type` drive index selection
(Contract E) and rule scoping (Contract D). `score` is added later by WS-4.
