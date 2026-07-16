"""M5 eval harness: synthetic (alert, triage) scenarios for the NIS2 public
template layer, sourced from this repo's REAL contracts/rules/*.yml ids and
titles (not invented) so the eval exercises realistic detection content.

Each scenario is (name, alert, triage). `alert` mirrors the exact shape
services/ws4-detection/main.py::make_alert() produces.
"""
from __future__ import annotations

SCENARIOS: list[tuple[str, dict, dict]] = [
    ("bank_db_priv_esc", {
        "alert_id": "eval-1", "time": 1752000000000,
        "rule_id": "2a9d7b41-5e6c-4f88-bb12-3c0a1e7d4f02",
        "rule_title": "Privileged database operation outside maintenance window",
        "level": "critical", "score": 90, "sector": "bank", "tenant_id": "default",
    }, {"status": "triaged", "note": "confirmed unauthorized GRANT statement"}),

    ("common_bruteforce", {
        "alert_id": "eval-2", "time": 1752000100000,
        "rule_id": "6f1c8a2e-0d3b-4c11-9a21-7b5e2f9a1c01",
        "rule_title": "Authentication brute-force from single source",
        "level": "high", "score": 70, "sector": "common", "tenant_id": "default",
    }, {"status": "new", "note": ""}),

    ("common_port_scan", {
        "alert_id": "eval-3", "time": 1752000200000,
        "rule_id": "1d2c3b4a-5e6f-4708-8a91-0b1c2d3e4f05",
        "rule_title": "Port scan from single source (many distinct destination ports)",
        "level": "high", "score": 60, "sector": "common", "tenant_id": "default",
    }, {"status": "false_positive", "note": "internal vuln scanner, allowlisted after the fact"}),

    ("common_password_spray", {
        "alert_id": "eval-4", "time": 1752000300000,
        "rule_id": "4f8a2c61-9e3d-4b57-8a1c-6d2e5f7a8b90",
        "rule_title": "Password spray (one account, many distinct source IPs)",
        "level": "high", "score": 68, "sector": "common", "tenant_id": "acme",
    }, {"status": "triaged", "note": "credential-stuffing campaign, IPs blocked"}),

    ("common_impossible_travel", {
        "alert_id": "eval-5", "time": 1752000400000,
        "rule_id": "7081a2b3-c405-4de3-be5f-6a7b8c9d0e12",
        "rule_title": "Impossible travel (same account, distinct countries in a short window)",
        "level": "high", "score": 65, "sector": "common", "tenant_id": "default",
    }, {"status": "closed", "note": "VPN false positive, confirmed with user"}),

    ("common_lateral_movement", {
        "alert_id": "eval-6", "time": 1752000500000,
        "rule_id": "2e3d4c5b-6f70-4819-9b02-1c2d3e4f5061",
        "rule_title": "Lateral movement (one account auth success to many distinct hosts)",
        "level": "high", "score": 75, "sector": "common", "tenant_id": "default",
    }, {"status": "true_positive", "note": "compromised service account, rotated"}),

    ("common_priv_grant", {
        "alert_id": "eval-7", "time": 1752000600000,
        "rule_id": "7d3e9a52-1f6c-4a88-9b3d-2e5c8f1a6d40",
        "rule_title": "Privileged group membership grant",
        "level": "high", "score": 55, "sector": "common", "tenant_id": "default",
    }, {"status": "new", "note": ""}),

    ("dc_mass_vm_delete", {
        "alert_id": "eval-8", "time": 1752000700000,
        "rule_id": "8c4e1f90-7a2b-4d33-9e55-6f1b2c3a4d03",
        "rule_title": "Mass VM deletion via hypervisor API (ransomware / sabotage pattern)",
        "level": "critical", "score": 95, "sector": "datacenter", "tenant_id": "default",
    }, {"status": "triaged", "note": "confirmed sabotage, incident response engaged"}),

    ("ot_config_change", {
        "alert_id": "eval-9", "time": 1752000800000,
        "rule_id": "6f708192-a314-4cd2-ad4e-5f6a7b8c9d01",
        "rule_title": "OT configuration/firmware node changed",
        "level": "high", "score": 62, "sector": "datacenter", "tenant_id": "default",
    }, {"status": "new", "note": ""}),

    ("agent_destructive_command", {
        "alert_id": "eval-10", "time": 1752000900000,
        "rule_id": "5e6f7081-92a3-4bc4-ad2e-4f5a6b7c8d9e",
        "rule_title": "AI agent tool call carries a destructive command pattern",
        "level": "critical", "score": 85, "sector": "common", "tenant_id": "default",
    }, {"status": "triaged", "note": "agent session killed, command did not execute"}),

    ("n8n_webhook_exposed", {
        "alert_id": "eval-11", "time": 1752001000000,
        "rule_id": "8192a3b4-c516-4ef4-9c5f-6a7b8c9d0e13",
        "rule_title": "n8n new webhook exposed",
        "level": "medium", "score": 40, "sector": "common", "tenant_id": "default",
    }, {"status": "new", "note": ""}),

    # Edge case: minimal alert (missing optional fields) -- the eval must
    # prove the generator degrades gracefully, not just handle the happy path.
    ("minimal_alert_missing_fields", {
        "alert_id": "eval-12", "rule_title": "Unnamed rule",
    }, {}),
]
