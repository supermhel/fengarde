// WS-7 mock backend data. Lets the dashboard run with no live services.
// Shapes mirror Contract C (assets) and the `alerts` topic (Contract B/E).
window.SIEM_MOCK = {
  assets: [
    { mac: "AA:BB:CC:00:11:01", vendor: "Cisco", hostname: "core-switch-01",
      ip_current: "10.0.0.1", sector: "datacenter", type: "switch", status: "active",
      protocols_seen: ["SNMP", "SSH"], last_seen: "2026-06-16T12:00:00Z",
      ip_history: [{ ip: "10.0.0.1", from: "2026-06-01T00:00:00Z", to: null }] },
    { mac: "AA:BB:CC:DD:EE:01", vendor: "Dell", hostname: "wks-jdoe",
      ip_current: "10.20.30.40", sector: "bank", type: "server", status: "active",
      protocols_seen: ["Syslog", "WinEvent"], last_seen: "2026-06-16T11:59:00Z",
      ip_history: [
        { ip: "10.20.30.39", from: "2026-06-10T00:00:00Z", to: "2026-06-15T00:00:00Z" },
        { ip: "10.20.30.40", from: "2026-06-15T00:00:00Z", to: null }] },
    { mac: "DE:AD:BE:EF:00:07", vendor: "VMware", hostname: "prod-db-07",
      ip_current: "172.16.5.20", sector: "datacenter", type: "vm", status: "inactive",
      protocols_seen: ["API"], last_seen: "2026-06-16T10:01:00Z", ip_history: [] }
  ],
  alerts: [
    { alert_id: "al-1", time: 1750000100000, rule_title: "Mass VM deletion via hypervisor API",
      level: "critical", score: 85, sector: "datacenter", src_endpoint: { ip: "172.16.5.9" },
      actor: { user: { name: "svc_orchestrator" } },
      ai: { verdict: "malicious", summary: "5 VM deletes in 120s by svc_orchestrator", level: "critical" } },
    { alert_id: "al-2", time: 1750000000000, rule_title: "Privileged DB operation outside window",
      level: "critical", score: 85, sector: "bank", src_endpoint: { ip: "10.50.1.2" },
      actor: { user: { name: "dba1" } } },
    { alert_id: "al-3", time: 1750000200000, rule_title: "Auth brute-force from single source",
      level: "high", score: 70, sector: "common", src_endpoint: { ip: "203.0.113.5" },
      actor: { user: { name: "jdoe" } } }
  ]
  // 2026-08-20: `sources` (fake per-protocol counts) removed -- the Sources
  // view now derives real counts from getEvents() (siem.source_type), same
  // no-mock-fallback convention getEvents() itself already used.
};
