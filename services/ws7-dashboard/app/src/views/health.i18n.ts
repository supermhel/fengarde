// Strings for the Operations view's system-health panel (Prometheus via the
// read-only /api/prom/ proxy in templates/default.conf.template).

const en = {
  title: "System health",
  sourceNote: "Prometheus scrape targets (infra/prometheus.yml)",
  job: "Job",
  instance: "Instance",
  health: "Health",
  up: "up",
  down: "down",
  unknown: "unknown",
  lastScrape: "Last scrape",
  never: "never",
  lastError: "Last error",
  cpu: "CPU",
  memory: "Memory (RSS)",
  rate: "Bus events/s",
  noProcess: "The targets export no process_* metrics, so CPU and memory are not shown.",
  unreachable: "Prometheus is not reachable",
  unreachableHint: "Prometheus and Grafana run in the opt-in observability profile. Start them with:",
  noTargets: "Prometheus has no active scrape targets.",
  grafana: "Open Grafana",
  grafanaNote: "Grafana listens on 127.0.0.1:3000 by default, so this link only works on the FENGARDE host itself.",
};

const de: typeof en = {
  title: "Systemzustand",
  sourceNote: "Prometheus-Scrape-Ziele (infra/prometheus.yml)",
  job: "Job",
  instance: "Instanz",
  health: "Zustand",
  up: "erreichbar",
  down: "ausgefallen",
  unknown: "unbekannt",
  lastScrape: "Letzter Abruf",
  never: "nie",
  lastError: "Letzter Fehler",
  cpu: "CPU",
  memory: "Speicher (RSS)",
  rate: "Bus-Ereignisse/s",
  noProcess: "Die Ziele liefern keine process_*-Metriken, daher werden CPU und Speicher nicht angezeigt.",
  unreachable: "Prometheus ist nicht erreichbar",
  unreachableHint: "Prometheus und Grafana laufen im optionalen Profil „observability“. Starten mit:",
  noTargets: "Prometheus hat keine aktiven Scrape-Ziele.",
  grafana: "Grafana öffnen",
  grafanaNote: "Grafana lauscht standardmäßig nur auf 127.0.0.1:3000; der Link funktioniert daher nur direkt auf dem FENGARDE-Host.",
};

export const H = { en, de };
