import type { Alert, OcsfEvent, OpsMetrics, Result, Rule } from "../data/api";
import type { Stage } from "../hmi/hmi";
import type { Dict } from "./i18n";

type Ops = Partial<Record<string, Result<OpsMetrics>>>;

export function num(m: Result<OpsMetrics> | undefined, pick: (m: OpsMetrics) => unknown): number {
  if (!m || !m.ok) return 0;
  const v = pick(m.data);
  return typeof v === "number" ? v : 0;
}
export function deadletters(m: Result<OpsMetrics> | undefined): number {
  if (!m || !m.ok) return 0;
  return Object.entries(m.data.extra || {})
    .filter(([k, v]) => k.endsWith("deadletter_depth") && typeof v === "number")
    .reduce((s, [, v]) => s + (v as number), 0);
}
export const acked = (m: Result<OpsMetrics> | undefined, topic: string) => num(m, (d) => d.topics?.[topic]?.acked);

/** The five pipeline stages, each read from its own workstream's real /metrics. */
export function pipelineStages(t: Dict, ops: Ops, rules: Result<{ rules: Rule[]; count: number }> | null, alerts: Alert[], events: OcsfEvent[]): Stage[] {
  const dl = (k: string, what = "") => { const n = deadletters(ops[k]); return n ? `${n} ${what}${t.deadLettered}` : undefined; };
  return [
    { key: "ws1", name: "Collect", sub: "WS-1 collectors", metric: ops.ws1 ?? null, value: num(ops.ws1, (d) => d.extra?.events_produced), abnormal: dl("ws1") },
    { key: "ws2", name: "Normalize", sub: "WS-2 → OCSF", metric: ops.ws2 ?? null, value: acked(ops.ws2, "raw.events"), abnormal: dl("ws2") },
    { key: "ws4", name: "Detect", sub: `WS-4 · ${rules?.ok ? rules.data.count : "?"} ${t.rules}`, metric: ops.ws4 ?? null, value: acked(ops.ws4, "normalized.events"), abnormal: dl("ws4") },
    { key: "ws8", name: "Correlate", sub: `WS-8 · ${num(ops.ws8, (d) => d.extra?.ws8_active_tracks)} tracks`, metric: ops.ws8 ?? null, value: acked(ops.ws8, "alerts"), abnormal: dl("ws8") },
    { key: "ws3", name: "Index", sub: "WS-3 · OpenSearch", metric: ops.ws3 ?? null, value: alerts.length + events.length, abnormal: dl("ws3") },
  ];
}
