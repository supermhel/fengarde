import type { Alert } from "../data/api";

type Ai = NonNullable<Alert["ai"]>;

/**
 * WS-5 verdicts are indexed as their own docs keyed by event, not by alert, so an alert gets its verdict by sharing an event id.
 * A distinct-count alert's `event_ids` are the counted values (ports, hosts), not ingest ids, so the triggering id
 * (`trigger_event_id`) is tried as well.
 */
export function attachAi(alerts: Alert[], aiDocs: Alert[]): Alert[] {
  const byEvent = new Map<string, Ai>();
  for (const d of aiDocs) if (d.ai) for (const e of d.event_ids || []) byEvent.set(e, d.ai);
  return alerts.map((a) => {
    if (a.ai) return a;
    const ids = [...(a.event_ids || []), ...(a.trigger_event_id ? [a.trigger_event_id] : [])];
    const hit = ids.map((e) => byEvent.get(e)).find(Boolean);
    return hit ? { ...a, ai: hit } : a;
  });
}
