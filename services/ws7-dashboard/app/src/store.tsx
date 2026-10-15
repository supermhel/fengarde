import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, setTenant, type Alert, type Incident, type OcsfEvent, type OpsMetrics, type Result, type Rule, type Session } from "./data/api";
import { dicts, initialLang, type Dict, type Lang } from "./lib/i18n";
import { RANGES, type RangeKey } from "./lib/time";

const POLL_MS = 10_000;
export const OPS_KEYS = ["ws1", "ws2", "ws4", "ws8", "ws3", "ws5"] as const;
export type OpsKey = (typeof OPS_KEYS)[number];

export interface ConsoleData {
  alerts: Result<Alert[]> | null;
  events: Result<OcsfEvent[]> | null;
  incidents: Result<{ incidents: Incident[]; count: number }> | null;
  rules: Result<{ rules: Rule[]; count: number }> | null;
  ops: Partial<Record<OpsKey, Result<OpsMetrics>>>;
  fetchedAt: number;
}

interface Ctx {
  t: Dict; lang: Lang; setLang: (l: Lang) => void;
  range: RangeKey; setRange: (r: RangeKey) => void; from: number; to: number;
  session: Session | null; rbac: boolean; setSession: (s: Session | null) => void;
  data: ConsoleData; refresh: () => void;
  triage: Record<string, { status: string; note: string }>;
  setLocalTriage: (id: string, v: { status: string; note: string }) => void;
  /** Admin-chosen tenant scope ("" = the session's own tenant). */
  tenant: string; setTenantScope: (t: string) => void; tenants: string[];
}

const C = createContext<Ctx | null>(null);
export const useConsole = () => {
  const c = useContext(C);
  if (!c) throw new Error("useConsole outside provider");
  return c;
};

export function ConsoleProvider({ session, rbac, setSession, children }: {
  session: Session | null; rbac: boolean; setSession: (s: Session | null) => void; children: ReactNode;
}) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const [range, setRange] = useState<RangeKey>("24h");
  const [data, setData] = useState<ConsoleData>({ alerts: null, events: null, incidents: null, rules: null, ops: {}, fetchedAt: 0 });
  const [triage, setTriage] = useState<Record<string, { status: string; note: string }>>({});
  const [now, setNow] = useState(Date.now());
  const [tenant, setTenantScope] = useState("");
  const inflight = useRef(false);

  const setLang = (l: Lang) => {
    setLangState(l);
    try { localStorage.setItem("fg.lang", l); } catch { /* storage blocked: still switches for this tab */ }
    document.documentElement.lang = l;
  };

  const refresh = useCallback(async () => {
    if (inflight.current) return;
    inflight.current = true;
    const t = Date.now();
    const gte = t - RANGES[range];
    setTenant(tenant || session?.tenant_id || null);
    const [rawAlerts, events, incidents, rules, ai, ...ops] = await Promise.all([
      api.alerts(gte), api.events(gte), api.incidents(), api.rules(), api.aiTriage(), ...OPS_KEYS.map((k) => api.ops(k)),
    ]);
    // WS-5 verdicts are indexed as their own docs keyed by event, not by alert:
    // join on shared event_ids, exactly like the classic console's attachAiTriage().
    const byEvent = new Map<string, NonNullable<Alert["ai"]>>();
    if (ai.ok) for (const d of ai.data) if (d.ai) for (const e of d.event_ids || []) byEvent.set(e, d.ai);
    // The alert/event routes proxy OpenSearch directly (no server-side tenant filter),
    // so an admin-chosen tenant scope is applied here; the other routes take ?tenant_id=.
    const inTenant = (x: { tenant_id?: string; siem?: { tenant?: string } }) => !tenant || (x.tenant_id || x.siem?.tenant || "default") === tenant;
    const alerts = rawAlerts.ok
      ? { ...rawAlerts, data: rawAlerts.data.filter(inTenant).map((a) => {
          if (a.ai) return a;
          const hit = (a.event_ids || []).map((e) => byEvent.get(e)).find(Boolean);
          return hit ? { ...a, ai: hit } : a;
        }) }
      : rawAlerts;
    // Data refresh never touches view state (selection, open faceplate, built evidence).
    const scopedEvents = events.ok ? { ...events, data: events.data.filter(inTenant) } : events;
    setData({ alerts, events: scopedEvents, incidents, rules, ops: Object.fromEntries(OPS_KEYS.map((k, i) => [k, ops[i]])), fetchedAt: t });
    setNow(t);
    inflight.current = false;
  }, [range, tenant, session]);

  useEffect(() => {
    refresh();
    const id = setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  // Tenants accumulate across refreshes: once scoped, the filtered data no longer shows the others.
  const seen = useRef(new Set<string>());
  const tenants = useMemo(() => {
    if (session?.tenant_id) seen.current.add(session.tenant_id);
    for (const a of data.alerts?.ok ? data.alerts.data : []) if (a.tenant_id) seen.current.add(a.tenant_id);
    return [...seen.current].sort();
  }, [data.alerts, session]);

  const value = useMemo<Ctx>(() => ({
    t: dicts[lang], lang, setLang, range, setRange, from: now - RANGES[range], to: now,
    session, rbac, setSession, data, refresh,
    triage, setLocalTriage: (id, v) => setTriage((m) => ({ ...m, [id]: v })),
    tenant, setTenantScope, tenants,
  }), [lang, range, now, session, rbac, data, refresh, triage, setSession, tenant, tenants]);

  return <C.Provider value={value}>{children}</C.Provider>;
}

/** Effective triage status: a local write this session wins over the indexed copy. */
export function triageOf(a: Alert, local: Ctx["triage"]): { status: string; note: string } {
  return local[a.alert_id] || { status: a.triage?.status || "new", note: a.triage?.note || "" };
}
