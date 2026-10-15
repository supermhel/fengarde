import { useEffect, useMemo, useState } from "react";
import type { OcsfEvent } from "../data/api";
import { Panel, Trend } from "../hmi/hmi";
import { bucket, fmtTime } from "../lib/time";
import { useConsole } from "../store";
import { E } from "./events.i18n";

const CLASS: Record<number, string> = {
  3002: "Authentication", 4001: "Network Activity", 4003: "DNS Activity", 6003: "API Activity",
  1007: "Process Activity", 3001: "Account Change", 2004: "Detection Finding",
};
const N = 48;
const CAP = 300;

export const FIELDS = ["source", "ip", "status", "class", "actor"] as const;
export type Field = (typeof FIELDS)[number];
export type Query = { tokens: { field: Field; value: string }[]; text: string[] };

export const classOf = (e: OcsfEvent): string => CLASS[e.class_uid ?? 0] ?? (e.class_uid != null ? String(e.class_uid) : "");

// field:value | field:"quoted value" | "phrase" | word. Unclosed quotes are accepted while typing.
const TOKEN = /(\w+):(?:"([^"]*)"?|(\S*))|"([^"]*)"?|(\S+)/g;

export function parseQuery(q: string): Query {
  const out: Query = { tokens: [], text: [] };
  for (const m of q.matchAll(TOKEN)) {
    const [all, f, quoted, bare, phrase, word] = m;
    const field = f?.toLowerCase();
    if (field && (FIELDS as readonly string[]).includes(field)) {
      const value = quoted ?? bare ?? "";
      if (value) out.tokens.push({ field: field as Field, value });
    } else {
      // Unknown prefixes (IPv6, clock times, foo:bar) stay free text.
      const term = f ? all : phrase ?? word ?? "";
      if (term) out.text.push(term);
    }
  }
  return out;
}

const quote = (v: string) => (/\s/.test(v) ? `"${v}"` : v);
export const formatQuery = (q: Query): string =>
  [...q.tokens.map((t) => `${t.field}:${quote(t.value)}`), ...q.text.map(quote)].join(" ");

const same = (a: string | undefined, b: string) => (a ?? "").toLowerCase() === b.toLowerCase();

export const hasToken = (q: Query, field: Field, value: string) => q.tokens.some((t) => t.field === field && same(t.value, value));

/** Add the token if absent, remove it if present; free text is kept. */
export function toggleToken(q: string, field: Field, value: string): string {
  const p = parseQuery(q);
  const i = p.tokens.findIndex((t) => t.field === field && same(t.value, value));
  if (i >= 0) p.tokens.splice(i, 1);
  else p.tokens.push({ field, value });
  return formatQuery(p);
}

export function matchEvent(e: OcsfEvent, q: Query): boolean {
  for (const { field, value } of q.tokens) {
    const ok = field === "source" ? same(e.siem?.source_type || "unknown", value)
      : field === "ip" ? same(e.src_endpoint?.ip, value) || same(e.dst_endpoint?.ip, value)
      : field === "status" ? same(e.status, value)
      : field === "class" ? same(classOf(e), value) || String(e.class_uid ?? "") === value
      : same(e.actor?.user?.name, value);
    if (!ok) return false;
  }
  if (!q.text.length) return true;
  const hay = [e.message, e.src_endpoint?.ip, e.dst_endpoint?.ip, e.actor?.user?.name, e.src_endpoint?.hostname,
    e.siem?.source_type, e.status, e.metadata?.uid].filter(Boolean).join("\n").toLowerCase();
  return q.text.every((w) => hay.includes(w.toLowerCase()));
}

function counts(rows: OcsfEvent[], get: (e: OcsfEvent) => string | undefined, limit?: number): [string, number][] {
  const m = new Map<string, number>();
  for (const e of rows) { const v = get(e); if (v) m.set(v, (m.get(v) || 0) + 1); }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

// Selection is keyed by ingest_id: the 10 s refresh replaces the objects but not the event.
const keyOf = (e: OcsfEvent, i: number) => e.siem?.ingest_id || `${e.time}:${i}`;

const FACET_ROW = { background: "none", border: 0, borderRadius: 4, padding: "2px 4px", width: "100%", textAlign: "left", cursor: "pointer" } as const;

export function Events() {
  const { t, lang, data, from, to } = useConsole();
  const e_ = E[lang];
  const [q, setQ] = useState("");
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [mode, setMode] = useState<"msg" | "ocsf">("msg");
  const [copied, setCopied] = useState<"" | "ok" | "fail">("");
  const events = useMemo(() => (data.events?.ok ? data.events.data : []), [data.events]);
  const query = useMemo(() => parseQuery(q), [q]);
  const rows = useMemo(() => events.filter((e) => matchEvent(e, query)).sort((a, b) => b.time - a.time), [events, query]);
  const keys = useMemo(() => rows.map(keyOf), [rows]);
  const shown = rows.slice(0, CAP);
  const openIdx = openKey ? keys.indexOf(openKey) : -1;
  const open: OcsfEvent | null = openIdx >= 0 ? rows[openIdx] : null;

  const facets: { field: Field; label: string; vals: [string, number][] }[] = useMemo(() => [
    { field: "source", label: t.parser, vals: counts(rows, (e) => e.siem?.source_type || "unknown") },
    { field: "class", label: t.class, vals: counts(rows, classOf) },
    { field: "status", label: t.status, vals: counts(rows, (e) => e.status) },
    { field: "ip", label: e_.topIps, vals: counts(rows, (e) => e.src_endpoint?.ip, 8) },
  ], [rows, t, e_]);

  const select = (k: string | null) => { setOpenKey(k); setCopied(""); };

  // j/k move the selection like Alarms; Esc closes the detail. select only calls stable setters.
  useEffect(() => {
    const onKey = (ev: KeyboardEvent) => {
      if ((ev.target as HTMLElement)?.closest("input, textarea, select")) return;
      const last = Math.min(keys.length, CAP) - 1;
      if (ev.key === "j" || ev.key === "ArrowDown") { const k = keys[Math.min(last, openIdx + 1)]; if (k) select(k); ev.preventDefault(); }
      if (ev.key === "k" || ev.key === "ArrowUp") { const k = keys[Math.max(0, openIdx - 1)]; if (k) select(k); ev.preventDefault(); }
      if (ev.key === "Escape") select(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [keys, openIdx]);

  async function copy(e: OcsfEvent) {
    try { await navigator.clipboard.writeText(JSON.stringify(e, null, 2)); setCopied("ok"); }
    catch { setCopied("fail"); } // clipboard is undefined on plain-http LAN deployments
  }

  const num = (n: number) => n.toLocaleString(lang);

  return (
    <>
      <h1 className="view-title">{t.events}<small>{num(rows.length)} / {num(events.length)}</small></h1>
      <div className="split">
        <div className="grid">
          <Panel title={e_.query}>
            <div className="filters">
              <input className="ctl mono" type="search" aria-label={e_.query} placeholder={e_.placeholder} value={q} onChange={(ev) => setQ(ev.target.value)} spellCheck={false} />
              {q && <button className="btn" onClick={() => setQ("")}>{t.clear}</button>}
            </div>
            {query.tokens.length > 0 && (
              <div className="filters" role="group" aria-label={e_.active}>
                {query.tokens.map((tk) => (
                  <button key={`${tk.field}:${tk.value}`} type="button" className="tag tac-t" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5 }}
                    aria-label={`${e_.remove} ${tk.field}:${tk.value}`} onClick={() => setQ(toggleToken(q, tk.field, tk.value))}>
                    {tk.field}:{tk.value}
                    <svg width="9" height="9" viewBox="0 0 10 10" aria-hidden><path d="M2 2l6 6M8 2 2 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>
                  </button>
                ))}
              </div>
            )}
            <p className="hint">{e_.hint}</p>
            <Trend series={bucket(rows.map((e) => e.time), from, to, N)} from={from} to={to} label={e_.histogram} lang={lang} />
          </Panel>

          <div className="grid g2">
            {facets.map((f) => {
              const max = Math.max(1, ...f.vals.map(([, n]) => n));
              return (
                <Panel key={f.field} title={f.label} aside={<span className="mono">{f.field}:</span>}>
                  {f.vals.length === 0 ? <p className="note">—</p> : (
                    <div className="bars">
                      {f.vals.map(([v, n]) => {
                        const on = hasToken(query, f.field, v);
                        return (
                          <button key={v} type="button" className="row" aria-pressed={on} title={`${f.field}:${quote(v)}`}
                            style={{ ...FACET_ROW, background: on ? "var(--brand-soft)" : "none" }} onClick={() => setQ(toggleToken(q, f.field, v))}>
                            <span className="name">{on ? <b>{v}</b> : v}</span>
                            <span className="track"><span className="fill" style={{ display: "block", width: `${(n / max) * 100}%`, background: on ? "var(--brand)" : "var(--brand-mid)" }} /></span>
                            <span className="n">{num(n)}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </Panel>
              );
            })}
          </div>

          <Panel title={`${num(rows.length)} ${t.events_}`}>
            {data.events && !data.events.ok ? <p className="empty"><b>{t.unreachable}.</b> {data.events.reason}</p>
              : events.length === 0 ? <p className="empty">{t.noData}</p>
              : rows.length === 0 ? <p className="empty">{e_.noMatch} <button className="btn" onClick={() => setQ("")}>{t.clear}</button></p> : (
              <>
                <div className="table-wrap">
                  <table className="data">
                    <thead><tr><th>{t.time}</th><th>{t.class}</th><th>{t.status}</th><th>{t.source}</th><th>{t.actor}</th><th>{t.parser}</th></tr></thead>
                    <tbody>
                      {shown.map((e, i) => (
                        <tr key={keys[i]} className="clk" aria-selected={keys[i] === openKey} onClick={() => select(keys[i])}>
                          <td className="muted" style={{ whiteSpace: "nowrap" }}>{fmtTime(e.time, lang)}</td>
                          <td>{classOf(e) || "—"}</td>
                          <td>{e.status || "—"}</td>
                          <td className="mono">{e.src_endpoint?.ip || "—"}</td>
                          <td>{e.actor?.user?.name || "—"}</td>
                          <td className="muted">{e.siem?.source_type}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {rows.length > CAP && <p className="note">{e_.shown(num(CAP), num(rows.length))}</p>}
              </>
            )}
          </Panel>
        </div>

        <aside className="faceplate" aria-label={t.events}>
          {open ? (
            <>
              <h2>{classOf(open) || "—"} · type_uid {open.type_uid ?? "—"}</h2>
              <h3>{open.siem?.source_type || "unknown"}</h3>
              <dl className="kv">
                <dt>{t.time}</dt><dd>{fmtTime(open.time, lang)}</dd>
                <dt>{t.status}</dt><dd>{open.status || "—"}</dd>
                <dt>{t.source}</dt><dd className="mono">{open.src_endpoint?.ip || "—"}{open.dst_endpoint?.ip ? ` → ${open.dst_endpoint.ip}${open.dst_endpoint.port ? `:${open.dst_endpoint.port}` : ""}` : ""}</dd>
                <dt>{t.actor}</dt><dd>{open.actor?.user?.name || "—"}</dd>
                <dt>{t.hostname}</dt><dd>{open.src_endpoint?.hostname || "—"}</dd>
                <dt>{e_.uid}</dt><dd className="mono">{open.metadata?.uid || "—"}</dd>
                <dt>{e_.ingest}</dt><dd className="mono">{open.siem?.ingest_id || "—"}</dd>
              </dl>
              <h2>
                {e_.payload}
                <span className="aside"><span className="seg">
                  <button aria-pressed={mode === "msg"} onClick={() => setMode("msg")}>{t.raw}</button>
                  <button aria-pressed={mode === "ocsf"} onClick={() => setMode("ocsf")}>{t.normalized}</button>
                </span></span>
              </h2>
              {mode === "msg" && !open.message ? <p className="note">{e_.noMessage}</p>
                : <pre className="raw">{mode === "msg" ? open.message : JSON.stringify(open, null, 2)}</pre>}
              <div className="actions">
                <button className="btn" onClick={() => copy(open)}>{copied === "ok" ? e_.copied : e_.copyJson}</button>
              </div>
              <p className="note" aria-live="polite">{copied === "fail" ? e_.copyFailed : ""}</p>
            </>
          ) : <><p className="empty">{t.select}</p><p className="note">j / k, Esc</p></>}
        </aside>
      </div>
    </>
  );
}
