import { useId, type ReactNode } from "react";
import type { GraphEdge, GraphNode, OpsMetrics, Result } from "../data/api";
import { priority, type Priority } from "../lib/severity";

/* ISA-101 alarm shapes: red square, amber triangle, yellow diamond, outlined circle. */
export function AlarmShape({ level, size = 14 }: { level: string | undefined; size?: number }) {
  const p: Priority = priority(level);
  const s = size;
  if (p === "critical")
    return <svg width={s} height={s} viewBox="0 0 14 14" aria-hidden><rect x="1" y="1" width="12" height="12" rx="1" fill="var(--red)" stroke="var(--ink)" strokeWidth="1" /></svg>;
  if (p === "high")
    return <svg width={s} height={s} viewBox="0 0 14 14" aria-hidden><path d="M7 1 13.2 12.5H.8z" fill="var(--amber)" stroke="var(--ink)" strokeWidth="1" strokeLinejoin="round" /></svg>;
  if (p === "medium")
    return <svg width={s} height={s} viewBox="0 0 14 14" aria-hidden><path d="M7 .8 13.2 7 7 13.2.8 7z" fill="var(--yellow)" stroke="var(--ink)" strokeWidth="1" /></svg>;
  return <svg width={s} height={s} viewBox="0 0 14 14" aria-hidden><circle cx="7" cy="7" r="5.2" fill="none" stroke="var(--ink-2)" strokeWidth="1.4" /></svg>;
}

export function Sev({ level }: { level: string | undefined }) {
  return <span className="sev"><AlarmShape level={level} />{priority(level)}</span>;
}

export function Panel({ title, aside, children, className = "" }: { title: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      <h2>{title}{aside != null && <span className="aside">{aside}</span>}</h2>
      {children}
    </section>
  );
}

/* One stroke icon set (24px grid, 1.8 stroke), drawn for this console. */
const ICONS: Record<string, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" /><rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" /></>,
  alarms: <><path d="M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15z" /><path d="M10 20.5h4" /></>,
  incidents: <><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="8" r="2.5" /><circle cx="10" cy="18" r="2.5" /><path d="M8.3 7l7.3.7M16.7 10.2l-5.3 5.9M7 8.4l2.3 7.2" /></>,
  events: <><path d="M8 6h13M8 12h13M8 18h13" /><circle cx="3.5" cy="6" r="1" /><circle cx="3.5" cy="12" r="1" /><circle cx="3.5" cy="18" r="1" /></>,
  coverage: <><rect x="3" y="3" width="8" height="8" rx="1.5" /><rect x="13" y="3" width="8" height="8" rx="1.5" /><rect x="3" y="13" width="8" height="8" rx="1.5" /><path d="M13 17h8M17 13v8" /></>,
  inventory: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5" /><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" /></>,
  operations: <path d="M3 12h4l2 7 4-14 2 7h6" />,
  audit: <><path d="M9 3h6l5 5v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" /><path d="M9 12h6M9 16h6M9 8h2" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1" /></>,
  account: <><circle cx="12" cy="8" r="4" /><path d="M4 21c1.3-4 4.4-6 8-6s6.7 2 8 6" /></>,
  sources: <><path d="M4 12a8 8 0 0 1 16 0" /><path d="M7.5 12a4.5 4.5 0 0 1 9 0" /><circle cx="12" cy="12" r="1.5" /><path d="M12 13.5V21" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <path d="M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z" />,
  classic: <><path d="M14 4h6v6" /><path d="M20 4 11 13" /><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></>,
};
export function Icon({ name, size = 18 }: { name: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {ICONS[name]}
    </svg>
  );
}

/* Trend recorder: one series over fixed buckets, a "now" cursor, optional alarm marks. */
export function Trend({ series, from, to, marks = [], label, lang, tone = "brand" }: {
  series: number[]; from: number; to: number; marks?: number[]; label: string; lang: string; tone?: "brand" | "alarm";
}) {
  const gid = useId();
  const col = tone === "alarm" ? "var(--amber)" : "var(--brand)";
  const W = 600, H = 150, L = 34, R = 8, T = 10, B = 22;
  const max = Math.max(1, ...series);
  const x = (i: number) => L + (i / Math.max(1, series.length - 1)) * (W - L - R);
  const y = (v: number) => T + (1 - v / max) * (H - T - B);
  const pts = series.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const tx = (t: number) => L + ((t - from) / (to - from)) * (W - L - R);
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => from + f * (to - from));
  const fmt = (t: number) => new Date(t).toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" });
  return (
    <div className={`trend tone-${tone}`}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${label}: max ${max} per interval`}>
        <defs>
          <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor={col} stopOpacity=".34" />
            <stop offset="1" stopColor={col} stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 0.5, 1].map((f) => <line key={f} className="grid-line" x1={L} x2={W - R} y1={T + f * (H - T - B)} y2={T + f * (H - T - B)} />)}
        <text className="axis" x={L - 6} y={T + 4} textAnchor="end">{max}</text>
        <text className="axis" x={L - 6} y={H - B + 4} textAnchor="end">0</text>
        {ticks.map((t, i) => <text key={i} className="axis" x={tx(t)} y={H - 6} textAnchor={i === 0 ? "start" : i === 4 ? "end" : "middle"}>{fmt(t)}</text>)}
        <polygon fill={`url(#${gid})`} points={`${L},${H - B} ${pts} ${W - R},${H - B}`} />
        <polyline className="line" points={pts} />
        <line className="now" x1={W - R} x2={W - R} y1={T} y2={H - B} />
        {marks.filter((t) => t >= from && t <= to).map((t, i) => (
          <path key={i} className="mark" d={`M${tx(t)} ${T + 1} l5 8.5h-10z`} />
        ))}
      </svg>
    </div>
  );
}

/* Pipeline mimic: process schematic. Teal = running, slate = idle, amber/red = abnormal/down. */
export type Stage = { key: string; name: string; sub: string; metric: Result<OpsMetrics> | null; value: number; abnormal?: string };

export function Mimic({ stages, downLabel = "metrics endpoint did not answer" }: { stages: Stage[]; downLabel?: string }) {
  const W = 980, H = 136, n = stages.length, gap = 30, bw = (W - gap * (n - 1)) / n, bh = 80, top = 12;
  const max = Math.max(1, ...stages.map((s) => s.value));
  return (
    <div className="mimic">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Pipeline schematic with per-stage throughput">
        {stages.map((s, i) => {
          const x = i * (bw + gap);
          const down = s.metric !== null && !s.metric.ok;
          const live = !down && s.value > 0;
          const cls = `node${down ? " down" : s.abnormal ? " abnormal" : live ? "" : " idle"}`;
          return (
            <g key={s.key}>
              {i > 0 && (
                <g>
                  <path className={`flow${live ? " live" : ""}`} d={`M${x - gap + 2} ${top + bh / 2}h${gap - 10}`} />
                  <path className={`arrow${live ? " live" : ""}`} d={`M${x - 9} ${top + bh / 2 - 5}l7 5-7 5z`} />
                </g>
              )}
              <g className={cls}>
                <rect className="body" x={x} y={top} width={bw} height={bh} rx="6" />
                <rect className="cap" x={x} y={top} width={bw} height="4" rx="2" />
                <text x={x + 12} y={top + 25} fontWeight="700" fontSize="15">{s.name}</text>
                <text className="sub" x={x + 12} y={top + 41}>{s.sub}</text>
                <rect className="bar-bg" x={x + 12} y={top + 52} width={bw - 24} height="7" rx="3.5" />
                <rect className="bar" x={x + 12} y={top + 52} width={Math.max(0, (bw - 24) * (s.value / max))} height="7" rx="3.5" />
                <text className="val" x={x + 12} y={top + 73} fontSize="13" fontWeight="600">{down ? "—" : s.value.toLocaleString()}</text>
              </g>
              {(down || s.abnormal) && (
                <text x={x + 2} y={H - 4} fontSize="11.5" fill="var(--ink)">{down ? downLabel : s.abnormal}</text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

/* Horizontal proportion bars; colour is categorical, the label and count carry the meaning. */
export function Bars({ rows }: { rows: [string, number][] }) {
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <div className="bars">
      {rows.map(([name, n], i) => (
        <div className="row" key={name}>
          <span className="name" title={name}>{name}</span>
          <span className="track"><span className={`fill c${i % 6}`} style={{ display: "block", width: `${(n / max) * 100}%` }} /></span>
          <span className="n">{n.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

/* Causal graph: entities top-down in first-seen order, edges labelled by kind. */
export function Graph({ nodes, edges, onPick }: { nodes: GraphNode[]; edges: GraphEdge[]; onPick?: (entityId: string) => void }) {
  const W = 420, rowH = 58, bw = 170, bh = 38;
  const order = nodes.map((n) => n.entity_id);
  const pos = (id: string) => {
    const i = Math.max(0, order.indexOf(id));
    return { x: (i % 2) * (W - bw), y: 10 + i * rowH };
  };
  const H = 20 + nodes.length * rowH;
  return (
    <div className="graph">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Causal graph with ${nodes.length} entities and ${edges.length} edges`}>
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0 0 10 5 0 10z" fill="var(--nominal)" />
          </marker>
        </defs>
        {edges.map((e, i) => {
          const a = pos(e.from), b = pos(e.to);
          const x1 = a.x + bw / 2, y1 = a.y + bh, x2 = b.x + bw / 2, y2 = b.y;
          return (
            <g key={i}>
              <path className="gedge" d={`M${x1} ${y1} C${x1} ${y1 + 16} ${x2} ${y2 - 16} ${x2} ${y2 - 2}`} />
              <text className="gsub" x={(x1 + x2) / 2 + 6} y={(y1 + y2) / 2 + 3}>{e.kind}</text>
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos(n.entity_id);
          return (
            <g key={n.entity_id} className={`gnode${onPick ? " pick" : ""}`} role={onPick ? "button" : undefined} tabIndex={onPick ? 0 : undefined}
              aria-label={onPick ? `${n.entity_type} ${n.entity_value}` : undefined}
              onClick={onPick ? () => onPick(n.entity_id) : undefined}
              onKeyDown={onPick ? (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onPick(n.entity_id); } } : undefined}>
              <rect x={p.x} y={p.y} width={bw} height={bh} rx="6" />
              <text className="gsub" x={p.x + 8} y={p.y + 14}>{n.entity_type}</text>
              <text x={p.x + 8} y={p.y + 30} fontWeight="600">{n.entity_value.length > 24 ? n.entity_value.slice(0, 23) + "…" : n.entity_value}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function Shield({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden>
      <path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z" fill="var(--brand)" />
      <path d="M8.5 12.2 11 14.6l4.6-5" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
