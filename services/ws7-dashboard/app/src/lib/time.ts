export const RANGES = { "1h": 3600e3, "24h": 864e5, "7d": 7 * 864e5, "30d": 30 * 864e5 } as const;
export type RangeKey = keyof typeof RANGES;

export function fmtTime(ms: number, lang: string): string {
  const d = new Date(ms);
  const sameDay = new Date().toDateString() === d.toDateString();
  return sameDay
    ? d.toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString(lang, { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function ago(ms: number, lang: string): string {
  const s = Math.round((Date.now() - ms) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  if (Math.abs(s) < 60) return rtf.format(-s, "second");
  if (Math.abs(s) < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (Math.abs(s) < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}

/** Count items per fixed-width bucket across [from, to). */
export function bucket(times: number[], from: number, to: number, n: number): number[] {
  const out = new Array(n).fill(0);
  const w = (to - from) / n;
  for (const t of times) {
    if (t < from || t >= to) continue;
    out[Math.min(n - 1, Math.floor((t - from) / w))]++;
  }
  return out;
}
