// ISA-101 alarm priority: shape + label carry severity; colour only reinforces it.
export type Priority = "critical" | "high" | "medium" | "low";

const ORDER: Record<Priority, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function priority(level: string | undefined): Priority {
  const l = (level || "").toLowerCase();
  if (l === "critical") return "critical";
  if (l === "high") return "high";
  if (l === "medium") return "medium";
  return "low";
}

export const rank = (level: string | undefined) => ORDER[priority(level)];

/** Abnormal = needs an operator's eye: critical/high not yet triaged away. */
export function isAbnormal(level: string | undefined, triageStatus?: string): boolean {
  const s = (triageStatus || "new").toLowerCase();
  if (s === "closed" || s === "false_positive") return false;
  return rank(level) >= ORDER.high;
}
