import { describe, expect, it } from "vitest";
import { isAbnormal, priority, rank } from "./severity";
import { bucket } from "./time";
import { dicts } from "./i18n";

describe("severity", () => {
  it("maps unknown levels to low, never to an alarm", () => {
    expect(priority("weird")).toBe("low");
    expect(isAbnormal("weird")).toBe(false);
  });
  it("treats untriaged high/critical as abnormal and triaged-away as normal", () => {
    expect(isAbnormal("high")).toBe(true);
    expect(isAbnormal("critical", "closed")).toBe(false);
    expect(isAbnormal("high", "false_positive")).toBe(false);
    expect(isAbnormal("medium")).toBe(false);
    expect(rank("critical")).toBeGreaterThan(rank("high"));
  });
});

describe("bucket", () => {
  it("counts into fixed buckets and drops out-of-range times", () => {
    expect(bucket([0, 1, 5, 9, 10, -1], 0, 10, 2)).toEqual([2, 2]);
  });
});

describe("i18n", () => {
  it("has every English key translated to German", () => {
    for (const k of Object.keys(dicts.en)) expect(dicts.de).toHaveProperty(k);
  });
});
