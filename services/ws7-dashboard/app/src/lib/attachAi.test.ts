import { describe, expect, it } from "vitest";
import { attachAi } from "./attachAi";
import type { Alert } from "../data/api";

const ai = { verdict: "suspicious", summary: "port sweep", level: "high", engine: "stub", model: null };
const aiDoc = (id: string): Alert => ({ alert_id: `ai-${id}`, event_ids: [id], ai }) as Alert;

describe("attachAi", () => {
  it("joins a count-window alert through its shared ingest id", () => {
    const out = attachAi([{ alert_id: "a1", event_ids: ["e1", "e2"] } as Alert], [aiDoc("e2")]);
    expect(out[0].ai?.verdict).toBe("suspicious");
  });

  it("joins a distinct-count alert through trigger_event_id (its event_ids are port values)", () => {
    const alert = { alert_id: "a2", event_ids: ["10000", "10001", "10002"], trigger_event_id: "ing-9" } as Alert;
    expect(attachAi([alert], [aiDoc("ing-9")])[0].ai?.verdict).toBe("suspicious");
  });

  it("leaves the alert untouched without a match and keeps an existing verdict", () => {
    const plain = { alert_id: "a3", event_ids: ["x"], trigger_event_id: null } as Alert;
    expect(attachAi([plain], [aiDoc("other")])[0]).toBe(plain);
    const own = { alert_id: "a4", ai: { ...ai, verdict: "benign" }, trigger_event_id: "ing-9" } as Alert;
    expect(attachAi([own], [aiDoc("ing-9")])[0].ai?.verdict).toBe("benign");
  });
});
