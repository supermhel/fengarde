import { describe, expect, it } from "vitest";
import type { OcsfEvent } from "../data/api";
import { E } from "./events.i18n";
import { formatQuery, matchEvent, parseQuery, toggleToken } from "./Events";

const ev: OcsfEvent = {
  time: 1, class_uid: 3002, status: "Failure", message: "Failed password for root from 10.0.0.5 port 22",
  src_endpoint: { ip: "10.0.0.5", hostname: "edge-01" }, dst_endpoint: { ip: "192.168.1.10" },
  actor: { user: { name: "root" } }, metadata: { uid: "abc-123" }, siem: { source_type: "linux_ssh", ingest_id: "i1" },
};
const m = (q: string, e: OcsfEvent = ev) => matchEvent(e, parseQuery(q));

describe("parseQuery", () => {
  it("splits field tokens from free text and keeps quoted values", () => {
    expect(parseQuery('source:linux_ssh failed class:"Network Activity" "two words"')).toEqual({
      tokens: [{ field: "source", value: "linux_ssh" }, { field: "class", value: "Network Activity" }],
      text: ["failed", "two words"],
    });
  });
  it("treats unknown prefixes (IPv6, times) as free text and ignores empty known fields", () => {
    expect(parseQuery("fe80::1 12:30 foo:bar ip:")).toEqual({ tokens: [], text: ["fe80::1", "12:30", "foo:bar"] });
  });
  it("accepts field names case-insensitively and unclosed quotes while typing", () => {
    expect(parseQuery('IP:10.0.0.5 actor:"john d').tokens).toEqual([{ field: "ip", value: "10.0.0.5" }, { field: "actor", value: "john d" }]);
  });
  it("round-trips through formatQuery", () => {
    const q = 'status:Failure class:"Network Activity" root';
    expect(formatQuery(parseQuery(q))).toBe(q);
  });
});

describe("matchEvent", () => {
  it("matches every field token case-insensitively", () => {
    expect(m("source:LINUX_SSH status:failure class:authentication actor:root")).toBe(true);
    expect(m("class:3002")).toBe(true);
    expect(m("status:Success")).toBe(false);
  });
  it("ip: matches source or destination", () => {
    expect(m("ip:10.0.0.5")).toBe(true);
    expect(m("ip:192.168.1.10")).toBe(true);
    expect(m("ip:10.0.0.6")).toBe(false);
  });
  it("free text ANDs terms across message, ips, user, host, parser, status and uid", () => {
    expect(m("password edge-01 abc-123")).toBe(true);
    expect(m("password nobody")).toBe(false);
  });
  it("files events without a parser under source:unknown", () => {
    expect(m("source:unknown", { time: 2 })).toBe(true);
  });
});

describe("toggleToken", () => {
  it("adds a missing token and removes a present one, keeping free text", () => {
    const added = toggleToken("root", "status", "Failure");
    expect(added).toBe("status:Failure root");
    expect(toggleToken(added, "status", "failure")).toBe("root");
    expect(toggleToken("", "class", "Network Activity")).toBe('class:"Network Activity"');
  });
});

describe("events i18n", () => {
  it("has every English key translated to German", () => {
    for (const k of Object.keys(E.en)) expect(E.de).toHaveProperty(k);
  });
});
