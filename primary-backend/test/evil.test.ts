import { describe, expect, it, vi } from "vitest";
import {
  base64Paths,
  createEvilRelay,
  duplicate,
  flipContentType,
  flipType,
  loadEvilRelay,
  parseBase64Field,
  parseEvilConfig,
  shouldDrop,
  tamper,
  type Attack,
  type RelayMessage,
} from "../src/evil.js";

const msg = (n: number, extra: Record<string, unknown> = {}): RelayMessage => ({
  to: "bob",
  from: "alice",
  type: "text",
  n,
  ...extra,
});
const relay = (attacks: Attack[], extra: Partial<{ dropEvery: number; swapWith: string }> = {}) =>
  createEvilRelay({
    attacks: new Set(attacks),
    dropEvery: extra.dropEvery ?? 3,
    swapWith: extra.swapWith ?? null,
  });
const ns = (ms: RelayMessage[]) => ms.map((m) => m.n);

// Deterministic rng returning the given values in turn.
const seq = (...values: number[]) => {
  let i = 0;
  return () => values[i++ % values.length]!;
};

describe("parseEvilConfig", () => {
  it("is off without EVIL_MODE", () => {
    expect(parseEvilConfig({})).toBeNull();
    expect(parseEvilConfig({ EVIL_MODE: "  " })).toBeNull();
  });
  it("parses attacks, drop interval and swap target", () => {
    const c = parseEvilConfig({
      EVIL_MODE: "Replay, drop,swap_key",
      EVIL_DROP_EVERY: "5",
      EVIL_SWAP_WITH: "mallory",
    })!;
    expect([...c.attacks]).toEqual(["replay", "drop", "swap_key"]);
    expect(c.dropEvery).toBe(5);
    expect(c.swapWith).toBe("mallory");
  });
  it("defaults EVIL_DROP_EVERY to 3 and rejects unknown attacks", () => {
    expect(parseEvilConfig({ EVIL_MODE: "drop", EVIL_DROP_EVERY: "zero" })!.dropEvery).toBe(3);
    expect(() => parseEvilConfig({ EVIL_MODE: "replay,nuke" })).toThrow(/nuke/);
  });
  it("logs a loud warning when enabled", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(loadEvilRelay({})).toBeNull();
    expect(warn).not.toHaveBeenCalled();
    expect(loadEvilRelay({ EVIL_MODE: "tamper" })).not.toBeNull();
    expect(warn.mock.calls[0]![0]).toMatch(/EVIL RELAY MODE IS ON/);
    warn.mockRestore();
  });
});

describe("pure transforms", () => {
  it("flip_type sets type to image without touching the input", () => {
    const m = msg(1);
    expect(flipType(m).type).toBe("image");
    expect(m.type).toBe("text");
  });

  it("flip_content_type flips the envelope's contentType, not the outer type", () => {
    const m = msg(1, { envelope: { contentType: "text", body: "x" } });
    const out = flipContentType(m);
    expect(out.envelope).toEqual({ contentType: "image", body: "x" });
    expect(out.type).toBe("text");
    expect((m.envelope as { contentType: string }).contentType).toBe("text"); // input untouched
    expect((flipContentType(out).envelope as { contentType: string }).contentType).toBe("text");
  });

  it("flip_content_type leaves frames without an envelope alone", () => {
    const m = msg(1);
    expect(flipContentType(m)).toBe(m);
    const bad = msg(1, { envelope: { contentType: 7 } });
    expect(flipContentType(bad)).toBe(bad);
  });

  it("duplicate returns two equal, independent copies", () => {
    const [a, b] = duplicate(msg(1, { header: { k: 1 } }));
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
  });

  it("shouldDrop drops every Nth", () => {
    expect([1, 2, 3, 4, 5, 6].map((n) => shouldDrop(n, 3))).toEqual([
      false, false, true, false, false, true,
    ]);
  });

  it("recognises prefixed base64, base64url and rejects other strings", () => {
    const raw = Buffer.from("0123456789abcdef");
    expect(parseBase64Field("GCM:" + raw.toString("base64"))).toMatchObject({
      prefix: "GCM:",
      encoding: "base64",
    });
    expect(parseBase64Field(Buffer.from([251, 255, 0, 1, 2, 3, 4, 5, 6, 7]).toString("base64url")))
      .toMatchObject({ prefix: "", encoding: "base64url" });
    expect(parseBase64Field("hello world, not base64")).toBeNull();
    expect(parseBase64Field("short")).toBeNull();
  });

  it("finds base64 fields, nested too, but never to/from/type", () => {
    const b64 = Buffer.alloc(32, 7).toString("base64");
    const m = msg(1, { ciphertext: "GCM:" + b64, header: { ek: b64 }, note: "plain text" });
    expect(base64Paths(m)).toEqual([["ciphertext"], ["header", "ek"]]);
  });

  it("tamper flips exactly one bit in one field and keeps the encoding", () => {
    const ct = Buffer.alloc(40, 0xaa);
    const m = msg(1, {
      ciphertext: "GCM:" + ct.toString("base64"),
      sig: Buffer.alloc(16, 1).toString("base64url"),
    });
    // rng: pick field 0 (ciphertext), byte 0.5*40 = 20, bit floor(0.4*8) = 3
    const out = tamper(m, seq(0, 0.5, 0.4));
    expect(out.sig).toBe(m.sig);
    expect(m.ciphertext).toBe("GCM:" + ct.toString("base64")); // input untouched
    const s = out.ciphertext as string;
    expect(s.startsWith("GCM:")).toBe(true);
    const got = Buffer.from(s.slice(4), "base64");
    const diff = Array.from(got, (b, i) => b ^ ct[i]!);
    expect(diff.filter((d) => d !== 0)).toEqual([1 << 3]);
    expect(diff[20]).toBe(1 << 3);
  });

  it("tamper leaves a message without base64 fields alone", () => {
    const m = msg(1);
    expect(tamper(m)).toBe(m);
  });
});

describe("relay pipeline", () => {
  it("passes messages through with no attacks", () => {
    const r = relay([]);
    expect(ns([1, 2, 3].flatMap((n) => r.process(msg(n))))).toEqual([1, 2, 3]);
  });

  it("drop removes every Nth message per sender/recipient pair", () => {
    const r = relay(["drop"], { dropEvery: 2 });
    expect(ns([1, 2, 3, 4].flatMap((n) => r.process(msg(n))))).toEqual([1, 3]);
    // A different pair has its own counter.
    expect(r.process({ ...msg(9), to: "carol" })).toHaveLength(1);
  });

  it("duplicate delivers everything twice", () => {
    const r = relay(["duplicate"]);
    expect(ns([1, 2].flatMap((n) => r.process(msg(n))))).toEqual([1, 1, 2, 2]);
  });

  it("reorder holds one message and releases it after the next", () => {
    const r = relay(["reorder"]);
    expect(ns(r.process(msg(1)))).toEqual([]);
    expect(ns(r.process(msg(2)))).toEqual([2, 1]);
    expect(ns(r.process(msg(3)))).toEqual([]);
    expect(ns(r.process(msg(4)))).toEqual([4, 3]);
  });

  it("replay re-sends the previous message after the next one", () => {
    const r = relay(["replay"]);
    expect(ns(r.process(msg(1)))).toEqual([1]);
    expect(ns(r.process(msg(2)))).toEqual([2, 1]);
    expect(ns(r.process(msg(3)))).toEqual([3, 2]);
  });

  it("flip_type and tamper apply to every delivered message", () => {
    const r = createEvilRelay(
      { attacks: new Set(["flip_type", "tamper"]), dropEvery: 3, swapWith: null },
      seq(0, 0, 0),
    );
    const ct = "GCM:" + Buffer.alloc(16).toString("base64");
    const [out] = r.process(msg(1, { ciphertext: ct }));
    expect(out!.type).toBe("image");
    expect(out!.ciphertext).not.toBe(ct);
  });

  it("flip_content_type applies in the relay pipeline", () => {
    const r = relay(["flip_content_type"]);
    const [out] = r.process(msg(1, { envelope: { contentType: "text" } }));
    expect((out!.envelope as { contentType: string }).contentType).toBe("image");
  });

  it("parses flip_content_type from EVIL_MODE", () => {
    expect([...parseEvilConfig({ EVIL_MODE: "flip_content_type" })!.attacks]).toEqual(["flip_content_type"]);
  });

  it("swap_key serves EVIL_SWAP_WITH's keys for everyone else", () => {
    const r = relay(["swap_key"], { swapWith: "mallory" });
    expect(r.keySource("bob")).toBe("mallory");
    expect(r.keySource("mallory")).toBe("mallory");
    expect(relay([], { swapWith: "mallory" }).keySource("bob")).toBe("bob");
    expect(relay(["swap_key"]).keySource("bob")).toBe("bob");
  });
});
