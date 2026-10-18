import { describe, expect, it, vi } from "vitest";
import {
  FILE_BYTES_PER_MINUTE,
  FILE_FRAMES_PER_MINUTE,
  MAX_ACTIVE_TRANSFERS,
  MAX_FILE_FRAME_DATA,
  TRANSFER_IDLE_MS,
  createFileChunkRelay,
} from "../src/fileRelay.js";
import type { MessagePolicy } from "../src/social.js";

const alice = { userId: "u-alice", username: "alice" };
const tid = (n = 0) => Buffer.from(new Uint8Array(16).fill(n)).toString("base64url");
const frame = (over: Record<string, unknown> = {}) => ({
  to: "bob",
  transferId: tid(),
  index: 0,
  nonceCounter: 0,
  data: new Uint8Array(1024 + 16),
  ...over,
});

function setup(policy: MessagePolicy = "ok", online = true) {
  let t = 0;
  const emitted: { to: string; event: string; payload: Record<string, unknown> }[] = [];
  const relay = createFileChunkRelay({
    policy: vi.fn(async () => policy),
    emitToUser: (to, event, payload) => {
      if (!online) return false;
      emitted.push({ to, event, payload: payload as Record<string, unknown> });
      return true;
    },
    now: () => t,
  });
  return { relay, emitted, advance: (ms: number) => (t += ms) };
}

describe("file:chunk relay", () => {
  it("forwards a valid chunk with `from` taken from the token, not the frame", async () => {
    const { relay, emitted } = setup();
    expect(await relay(alice, frame())).toEqual({ ok: true });
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toMatchObject({ to: "bob", event: "file:chunk", payload: { from: "alice", index: 0, nonceCounter: 0 } });
    expect(await relay(alice, { ...frame(), from: "mallory" })).toEqual({ ok: false, error: "INVALID" });
  });

  it.each<[string, Record<string, unknown>]>([
    ["missing to", { to: undefined }],
    ["bad transferId", { transferId: "not-an-id" }],
    ["15-byte transferId", { transferId: Buffer.alloc(15).toString("base64url") }],
    ["negative index", { index: -1 }],
    ["index past the chunk cap", { index: 4096 }],
    ["fractional counter", { nonceCounter: 1.5 }],
    ["counter past 2^32", { nonceCounter: 2 ** 32 }],
    ["string data", { data: "AAAA" }],
    ["data shorter than a GCM tag", { data: new Uint8Array(15) }],
  ])("rejects %s as INVALID", async (_name, over) => {
    const { relay, emitted } = setup();
    expect(await relay(alice, frame(over))).toEqual({ ok: false, error: "INVALID" });
    expect(emitted).toHaveLength(0);
  });

  it("rejects an oversize frame before parsing it", async () => {
    const { relay } = setup();
    expect(await relay(alice, frame({ data: new Uint8Array(MAX_FILE_FRAME_DATA + 1) }))).toEqual({ ok: false, error: "TOO_LARGE" });
    expect(await relay(alice, frame({ data: new Uint8Array(MAX_FILE_FRAME_DATA) }))).toEqual({ ok: true });
  });

  it("refuses blocked senders and non-friends", async () => {
    expect(await setup("blocked").relay(alice, frame())).toEqual({ ok: false, error: "BLOCKED" });
    expect(await setup("not_friends").relay(alice, frame())).toEqual({ ok: false, error: "NOT_FRIENDS" });
  });

  it("does not store chunks for an offline recipient", async () => {
    const { relay, emitted } = setup("ok", false);
    expect(await relay(alice, frame())).toEqual({ ok: false, error: "OFFLINE" });
    expect(emitted).toHaveLength(0);
  });

  it("limits frames per minute per sender", async () => {
    const { relay, advance } = setup();
    for (let i = 0; i < FILE_FRAMES_PER_MINUTE; i++) expect((await relay(alice, frame({ data: new Uint8Array(16) }))).ok).toBe(true);
    expect(await relay(alice, frame({ data: new Uint8Array(16) }))).toEqual({ ok: false, error: "RATE_LIMITED" });
    expect((await relay({ userId: "u-carol", username: "carol" }, frame({ data: new Uint8Array(16) }))).ok).toBe(true);
    advance(60_000);
    expect((await relay(alice, frame({ data: new Uint8Array(16) }))).ok).toBe(true);
  });

  it("limits bytes per minute per sender", async () => {
    const { relay } = setup();
    const big = new Uint8Array(MAX_FILE_FRAME_DATA);
    const fit = Math.floor(FILE_BYTES_PER_MINUTE / big.length);
    for (let i = 0; i < fit; i++) expect((await relay(alice, frame({ data: big }))).ok).toBe(true);
    expect(await relay(alice, frame({ data: big }))).toEqual({ ok: false, error: "RATE_LIMITED" });
  });

  it("caps concurrent transfers per sender; idle ones stop counting", async () => {
    const { relay, advance } = setup();
    for (let i = 0; i < MAX_ACTIVE_TRANSFERS; i++) expect((await relay(alice, frame({ transferId: tid(i) }))).ok).toBe(true);
    expect(await relay(alice, frame({ transferId: tid(99) }))).toEqual({ ok: false, error: "TOO_MANY_TRANSFERS" });
    expect((await relay(alice, frame({ transferId: tid(0), index: 1 }))).ok).toBe(true);
    advance(TRANSFER_IDLE_MS);
    expect((await relay(alice, frame({ transferId: tid(99) }))).ok).toBe(true);
  });

  it("reports a failed relationship check as SERVER_ERROR", async () => {
    const relay = createFileChunkRelay({
      policy: async () => {
        throw new Error("db down");
      },
      emitToUser: () => true,
    });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await relay(alice, frame())).toEqual({ ok: false, error: "SERVER_ERROR" });
    spy.mockRestore();
  });
});
