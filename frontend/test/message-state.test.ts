/**
 * Persisted resend outbox and seen ids (services/messageState.ts), and the
 * messaging.ts race recovery on top of them across a simulated refresh.
 */
import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { compareBytes, fromBase64url } from "../src/crypto/encoding";
import { createMutexLock } from "../src/crypto/session";
import {
  IndexedDbMessageState,
  MAX_OUTBOX_ITEMS,
  MAX_SEEN_PER_PEER,
  type OutgoingItem,
} from "../src/services/messageState";
import type { Protocol } from "../src/services/protocol";
import { recv, send, te, td, world } from "./helpers";

const sent = vi.hoisted(() => [] as unknown[]);
vi.mock("../src/services/socket", () => ({
  socket: {
    timeout: () => ({
      emit: (_event: string, payload: unknown, cb: (err: Error | null, ack?: { success: boolean }) => void) => {
        sent.push(payload);
        cb(null, { success: true });
      },
    }),
  },
}));
vi.mock("react-hot-toast", () => ({ default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

const { track, resendAfterSessionSwitch } = await import("../src/services/messaging");

const newKey = () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
let dbCount = 0;
const freshName = () => `krypt-msgstate-test-${++dbCount}`;

const item = (id: string, attachment?: Uint8Array): OutgoingItem => ({
  contentType: attachment ? "image" : "text",
  msg: { v: 1, id, sentAt: 1, ...(attachment ? {} : { text: `text ${id}` }) },
  ...(attachment ? { attachment } : {}),
});

beforeEach(() => {
  sent.length = 0;
});

describe("IndexedDbMessageState", () => {
  it("outbox and seen ids survive a reopen (a refresh) with the same key", async () => {
    const key = await newKey();
    const dbName = freshName();
    const a = new IndexedDbMessageState({ key, dbName });
    const pic = crypto.getRandomValues(new Uint8Array(300));
    await a.appendOutbox("bob", "S1", item("m1"));
    await a.appendOutbox("bob", "S1", item("m2", pic));
    await a.markSeen("bob", "x1");
    await a.close();

    const b = new IndexedDbMessageState({ key, dbName });
    expect(await b.peekOutbox("bob")).toEqual({ sessionId: "S1", items: [item("m1"), item("m2", pic)] });
    expect(await b.hasSeen("bob", "x1")).toBe(true);
    expect(await b.hasSeen("bob", "x2")).toBe(false);
    expect(await b.hasSeen("carol", "x1")).toBe(false);
    await b.close();
  });

  it("a new session replaces the outbox; take removes it exactly once", async () => {
    const s = new IndexedDbMessageState({ key: await newKey(), dbName: freshName() });
    await s.appendOutbox("bob", "S1", item("m1"));
    await s.appendOutbox("bob", "S2", item("m2"));
    expect(await s.peekOutbox("bob")).toEqual({ sessionId: "S2", items: [item("m2")] });
    const [x, y] = await Promise.all([s.takeOutbox("bob"), s.takeOutbox("bob")]);
    expect([x, y].filter(Boolean)).toHaveLength(1);
    expect(await s.peekOutbox("bob")).toBeUndefined();
    await s.appendOutbox("bob", "S3", item("m3"));
    await s.clearOutbox("bob");
    expect(await s.peekOutbox("bob")).toBeUndefined();
  });

  it("two tabs sharing a lock never lose each other's appends", async () => {
    const key = await newKey();
    const dbName = freshName();
    const lock = createMutexLock();
    const tab1 = new IndexedDbMessageState({ key, dbName, lock });
    const tab2 = new IndexedDbMessageState({ key, dbName, lock });
    await Promise.all(
      Array.from({ length: 10 }, (_, i) => (i % 2 ? tab1 : tab2).appendOutbox("bob", "S1", item(`m${i}`))),
    );
    await Promise.all(Array.from({ length: 10 }, (_, i) => (i % 2 ? tab1 : tab2).markSeen("bob", `x${i}`)));
    expect((await tab1.peekOutbox("bob"))!.items.map((i) => i.msg.id).sort()).toEqual(
      Array.from({ length: 10 }, (_, i) => `m${i}`).sort(),
    );
    for (let i = 0; i < 10; i++) expect(await tab2.hasSeen("bob", `x${i}`)).toBe(true);
  });

  it("is bounded: oldest outbox items and seen ids are dropped first", async () => {
    const s = new IndexedDbMessageState({ key: await newKey(), dbName: freshName() });
    for (let i = 0; i < MAX_OUTBOX_ITEMS + 3; i++) await s.appendOutbox("bob", "S1", item(`m${i}`));
    const ids = (await s.peekOutbox("bob"))!.items.map((i) => i.msg.id);
    expect(ids).toHaveLength(MAX_OUTBOX_ITEMS);
    expect(ids[0]).toBe("m3");
    for (let i = 0; i < MAX_SEEN_PER_PEER + 1; i++) await s.markSeen("bob", `x${i}`);
    expect(await s.hasSeen("bob", "x0")).toBe(false);
    expect(await s.hasSeen("bob", "x1")).toBe(true);
    expect(await s.hasSeen("bob", `x${MAX_SEEN_PER_PEER}`)).toBe(true);
  }, 60_000);

  it("is sealed: a wrong key or a record moved to another peer's slot fails to open", async () => {
    const dbName = freshName();
    const key = await newKey();
    const s = new IndexedDbMessageState({ key, dbName });
    await s.appendOutbox("bob", "S1", item("secret-id"));
    await s.markSeen("bob", "x1");
    await s.close();

    const other = new IndexedDbMessageState({ key: await newKey(), dbName });
    await expect(other.peekOutbox("bob")).rejects.toThrow();
    await expect(other.hasSeen("bob", "x1")).rejects.toThrow();
    await other.close();

    // Raw records hold no plaintext, and copying bob's record to carol's slot fails.
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const r = indexedDB.open(dbName, 1);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
    const raw = await new Promise<{ iv: Uint8Array; ct: Uint8Array }>((resolve) => {
      const r = db.transaction("outbox").objectStore("outbox").get("bob");
      r.onsuccess = () => resolve(r.result);
    });
    expect(td.decode(raw.ct)).not.toContain("secret-id");
    await new Promise<void>((resolve) => {
      const tx = db.transaction("outbox", "readwrite");
      tx.objectStore("outbox").put(raw, "carol");
      tx.oncomplete = () => resolve();
    });
    db.close();
    const again = new IndexedDbMessageState({ key, dbName });
    await expect(again.peekOutbox("carol")).rejects.toThrow();
    expect((await again.peekOutbox("bob"))!.items[0].msg.id).toBe("secret-id");
  });
});

describe("race recovery across a refresh (messaging.ts)", () => {
  it("messages sent on the losing session are re-sent after a refresh", async () => {
    const { alice, bob } = await world();
    const key = await newKey();
    const dbName = freshName();
    const asProtocol = (state: IndexedDbMessageState) =>
      ({ username: "alice", session: alice.sm, messageState: state, kt: { gossip: () => null } }) as unknown as Protocol;

    // Both start at once; make alice the loser so her message needs re-sending.
    let fromAlice = await send(alice, bob, "lost?");
    let fromBob = await send(bob, alice, "hi");
    while (compareBytes(fromBase64url(fromAlice.sessionId), fromBase64url(fromBob.sessionId)) < 0) {
      // Alice won; start over with fresh sessions until she loses (p = 1/2 per try).
      await alice.sm.closeSession("bob");
      await bob.sm.closeSession("alice");
      fromAlice = await send(alice, bob, "lost?");
      fromBob = await send(bob, alice, "hi");
    }
    const tab = new IndexedDbMessageState({ key, dbName });
    const lostItem: OutgoingItem = { contentType: "text", msg: { v: 1, id: "m-lost", sentAt: 1, text: "lost?" } };
    await track(asProtocol(tab), "bob", fromAlice.sessionId, lostItem);
    await expect(bob.sm.decrypt(fromAlice)).rejects.toMatchObject({ code: "SESSION_SUPERSEDED" });
    await tab.close();

    // Refresh: a new tab opens the same database; then bob's init arrives.
    const tab2 = new IndexedDbMessageState({ key, dbName });
    expect((await tab2.peekOutbox("bob"))!.items).toHaveLength(1);
    const r = await alice.sm.decrypt(fromBob);
    await resendAfterSessionSwitch(asProtocol(tab2), "bob", r.sessionId);
    expect(sent).toHaveLength(1);
    const resent = (sent[0] as { envelope: unknown }).envelope;
    const got = await bob.sm.decrypt(resent);
    expect(got.sessionId).toBe(fromBob.sessionId);
    expect(JSON.parse(td.decode(got.plaintext)).id).toBe("m-lost");
    // The outbox is consumed; a second switch notice sends nothing.
    await resendAfterSessionSwitch(asProtocol(tab2), "bob", r.sessionId);
    expect(sent).toHaveLength(1);
    expect(await recv(alice, await bob.sm.encrypt("alice", te.encode("ok"), "text"))).toBe("ok");
  });
});
