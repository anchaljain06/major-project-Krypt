import { describe, expect, it } from "vitest";
import {
  enqueue,
  flush,
  MAILBOX_BYTE_QUOTA,
  MAILBOX_QUOTA,
  MAILBOX_TTL_MS,
  type MailboxStore,
} from "../src/mailbox.js";

interface Row {
  id: string;
  to: string;
  from: string;
  payload: unknown;
  bytes: number;
  createdAt: number;
}

/** In-memory MailboxStore with a controllable clock. */
function fakeStore() {
  const rows: Row[] = [];
  let seq = 0;
  let clock = 1_000_000;
  const deleted: string[][] = [];
  const store: MailboxStore & {
    rows: Row[];
    deleted: string[][];
    tick(ms: number): void;
    onFetch?: () => void;
  } = {
    rows,
    deleted,
    tick(ms) {
      clock += ms;
    },
    async usage(to, notBefore) {
      const live = rows.filter((r) => r.to === to && r.createdAt >= notBefore.getTime());
      return { count: live.length, bytes: live.reduce((n, r) => n + r.bytes, 0) };
    },
    async insert({ to, from, payload, bytes }) {
      rows.push({ id: `m${++seq}`, to, from, payload, bytes, createdAt: clock++ });
    },
    async fetch(to, notBefore, limit) {
      store.onFetch?.();
      return rows
        .filter((r) => r.to === to && r.createdAt >= notBefore.getTime())
        .sort((a, b) => a.createdAt - b.createdAt)
        .slice(0, limit)
        .map(({ id, payload }) => ({ id, payload }));
    },
    async deleteIds(ids) {
      deleted.push([...ids]);
      for (const id of ids) {
        const i = rows.findIndex((r) => r.id === id);
        if (i >= 0) rows.splice(i, 1);
      }
    },
    async purgeExpired(cutoff) {
      const before = rows.length;
      for (let i = rows.length - 1; i >= 0; i--) {
        if (rows[i]!.createdAt < cutoff.getTime()) rows.splice(i, 1);
      }
      return before - rows.length;
    },
  };
  return { store, now: () => clock };
}

describe("mailbox flush", () => {
  it("delivers in createdAt order and deletes exactly the delivered ids", async () => {
    const { store, now } = fakeStore();
    for (let i = 1; i <= 3; i++) await enqueue(store, { to: "bob", from: "alice", payload: i });
    await enqueue(store, { to: "carol", from: "alice", payload: "c" });

    const got: unknown[] = [];
    const n = await flush(store, "bob", (p) => (got.push(p), true), now());
    expect(n).toBe(3);
    expect(got).toEqual([1, 2, 3]);
    expect(store.deleted.flat()).toEqual(["m1", "m2", "m3"]);
    expect(store.rows.map((r) => r.to)).toEqual(["carol"]);
  });

  it("keeps a message that arrives after the fetch", async () => {
    const { store, now } = fakeStore();
    await enqueue(store, { to: "bob", from: "alice", payload: "early" });
    // Simulate a message landing between the fetch and the delete.
    let injected = false;
    store.onFetch = () => {
      if (!injected) {
        injected = true;
        queueMicrotask(() => void store.insert({ to: "bob", from: "alice", payload: "late", bytes: 6 }));
      }
    };
    const got: unknown[] = [];
    await flush(store, "bob", (p) => (got.push(p), true), now());
    expect(got).toEqual(["early"]);
    expect(store.rows.map((r) => r.payload)).toEqual(["late"]);
  });

  it("stops when the socket goes away and only deletes what was handed over", async () => {
    const { store, now } = fakeStore();
    for (let i = 1; i <= 4; i++) await enqueue(store, { to: "bob", from: "alice", payload: i });
    let budget = 2;
    const n = await flush(store, "bob", () => budget-- > 0, now());
    expect(n).toBe(2);
    expect(store.rows.map((r) => r.payload)).toEqual([3, 4]);
  });

  it("flushes more than one batch", async () => {
    const { store, now } = fakeStore();
    for (let i = 0; i < 250; i++) await enqueue(store, { to: "bob", from: "alice", payload: i });
    const got: unknown[] = [];
    expect(await flush(store, "bob", (p) => (got.push(p), true), now())).toBe(250);
    expect(got).toEqual(Array.from({ length: 250 }, (_, i) => i));
    expect(store.rows).toHaveLength(0);
  });

  it("never delivers expired messages; the periodic purge removes them", async () => {
    const { store, now } = fakeStore();
    await enqueue(store, { to: "bob", from: "alice", payload: "old" });
    store.tick(MAILBOX_TTL_MS + 1);
    await enqueue(store, { to: "bob", from: "alice", payload: "new" });
    const got: unknown[] = [];
    await flush(store, "bob", (p) => (got.push(p), true), now());
    expect(got).toEqual(["new"]);
    expect(store.rows).toHaveLength(1);
    expect(await store.purgeExpired(new Date(now() - MAILBOX_TTL_MS))).toBe(1);
    expect(store.rows).toHaveLength(0);
  });
});

describe("mailbox quota", () => {
  it(`rejects the ${MAILBOX_QUOTA + 1}th waiting message for one recipient`, async () => {
    const { store, now } = fakeStore();
    for (let i = 0; i < MAILBOX_QUOTA; i++) {
      expect(await enqueue(store, { to: "bob", from: "alice", payload: i }, now())).toBe(
        "queued",
      );
    }
    expect(await enqueue(store, { to: "bob", from: "alice", payload: "x" }, now())).toBe(
      "mailbox_full",
    );
    // Other recipients are unaffected.
    expect(await enqueue(store, { to: "carol", from: "alice", payload: "y" }, now())).toBe(
      "queued",
    );
  });

  it("does not count expired rows against the quota", async () => {
    const { store, now } = fakeStore();
    for (let i = 0; i < MAILBOX_QUOTA; i++) {
      await enqueue(store, { to: "bob", from: "alice", payload: i });
    }
    store.tick(MAILBOX_TTL_MS + MAILBOX_QUOTA + 1);
    expect(await enqueue(store, { to: "bob", from: "alice", payload: "x" }, now())).toBe(
      "queued",
    );
  });

  it(`rejects a message that would push the recipient past ${MAILBOX_BYTE_QUOTA} bytes`, async () => {
    const { store, now } = fakeStore();
    // 16 MB-ish payloads: three fit under 50 MB, the fourth does not.
    const big = "x".repeat(16 * 1024 * 1024);
    for (let i = 0; i < 3; i++) {
      expect(await enqueue(store, { to: "bob", from: "alice", payload: big }, now())).toBe("queued");
    }
    expect(store.rows[0]!.bytes).toBe(big.length + 2); // JSON string quotes
    expect(await enqueue(store, { to: "bob", from: "alice", payload: big }, now())).toBe("mailbox_full");
    // A small message still fits in the remaining ~2 MB.
    expect(await enqueue(store, { to: "bob", from: "alice", payload: { c: "hi" } }, now())).toBe("queued");
    // Other recipients are unaffected, and expired rows stop counting.
    expect(await enqueue(store, { to: "carol", from: "alice", payload: big }, now())).toBe("queued");
    store.tick(MAILBOX_TTL_MS + 10);
    expect(await enqueue(store, { to: "bob", from: "alice", payload: big }, now())).toBe("queued");
  });
});
