import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { mlkem1024 } from "../src/crypto/pq";
import {
  IndexedDbPrekeyStore,
  IndexedDbSessionStore,
  MemorySessionStore,
  deserializeRecord,
  serializeRecord,
  type PeerRecord,
} from "../src/crypto/session-store";
import { Directory, makeParty, managerFor, recv, send } from "./helpers";

const newKey = () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
let dbCounter = 0;
const dbName = () => `test-db-${++dbCounter}`;

const record = (): PeerRecord => ({
  session: null,
  closed: ["abc", "def"],
});

describe("serialization", () => {
  it("round-trips nested byte arrays", () => {
    const rec = { session: { sessionId: new Uint8Array([1, 2, 3]), nested: { k: new Uint8Array(0) } }, closed: [] };
    const back = deserializeRecord(serializeRecord(rec as unknown as PeerRecord)) as unknown as typeof rec;
    expect(back.session.sessionId).toEqual(new Uint8Array([1, 2, 3]));
    expect(back.session.nested.k).toEqual(new Uint8Array(0));
  });

  it("memory store returns copies, never live objects", async () => {
    const s = new MemorySessionStore();
    const rec = record();
    await s.save("bob", rec);
    rec.closed.push("mutated");
    const a = await s.load("bob");
    a!.closed.push("x");
    expect((await s.load("bob"))!.closed).toEqual(["abc", "def"]);
  });
});

describe("IndexedDbSessionStore", () => {
  it("stores records encrypted and reads them back", async () => {
    const key = await newKey();
    const name = dbName();
    const store = new IndexedDbSessionStore({ key, dbName: name });
    expect(await store.load("bob")).toBeUndefined();
    await store.save("bob", record());
    expect(await store.load("bob")).toEqual(record());

    // The raw value in IndexedDB is ciphertext, not JSON.
    const raw = await new Promise<{ iv: Uint8Array; ct: Uint8Array }>((resolve) => {
      const r = indexedDB.open(name);
      r.onsuccess = () => {
        const g = r.result.transaction("sessions").objectStore("sessions").get("bob");
        g.onsuccess = () => resolve(g.result);
      };
    });
    expect(raw.iv).toHaveLength(12);
    expect(new TextDecoder().decode(raw.ct)).not.toContain("closed");
    await store.close();
  });

  it("fails to read with the wrong key or from another peer's slot", async () => {
    const name = dbName();
    const store = new IndexedDbSessionStore({ key: await newKey(), dbName: name });
    await store.save("bob", record());
    await store.close();
    const other = new IndexedDbSessionStore({ key: await newKey(), dbName: name });
    await expect(other.load("bob")).rejects.toThrow();
    await other.close();

    // Copy bob's sealed record into carol's slot: the AAD binds it to "bob".
    const key = await newKey();
    const s2 = new IndexedDbSessionStore({ key, dbName: dbName() });
    await s2.save("bob", record());
    const db = await (s2 as unknown as { db: Promise<IDBDatabase> }).db;
    const sealed = await new Promise((resolve) => {
      const g = db.transaction("sessions").objectStore("sessions").get("bob");
      g.onsuccess = () => resolve(g.result);
    });
    await new Promise<void>((resolve) => {
      const tx = db.transaction("sessions", "readwrite");
      tx.objectStore("sessions").put(sealed, "carol");
      tx.oncomplete = () => resolve();
    });
    await expect(s2.load("carol")).rejects.toThrow();
    await s2.close();
  });

  it("backs a full conversation, including a restart of both managers", async () => {
    const dir = new Directory();
    const alice = await makeParty(dir, "alice");
    const bob = await makeParty(dir, "bob");
    const aStore = new IndexedDbSessionStore({ key: await newKey(), dbName: dbName() });
    const bStore = new IndexedDbSessionStore({ key: await newKey(), dbName: dbName() });
    alice.sm = managerFor(alice, dir, { store: aStore });
    bob.sm = managerFor(bob, dir, { store: bStore });
    for (let i = 0; i < 5; i++) {
      expect(await recv(bob, await send(alice, bob, `a${i}`))).toBe(`a${i}`);
      expect(await recv(alice, await send(bob, alice, `b${i}`))).toBe(`b${i}`);
    }
    // "Reload the page": new managers over the same databases.
    alice.sm = managerFor(alice, dir, { store: aStore });
    bob.sm = managerFor(bob, dir, { store: bStore });
    expect(await recv(bob, await send(alice, bob, "after restart"))).toBe("after restart");
    expect((await alice.sm.getStatus("bob"))!.epoch).toBe(10);
    await aStore.close();
    await bStore.close();
  });
});

describe("IndexedDbPrekeyStore", () => {
  it("keeps SPK and OPK keyIds in separate namespaces and ties session-id memory to the SPK", async () => {
    const store = new IndexedDbPrekeyStore({ key: await newKey(), dbName: dbName() });
    const a = mlkem1024.keygen();
    const b = mlkem1024.keygen();
    await store.putSignedPrekey({ keyId: 5, ...a, createdAt: 1 });
    await store.putOneTimePrekeys([{ keyId: 5, ...b, createdAt: 2 }]);
    expect((await store.getSignedPrekey(5))!.publicKey).toEqual(a.publicKey);
    expect((await store.getOneTimePrekey(5))!.publicKey).toEqual(b.publicKey);
    expect(await store.countOneTimePrekeys()).toBe(1);

    await store.deleteOneTimePrekey(5);
    expect(await store.getOneTimePrekey(5)).toBeUndefined();
    expect(await store.getSignedPrekey(5)).toBeDefined();

    await store.putSignedPrekey({ keyId: 50, ...b, createdAt: 3 });
    await store.recordAcceptedSession(5, "sid-1");
    await store.recordAcceptedSession(50, "sid-2");
    expect(await store.hasAcceptedSession(5, "sid-1")).toBe(true);
    expect(await store.hasAcceptedSession(50, "sid-1")).toBe(false);
    await store.deleteSignedPrekey(5);
    expect(await store.getSignedPrekey(5)).toBeUndefined();
    expect(await store.hasAcceptedSession(5, "sid-1")).toBe(false);
    expect(await store.hasAcceptedSession(50, "sid-2")).toBe(true);
    expect((await store.listSignedPrekeyIds()).sort()).toEqual([50]);
    await store.close();
  });
});
