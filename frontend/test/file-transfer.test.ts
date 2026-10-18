/**
 * File transfer orchestration (services/fileTransfer.ts + fileStore.ts) between
 * two managers over a fake relay: happy path, tampering, crash points,
 * cross-tab counters, resume, cancel, expiry and quotas (plan Phase E 2-6).
 */
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { compareBytes } from "../src/crypto/encoding";
import {
  FILE_CHUNK_SIZE,
  MAX_FILE_BYTES,
  chunkAad,
  chunkNonce,
  parseFileControl,
  type FileControl,
} from "../src/crypto/fileManifest";
import { encryptFileChunk, importFileKey } from "../src/crypto/fileTransfer";
import { createMutexLock } from "../src/crypto/session";
import { FileStore } from "../src/services/fileStore";
import {
  MAX_ACTIVE_TRANSFERS,
  TRANSFER_TTL_MS,
  WINDOW,
  FileTransferManager,
  type ChunkFrame,
  type ChunkSendResult,
} from "../src/services/fileTransfer";

const MiB = FILE_CHUNK_SIZE;
let dbCount = 0;
const newKey = () => crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);

function fileOf(size: number): { blob: Blob; bytes: Uint8Array } {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i += 4096) bytes[i] = (i / 4096) & 255;
  bytes[size - 1] = 7;
  return { blob: new Blob([bytes]), bytes };
}

async function until(cond: () => boolean | Promise<boolean>, ms = 10_000) {
  const end = Date.now() + ms;
  while (!(await cond())) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

interface Sent extends ChunkFrame {
  from: string;
}

/** Alice and Bob over a fake relay. `chunkHook` can rewrite or refuse a chunk before delivery. */
async function world(opts: { chunkSize?: number } = {}) {
  const clock = { t: 1_000_000 };
  const net = {
    online: true,
    frames: [] as Sent[],
    controls: [] as { from: string; ctl: FileControl }[],
    chunkHook: null as null | ((f: Sent) => ChunkSendResult | Sent | "crash"),
  };
  const managers: Record<string, FileTransferManager> = {};
  const stores: Record<string, FileStore> = {};
  const key = await newKey();

  const make = (self: string, store?: FileStore) => {
    const s = store ?? new FileStore({ key, dbName: `krypt-files-test-${++dbCount}` });
    stores[self] = s;
    const m = new FileTransferManager({
      self,
      store: s,
      lock: createMutexLock(),
      ackDelayMs: 20,
      chunkSize: opts.chunkSize,
      now: () => clock.t,
      sendControl: async (to, ctl) => {
        const copy = parseFileControl(JSON.parse(JSON.stringify(ctl)));
        net.controls.push({ from: self, ctl: copy });
        setTimeout(() => void managers[to].onControl(self, copy), 0);
      },
      sendChunk: async (to, frame) => {
        let f: Sent = { from: self, ...frame, data: frame.data.slice() };
        net.frames.push(f);
        if (net.chunkHook) {
          const h = net.chunkHook(f);
          if (h === "crash") throw new Error("crash");
          if (typeof h === "string") return h;
          f = h;
        }
        if (!net.online) return "OFFLINE";
        void managers[to].onChunk(self, f);
        return "ok";
      },
    });
    managers[self] = m;
    return m;
  };
  const alice = make("alice");
  const bob = make("bob");
  await Promise.all([alice.whenReady(), bob.whenReady()]);
  return { alice, bob, net, clock, stores, make, managers };
}

const status = (m: FileTransferManager, id: string) => m.get(id)?.status;

async function sendAndAccept(w: Awaited<ReturnType<typeof world>>, size: number) {
  const { blob, bytes } = fileOf(size);
  const man = await w.alice.offer("bob", blob, "data.bin");
  await until(() => status(w.bob, man.transferId) === "offered");
  await w.bob.accept(man.transferId);
  return { man, bytes, id: man.transferId };
}

describe("file transfer", () => {
  it("sends a multi-chunk file; Bob downloads the exact bytes; both sides clean up", async () => {
    const w = await world();
    const { id, bytes } = await sendAndAccept(w, 2.5 * MiB);
    await until(() => status(w.alice, id) === "complete" && status(w.bob, id) === "complete");
    const { blob, name } = await w.bob.download(id);
    expect(name).toBe("data.bin");
    expect(blob.type).toBe("application/octet-stream");
    expect(compareBytes(new Uint8Array(await blob.arrayBuffer()), bytes)).toBe(0);
    expect(await w.stores.alice.countData(id)).toEqual({ packets: 0, chunks: 0 });
    expect(await w.stores.bob.countData(id)).toEqual({ packets: 0, chunks: 3 });
    // Acks are batched, not one per chunk.
    expect(w.net.controls.filter((c) => c.ctl.op === "ack").length).toBeLessThan(3);
  });

  it("a sender configured for 256 KiB chunks splits the file into 256 KiB chunks", async () => {
    const w = await world({ chunkSize: 256 * 1024 });
    const { id, man, bytes } = await sendAndAccept(w, MiB + 1);
    expect(man.chunkSize).toBe(256 * 1024);
    expect(man.chunkCount).toBe(5);
    await until(() => status(w.bob, id) === "complete");
    expect(compareBytes(new Uint8Array(await (await w.bob.download(id)).blob.arrayBuffer()), bytes)).toBe(0);
  });

  it("refuses a chunk size outside 64 KiB-4 MiB", async () => {
    await expect(world({ chunkSize: 4 * MiB + 1 })).rejects.toThrow(/Chunk size/);
    await expect(world({ chunkSize: 1024 })).rejects.toThrow(/Chunk size/);
  });

  it("sends a zero-byte file as one authenticated empty chunk", async () => {
    const w = await world();
    const { id } = await sendAndAccept(w, 0);
    await until(() => status(w.bob, id) === "complete");
    expect(w.net.frames).toHaveLength(1);
    expect(w.net.frames[0].data).toHaveLength(16);
    expect((await w.bob.download(id)).blob.size).toBe(0);
  });

  it("keeps at most WINDOW chunks unacknowledged", async () => {
    const w = await world();
    w.net.chunkHook = (f) => ({ ...f, transferId: "AAAAAAAAAAAAAAAAAAAAAA" }); // Bob drops them all
    const { id } = await sendAndAccept(w, 12 * MiB);
    await until(() => w.net.frames.length === WINDOW);
    await new Promise((r) => setTimeout(r, 50));
    expect(w.net.frames).toHaveLength(WINDOW);
    expect(status(w.alice, id)).toBe("sending");
  });

  it("Bob declines: Alice's transfer is cancelled and nothing is sent", async () => {
    const w = await world();
    const { blob } = fileOf(MiB);
    const man = await w.alice.offer("bob", blob, "x.bin");
    await until(() => status(w.bob, man.transferId) === "offered");
    await w.bob.reject(man.transferId);
    await until(() => status(w.alice, man.transferId) === "cancelled");
    expect(w.net.frames).toHaveLength(0);
  });

  it("drops a tampered chunk; resume re-sends the saved packet byte for byte", async () => {
    const w = await world();
    let tampered = false;
    w.net.chunkHook = (f) => {
      if (f.index !== 1 || tampered) return f;
      tampered = true;
      const data = f.data.slice();
      data[5] ^= 1;
      return { ...f, data };
    };
    const { id, bytes } = await sendAndAccept(w, 3 * MiB);
    await until(() => w.bob.get(id)?.done === 2);
    await new Promise((r) => setTimeout(r, 60));
    expect(status(w.bob, id)).toBe("receiving");
    await w.bob.resumeWith("alice");
    await until(() => status(w.bob, id) === "complete");
    const index1 = w.net.frames.filter((f) => f.index === 1);
    expect(index1).toHaveLength(2);
    expect(index1[1].nonceCounter).toBe(index1[0].nonceCounter);
    expect(compareBytes(new Uint8Array(await (await w.bob.download(id)).blob.arrayBuffer()), bytes)).toBe(0);
  });

  describe("receiver drops frames that do not belong", () => {
    async function setup() {
      const w = await world();
      w.net.chunkHook = () => "OFFLINE"; // Alice pauses; we feed Bob by hand
      const { id, man } = await sendAndAccept(w, 2 * MiB);
      await until(() => status(w.alice, id) === "paused");
      const key = await importFileKey(man.fileKey);
      const chunk = async (index: number, counter: number, len = MiB, from = "alice", to = "bob") =>
        encryptFileChunk({ fileKey: key, nonce: chunkNonce(man, counter), plaintext: new Uint8Array(len), aad: chunkAad(man, from, to, index, counter) });
      return { w, id, chunk };
    }

    it.each<[string, (c: Awaited<ReturnType<typeof setup>>) => Promise<[string, unknown]>]>([
      ["from another user", async ({ id, chunk }) => ["mallory", { transferId: id, index: 0, nonceCounter: 0, data: await chunk(0, 0, MiB, "mallory") }]],
      ["for an unknown transfer", async ({ chunk }) => ["alice", { transferId: "AAAAAAAAAAAAAAAAAAAAAA", index: 0, nonceCounter: 0, data: await chunk(0, 0) }]],
      ["with an out-of-range index", async ({ id, chunk }) => ["alice", { transferId: id, index: 2, nonceCounter: 0, data: await chunk(1, 0) }]],
      ["with a large index gap", async ({ id, chunk }) => ["alice", { transferId: id, index: 4000, nonceCounter: 0, data: await chunk(1, 0) }]],
      ["with the wrong size", async ({ id, chunk }) => ["alice", { transferId: id, index: 0, nonceCounter: 0, data: (await chunk(0, 0)).subarray(1) }]],
      ["moved to another index", async ({ id, chunk }) => ["alice", { transferId: id, index: 1, nonceCounter: 0, data: await chunk(0, 0) }]],
      ["with a changed counter", async ({ id, chunk }) => ["alice", { transferId: id, index: 0, nonceCounter: 1, data: await chunk(0, 0) }]],
      ["with a bad counter", async ({ id, chunk }) => ["alice", { transferId: id, index: 0, nonceCounter: -1, data: await chunk(0, 0) }]],
      ["with string data", async ({ id }) => ["alice", { transferId: id, index: 0, nonceCounter: 0, data: "AAAA" }]],
    ])("%s", async (_name, make) => {
      const c = await setup();
      const [from, frame] = await make(c);
      await c.w.bob.onChunk(from, frame);
      expect(c.w.bob.get(c.id)?.done).toBe(0);
      expect(await c.w.stores.bob.countData(c.id)).toEqual({ packets: 0, chunks: 0 });
    });

    it("a replayed chunk is stored once; a reused counter on another index is refused", async () => {
      const c = await setup();
      const f0 = { transferId: c.id, index: 0, nonceCounter: 5, data: await c.chunk(0, 5) };
      await c.w.bob.onChunk("alice", f0);
      await c.w.bob.onChunk("alice", f0);
      expect(c.w.bob.get(c.id)?.done).toBe(1);
      await c.w.bob.onChunk("alice", { transferId: c.id, index: 1, nonceCounter: 5, data: await c.chunk(1, 5) });
      expect(c.w.bob.get(c.id)?.done).toBe(1);
      await c.w.bob.onChunk("alice", { transferId: c.id, index: 1, nonceCounter: 6, data: await c.chunk(1, 6) });
      expect(c.w.bob.get(c.id)?.status).toBe("complete");
    });

    it("ignores chunks before the offer is accepted", async () => {
      const w = await world();
      const { blob } = fileOf(MiB);
      const man = await w.alice.offer("bob", blob, "x.bin");
      await until(() => status(w.bob, man.transferId) === "offered");
      const key = await importFileKey(man.fileKey);
      const data = await encryptFileChunk({ fileKey: key, nonce: chunkNonce(man, 0), plaintext: new Uint8Array(MiB), aad: chunkAad(man, "alice", "bob", 0, 0) });
      await w.bob.onChunk("alice", { transferId: man.transferId, index: 0, nonceCounter: 0, data });
      expect(w.bob.get(man.transferId)?.done).toBe(0);
    });
  });

  describe("crash safety", () => {
    it("a counter burned by a crash after reservation is never used", async () => {
      const w = await world();
      const { blob } = fileOf(2 * MiB);
      const man = await w.alice.offer("bob", blob, "x.bin");
      expect(await w.stores.alice.reserveCounter(man.transferId)).toBe(0);
      expect(await w.stores.alice.reserveCounter(man.transferId)).toBe(1);
      await until(() => status(w.bob, man.transferId) === "offered");
      await w.bob.accept(man.transferId);
      await until(() => status(w.bob, man.transferId) === "complete");
      expect(w.net.frames.map((f) => f.nonceCounter)).toEqual([2, 3]);
    });

    it("a crash after the packet was saved: the restarted sender re-sends the identical bytes", async () => {
      const w = await world();
      w.net.chunkHook = () => "crash";
      const { id } = await sendAndAccept(w, MiB);
      await until(() => status(w.alice, id) === "paused");
      const saved = await w.stores.alice.getPacket(id, 0);
      expect(saved).toBeDefined();
      // "Restart": a new manager on the same store, without the File.
      w.net.chunkHook = null;
      const alice2 = w.make("alice", w.stores.alice);
      await alice2.whenReady();
      expect(status(alice2, id)).toBe("paused");
      await w.bob.resumeWith("alice");
      await until(() => status(w.bob, id) === "complete");
      const sends = w.net.frames.filter((f) => f.index === 0);
      expect(sends).toHaveLength(2);
      expect(compareBytes(sends[1].data, sends[0].data)).toBe(0);
      expect(sends[1].nonceCounter).toBe(sends[0].nonceCounter);
    });

    it("a restarted sender without the file cancels instead of guessing", async () => {
      const w = await world();
      w.net.chunkHook = (f) => (f.index === 1 ? "crash" : f);
      const { id } = await sendAndAccept(w, 4 * MiB);
      await until(() => status(w.alice, id) === "paused");
      w.net.chunkHook = null;
      const alice2 = w.make("alice", w.stores.alice);
      await alice2.whenReady();
      await w.bob.resumeWith("alice");
      await until(() => status(alice2, id) === "cancelled" && status(w.bob, id) === "cancelled");
      expect(alice2.get(id)?.note).toMatch(/no longer open/);
    });

    it("a sender page that closed mid-send comes back paused", async () => {
      const w = await world();
      w.net.chunkHook = () => "ok"; // relay accepts, Bob never sees them
      const { id } = await sendAndAccept(w, 2 * MiB);
      await until(() => w.net.frames.length === 2);
      const alice2 = w.make("alice", w.stores.alice);
      await alice2.whenReady();
      expect(status(alice2, id)).toBe("paused");
    });

    it("two tabs reserving counters at once never get the same one", async () => {
      const key = await newKey();
      const name = `krypt-files-test-${++dbCount}`;
      const a = new FileStore({ key, dbName: name });
      const b = new FileStore({ key, dbName: name });
      const got = await Promise.all(Array.from({ length: 100 }, (_, i) => (i % 2 ? a : b).reserveCounter("t")));
      expect(new Set(got).size).toBe(100);
      expect(Math.max(...got)).toBe(99);
    });
  });

  it("resume after a disconnect sends only the missing chunks", async () => {
    const w = await world();
    w.net.chunkHook = (f) => (f.index >= 3 ? "OFFLINE" : f);
    const { id, bytes } = await sendAndAccept(w, 6 * MiB);
    await until(() => status(w.alice, id) === "paused" && w.bob.get(id)?.done === 3);
    expect(w.alice.get(id)?.note).toMatch(/Waiting for bob/);
    const before = w.net.frames.length;
    w.net.chunkHook = null;
    await w.bob.resumeWith("alice");
    await until(() => status(w.bob, id) === "complete");
    expect(w.net.frames.slice(before).map((f) => f.index)).toEqual([3, 4, 5]);
    expect(compareBytes(new Uint8Array(await (await w.bob.download(id)).blob.arrayBuffer()), bytes)).toBe(0);
  });

  it("cancel mid-transfer stops both sides and deletes their data", async () => {
    const w = await world();
    w.net.chunkHook = (f) => (f.index >= 2 ? "OFFLINE" : f);
    const { id } = await sendAndAccept(w, 4 * MiB);
    await until(() => w.bob.get(id)?.done === 2);
    await w.alice.cancel(id);
    await until(() => status(w.bob, id) === "cancelled");
    expect(status(w.alice, id)).toBe("cancelled");
    expect(await w.stores.alice.countData(id)).toEqual({ packets: 0, chunks: 0 });
    expect(await w.stores.bob.countData(id)).toEqual({ packets: 0, chunks: 0 });
    await expect(w.bob.download(id)).rejects.toThrow(/not available/);
  });

  it("expiry: idle transfers stop and lose their data; finished ones are deleted a TTL later", async () => {
    const w = await world();
    w.net.chunkHook = (f) => (f.index >= 1 ? "OFFLINE" : f);
    const { id } = await sendAndAccept(w, 2 * MiB);
    // Wait for Alice to pause too: her pause stamps updatedAt, and it must land before the clock moves.
    await until(() => status(w.alice, id) === "paused" && w.bob.get(id)?.done === 1);
    w.clock.t += TRANSFER_TTL_MS + 1;
    await w.bob.expire();
    await w.alice.expire();
    expect(status(w.bob, id)).toBe("expired");
    expect(status(w.alice, id)).toBe("cancelled");
    expect(await w.stores.bob.countData(id)).toEqual({ packets: 0, chunks: 0 });
    w.clock.t += TRANSFER_TTL_MS + 1;
    await w.bob.expire();
    expect(w.bob.get(id)).toBeUndefined();
    expect(await w.stores.bob.getTransfer(id)).toBeUndefined();
  });

  describe("quotas", () => {
    it("refuses files over MAX_FILE_BYTES before reading them", async () => {
      const w = await world();
      await expect(w.alice.offer("bob", { size: MAX_FILE_BYTES + 1, type: "" } as Blob, "huge.bin")).rejects.toThrow(/too large/);
    });

    it(`at most ${MAX_ACTIVE_TRANSFERS} outgoing transfers; the receiver declines more than ${MAX_ACTIVE_TRANSFERS} itself`, async () => {
      const w = await world();
      for (let i = 0; i < MAX_ACTIVE_TRANSFERS; i++) await w.alice.offer("bob", fileOf(10).blob, `f${i}`);
      await expect(w.alice.offer("bob", fileOf(10).blob, "one-more")).rejects.toThrow(/At most/);
      await until(() => w.bob.list().length === MAX_ACTIVE_TRANSFERS);

      const carol = w.make("carol");
      await carol.whenReady();
      const man = await carol.offer("bob", fileOf(10).blob, "from-carol");
      await until(() => status(w.bob, man.transferId) === "cancelled");
      expect(w.bob.get(man.transferId)?.note).toMatch(/Declined automatically/);
      await until(() => status(carol, man.transferId) === "cancelled");
    });
  });
});
