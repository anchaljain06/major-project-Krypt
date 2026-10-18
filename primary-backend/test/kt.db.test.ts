import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { KtLog, NodeCache, logKeyFromSeed, memoryKtStorage, prismaKtStorage } from "../src/kt.js";
import { MemoryNodeStore, MerkleLog, hashLeaf, verifyTreeHead } from "../src/vendor/krypt-shared/index.js";
import { randomLeafBytes } from "./ktHelpers.js";

// Optional DB-backed test, like prekeys.db.test.ts. Needs TEST_DATABASE_URL
// pointing at a THROWAWAY, fully migrated Postgres: it empties the KT tables.
//   docker run -d --name krypt-pg-test -p 55432:5432 -e POSTGRES_PASSWORD=pw postgres:16-alpine
//   DATABASE_URL=postgresql://postgres:pw@localhost:55432/postgres npx prisma migrate deploy
//   TEST_DATABASE_URL=postgresql://postgres:pw@localhost:55432/postgres npm test
const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)("Postgres KT storage", async () => {
  if (!url) return;
  process.env.DATABASE_URL = url;
  const { PrismaClient } = await import("@prisma/client");
  // Two clients = two connection pools, standing in for two server processes.
  const p1 = new PrismaClient();
  const p2 = new PrismaClient();
  const key = logKeyFromSeed(new Uint8Array(32).fill(3));

  const wipe = () => p1.$executeRawUnsafe(`TRUNCATE "KtLeaf", "KtNode", "KtSth"`);
  beforeAll(wipe);
  afterAll(async () => {
    await wipe();
    await p1.$disconnect();
    await p2.$disconnect();
  });

  it("matches MemoryNodeStore exactly, with appends racing from two processes", async () => {
    // Separate KtLog instances (separate in-process mutexes): only the
    // Postgres advisory lock keeps their appends from interleaving.
    const a = new KtLog(prismaKtStorage(p1), key, { sthIntervalMs: 0 });
    const b = new KtLog(prismaKtStorage(p2), key, { sthIntervalMs: 0 });
    const N = 120;
    const leaves = Array.from({ length: N }, () => randomLeafBytes());
    const rows = await Promise.all(leaves.map((l, i) => (i % 2 ? a : b).append(l.bytes, l.ownerSig)));
    expect(rows.map((r) => r.index).sort((x, y) => x - y)).toEqual([...Array(N).keys()]);

    // Rebuild in memory in the order the DB assigned.
    const dbLeaves = await a.storage.leaves(0, N);
    expect(dbLeaves.map((l) => l.index)).toEqual([...Array(N).keys()]);
    const mem = new MerkleLog(new MemoryNodeStore());
    for (const l of dbLeaves) {
      expect(l.leafHash).toEqual(await hashLeaf(l.leaf));
      await mem.append(l.leafHash);
    }

    // A fresh cache, so every node really comes from Postgres.
    const fresh = prismaKtStorage(p2, new NodeCache());
    const pg = new MerkleLog(fresh.nodes, N);
    // One node per perfect subtree: 2N - popcount(N).
    expect(await p1.ktNode.count()).toBe(2 * N - N.toString(2).split("1").length + 1);
    for (const n of [1, 2, 5, 16, 17, 63, 64, 65, 100, N]) {
      expect(await pg.root(n)).toEqual(await mem.root(n));
      for (const i of [0, n >> 1, n - 1]) expect(await pg.inclusionProof(i, n)).toEqual(await mem.inclusionProof(i, n));
      for (const m of [1, Math.ceil(n / 2), n]) expect(await pg.consistencyProof(m, n)).toEqual(await mem.consistencyProof(m, n));
      expect((await pg.compactRange(n)).hashes).toEqual((await mem.compactRange(n)).hashes);
    }

    // Every append published a head (interval 0); each is signed and sizes are unique.
    const sths = await p1.ktSth.findMany({ orderBy: { treeSize: "asc" } });
    expect(sths.map((s) => Number(s.treeSize))).toEqual([...Array(N).keys()].map((i) => i + 1));
    const latest = await a.latestSth();
    expect(latest.treeSize).toBe(N);
    expect(latest.rootHash).toEqual(await mem.root());
    expect(await verifyTreeHead(latest, key.verify)).toBe(true);
  });

  it("finds a user's latest leaf below a size, and agrees with memory storage", async () => {
    const pg = prismaKtStorage(p1);
    const mem = memoryKtStorage();
    const N = await pg.size();
    for (const l of await pg.leaves(0, N)) await mem.insertLeaf(l);
    const target = (await pg.leaves(37, 38))[0]!;
    expect((await pg.latestLeafForUser(target.userHash))?.index).toBe(37);
    expect(await pg.latestLeafForUser(target.userHash, 37)).toBeNull();
    expect(await pg.latestLeafForUser(target.userHash, 38)).toEqual(await mem.latestLeafForUser(target.userHash, 38));
  });

  it("rolls back a failed append, nodes included, and keeps the cache clean", async () => {
    const cache = new NodeCache();
    const pg = prismaKtStorage(p1, cache);
    const failing = {
      ...pg,
      locked: <T,>(fn: Parameters<typeof pg.locked<T>>[0]) =>
        pg.locked((tx) =>
          fn({
            ...tx,
            insertLeaf: async () => {
              throw new Error("boom");
            },
          }),
        ),
    };
    const before = { leaves: await p1.ktLeaf.count(), nodes: await p1.ktNode.count() };
    const l = randomLeafBytes();
    await expect(new KtLog(failing, key).append(l.bytes, l.ownerSig)).rejects.toThrow("boom");
    expect({ leaves: await p1.ktLeaf.count(), nodes: await p1.ktNode.count() }).toEqual(before);
    expect(cache.get(0, before.leaves)).toBeUndefined();
    // And the log still appends correctly afterwards.
    const row = await new KtLog(pg, key).append(l.bytes, l.ownerSig);
    expect(row.index).toBe(before.leaves);
  });
});
