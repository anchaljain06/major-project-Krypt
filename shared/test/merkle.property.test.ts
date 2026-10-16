// Property tests: every honest proof verifies; every tampered one fails.
// One 300-leaf log is built once and queried at random prefix sizes, which is
// equivalent to building a fresh tree per size because nodes are append-only.

import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.ts";
import {
  CompactRange,
  MemoryNodeStore,
  MerkleLog,
  consistencyProof,
  hashLeaf,
  inclusionProof,
  merkleTreeHash,
  verifyConsistency,
  verifyInclusion,
  type Hash,
} from "../src/merkle.ts";
import { flipBit, syntheticLeaf } from "./helpers.ts";

const MAX = 300;
const LEAVES = Array.from({ length: MAX }, (_, i) => syntheticLeaf(i));
let leafHashes: Hash[] = [];
let roots: Hash[] = []; // roots[n] = MTH of the first n leaves
const log = new MerkleLog(new MemoryNodeStore());

beforeAll(async () => {
  leafHashes = await Promise.all(LEAVES.map(hashLeaf));
  roots = [await log.root()];
  let range = CompactRange.empty();
  for (const h of leafHashes) {
    await log.append(h);
    range = await range.append(h);
    const r = await log.root();
    // The compact range and the stored log must agree at every size.
    expect(toHex(await range.root())).toBe(toHex(r));
    roots.push(r);
  }
});

const sizeAndIndex = fc.integer({ min: 1, max: MAX }).chain((n) => fc.tuple(fc.constant(n), fc.nat(n - 1)));
const oldAndNew = fc.integer({ min: 1, max: MAX }).chain((n) => fc.tuple(fc.integer({ min: 1, max: n }), fc.constant(n)));

describe("exhaustive small trees", () => {
  it("all inclusion and consistency proofs for n <= 40 verify", async () => {
    for (let n = 1; n <= 40; n++) {
      for (let i = 0; i < n; i++) {
        const p = await log.inclusionProof(i, n);
        expect(await verifyInclusion(i, n, leafHashes[i]!, p, roots[n]!), `incl ${i}/${n}`).toBe(true);
      }
      for (let m = 1; m <= n; m++) {
        const p = await log.consistencyProof(m, n);
        expect(await verifyConsistency(m, n, roots[m]!, roots[n]!, p), `cons ${m}->${n}`).toBe(true);
      }
    }
  });
});

describe("inclusion properties", () => {
  it("list-based and store-based generators agree with each other and the root", async () => {
    await fc.assert(
      fc.asyncProperty(sizeAndIndex, async ([n, i]) => {
        const leaves = LEAVES.slice(0, n);
        expect(toHex(await merkleTreeHash(leaves))).toBe(toHex(roots[n]!));
        const a = await inclusionProof(leaves, i);
        const b = await log.inclusionProof(i, n);
        expect(a.map(toHex)).toEqual(b.map(toHex));
      }),
      { numRuns: 40 },
    );
  });

  it("honest proofs verify", async () => {
    await fc.assert(
      fc.asyncProperty(sizeAndIndex, async ([n, i]) => {
        const p = await log.inclusionProof(i, n);
        return verifyInclusion(i, n, leafHashes[i]!, p, roots[n]!);
      }),
      { numRuns: 300 },
    );
  });

  it("tampered proofs, roots, leaves, indices and sizes fail", async () => {
    await fc.assert(
      fc.asyncProperty(sizeAndIndex, fc.nat(), fc.nat(255), async ([n, i], pick, bit) => {
        const p = await log.inclusionProof(i, n);
        const leaf = leafHashes[i]!;
        const root = roots[n]!;
        const checks: Promise<boolean>[] = [
          verifyInclusion(i, n, flipBit(leaf, bit), p, root),
          verifyInclusion(i, n, leaf, p, flipBit(root, bit)),
          verifyInclusion(i, n, leaf, [...p, root], root),
          verifyInclusion(i, n, leaf, [root, ...p], root),
          verifyInclusion(n, n, leaf, p, root),
        ];
        if (p.length > 0) {
          const j = pick % p.length;
          checks.push(verifyInclusion(i, n, leaf, p.map((h, k) => (k === j ? flipBit(h, bit) : h)), root));
          checks.push(verifyInclusion(i, n, leaf, p.slice(0, -1), root));
          // Reordering the path changes left/right placement; a no-op for length 1.
          if (p.length > 1) checks.push(verifyInclusion(i, n, leaf, [...p].reverse(), root));
        }
        // A different index in the same tree must not accept this leaf's proof
        // (the leaf hash itself differs, so use the other leaf's hash too).
        if (n > 1) {
          const other = (i + 1 + (pick % (n - 1))) % n;
          checks.push(verifyInclusion(other, n, leaf, p, root));
        }
        // The proof must not verify against a different tree size's root.
        if (n < MAX) checks.push(verifyInclusion(i, n + 1, leaf, p, roots[n + 1]!));
        const results = await Promise.all(checks);
        return results.every((ok) => !ok);
      }),
      { numRuns: 300 },
    );
  });
});

describe("consistency properties", () => {
  it("list-based and store-based generators agree", async () => {
    await fc.assert(
      fc.asyncProperty(oldAndNew, async ([m, n]) => {
        const a = await consistencyProof(LEAVES.slice(0, n), m);
        const b = await log.consistencyProof(m, n);
        expect(a.map(toHex)).toEqual(b.map(toHex));
      }),
      { numRuns: 40 },
    );
  });

  it("honest proofs verify", async () => {
    await fc.assert(
      fc.asyncProperty(oldAndNew, async ([m, n]) => {
        const p = await log.consistencyProof(m, n);
        return verifyConsistency(m, n, roots[m]!, roots[n]!, p);
      }),
      { numRuns: 300 },
    );
  });

  it("tampered proofs, roots and sizes fail", async () => {
    await fc.assert(
      fc.asyncProperty(oldAndNew, fc.nat(), fc.nat(255), async ([m, n], pick, bit) => {
        const p = await log.consistencyProof(m, n);
        const oldR = roots[m]!;
        const newR = roots[n]!;
        const checks: Promise<boolean>[] = [
          verifyConsistency(m, n, flipBit(oldR, bit), newR, p),
          verifyConsistency(m, n, oldR, flipBit(newR, bit), p),
          verifyConsistency(m, n, oldR, newR, [...p, newR]),
          verifyConsistency(m, n, oldR, newR, [oldR, ...p]),
          verifyConsistency(0, n, oldR, newR, p),
          verifyConsistency(n + 1, n, oldR, newR, p),
        ];
        if (m < n) {
          // Swapped roots, a forked new root, a truncated or edited proof.
          checks.push(verifyConsistency(m, n, newR, oldR, p));
          checks.push(verifyConsistency(m, n, oldR, newR, []));
          checks.push(verifyConsistency(m, n, oldR, newR, p.slice(0, -1)));
          const j = pick % p.length;
          checks.push(verifyConsistency(m, n, oldR, newR, p.map((h, k) => (k === j ? flipBit(h, bit) : h))));
          // The same proof must not link different sizes.
          if (m > 1) checks.push(verifyConsistency(m - 1, n, roots[m - 1]!, newR, p));
          if (n < MAX) checks.push(verifyConsistency(m, n + 1, oldR, roots[n + 1]!, p));
        } else {
          // m == n: any non-empty proof or root mismatch fails.
          checks.push(verifyConsistency(m, n, oldR, newR, [oldR]));
          if (m > 1) checks.push(verifyConsistency(m, n, roots[m - 1]!, newR, []));
        }
        const results = await Promise.all(checks);
        return results.every((ok) => !ok);
      }),
      { numRuns: 300 },
    );
  });
});

describe("compact range authentication", () => {
  it("fromHashes accepts the real range and rejects a tampered one", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: MAX }), fc.nat(), fc.nat(255), async (n, pick, bit) => {
        const real = await log.compactRange(n);
        await CompactRange.fromHashes(n, [...real.hashes], roots[n]!);
        const j = pick % real.hashes.length;
        const bad = real.hashes.map((h, k) => (k === j ? flipBit(h, bit) : h));
        await expect(CompactRange.fromHashes(n, bad, roots[n]!)).rejects.toThrow();
      }),
      { numRuns: 100 },
    );
  });
});
