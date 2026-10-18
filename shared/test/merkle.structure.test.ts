// Proof-shape tests ported from transparency-dev/merkle proof/proof_test.go
// (TestInclusion, TestConsistency). Upstream lists the node IDs (level, index)
// a proof is made of; a `rehash(begin, end)` span marks nodes that are folded
// into one ephemeral node (r = ids[begin]; r = H(ids[j], r) for the rest)
// because the tree's right border is not a perfect subtree.
//
// We turn the node IDs into hashes over a synthetic 128-leaf tree and compare
// with what our generator returns, so these tests check proof *generation*
// independently of our own verifier.

import { beforeAll, describe, expect, it } from "vitest";
import { toHex } from "../src/bytes.ts";
import {
  MemoryNodeStore,
  MerkleLog,
  consistencyProof,
  hashChildren,
  hashLeaf,
  inclusionProof,
  type Hash,
} from "../src/merkle.ts";
import { syntheticLeaf } from "./helpers.ts";

type Id = [level: number, index: number];
interface Expected {
  ids: Id[];
  rehash?: [begin: number, end: number];
}
const nodes = (...ids: Id[]): Expected => ({ ids });
const rehash = (begin: number, end: number, ...ids: Id[]): Expected => ({ ids, rehash: [begin, end] });

const LEAVES = Array.from({ length: 128 }, (_, i) => syntheticLeaf(i));
const store = new MemoryNodeStore();
const log = new MerkleLog(store);

beforeAll(async () => {
  for (const leaf of LEAVES) await log.append(await hashLeaf(leaf));
});

async function expectedHashes(e: Expected): Promise<string[]> {
  const hashes = e.ids.map(([l, i]) => {
    const h = store.get(l, i);
    if (!h) throw new Error(`missing reference node ${l},${i}`);
    return h;
  });
  if (!e.rehash) return hashes.map(toHex);
  const [b, end] = e.rehash;
  let r: Hash = hashes[b]!;
  for (let j = b + 1; j < end; j++) r = await hashChildren(hashes[j]!, r);
  return [...hashes.slice(0, b), r, ...hashes.slice(end)].map(toHex);
}

describe("inclusion proof shape (proof_test.go TestInclusion)", () => {
  const cases: [size: number, index: number, want: Expected][] = [
    [1, 0, nodes()],
    [2, 0, nodes([0, 1])],
    [2, 1, nodes([0, 0])],
    [3, 1, rehash(1, 2, [0, 0], [0, 2])],
    [7, 0, rehash(2, 4, [0, 1], [1, 1], [0, 6], [1, 2])],
    [7, 1, rehash(2, 4, [0, 0], [1, 1], [0, 6], [1, 2])],
    [7, 2, rehash(2, 4, [0, 3], [1, 0], [0, 6], [1, 2])],
    [7, 3, rehash(2, 4, [0, 2], [1, 0], [0, 6], [1, 2])],
    [7, 4, rehash(1, 2, [0, 5], [0, 6], [2, 0])],
    [7, 5, rehash(1, 2, [0, 4], [0, 6], [2, 0])],
    [7, 6, nodes([1, 2], [2, 0])],
    [4, 2, nodes([0, 3], [1, 0])],
    [5, 3, rehash(2, 3, [0, 2], [1, 0], [0, 4])],
    [6, 3, rehash(2, 3, [0, 2], [1, 0], [1, 2])],
    [6, 4, nodes([0, 5], [2, 0])],
    [15, 10, rehash(2, 4, [0, 11], [1, 4], [0, 14], [1, 6], [3, 0])],
    [31, 24, rehash(2, 4, [0, 25], [1, 13], [0, 30], [1, 14], [3, 2], [4, 0])],
    [95, 81, rehash(3, 6, [0, 80], [1, 41], [2, 21], [0, 94], [1, 46], [2, 22], [4, 4], [6, 0])],
  ];

  it.each(cases)("size %i index %i", async (size, index, want) => {
    const exp = await expectedHashes(want);
    expect((await log.inclusionProof(index, size)).map(toHex)).toEqual(exp);
    expect((await inclusionProof(LEAVES.slice(0, size), index)).map(toHex)).toEqual(exp);
  });

  it.each([
    [0, 0],
    [0, 1],
    [1, 2],
    [0, 3],
    [7, 8],
  ])("rejects size %i index %i", async (size, index) => {
    await expect(log.inclusionProof(index, size)).rejects.toThrow(RangeError);
    await expect(inclusionProof(LEAVES.slice(0, size), index)).rejects.toThrow(RangeError);
  });
});

describe("consistency proof shape (proof_test.go TestConsistency)", () => {
  const cases: [m: number, n: number, want: Expected][] = [
    [1, 2, nodes([0, 1])],
    [1, 4, nodes([0, 1], [1, 1])],
    [1, 6, rehash(2, 3, [0, 1], [1, 1], [1, 2])],
    [2, 3, rehash(0, 1, [0, 2])],
    [2, 8, nodes([1, 1], [2, 1])],
    [3, 7, rehash(3, 5, [0, 2], [0, 3], [1, 0], [0, 6], [1, 2])],
    [4, 7, rehash(0, 2, [0, 6], [1, 2])],
    [5, 7, rehash(2, 3, [0, 4], [0, 5], [0, 6], [2, 0])],
    [6, 7, rehash(1, 2, [1, 2], [0, 6], [2, 0])],
    [7, 8, nodes([0, 6], [0, 7], [1, 2], [2, 0])],
    [1, 1, nodes()],
    [2, 2, nodes()],
    [3, 3, nodes()],
    [4, 4, nodes()],
    [5, 5, nodes()],
    [7, 7, nodes()],
    [8, 8, nodes()],
    [2, 4, nodes([1, 1])],
    [3, 5, rehash(3, 4, [0, 2], [0, 3], [1, 0], [0, 4])],
    [3, 6, rehash(3, 4, [0, 2], [0, 3], [1, 0], [1, 2])],
    [4, 6, rehash(0, 1, [1, 2])],
    [1, 7, rehash(2, 4, [0, 1], [1, 1], [0, 6], [1, 2])],
    [10, 15, rehash(2, 4, [1, 4], [1, 5], [0, 14], [1, 6], [3, 0])],
    [24, 31, rehash(1, 4, [3, 2], [0, 30], [1, 14], [2, 6], [4, 0])],
    [81, 95, rehash(4, 7, [0, 80], [0, 81], [1, 41], [2, 21], [0, 94], [1, 46], [2, 22], [4, 4], [6, 0])],
  ];

  it.each(cases)("m %i n %i", async (m, n, want) => {
    const exp = await expectedHashes(want);
    expect((await log.consistencyProof(m, n)).map(toHex)).toEqual(exp);
    expect((await consistencyProof(LEAVES.slice(0, n), m)).map(toHex)).toEqual(exp);
  });

  it.each([
    [5, 0],
    [9, 8],
    [0, 5],
    [0, 0],
  ])("rejects m %i n %i", async (m, n) => {
    await expect(log.consistencyProof(m, n)).rejects.toThrow(RangeError);
    await expect(consistencyProof(LEAVES.slice(0, n), m)).rejects.toThrow(RangeError);
  });
});
