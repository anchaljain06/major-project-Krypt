// Known-answer tests ported from transparency-dev/merkle (Apache-2.0):
//   rfc6962/rfc6962_test.go        hasher outputs
//   testonly/constants.go          RFC 6962 reference tree (8 leaves)
//   testdata/{inclusion,consistency} verifier probes (bundled in test/vectors)

import { describe, expect, it } from "vitest";
import { toHex, utf8 } from "../src/bytes.ts";
import {
  CompactRange,
  MemoryNodeStore,
  MerkleLog,
  consistencyProof,
  emptyRoot,
  hashChildren,
  hashLeaf,
  inclusionProof,
  merkleTreeHash,
  verifyConsistency,
  verifyInclusion,
} from "../src/merkle.ts";
import { TDM_LEAF_INPUTS, b64, hx, u64 } from "./helpers.ts";
import inclusionVectors from "./vectors/tdm-inclusion.json" with { type: "json" };
import consistencyVectors from "./vectors/tdm-consistency.json" with { type: "json" };

describe("RFC 6962 hasher (rfc6962_test.go)", () => {
  it("empty root is SHA-256 of the empty string", async () => {
    expect(toHex(await emptyRoot())).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
  it("empty leaf differs from empty root", async () => {
    expect(toHex(await hashLeaf(new Uint8Array(0)))).toBe(
      "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    );
  });
  it("leaf hash", async () => {
    expect(toHex(await hashLeaf(utf8("L123456")))).toBe(
      "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56",
    );
  });
  it("node hash", async () => {
    expect(toHex(await hashChildren(utf8("N123"), utf8("N456")))).toBe(
      "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb",
    );
  });
  it("is second-preimage resistant and order dependent", async () => {
    const h1 = await hashLeaf(utf8("Hello"));
    const h2 = await hashLeaf(utf8("World"));
    expect(toHex(h1)).not.toBe(toHex(h2));
    const node = await hashChildren(h1, h2);
    // An interior node must not collide with a leaf over the same bytes.
    const forged = await hashLeaf(new Uint8Array([...h1, ...h2]));
    expect(toHex(node)).not.toBe(toHex(forged));
    expect(toHex(await hashChildren(h2, h1))).not.toBe(toHex(node));
  });
});

// testonly/constants.go
const ROOTS = [
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
const NODE_HASHES = [
  [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
    "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
    "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
    "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
  ],
  [
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
    "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
  ],
  [
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
  ],
  ["5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"],
];
// CompactTrees(): perfect-subtree roots for each prefix size, as (level, index).
const COMPACT: [number, number][][] = [
  [],
  [[0, 0]],
  [[1, 0]],
  [[1, 0], [0, 2]],
  [[2, 0]],
  [[2, 0], [0, 4]],
  [[2, 0], [1, 2]],
  [[2, 0], [1, 2], [0, 6]],
  [[3, 0]],
];

describe("RFC 6962 reference tree (testonly/constants.go)", () => {
  it("MTH of every prefix matches RootHashes()", async () => {
    for (let n = 0; n <= 8; n++) {
      expect(toHex(await merkleTreeHash(TDM_LEAF_INPUTS.slice(0, n))), `size ${n}`).toBe(ROOTS[n]);
    }
  });

  it("MerkleLog stores exactly NodeHashes() and reports every prefix root", async () => {
    const store = new MemoryNodeStore();
    const log = new MerkleLog(store);
    for (const leaf of TDM_LEAF_INPUTS) await log.append(await hashLeaf(leaf));
    NODE_HASHES.forEach((level, l) =>
      level.forEach((h, i) => expect(toHex(store.get(l, i)!), `node ${l},${i}`).toBe(h)),
    );
    expect(store.count).toBe(15);
    for (let n = 0; n <= 8; n++) expect(toHex(await log.root(n))).toBe(ROOTS[n]);
  });

  it("CompactRange matches CompactTrees() at every size", async () => {
    let range = CompactRange.empty();
    const log = new MerkleLog(new MemoryNodeStore());
    for (let n = 0; n <= 8; n++) {
      const want = COMPACT[n]!.map(([l, i]) => NODE_HASHES[l]![i]!);
      expect(range.hashes.map(toHex), `size ${n}`).toEqual(want);
      expect(toHex(await range.root())).toBe(ROOTS[n]);
      expect((await log.compactRange()).hashes.map(toHex)).toEqual(want);
      if (n < 8) {
        const lh = await hashLeaf(TDM_LEAF_INPUTS[n]!);
        range = await range.append(lh);
        await log.append(lh);
      }
    }
  });

  it("every inclusion and consistency proof of the reference tree verifies", async () => {
    for (let n = 1; n <= 8; n++) {
      const leaves = TDM_LEAF_INPUTS.slice(0, n);
      const root = hx(ROOTS[n]!);
      for (let i = 0; i < n; i++) {
        const proof = await inclusionProof(leaves, i);
        expect(await verifyInclusion(i, n, await hashLeaf(leaves[i]!), proof, root)).toBe(true);
      }
      for (let m = 1; m <= n; m++) {
        const proof = await consistencyProof(leaves, m);
        expect(await verifyConsistency(m, n, hx(ROOTS[m]!), root, proof)).toBe(true);
      }
    }
  });
});

interface InclusionProbe {
  file: string;
  leafIdx: number | string;
  treeSize: number | string;
  root: string;
  leafHash: string;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
}
interface ConsistencyProbe {
  file: string;
  size1: number | string;
  size2: number | string;
  root1: string;
  root2: string;
  proof: string[] | null;
  desc: string;
  wantErr: boolean;
}

describe("transparency-dev/merkle testdata probes", () => {
  const inc = inclusionVectors.probes as InclusionProbe[];
  const con = consistencyVectors.probes as ConsistencyProbe[];

  it("bundles a substantial set", () => {
    expect(inc.length).toBeGreaterThanOrEqual(90);
    expect(con.length).toBeGreaterThanOrEqual(90);
  });

  it.each(inc.map((p) => [p.file, p] as const))("inclusion %s", async (_file, p) => {
    const ok = await verifyInclusion(
      u64(p.leafIdx),
      u64(p.treeSize),
      b64(p.leafHash),
      (p.proof ?? []).map(b64),
      b64(p.root),
    );
    expect(ok, p.desc).toBe(!p.wantErr);
  });

  // Deliberate deviation: upstream accepts m == n with equal roots of any
  // length ("don't care 2", 12 bytes). We reject every hash that is not 32
  // bytes, since no real Krypt root can have another length.
  const STRICTER = new Set(["consistency/additional/sizes-are-equal-one-and-proof-is-empty.json"]);

  it.each(con.map((p) => [p.file, p] as const))("consistency %s", async (file, p) => {
    const ok = await verifyConsistency(
      u64(p.size1),
      u64(p.size2),
      b64(p.root1),
      b64(p.root2),
      (p.proof ?? []).map(b64),
    );
    expect(ok, p.desc).toBe(STRICTER.has(file) ? false : !p.wantErr);
  });
});
