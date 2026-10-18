import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { beforeAll, describe, expect, it } from "vitest";
import { sha256, toBase64 } from "../src/bytes.ts";
import {
  parseConsistencyResponse,
  parseLeavesResponse,
  parseLookupResponse,
  type LeafEntry,
  type LookupResponse,
} from "../src/api.ts";
import {
  KtOp,
  attachOwnerSig,
  buildLeafBody,
  encodeLeaf,
  hashUsername,
  ownerSignedMessage,
  type KtLeaf,
} from "../src/leaf.ts";
import { CompactRange, MemoryNodeStore, MerkleLog, emptyRoot, hashLeaf } from "../src/merkle.ts";
import { checkSthChain, selfMonitor, verifyLeafRange, verifyLookup, type KnownKey } from "../src/monitor.ts";
import { signTreeHead, sthToJson, type SignedTreeHead } from "../src/sth.ts";
import { flipBit } from "./helpers.ts";

const logKey = ml_dsa87.keygen(new Uint8Array(32).fill(3));
const verifySth = (m: Uint8Array, s: Uint8Array) => ml_dsa87.verify(s, m, logKey.publicKey);
const verifySig = (m: Uint8Array, s: Uint8Array, pk: Uint8Array) => ml_dsa87.verify(s, m, pk);

interface User {
  name: string;
  keys: { publicKey: Uint8Array; secretKey: Uint8Array }[];
  kem: Uint8Array[];
}

// A small honest log: alice registers, bob registers, alice rotates, carol registers.
const alice: User = {
  name: "alice",
  keys: [ml_dsa87.keygen(new Uint8Array(32).fill(11)), ml_dsa87.keygen(new Uint8Array(32).fill(12))],
  kem: [new Uint8Array(1184).fill(1), new Uint8Array(1184).fill(2)],
};
const bob: User = { name: "Bob", keys: [ml_dsa87.keygen(new Uint8Array(32).fill(13))], kem: [new Uint8Array(1184).fill(3)] };
const mallory = ml_dsa87.keygen(new Uint8Array(32).fill(66));

const entries: LeafEntry[] = [];
const decoded: KtLeaf[] = [];
const log = new MerkleLog(new MemoryNodeStore());
const sths: SignedTreeHead[] = []; // sths[n] = head at size n

async function append(user: User, op: KtLeaf["op"], version: number, signerIdx: number, keyIdx = version - 1) {
  const body = await buildLeafBody({
    op,
    username: user.name,
    keyVersion: version,
    mldsaPk: user.keys[keyIdx]!.publicKey,
    mlkemPk: user.kem[keyIdx]!,
    timestampMs: 1_760_000_000_000 + entries.length,
  });
  const sig = ml_dsa87.sign(ownerSignedMessage(body), user.keys[signerIdx]!.secretKey);
  const leaf = await attachOwnerSig(body, sig);
  const bytes = encodeLeaf(leaf);
  await log.append(await hashLeaf(bytes));
  entries.push({ index: entries.length, leaf: bytes, ownerSig: sig });
  decoded.push(leaf);
  sths[log.size] = await signTreeHead(
    { treeSize: log.size, rootHash: await log.root(), timestampMs: 1_760_000_000_000 + log.size },
    (m) => ml_dsa87.sign(m, logKey.secretKey),
  );
}

beforeAll(async () => {
  sths[0] = await signTreeHead({ treeSize: 0, rootHash: await emptyRoot(), timestampMs: 1 }, (m) =>
    ml_dsa87.sign(m, logKey.secretKey),
  );
  await append(alice, KtOp.Register, 1, 0);
  await append(bob, KtOp.Register, 1, 0);
  await append(alice, KtOp.Rotate, 2, 0);
  await append(bob, KtOp.Register, 1, 0); // harmless duplicate-looking entry, still bob's own key
});

async function lookup(index: number, size = log.size): Promise<LookupResponse> {
  return {
    sth: sths[size]!,
    leafIndex: index,
    leaf: entries[index]!.leaf,
    ownerSig: entries[index]!.ownerSig,
    proof: await log.inclusionProof(index, size),
  };
}

describe("checkSthChain", () => {
  it("accepts first contact, growth and identical heads", async () => {
    expect(await checkSthChain(null, sths[3]!, [])).toEqual({ ok: true });
    expect(await checkSthChain(sths[0]!, sths[3]!, [])).toEqual({ ok: true });
    expect(await checkSthChain(sths[1]!, sths[4]!, await log.consistencyProof(1, 4))).toEqual({ ok: true });
    expect(await checkSthChain(sths[4]!, sths[4]!, [])).toEqual({ ok: true });
  });

  it("flags shrinking, forks and bad proofs", async () => {
    expect(await checkSthChain(sths[4]!, sths[2]!, [])).toMatchObject({ ok: false, kind: "shrank" });
    const forked = { ...sths[3]!, rootHash: flipBit(sths[3]!.rootHash, 0) };
    expect(await checkSthChain(sths[3]!, forked, [])).toMatchObject({ ok: false, kind: "fork" });
    expect(await checkSthChain(sths[1]!, sths[4]!, await log.consistencyProof(2, 4))).toMatchObject({
      ok: false,
      kind: "inconsistent",
    });
    // History rewrite: same size 4, but leaf 1 replaced. The proof from the
    // honest size-2 head cannot link to it.
    const rewritten = new MerkleLog(new MemoryNodeStore());
    for (const [i, e] of entries.entries()) await rewritten.append(await hashLeaf(i === 1 ? flipBit(e.leaf, 900) : e.leaf));
    const evil = { treeSize: 4, rootHash: await rewritten.root(), timestampMs: 9 };
    expect(await checkSthChain(sths[2]!, evil, await rewritten.consistencyProof(2, 4))).toMatchObject({
      ok: false,
      kind: "inconsistent",
    });
    const badEmpty = { ...sths[0]!, rootHash: new Uint8Array(32) };
    expect(await checkSthChain(badEmpty, sths[2]!, [])).toMatchObject({ ok: false, kind: "fork" });
  });
});

describe("verifyLookup", () => {
  it("accepts an honest lookup and returns the leaf", async () => {
    const r = await lookup(2);
    const res = await verifyLookup({
      username: "ALICE",
      response: r,
      verifySth,
      mldsaPk: alice.keys[1]!.publicKey,
      mlkemPk: alice.kem[1]!,
      minKeyVersion: 2,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.leaf.keyVersion).toBe(2);
    // Register leaves can also have their self-signature checked.
    const reg = await verifyLookup({
      username: "bob",
      response: await lookup(1),
      verifySth,
      mldsaPk: bob.keys[0]!.publicKey,
      verifySig,
    });
    expect(reg.ok).toBe(true);
  });

  it("rejects every kind of tampering", async () => {
    const r = await lookup(2);
    const base = { username: "alice", response: r, verifySth };
    const reasons = async (o: Partial<Parameters<typeof verifyLookup>[0]>) => {
      const res = await verifyLookup({ ...base, ...o });
      expect(res.ok).toBe(false);
      return res.ok ? "" : res.reason;
    };
    expect(await reasons({ response: { ...r, sth: { ...r.sth, signature: flipBit(r.sth.signature, 7) } } })).toMatch(/STH/);
    expect(await reasons({ username: "bob" })).toMatch(/different user/);
    expect(await reasons({ response: { ...r, leafIndex: 1 } })).toMatch(/inclusion/);
    expect(await reasons({ response: { ...r, proof: r.proof.slice(1) } })).toMatch(/inclusion/);
    expect(await reasons({ response: { ...r, ownerSig: flipBit(r.ownerSig, 1) } })).toMatch(/ownerSig/);
    expect(await reasons({ response: { ...r, leaf: r.leaf.subarray(1) } })).toMatch(/malformed/);
    expect(await reasons({ mldsaPk: mallory.publicKey })).toMatch(/ML-DSA/);
    expect(await reasons({ mlkemPk: new Uint8Array(1184) })).toMatch(/ML-KEM/);
    expect(await reasons({ minKeyVersion: 3 })).toMatch(/pinned/);
    // Signed head of an older tree that does not contain leaf 2.
    expect(await reasons({ response: { ...r, sth: sths[2]! } })).toMatch(/inclusion/);
  });

  it("rejects a rogue register leaf the server signed for itself only if checked", async () => {
    // Server swaps in mallory's key for "bob" with a self-signed register: the
    // lookup checks pass (KT does not prevent this), which is why owners must
    // self-monitor. See selfMonitor below.
    const body = await buildLeafBody({
      op: KtOp.Register,
      username: "bob",
      keyVersion: 2,
      mldsaPk: mallory.publicKey,
      mlkemPk: new Uint8Array(1184),
      timestampMs: 5,
    });
    const sig = ml_dsa87.sign(ownerSignedMessage(body), mallory.secretKey);
    const leaf = await attachOwnerSig(body, sig);
    const roguePresent = selfMonitor(await hashUsername("bob"), [], [{ index: 9, leaf }]);
    expect(roguePresent).toHaveLength(1);
    expect(roguePresent[0]!.kind).toBe("unknown-key");
  });
});

describe("selfMonitor", () => {
  it("is silent for the owner's own keys and other users", async () => {
    const known: KnownKey[] = [
      { keyVersion: 1, mldsaPkHash: await sha256(alice.keys[0]!.publicKey), mlkemPkHash: await sha256(alice.kem[0]!) },
      { keyVersion: 2, mldsaPkHash: await sha256(alice.keys[1]!.publicKey), mlkemPkHash: await sha256(alice.kem[1]!) },
    ];
    const leaves = decoded.map((leaf, index) => ({ index, leaf }));
    expect(selfMonitor(await hashUsername("alice"), known, leaves)).toEqual([]);
  });

  it("alerts on unknown keys and revokes the owner did not make", async () => {
    const known: KnownKey[] = [
      { keyVersion: 1, mldsaPkHash: await sha256(alice.keys[0]!.publicKey), mlkemPkHash: await sha256(alice.kem[0]!) },
    ];
    const revokeBody = { ...decoded[0]!, op: KtOp.Revoke };
    const leaves = [
      ...decoded.map((leaf, index) => ({ index, leaf })),
      { index: 4, leaf: revokeBody },
    ];
    const alerts = selfMonitor(await hashUsername("alice"), known, leaves);
    expect(alerts.map((a) => [a.kind, a.index])).toEqual([
      ["unknown-key", 2],
      ["unexpected-revoke", 4],
    ]);
    // Once the owner marks the key revoked, its revoke leaf is expected.
    const after = selfMonitor(await hashUsername("alice"), [{ ...known[0]!, revoked: true }], [{ index: 4, leaf: revokeBody }]);
    expect(after).toEqual([]);
  });
});

describe("verifyLeafRange and wire parsing", () => {
  it("authenticates a /kt/leaves page against the signed head", async () => {
    const at1 = await log.compactRange(1);
    // Simulate the JSON round-trip the client would do.
    const json = {
      from: 1,
      to: 4,
      compactRange: at1.hashes.map(toBase64),
      leaves: entries.slice(1).map((e) => ({ index: e.index, leaf: toBase64(e.leaf), ownerSig: toBase64(e.ownerSig) })),
    };
    const page = parseLeavesResponse(JSON.parse(JSON.stringify(json)));
    const start = await CompactRange.fromHashes(page.from, page.compactRange, sths[1]!.rootHash);
    const res = await verifyLeafRange(start, page.leaves, sths[4]!);
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.leaves.map((l) => l.index)).toEqual([1, 2, 3]);
      expect(res.range.size).toBe(4);
    }
  });

  it("detects hidden, extra, reordered or altered leaves", async () => {
    const start = await log.compactRange(1);
    const page = entries.slice(1);
    const fail = async (es: LeafEntry[]) => expect((await verifyLeafRange(start, es, sths[4]!)).ok).toBe(false);
    await fail(page.slice(0, 2));
    await fail([...page, page[0]!]);
    await fail([page[1]!, page[0]!, page[2]!].map((e, i) => ({ ...e, index: i + 1 })));
    await fail(page.map((e, i) => (i === 1 ? { ...e, leaf: flipBit(e.leaf, 1000) } : e)));
    await fail(page.map((e, i) => (i === 1 ? { ...e, ownerSig: flipBit(e.ownerSig, 3) } : e)));
    await fail(page.map((e, i) => (i === 1 ? { ...e, index: 7 } : e)));
  });

  it("parsers reject malformed JSON", async () => {
    expect(() => parseLeavesResponse({ from: 1, to: 2, compactRange: [], leaves: [] })).toThrow();
    expect(() => parseLeavesResponse({ from: 2, to: 1, compactRange: [], leaves: [] })).toThrow();
    expect(() =>
      parseLeavesResponse({ from: 0, to: 1, compactRange: [], leaves: [{ index: 1, leaf: toBase64(entries[0]!.leaf), ownerSig: "" }] }),
    ).toThrow();
    expect(parseConsistencyResponse({ from: 1, to: 1, proof: [] }).proof).toEqual([]);
    expect(() => parseConsistencyResponse({ from: 1, to: 2, proof: ["AAAA"] })).toThrow();
    const r = await lookup(0);
    const json = {
      sth: sthToJson(r.sth),
      leafIndex: 0,
      leaf: toBase64(r.leaf),
      ownerSig: toBase64(r.ownerSig),
      proof: r.proof.map(toBase64),
    };
    expect(parseLookupResponse(JSON.parse(JSON.stringify(json)))).toEqual(r);
    expect(() => parseLookupResponse({ ...json, leaf: toBase64(new Uint8Array(10)) })).toThrow();
  });
});
