import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { bytesEqual, sha256, toHex, utf8 } from "../src/bytes.ts";
import {
  KT_LEAF_SIZE,
  KtOp,
  attachOwnerSig,
  buildLeafBody,
  decodeLeaf,
  encodeLeaf,
  hashUsername,
  ktLeafHash,
  normalizeUsername,
  ownerSignedMessage,
  ownerSigner,
  verifyOwnerSig,
  type KtLeaf,
} from "../src/leaf.ts";
import { hashChildren, hashLeaf } from "../src/merkle.ts";

const bytes32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
const leafArb: fc.Arbitrary<KtLeaf> = fc.record({
  op: fc.constantFrom(KtOp.Register, KtOp.Rotate, KtOp.Revoke),
  userHash: bytes32,
  keyVersion: fc.nat(0xffffffff),
  mldsaPkHash: bytes32,
  mlkemPkHash: bytes32,
  timestampMs: fc.nat(Number.MAX_SAFE_INTEGER),
  ownerSigHash: bytes32,
});

const nobleVerify = (msg: Uint8Array, sig: Uint8Array, pk: Uint8Array) => ml_dsa87.verify(sig, msg, pk);

describe("leaf encoding", () => {
  it("round-trips any valid leaf at exactly 153 bytes", () => {
    fc.assert(
      fc.property(leafArb, (leaf) => {
        const enc = encodeLeaf(leaf);
        expect(enc.length).toBe(KT_LEAF_SIZE);
        expect(decodeLeaf(enc)).toEqual(leaf);
        expect(toHex(encodeLeaf(decodeLeaf(enc)))).toBe(toHex(enc));
      }),
      { numRuns: 500 },
    );
  });

  it("has the field layout of strategy §5.2", () => {
    const leaf: KtLeaf = {
      op: KtOp.Rotate,
      userHash: new Uint8Array(32).fill(0xaa),
      keyVersion: 0x01020304,
      mldsaPkHash: new Uint8Array(32).fill(0xbb),
      mlkemPkHash: new Uint8Array(32).fill(0xcc),
      timestampMs: 0x0102030405,
      ownerSigHash: new Uint8Array(32).fill(0xdd),
    };
    const hex = toHex(encodeLeaf(leaf));
    expect(hex).toBe(
      toHex(utf8("KRYPT-KT-v1\0")) +
        "02" +
        "aa".repeat(32) +
        "01020304" +
        "bb".repeat(32) +
        "cc".repeat(32) +
        "0000000102030405" +
        "dd".repeat(32),
    );
  });

  it("rejects wrong length, wrong tag, unknown op and oversized integers", () => {
    const good = encodeLeaf({
      op: KtOp.Register,
      userHash: new Uint8Array(32),
      keyVersion: 1,
      mldsaPkHash: new Uint8Array(32),
      mlkemPkHash: new Uint8Array(32),
      timestampMs: 1,
      ownerSigHash: new Uint8Array(32),
    });
    expect(() => decodeLeaf(good.subarray(0, 152))).toThrow();
    expect(() => decodeLeaf(new Uint8Array([...good, 0]))).toThrow();
    const badTag = new Uint8Array(good);
    badTag[11] = 0x41; // drop the NUL terminator of the tag
    expect(() => decodeLeaf(badTag)).toThrow();
    for (const op of [0, 4, 255]) {
      const badOp = new Uint8Array(good);
      badOp[12] = op;
      expect(() => decodeLeaf(badOp)).toThrow();
    }
    const hugeTs = new Uint8Array(good);
    hugeTs.fill(0xff, 113, 121);
    expect(() => decodeLeaf(hugeTs)).toThrow(RangeError);
    const base = decodeLeaf(good);
    expect(() => encodeLeaf({ ...base, keyVersion: 2 ** 32 })).toThrow(RangeError);
    expect(() => encodeLeaf({ ...base, keyVersion: -1 })).toThrow(RangeError);
    expect(() => encodeLeaf({ ...base, userHash: new Uint8Array(31) })).toThrow(TypeError);
    expect(() => encodeLeaf({ ...base, op: 7 as KtLeaf["op"] })).toThrow(RangeError);
  });
});

describe("usernames", () => {
  it("lower-cases, then NFC-normalises", async () => {
    expect(normalizeUsername("ALICE")).toBe("alice");
    // "e" + combining acute (NFD) and precomposed "é" are one user.
    expect(normalizeUsername("José")).toBe("josé");
    expect(toHex(await hashUsername("JOSÉ"))).toBe(toHex(await hashUsername("josé")));
    expect(toHex(await hashUsername("alice"))).not.toBe(toHex(await hashUsername("alice ")));
  });

  it("hashes with the krypt-user domain tag", async () => {
    expect(toHex(await hashUsername("Bob"))).toBe(toHex(await sha256(utf8("krypt-user\0bob"))));
    expect(toHex(await hashUsername("bob"))).not.toBe(toHex(await sha256(utf8("bob"))));
  });
});

describe("domain separation", () => {
  it("leaf hash is SHA-256(0x00 || leaf) and differs from a plain hash or a node hash", async () => {
    await fc.assert(
      fc.asyncProperty(leafArb, async (leaf) => {
        const enc = encodeLeaf(leaf);
        const lh = await ktLeafHash(leaf);
        expect(toHex(lh)).toBe(toHex(await sha256(Uint8Array.of(0), enc)));
        expect(toHex(lh)).not.toBe(toHex(await sha256(enc)));
        // A 64-byte leaf could pose as a node; ours are 153 bytes and prefixed anyway.
        expect(toHex(lh)).not.toBe(toHex(await hashChildren(enc.subarray(0, 32), enc.subarray(32, 64))));
      }),
      { numRuns: 50 },
    );
  });

  it("owner-signed message cannot be mistaken for a leaf", async () => {
    await fc.assert(
      fc.property(leafArb, (leaf) => {
        const msg = ownerSignedMessage(leaf);
        const enc = encodeLeaf(leaf);
        expect(msg.length).toBe(18 + 109);
        expect(bytesEqual(msg.subarray(0, 12), enc.subarray(0, 12))).toBe(false);
        expect(() => decodeLeaf(msg)).toThrow();
      }),
      { numRuns: 100 },
    );
  });

  it("every field changes the leaf hash", async () => {
    const base: KtLeaf = {
      op: KtOp.Register,
      userHash: new Uint8Array(32),
      keyVersion: 1,
      mldsaPkHash: new Uint8Array(32),
      mlkemPkHash: new Uint8Array(32),
      timestampMs: 1,
      ownerSigHash: new Uint8Array(32),
    };
    const one = new Uint8Array(32).fill(1);
    const variants: KtLeaf[] = [
      { ...base, op: KtOp.Rotate },
      { ...base, userHash: one },
      { ...base, keyVersion: 2 },
      { ...base, mldsaPkHash: one },
      { ...base, mlkemPkHash: one },
      { ...base, timestampMs: 2 },
      { ...base, ownerSigHash: one },
    ];
    const hashes = new Set([toHex(await ktLeafHash(base))]);
    for (const v of variants) hashes.add(toHex(await ktLeafHash(v)));
    expect(hashes.size).toBe(variants.length + 1);
    expect(toHex(await ktLeafHash(base))).toBe(toHex(await hashLeaf(encodeLeaf(base))));
  });
});

describe("owner signatures with ML-DSA-87", () => {
  const k1 = ml_dsa87.keygen(new Uint8Array(32).fill(1));
  const k2 = ml_dsa87.keygen(new Uint8Array(32).fill(2));
  const kem1 = new Uint8Array(1184).fill(7);
  const kem2 = new Uint8Array(1184).fill(8);

  it("names the signer per op", () => {
    expect(ownerSigner(KtOp.Register)).toBe("new-key");
    expect(ownerSigner(KtOp.Rotate)).toBe("previous-key");
    expect(ownerSigner(KtOp.Revoke)).toBe("revoked-key");
  });

  it("register is self-signed; rotate is signed by the previous key", async () => {
    const regBody = await buildLeafBody({
      op: KtOp.Register,
      username: "Bob",
      keyVersion: 1,
      mldsaPk: k1.publicKey,
      mlkemPk: kem1,
      timestampMs: 1_700_000_000_000,
    });
    const regSig = ml_dsa87.sign(ownerSignedMessage(regBody), k1.secretKey);
    const reg = await attachOwnerSig(regBody, regSig);
    expect(await verifyOwnerSig(reg, regSig, k1.publicKey, nobleVerify)).toBe(true);
    // Signed by the right key but presented with another key: rejected.
    expect(await verifyOwnerSig(reg, regSig, k2.publicKey, nobleVerify)).toBe(false);

    const rotBody = await buildLeafBody({
      op: KtOp.Rotate,
      username: "bob",
      keyVersion: 2,
      mldsaPk: k2.publicKey,
      mlkemPk: kem2,
      timestampMs: 1_700_000_100_000,
    });
    const rotSig = ml_dsa87.sign(ownerSignedMessage(rotBody), k1.secretKey);
    const rot = await attachOwnerSig(rotBody, rotSig);
    expect(await verifyOwnerSig(rot, rotSig, k1.publicKey, nobleVerify)).toBe(true);
    // A server that only has the new key (it generated it) cannot forge a rotation.
    const forged = ml_dsa87.sign(ownerSignedMessage(rotBody), k2.secretKey);
    expect(await verifyOwnerSig(await attachOwnerSig(rotBody, forged), forged, k1.publicKey, nobleVerify)).toBe(false);
    // A signature that does not match the leaf's hash is rejected before verifying.
    expect(await verifyOwnerSig(rot, regSig, k1.publicKey, nobleVerify)).toBe(false);
  });
});
