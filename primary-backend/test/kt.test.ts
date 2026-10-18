import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import {
  KtError,
  KtLog,
  checkSubmission,
  loadLogKey,
  logKeyFromSeed,
  memoryKtStorage,
  parseIdentityKey,
  type StoredLeaf,
} from "../src/kt.js";
import {
  KtOp,
  consistencyProof,
  decodeLeaf,
  hashLeaf,
  inclusionProof,
  merkleTreeHash,
  toBase64,
  verifyConsistency,
  verifyInclusion,
  verifyTreeHead,
} from "../src/vendor/krypt-shared/index.js";
import { newIdentity, randomLeafBytes, signedLeaf, type TestIdentity } from "./ktHelpers.js";

const key = logKeyFromSeed(new Uint8Array(32).fill(7));

function clock(start = 1_700_000_000_000) {
  let t = start;
  return { now: () => t, advance: (ms: number) => (t += ms) };
}

describe("KtLog over memory storage", () => {
  it("matches the list-based RFC 9162 functions for every size", async () => {
    const log = new KtLog(memoryKtStorage(), key);
    const leaves: Uint8Array[] = [];
    for (let i = 0; i < 70; i++) {
      const { bytes, ownerSig } = randomLeafBytes();
      const row = await log.append(bytes, ownerSig);
      expect(row.index).toBe(i);
      leaves.push(bytes);
    }
    const view = log.honestView();
    for (const n of [1, 2, 3, 7, 8, 9, 31, 32, 33, 64, 70]) {
      const ml = await view.log(n);
      expect(await ml.root(n)).toEqual(await merkleTreeHash(leaves.slice(0, n)));
      for (const i of [0, Math.floor(n / 2), n - 1]) {
        expect(await ml.inclusionProof(i, n)).toEqual(await inclusionProof(leaves.slice(0, n), i));
      }
      for (const m of [1, Math.ceil(n / 3), n]) {
        expect(await ml.consistencyProof(m, n)).toEqual(await consistencyProof(leaves.slice(0, n), m));
      }
    }
  });

  it("serialises concurrent appends", async () => {
    const storage = memoryKtStorage();
    const log = new KtLog(storage, key);
    const rows = await Promise.all(Array.from({ length: 40 }, () => log.append(randomLeafBytes().bytes, new Uint8Array(4))));
    expect(rows.map((r) => r.index).sort((a, b) => a - b)).toEqual([...Array(40).keys()]);
    const root = await (await log.honestView().log(40)).root();
    expect(root).toEqual(await merkleTreeHash(storage.rows.map((r) => r.leaf)));
  });

  it("publishes tree heads lazily: at most once per interval, only when the size changed", async () => {
    const c = clock();
    const storage = memoryKtStorage();
    const log = new KtLog(storage, key, { now: c.now });

    const empty = await log.latestSth(); // no head yet: publish one now
    expect(empty.treeSize).toBe(0);
    expect(toBase64(empty.rootHash)).toBe("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    expect(await verifyTreeHead(empty, key.verify)).toBe(true);

    await log.append(randomLeafBytes().bytes, new Uint8Array(1)); // not due yet
    expect((await log.latestSth()).treeSize).toBe(0);

    c.advance(5 * 60 * 1000 - 1);
    expect((await log.latestSth()).treeSize).toBe(0);
    c.advance(1);
    const one = await log.latestSth(); // due: published on read
    expect(one.treeSize).toBe(1);
    expect(one.timestampMs).toBe(c.now());

    c.advance(60 * 60 * 1000); // no growth: no new head
    expect(await log.latestSth()).toEqual(one);
    expect(storage.sths).toHaveLength(2);

    await log.append(randomLeafBytes().bytes, new Uint8Array(1)); // due: published on append
    expect(storage.sths.map((s) => s.treeSize)).toEqual([0, 1, 2]);
    const head = (await log.latestSth());
    expect(await verifyTreeHead(head, key.verify)).toBe(true);
    const proof = await (await log.honestView().log(2)).consistencyProof(1, 2);
    expect(await verifyConsistency(1, 2, one.rootHash, head.rootHash, proof)).toBe(true);
  });

  it("serves inclusion proofs for the user's latest leaf", async () => {
    const log = new KtLog(memoryKtStorage(), key, { sthIntervalMs: 0 });
    const alice = newIdentity(1);
    for (let i = 0; i < 5; i++) await log.append(randomLeafBytes().bytes, new Uint8Array(1));
    const reg = await signedLeaf({ op: KtOp.Register, username: "Alice", keyVersion: 1, about: alice, signer: alice });
    await log.append(reg.bytes, reg.ownerSig);
    const sth = await log.latestSth();
    const entry = (await log.honestView().latestLeafForUser(decodeLeaf(reg.bytes).userHash, sth.treeSize))!;
    expect(entry.index).toBe(5);
    const proof = await (await log.honestView().log(sth.treeSize)).inclusionProof(5, sth.treeSize);
    expect(await verifyInclusion(5, sth.treeSize, await hashLeaf(entry.leaf), proof, sth.rootHash)).toBe(true);
  });
});

describe("loadLogKey", () => {
  it("accepts a 32-byte seed or a full secret key, and refuses anything else", () => {
    const seed = new Uint8Array(32).fill(9);
    const fromSeed = loadLogKey({ KT_LOG_SK: toBase64(seed) });
    expect(fromSeed.publicKey).toEqual(ml_dsa87.keygen(seed).publicKey);
    const fromSk = loadLogKey({ KT_LOG_SK: toBase64(ml_dsa87.keygen(seed).secretKey) });
    expect(fromSk.publicKey).toEqual(fromSeed.publicKey);
    const msg = new Uint8Array([1, 2, 3]);
    expect(fromSeed.verify(msg, fromSk.sign(msg))).toBe(true);
    expect(() => loadLogKey({ KT_LOG_SK: toBase64(new Uint8Array(31)) })).toThrow(/32-byte seed/);
    expect(() => loadLogKey({ KT_LOG_SK: "not base64!" })).toThrow(/base64/);
  });
});

describe("parseIdentityKey", () => {
  it("reads the frontend's exportPublicIdentity JSON and rejects legacy keys", () => {
    const id = newIdentity(2);
    const parsed = parseIdentityKey(id.identityKeyPub)!;
    expect(parsed.mldsaPk).toEqual(id.dsa.publicKey);
    expect(parsed.mlkemPk).toEqual(id.kem.publicKey);
    expect(parseIdentityKey(toBase64(id.kem.publicKey))).toBeNull(); // legacy raw KEM key
    expect(parseIdentityKey(JSON.stringify({ kem: toBase64(id.kem.publicKey) }))).toBeNull();
    expect(parseIdentityKey(null)).toBeNull();
  });
});

describe("checkSubmission (register / rotate / revoke)", () => {
  const k1 = newIdentity(11);
  const k2 = newIdentity(12);
  const mallory = newIdentity(13);
  const now = Date.now();

  async function submission(op: KtOp, keyVersion: number, about: TestIdentity, signer: TestIdentity, identity = about, ts = now) {
    const l = await signedLeaf({ op, username: "bob", keyVersion, about, signer, timestampMs: ts });
    const ident = parseIdentityKey(identity.identityKeyPub)!;
    return {
      sub: { leaf: l.leaf, ownerSig: l.ownerSig, signerPk: signer.dsa.publicKey, identity: ident },
      stored: { index: 0, leaf: l.bytes, leafHash: new Uint8Array(32), userHash: l.leaf.userHash, keyVersion, ownerSig: l.ownerSig } satisfies StoredLeaf,
    };
  }
  const refuses = async (p: Promise<void>, status: number, msg: RegExp) => {
    const err = await p.then(() => null, (e) => e);
    expect(err).toBeInstanceOf(KtError);
    expect(err.status).toBe(status);
    expect(err.message).toMatch(msg);
  };

  it("register: only first, version 1, signed by the new key", async () => {
    const reg = await submission(KtOp.Register, 1, k1, k1);
    await expect(checkSubmission(reg.sub, null, now)).resolves.toBeUndefined();
    await refuses(checkSubmission(reg.sub, reg.stored, now), 409, /already registered/);
    const v2 = await submission(KtOp.Register, 2, k1, k1);
    await refuses(checkSubmission(v2.sub, null, now), 400, /key_version 1/);
    const otherSigner = await submission(KtOp.Register, 1, k1, mallory);
    await refuses(checkSubmission(otherSigner.sub, null, now), 400, /key the leaf names/);
    const notStoredKey = await submission(KtOp.Register, 1, mallory, mallory, k1);
    await refuses(checkSubmission(notStoredKey.sub, null, now), 400, /fingerprints/);
    const stale = await submission(KtOp.Register, 1, k1, k1, k1, now - 11 * 60 * 1000);
    await refuses(checkSubmission(stale.sub, null, now), 400, /timestamp/);
  });

  it("rotate: version + 1, signed by the previous key", async () => {
    const reg = await submission(KtOp.Register, 1, k1, k1);
    const rot = await submission(KtOp.Rotate, 2, k2, k1);
    await expect(checkSubmission(rot.sub, reg.stored, now)).resolves.toBeUndefined();
    await refuses(checkSubmission(rot.sub, null, now), 409, /use register/);
    const selfSigned = await submission(KtOp.Rotate, 2, k2, k2);
    await refuses(checkSubmission(selfSigned.sub, reg.stored, now), 400, /previous key/);
    const skip = await submission(KtOp.Rotate, 3, k2, k1);
    await refuses(checkSubmission(skip.sub, reg.stored, now), 409, /key_version 2/);
  });

  it("revoke: names the current key, signed by it; nothing follows", async () => {
    const reg = await submission(KtOp.Register, 1, k1, k1);
    const rev = await submission(KtOp.Revoke, 1, k1, k1);
    await expect(checkSubmission(rev.sub, reg.stored, now)).resolves.toBeUndefined();
    const wrongKey = await submission(KtOp.Revoke, 1, k2, k2);
    await refuses(checkSubmission(wrongKey.sub, reg.stored, now), 409, /current key/);
    const rot = await submission(KtOp.Rotate, 2, k2, k1);
    await refuses(checkSubmission(rot.sub, rev.stored, now), 409, /revoked/);
  });

  it("refuses a signature that does not verify or does not match the leaf", async () => {
    const reg = await submission(KtOp.Register, 1, k1, k1);
    const flipped = new Uint8Array(reg.sub.ownerSig);
    flipped[100]! ^= 1;
    await refuses(checkSubmission({ ...reg.sub, ownerSig: flipped }, null, now), 400, /owner_sig hash/);
    // A matching hash but a forged signature (the evil relay's rogue leaf).
    const forged = globalThis.crypto.getRandomValues(new Uint8Array(4627));
    const { attachOwnerSig } = await import("../src/vendor/krypt-shared/index.js");
    const leaf = await attachOwnerSig(reg.sub.leaf, forged);
    await refuses(checkSubmission({ ...reg.sub, leaf, ownerSig: forged }, null, now), 400, /Invalid owner signature/);
  });
});
