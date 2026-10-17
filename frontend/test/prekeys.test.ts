import { describe, expect, it } from "vitest";
import { generateUserIdentityKeys, exportPublicIdentity } from "../src/crypto/mlkem";
import { fromBase64url, toBase64url } from "../src/crypto/encoding";
import { HandshakeError } from "../src/crypto/errors";
import { mldsaVerify, mlkem1024 } from "../src/crypto/pq";
import {
  MemoryPrekeyStore,
  createOneTimePrekeys,
  createPrekeyUpload,
  parseIdentityKey,
  prekeySignedMessage,
  verifyBundle,
  type PrekeyBundleWire,
} from "../src/crypto/prekeys";

// Today's identity bundle, produced by the existing mlkem.ts code.
const bobKeys = generateUserIdentityKeys();
const bobIdentityKey = exportPublicIdentity(bobKeys);
const eveKeys = generateUserIdentityKeys();

async function bobBundle(withOpk = true) {
  const store = new MemoryPrekeyStore();
  const upload = await createPrekeyUpload(bobKeys.dsaSecretKey, store, 3);
  const bundle: PrekeyBundleWire = {
    username: "bob",
    identityKey: bobIdentityKey,
    signedPrekey: upload.signedPrekey,
    oneTimePrekey: withOpk ? upload.oneTimePrekeys[0] : null,
  };
  return { store, upload, bundle };
}

const codeOf = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    if (e instanceof HandshakeError) return e.code;
    throw e;
  }
  return "OK";
};

describe("prekey generation", () => {
  it("creates one SPK and N OPKs, signed under distinct labels, private halves stored", async () => {
    const { store, upload } = await bobBundle();
    expect(upload.oneTimePrekeys).toHaveLength(3);
    expect(await store.countOneTimePrekeys()).toBe(3);

    const spk = upload.signedPrekey;
    const spkPub = fromBase64url(spk.publicKey);
    expect(spkPub.length).toBe(1568);
    expect(mldsaVerify(bobKeys.dsaPublicKey, prekeySignedMessage("spk", spk.keyId, spkPub), fromBase64url(spk.signature))).toBe(true);
    // The same signature does NOT verify under the OPK label (domain separation).
    expect(mldsaVerify(bobKeys.dsaPublicKey, prekeySignedMessage("opk", spk.keyId, spkPub), fromBase64url(spk.signature))).toBe(false);

    const rec = await store.getSignedPrekey(spk.keyId);
    const { cipherText, sharedSecret } = mlkem1024.encapsulate(spkPub);
    expect(mlkem1024.decapsulate(cipherText, rec!.secretKey)).toEqual(sharedSecret);

    const ids = new Set(upload.oneTimePrekeys.map((o) => o.keyId));
    expect(ids.size).toBe(3);
    for (const id of ids) {
      expect(id).toBeGreaterThanOrEqual(1);
      expect(id).toBeLessThanOrEqual(0x7fffffff);
    }
  });

  it("refill adds keys without colliding with existing ids", async () => {
    const { store } = await bobBundle();
    const more = await createOneTimePrekeys(bobKeys.dsaSecretKey, store, 5);
    expect(more).toHaveLength(5);
    expect(await store.countOneTimePrekeys()).toBe(8);
  });

  it("deleting an SPK also forgets the session ids accepted under it", async () => {
    const { store, upload } = await bobBundle();
    await store.recordAcceptedSession(upload.signedPrekey.keyId, "abc");
    expect(await store.hasAcceptedSession(upload.signedPrekey.keyId, "abc")).toBe(true);
    await store.deleteSignedPrekey(upload.signedPrekey.keyId);
    expect(await store.hasAcceptedSession(upload.signedPrekey.keyId, "abc")).toBe(false);
  });
});

describe("parseIdentityKey (today's mlkem.ts format)", () => {
  it("extracts the ML-DSA-87 public key", () => {
    expect(parseIdentityKey(bobIdentityKey)).toEqual(bobKeys.dsaPublicKey);
  });
  it("rejects non-JSON, a missing dsa field and a wrong length", () => {
    expect(codeOf(() => parseIdentityKey("not json"))).toBe("BAD_BUNDLE");
    expect(codeOf(() => parseIdentityKey(JSON.stringify({ kem: "AAAA" })))).toBe("BAD_BUNDLE");
    expect(codeOf(() => parseIdentityKey(JSON.stringify({ dsa: "AAAA" })))).toBe("BAD_BUNDLE");
  });
});

describe("verifyBundle", () => {
  it("accepts a valid bundle with and without a one-time prekey", async () => {
    const { bundle } = await bobBundle();
    const v = verifyBundle(bundle, "bob");
    expect(v.identityDsaPub).toEqual(bobKeys.dsaPublicKey);
    expect(v.oneTimePrekey).not.toBeNull();
    const { bundle: noOpk } = await bobBundle(false);
    expect(verifyBundle(noOpk, "bob").oneTimePrekey).toBeNull();
  });

  it("rejects a bundle without a signed prekey or for another user", async () => {
    const { bundle } = await bobBundle();
    expect(codeOf(() => verifyBundle({ ...bundle, signedPrekey: null }, "bob"))).toBe("NO_SIGNED_PREKEY");
    expect(codeOf(() => verifyBundle(bundle, "carol"))).toBe("BAD_BUNDLE");
  });

  it("rejects swapped signatures and keys signed by someone else", async () => {
    const { bundle, upload } = await bobBundle();
    const swapped = { ...bundle, signedPrekey: { ...bundle.signedPrekey!, signature: upload.oneTimePrekeys[1].signature } };
    expect(codeOf(() => verifyBundle(swapped, "bob"))).toBe("BAD_PREKEY_SIGNATURE");
    const eveIdentity = { ...bundle, identityKey: exportPublicIdentity(eveKeys) };
    expect(codeOf(() => verifyBundle(eveIdentity, "bob"))).toBe("BAD_PREKEY_SIGNATURE");
  });

  it("rejects an OPK presented as the SPK and an SPK presented as an OPK (distinct labels)", async () => {
    const { bundle, upload } = await bobBundle();
    const opkAsSpk = { ...bundle, signedPrekey: upload.oneTimePrekeys[1] };
    expect(codeOf(() => verifyBundle(opkAsSpk, "bob"))).toBe("BAD_PREKEY_SIGNATURE");
    const spkAsOpk = { ...bundle, oneTimePrekey: upload.signedPrekey };
    expect(codeOf(() => verifyBundle(spkAsOpk, "bob"))).toBe("BAD_PREKEY_SIGNATURE");
  });

  it("rejects malformed fields", async () => {
    const { bundle } = await bobBundle();
    const spk = bundle.signedPrekey!;
    const short = toBase64url(fromBase64url(spk.publicKey).subarray(1));
    expect(codeOf(() => verifyBundle({ ...bundle, signedPrekey: { ...spk, publicKey: short } }, "bob"))).toBe("BAD_BUNDLE");
    expect(codeOf(() => verifyBundle({ ...bundle, signedPrekey: { ...spk, publicKey: spk.publicKey + "=" } }, "bob"))).toBe("BAD_BUNDLE");
    expect(codeOf(() => verifyBundle({ ...bundle, signedPrekey: { ...spk, keyId: 0 } }, "bob"))).toBe("BAD_BUNDLE");
    expect(codeOf(() => verifyBundle({ ...bundle, signedPrekey: { ...spk, keyId: spk.keyId + 1 } }, "bob"))).toBe(
      "BAD_PREKEY_SIGNATURE",
    );
  });
});
