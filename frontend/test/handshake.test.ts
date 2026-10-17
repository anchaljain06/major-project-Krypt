import { describe, expect, it } from "vitest";
import { DecryptError } from "../src/crypto/errors";
import { initiate, respond, transcript, type InitHeader, type TranscriptFields } from "../src/crypto/handshake";
import { mldsaKeygen, KEM_SUITES } from "../src/crypto/pq";
import { MemoryPrekeyStore, createPrekeyUpload, verifyBundle } from "../src/crypto/prekeys";
import { exportPublicIdentity } from "../src/crypto/mlkem";

const alice = mldsaKeygen();
const bob = mldsaKeygen();
const mallory = mldsaKeygen();
const identityJson = (pub: Uint8Array) => exportPublicIdentity({ kemPublicKey: new Uint8Array(1568), dsaPublicKey: pub });

async function setup(withOpk: boolean) {
  const store = new MemoryPrekeyStore();
  const upload = await createPrekeyUpload(bob.secretKey, store, 1);
  const bundle = verifyBundle(
    {
      username: "bob",
      identityKey: identityJson(bob.publicKey),
      signedPrekey: upload.signedPrekey,
      oneTimePrekey: withOpk ? upload.oneTimePrekeys[0] : null,
    },
    "bob",
  );
  return { store, bundle };
}

async function bobResponds(store: MemoryPrekeyStore, init: InitHeader, suite: (typeof KEM_SUITES)[number], ik = alice.publicKey) {
  return respond({
    self: { username: "bob", dsaPub: bob.publicKey },
    initiator: { username: "alice", dsaPub: ik },
    suite,
    init,
    spk: (await store.getSignedPrekey(init.spkId))!,
    opk: init.opkId === null ? null : (await store.getOneTimePrekey(init.opkId))!,
  });
}

describe("Krypt-X3K", () => {
  for (const suite of KEM_SUITES) {
    for (const withOpk of [true, false]) {
      it(`${suite}, ${withOpk ? "with" : "without"} OPK: both sides derive RK0, CK0 and sessionId = H(T)`, async () => {
        const { store, bundle } = await setup(withOpk);
        const a = await initiate({ self: { username: "alice", dsaPub: alice.publicKey, dsaSec: alice.secretKey }, bundle, suite });
        expect(a.init.opkId === null).toBe(!withOpk);
        const b = await bobResponds(store, a.init, suite);
        expect(b.sessionId).toEqual(a.sessionId);
        expect(b.rk).toEqual(a.rk);
        expect(b.ck).toEqual(a.ck);
        expect(b.peerEk).toEqual(a.ourEk);
        expect(a.rk).not.toEqual(a.ck);
      });
    }
  }

  it("rejects a forged or transplanted initiator signature", async () => {
    const { store, bundle } = await setup(true);
    const a = await initiate({ self: { username: "alice", dsaPub: alice.publicKey, dsaSec: alice.secretKey }, bundle, suite: "mlkem768" });
    // Wrong identity key for Alice (e.g. Mallory claims to be Alice).
    await expect(bobResponds(store, a.init, "mlkem768", mallory.publicKey)).rejects.toThrow(DecryptError);
    // Any change to a transcript field invalidates σ_A.
    const ct1 = a.init.ct1.slice();
    ct1[0] ^= 1;
    await expect(bobResponds(store, { ...a.init, ct1 }, "mlkem768")).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
    const ek = a.init.ek.slice();
    ek[5] ^= 1;
    await expect(bobResponds(store, { ...a.init, ek }, "mlkem768")).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
    // A suite downgrade/confusion changes T as well.
    await expect(bobResponds(store, a.init, "xwing")).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
  });

  it("transcript changes when any field changes (including absent vs present OPK)", () => {
    const base: TranscriptFields = {
      suite: "mlkem768",
      initiator: "alice",
      responder: "bob",
      ikA: new Uint8Array([1]),
      ikB: new Uint8Array([2]),
      spkId: 7,
      spkPub: new Uint8Array([3]),
      opkId: null,
      opkPub: null,
      ct1: new Uint8Array([4]),
      ct2: null,
      ekA: new Uint8Array([5]),
    };
    const t0 = Buffer.from(transcript(base)).toString("hex");
    const variants: Partial<TranscriptFields>[] = [
      { suite: "xwing" },
      { initiator: "alicf" },
      { responder: "boc" },
      { spkId: 8 },
      { opkId: 1, opkPub: new Uint8Array(0), ct2: new Uint8Array(0) },
      { ct1: new Uint8Array([4, 0]) },
      { ekA: new Uint8Array([6]) },
      // Moving a byte between adjacent fields must change T (length prefixes).
      { initiator: "alic", responder: "ebob" },
    ];
    for (const v of variants) {
      expect(Buffer.from(transcript({ ...base, ...v })).toString("hex")).not.toBe(t0);
    }
  });
});
