/**
 * Krypt-X3K handshake (spec section 4): a PQXDH-style, KEM-only handshake.
 *
 * Both functions are pure computations over keys; they never touch storage.
 * The SessionManager does the lookups (prekeys, identities, replay memory)
 * and commits state only after the first message decrypts.
 */
import { sha256 } from "@krypt/shared";
import { EMPTY, LABELS, lp, u32 } from "./encoding";
import { DecryptError } from "./errors";
import { kdfHandshake } from "./kdf";
import { mldsaSign, mldsaVerify, prekeyKem, ratchetKem, type KemSuite } from "./pq";
import type { PrekeyRecord, VerifiedBundle } from "./prekeys";

/** Fields Alice attaches to every epoch-0 message until Bob replies. */
export interface InitHeader {
  spkId: number;
  opkId: number | null;
  ct1: Uint8Array;
  ct2: Uint8Array | null;
  /** Alice's first ratchet public key ek_A¹. */
  ek: Uint8Array;
  /** σ_A = Sign(IK_A, lp("Krypt-init", H(T))). */
  sig: Uint8Array;
}

export interface TranscriptFields {
  suite: KemSuite;
  initiator: string;
  responder: string;
  ikA: Uint8Array;
  ikB: Uint8Array;
  spkId: number;
  spkPub: Uint8Array;
  opkId: number | null;
  opkPub: Uint8Array | null;
  ct1: Uint8Array;
  ct2: Uint8Array | null;
  ekA: Uint8Array;
}

/**
 * T = lp("Krypt-v1", suite, A, B, IK_A, IK_B, u32(spkId), SPK_B,
 *        u32(opkId) | ε, OPK_B | ε, ct1, ct2 | ε, ek_A¹)
 */
export function transcript(f: TranscriptFields): Uint8Array {
  return lp(
    LABELS.transcript,
    f.suite,
    f.initiator,
    f.responder,
    f.ikA,
    f.ikB,
    u32(f.spkId),
    f.spkPub,
    f.opkId === null ? EMPTY : u32(f.opkId),
    f.opkPub ?? EMPTY,
    f.ct1,
    f.ct2 ?? EMPTY,
    f.ekA,
  );
}

const initSignedMessage = (hT: Uint8Array) => lp(LABELS.init, hT);

export interface InitiatorResult {
  /** sessionId = H(T). */
  sessionId: Uint8Array;
  rk: Uint8Array;
  /** CK0: Alice's sending chain for epoch 0. */
  ck: Uint8Array;
  init: InitHeader;
  /** Alice's first ratchet key pair; Bob's bootstrap encapsulates to ourEk. */
  ourEk: Uint8Array;
  ourDk: Uint8Array;
}

/** Alice's side (spec 4.1). `bundle` must already be verified and trusted. */
export async function initiate(params: {
  self: { username: string; dsaPub: Uint8Array; dsaSec: Uint8Array };
  bundle: VerifiedBundle;
  suite: KemSuite;
}): Promise<InitiatorResult> {
  const { self, bundle, suite } = params;
  const spk = bundle.signedPrekey;
  const opk = bundle.oneTimePrekey;

  const e1 = prekeyKem.encapsulate(spk.publicKey);
  const e2 = opk ? prekeyKem.encapsulate(opk.publicKey) : null;
  const ratchet = ratchetKem(suite).keygen();

  const T = transcript({
    suite,
    initiator: self.username,
    responder: bundle.username,
    ikA: self.dsaPub,
    ikB: bundle.identityDsaPub,
    spkId: spk.keyId,
    spkPub: spk.publicKey,
    opkId: opk?.keyId ?? null,
    opkPub: opk?.publicKey ?? null,
    ct1: e1.cipherText,
    ct2: e2?.cipherText ?? null,
    ekA: ratchet.publicKey,
  });
  const hT = await sha256(T);
  const { rk, ck } = await kdfHandshake(e1.sharedSecret, e2?.sharedSecret ?? EMPTY, hT);
  const sig = mldsaSign(self.dsaSec, initSignedMessage(hT));

  return {
    sessionId: hT,
    rk,
    ck,
    init: {
      spkId: spk.keyId,
      opkId: opk?.keyId ?? null,
      ct1: e1.cipherText,
      ct2: e2?.cipherText ?? null,
      ek: ratchet.publicKey,
      sig,
    },
    ourEk: ratchet.publicKey,
    ourDk: ratchet.secretKey,
  };
}

export interface ResponderResult {
  sessionId: Uint8Array;
  rk: Uint8Array;
  /** CK0: Bob's receiving chain for epoch 0. */
  ck: Uint8Array;
  /** ek_A¹, which Bob's bootstrap send step encapsulates to. */
  peerEk: Uint8Array;
}

/**
 * Bob's side (spec 4.2), given the prekey records named by the init header.
 * Throws DecryptError("BAD_SIGNATURE") if σ_A does not verify. The caller
 * checks that the returned sessionId equals the envelope's sessionId.
 */
export async function respond(params: {
  self: { username: string; dsaPub: Uint8Array };
  initiator: { username: string; dsaPub: Uint8Array };
  suite: KemSuite;
  init: InitHeader;
  spk: PrekeyRecord;
  opk: PrekeyRecord | null;
}): Promise<ResponderResult> {
  const { self, initiator, suite, init, spk, opk } = params;
  if ((init.opkId === null) !== (opk === null) || (init.opkId === null) !== (init.ct2 === null)) {
    throw new DecryptError("MALFORMED", "one-time prekey fields are inconsistent");
  }

  const T = transcript({
    suite,
    initiator: initiator.username,
    responder: self.username,
    ikA: initiator.dsaPub,
    ikB: self.dsaPub,
    spkId: init.spkId,
    spkPub: spk.publicKey,
    opkId: init.opkId,
    opkPub: opk?.publicKey ?? null,
    ct1: init.ct1,
    ct2: init.ct2,
    ekA: init.ek,
  });
  const hT = await sha256(T);
  // Verify before decapsulating: an unauthenticated init costs one signature check.
  if (!mldsaVerify(initiator.dsaPub, initSignedMessage(hT), init.sig)) {
    throw new DecryptError("BAD_SIGNATURE", "initiator signature does not verify");
  }
  const ss1 = prekeyKem.decapsulate(init.ct1, spk.secretKey);
  const ss2 = opk && init.ct2 ? prekeyKem.decapsulate(init.ct2, opk.secretKey) : EMPTY;
  const { rk, ck } = await kdfHandshake(ss1, ss2, hT);
  return { sessionId: hT, rk, ck, peerEk: init.ek };
}
