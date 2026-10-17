import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import {
  attachOwnerSig,
  buildLeafBody,
  encodeLeaf,
  ownerSignedMessage,
  toBase64,
  type KtOp,
} from "../src/vendor/krypt-shared/index.js";

export interface TestIdentity {
  dsa: { publicKey: Uint8Array; secretKey: Uint8Array };
  kem: { publicKey: Uint8Array };
  /** User.identityKeyPub as the frontend writes it (exportPublicIdentity). */
  identityKeyPub: string;
}

export function newIdentity(seedByte?: number): TestIdentity {
  const dsa = ml_dsa87.keygen(seedByte === undefined ? undefined : new Uint8Array(32).fill(seedByte));
  const kem = ml_kem1024.keygen(seedByte === undefined ? undefined : new Uint8Array(64).fill(seedByte));
  return {
    dsa,
    kem: { publicKey: kem.publicKey },
    identityKeyPub: JSON.stringify({
      version: "ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)",
      kem: toBase64(kem.publicKey),
      dsa: toBase64(dsa.publicKey),
    }),
  };
}

/** A leaf naming `about`'s key, owner-signed by `signer`. */
export async function signedLeaf(opts: {
  op: KtOp;
  username: string;
  keyVersion: number;
  about: TestIdentity;
  signer: TestIdentity;
  timestampMs?: number;
}) {
  const body = await buildLeafBody({
    op: opts.op,
    username: opts.username,
    keyVersion: opts.keyVersion,
    mldsaPk: opts.about.dsa.publicKey,
    mlkemPk: opts.about.kem.publicKey,
    timestampMs: opts.timestampMs ?? Date.now(),
  });
  const ownerSig = ml_dsa87.sign(ownerSignedMessage(body), opts.signer.dsa.secretKey);
  const leaf = await attachOwnerSig(body, ownerSig);
  return { leaf, bytes: encodeLeaf(leaf), ownerSig };
}

/** A well-formed leaf with random contents (no valid signature). */
export function randomLeafBytes(): { bytes: Uint8Array; ownerSig: Uint8Array } {
  const r = (n: number) => globalThis.crypto.getRandomValues(new Uint8Array(n));
  const tag = new TextEncoder().encode("KRYPT-KT-v1\0");
  const leaf = new Uint8Array(153);
  leaf.set(tag, 0);
  leaf[12] = 1 + Math.floor(Math.random() * 3);
  leaf.set(r(32), 13);
  leaf.set(Uint8Array.of(0, 0, 0, 1), 45);
  leaf.set(r(64), 49);
  leaf.set(Uint8Array.of(0, 0, 1, 0x90, 0, 0, 0, 0), 113);
  leaf.set(r(32), 121);
  return { bytes: leaf, ownerSig: r(64) };
}
