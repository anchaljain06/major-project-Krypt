// Key transparency leaf encoding (strategy §5.2). Fixed width, big-endian, 153 bytes:
//
//   offset size field
//        0   12 "KRYPT-KT-v1\0"                 domain tag
//       12    1 op                              1 register, 2 rotate, 3 revoke
//       13   32 user_hash                       SHA-256("krypt-user\0" || NFC(lower(username)))
//       45    4 key_version                     u32
//       49   32 SHA-256(mldsa_pk)               ML-DSA-87 identity key
//       81   32 SHA-256(mlkem_pk)               ML-KEM identity key
//      113    8 timestamp_ms                    u64, Unix ms, chosen by the owner
//      121   32 SHA-256(owner_sig)
//
// The log's Merkle leaf hash is SHA-256(0x00 || these 153 bytes) (merkle.ts).
//
// What owner_sig signs
// --------------------
// owner_sig = ML-DSA-87.Sign(signer_sk, ownerSignedMessage(leaf)), where
//
//   ownerSignedMessage = "KRYPT-KT-OWNER-v1\0" || op || user_hash || u32 key_version
//                        || SHA-256(mldsa_pk) || SHA-256(mlkem_pk) || u64 timestamp_ms
//
// i.e. every leaf field except the signature hash, under a different domain
// tag so a signed message can never be confused with a leaf or any other
// Krypt signature. The signer depends on op (see ownerSigner):
//
//   register  the NEW ML-DSA key (proof of possession, key_version 1, or
//             previous + 1 when an owner who lost every key re-registers)
//   rotate    the PREVIOUS ML-DSA key, i.e. the key of key_version - 1. This is
//             what stops the server inventing a rotation: it cannot sign with
//             a key it never had.
//   revoke    the key being revoked (key_version and both hashes name it).
//
// The leaf stores only SHA-256(owner_sig) to keep leaves fixed width; the
// server stores the full signature next to the leaf and serves it with
// /kt/leaves and /kt/proof so anyone can check it.
//
// A register after earlier leaves for the same user is a key reset. Clients
// must show it as a safety-number change, because only the new key vouches
// for it.

import {
  bytesEqual,
  concatBytes,
  readU32be,
  readU64be,
  sha256,
  u32be,
  u64be,
  u8,
  utf8,
} from "./bytes.ts";
import { hashLeaf, type Hash } from "./merkle.ts";

export const KT_LEAF_TAG = utf8("KRYPT-KT-v1\0");
export const KT_OWNER_SIG_TAG = utf8("KRYPT-KT-OWNER-v1\0");
export const KT_USER_TAG = utf8("krypt-user\0");
export const KT_LEAF_SIZE = 153;

export const KtOp = { Register: 1, Rotate: 2, Revoke: 3 } as const;
export type KtOp = (typeof KtOp)[keyof typeof KtOp];

export interface KtLeaf {
  op: KtOp;
  /** SHA-256("krypt-user\0" || NFC(lower(username))), 32 bytes. */
  userHash: Uint8Array;
  keyVersion: number;
  /** SHA-256 of the ML-DSA-87 public key. */
  mldsaPkHash: Uint8Array;
  /** SHA-256 of the ML-KEM public key. */
  mlkemPkHash: Uint8Array;
  timestampMs: number;
  /** SHA-256 of the owner signature over ownerSignedMessage(). */
  ownerSigHash: Uint8Array;
}

/** The leaf without its signature hash: exactly the fields the owner signs. */
export type KtLeafBody = Omit<KtLeaf, "ownerSigHash">;

/**
 * Canonical username: lower-case, then Unicode NFC, in the order the strategy
 * fixes. toLowerCase is locale independent, so every client agrees.
 */
export function normalizeUsername(username: string): string {
  return username.toLowerCase().normalize("NFC");
}

export function hashUsername(username: string): Promise<Hash> {
  return sha256(KT_USER_TAG, utf8(normalizeUsername(username)));
}

function isOp(v: number): v is KtOp {
  return v === KtOp.Register || v === KtOp.Rotate || v === KtOp.Revoke;
}

function check32(name: string, b: Uint8Array): void {
  if (!(b instanceof Uint8Array) || b.length !== 32) throw new TypeError(`${name} must be 32 bytes`);
}

function checkBody(leaf: KtLeafBody): void {
  if (!isOp(leaf.op)) throw new RangeError(`unknown op ${leaf.op}`);
  check32("userHash", leaf.userHash);
  check32("mldsaPkHash", leaf.mldsaPkHash);
  check32("mlkemPkHash", leaf.mlkemPkHash);
}

/** Fields shared by the leaf and the owner-signed message, in leaf order. */
function bodyBytes(leaf: KtLeafBody): Uint8Array {
  checkBody(leaf);
  return concatBytes(
    u8(leaf.op),
    leaf.userHash,
    u32be(leaf.keyVersion),
    leaf.mldsaPkHash,
    leaf.mlkemPkHash,
    u64be(leaf.timestampMs),
  );
}

export function encodeLeaf(leaf: KtLeaf): Uint8Array {
  check32("ownerSigHash", leaf.ownerSigHash);
  return concatBytes(KT_LEAF_TAG, bodyBytes(leaf), leaf.ownerSigHash);
}

/** Parses a 153-byte leaf. Throws on any deviation from the format. */
export function decodeLeaf(bytes: Uint8Array): KtLeaf {
  if (bytes.length !== KT_LEAF_SIZE) throw new RangeError(`KT leaf must be ${KT_LEAF_SIZE} bytes, got ${bytes.length}`);
  if (!bytesEqual(bytes.subarray(0, 12), KT_LEAF_TAG)) throw new Error("not a KRYPT-KT-v1 leaf");
  const op = bytes[12]!;
  if (!isOp(op)) throw new RangeError(`unknown op ${op}`);
  return {
    op,
    userHash: bytes.slice(13, 45),
    keyVersion: readU32be(bytes, 45),
    mldsaPkHash: bytes.slice(49, 81),
    mlkemPkHash: bytes.slice(81, 113),
    timestampMs: readU64be(bytes, 113),
    ownerSigHash: bytes.slice(121, 153),
  };
}

/** The bytes the owner signs for this leaf (see the header comment). */
export function ownerSignedMessage(leaf: KtLeafBody): Uint8Array {
  return concatBytes(KT_OWNER_SIG_TAG, bodyBytes(leaf));
}

/** Which key must have produced owner_sig. */
export function ownerSigner(op: KtOp): "new-key" | "previous-key" | "revoked-key" {
  switch (op) {
    case KtOp.Register:
      return "new-key";
    case KtOp.Rotate:
      return "previous-key";
    case KtOp.Revoke:
      return "revoked-key";
  }
}

/** Merkle leaf hash of a KT leaf: SHA-256(0x00 || encodeLeaf(leaf)). */
export function ktLeafHash(leaf: KtLeaf): Promise<Hash> {
  return hashLeaf(encodeLeaf(leaf));
}

export interface BuildLeafInput {
  op: KtOp;
  username: string;
  keyVersion: number;
  /** Full ML-DSA-87 public key of the key this leaf is about. */
  mldsaPk: Uint8Array;
  /** Full ML-KEM public key of the key this leaf is about. */
  mlkemPk: Uint8Array;
  timestampMs: number;
}

/** Hashes the inputs into a leaf body, ready for ownerSignedMessage(). */
export async function buildLeafBody(input: BuildLeafInput): Promise<KtLeafBody> {
  return {
    op: input.op,
    userHash: await hashUsername(input.username),
    keyVersion: input.keyVersion,
    mldsaPkHash: await sha256(input.mldsaPk),
    mlkemPkHash: await sha256(input.mlkemPk),
    timestampMs: input.timestampMs,
  };
}

/** Completes a leaf body with the hash of its owner signature. */
export async function attachOwnerSig(body: KtLeafBody, ownerSig: Uint8Array): Promise<KtLeaf> {
  return { ...body, ownerSigHash: await sha256(ownerSig) };
}

export type VerifySigFn = (msg: Uint8Array, sig: Uint8Array, publicKey: Uint8Array) => boolean | Promise<boolean>;

/**
 * Checks owner_sig against the leaf: its hash must match, and it must verify
 * under `signerPk`, the ML-DSA key named by ownerSigner(leaf.op). For
 * register and revoke that is the leaf's own key, which is checked here. For
 * a rotation the caller passes the previous leaf's key and must check
 * SHA-256(signerPk) against that previous leaf's mldsaPkHash.
 */
export async function verifyOwnerSig(
  leaf: KtLeaf,
  ownerSig: Uint8Array,
  signerPk: Uint8Array,
  verify: VerifySigFn,
): Promise<boolean> {
  if (!bytesEqual(await sha256(ownerSig), leaf.ownerSigHash)) return false;
  if (ownerSigner(leaf.op) !== "previous-key" && !bytesEqual(await sha256(signerPk), leaf.mldsaPkHash)) {
    return false;
  }
  return verify(ownerSignedMessage(leaf), ownerSig, signerPk);
}
