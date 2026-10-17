// GENERATED from shared/src by primary-backend/scripts/vendor-shared.mjs. Do not edit;
// change shared/ and run `npm run vendor:shared`.
// Signed tree heads and witness cosignatures.
//
// Tree head (strategy §5.2), fixed width, 60 bytes:
//
//   "KRYPT-STH-v1" (12 bytes, no NUL) || u64 tree_size || root_hash (32) || u64 timestamp_ms
//
// The log signs these 60 bytes. Krypt signs with ML-DSA-87 (FIPS 204, empty
// context string); this package never calls a signature scheme itself, it
// takes sign/verify callbacks, so it stays dependency-free and the scheme can
// change without touching the formats.
//
// Cosignature, after C2SP tlog-cosignature: a witness signs a statement that
// it saw this tree head, verified it is consistent with every head it saw
// before, at a given time:
//
//   "KRYPT-COSIG-v1\0" || u8 len(name) || name (UTF-8)
//   || u64 cosign_timestamp_ms || log_id (32) || tree head (60 bytes as above)
//
// log_id = SHA-256(log's STH public key). It binds the cosignature to one log,
// so a witness serving several logs cannot have a cosignature for log A
// replayed as one for log B. Like C2SP, the witness signs the tree head
// contents, not the log's signature bytes. Krypt witnesses use ML-DSA-44, as
// C2SP recommends for new deployments (see witness/README.md).

import {
  bytesEqual,
  concatBytes,
  fromBase64,
  readU64be,
  sha256,
  toBase64,
  u64be,
  u8,
  utf8,
} from "./bytes.js";
import { HASH_SIZE, type Hash } from "./merkle.js";

export const STH_TAG = utf8("KRYPT-STH-v1");
export const TREE_HEAD_SIZE = 12 + 8 + 32 + 8;
export const COSIG_TAG = utf8("KRYPT-COSIG-v1\0");

export interface TreeHead {
  treeSize: number;
  rootHash: Hash;
  timestampMs: number;
}

export interface SignedTreeHead extends TreeHead {
  /** Log signature over encodeTreeHead(). */
  signature: Uint8Array;
}

export interface Cosignature {
  /** Witness name, 1..255 bytes of UTF-8, no newlines. */
  witness: string;
  /** When the witness cosigned, Unix ms. Lets clients judge freshness. */
  timestampMs: number;
  signature: Uint8Array;
}

/** Signs a message. Krypt: ML-DSA-87 for the log, ML-DSA-44 for witnesses. */
export type SignFn = (msg: Uint8Array) => Uint8Array | Promise<Uint8Array>;
/** Verifies a signature over msg under a key the callback already holds. */
export type VerifyFn = (msg: Uint8Array, sig: Uint8Array) => boolean | Promise<boolean>;

export function encodeTreeHead(th: TreeHead): Uint8Array {
  if (!(th.rootHash instanceof Uint8Array) || th.rootHash.length !== HASH_SIZE) {
    throw new TypeError("rootHash must be 32 bytes");
  }
  return concatBytes(STH_TAG, u64be(th.treeSize), th.rootHash, u64be(th.timestampMs));
}

export function decodeTreeHead(b: Uint8Array): TreeHead {
  if (b.length !== TREE_HEAD_SIZE) throw new RangeError(`tree head must be ${TREE_HEAD_SIZE} bytes`);
  if (!bytesEqual(b.subarray(0, 12), STH_TAG)) throw new Error("not a KRYPT-STH-v1 tree head");
  return {
    treeSize: readU64be(b, 12),
    rootHash: b.slice(20, 52),
    timestampMs: readU64be(b, 52),
  };
}

export async function signTreeHead(th: TreeHead, sign: SignFn): Promise<SignedTreeHead> {
  const signature = await sign(encodeTreeHead(th));
  return { treeSize: th.treeSize, rootHash: th.rootHash, timestampMs: th.timestampMs, signature };
}

/** False (never throws) on a malformed head or a bad signature. */
export async function verifyTreeHead(sth: SignedTreeHead, verify: VerifyFn): Promise<boolean> {
  let msg: Uint8Array;
  try {
    msg = encodeTreeHead(sth);
  } catch {
    return false;
  }
  try {
    return (await verify(msg, sth.signature)) === true;
  } catch {
    return false;
  }
}

/** log_id = SHA-256(log public key). */
export function logIdFromPublicKey(logPublicKey: Uint8Array): Promise<Hash> {
  return sha256(logPublicKey);
}

function witnessNameBytes(name: string): Uint8Array {
  const b = utf8(name);
  if (b.length < 1 || b.length > 255 || /[\n\r]/.test(name)) {
    throw new RangeError("witness name must be 1..255 UTF-8 bytes without newlines");
  }
  return b;
}

/** The exact bytes a witness signs. */
export function cosignatureMessage(witness: string, timestampMs: number, logId: Hash, th: TreeHead): Uint8Array {
  if (!(logId instanceof Uint8Array) || logId.length !== HASH_SIZE) throw new TypeError("logId must be 32 bytes");
  const name = witnessNameBytes(witness);
  return concatBytes(COSIG_TAG, u8(name.length), name, u64be(timestampMs), logId, encodeTreeHead(th));
}

export async function cosignTreeHead(
  th: TreeHead,
  logId: Hash,
  witness: string,
  timestampMs: number,
  sign: SignFn,
): Promise<Cosignature> {
  const signature = await sign(cosignatureMessage(witness, timestampMs, logId, th));
  return { witness, timestampMs, signature };
}

/** False (never throws) on a malformed input or a bad signature. */
export async function verifyCosignature(
  th: TreeHead,
  logId: Hash,
  cosig: Cosignature,
  verify: VerifyFn,
): Promise<boolean> {
  try {
    const msg = cosignatureMessage(cosig.witness, cosig.timestampMs, logId, th);
    return (await verify(msg, cosig.signature)) === true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// JSON wire formats (base64 for bytes, numbers for integers).

export interface SignedTreeHeadJson {
  treeSize: number;
  rootHash: string;
  timestamp: number;
  signature: string;
}

export interface CosignatureJson {
  witness: string;
  timestamp: number;
  signature: string;
}

export function sthToJson(sth: SignedTreeHead): SignedTreeHeadJson {
  return {
    treeSize: sth.treeSize,
    rootHash: toBase64(sth.rootHash),
    timestamp: sth.timestampMs,
    signature: toBase64(sth.signature),
  };
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function uintField(o: Record<string, unknown>, k: string): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new TypeError(`${k} must be a non-negative integer`);
  return v;
}

function b64Field(o: Record<string, unknown>, k: string): Uint8Array {
  const v = o[k];
  if (typeof v !== "string") throw new TypeError(`${k} must be a base64 string`);
  return fromBase64(v);
}

/** Parses and shape-checks untrusted JSON. Does not verify the signature. */
export function sthFromJson(v: unknown): SignedTreeHead {
  if (!isObject(v)) throw new TypeError("STH must be an object");
  const rootHash = b64Field(v, "rootHash");
  if (rootHash.length !== HASH_SIZE) throw new TypeError("rootHash must be 32 bytes");
  return {
    treeSize: uintField(v, "treeSize"),
    rootHash,
    timestampMs: uintField(v, "timestamp"),
    signature: b64Field(v, "signature"),
  };
}

export function cosignatureToJson(c: Cosignature): CosignatureJson {
  return { witness: c.witness, timestamp: c.timestampMs, signature: toBase64(c.signature) };
}

export function cosignatureFromJson(v: unknown): Cosignature {
  if (!isObject(v)) throw new TypeError("cosignature must be an object");
  if (typeof v.witness !== "string") throw new TypeError("witness must be a string");
  witnessNameBytes(v.witness);
  return { witness: v.witness, timestampMs: uintField(v, "timestamp"), signature: b64Field(v, "signature") };
}

/** Decodes a list of base64 hashes (proofs, compact ranges) from JSON. */
export function hashesFromJson(v: unknown): Hash[] {
  if (!Array.isArray(v)) throw new TypeError("expected an array of base64 hashes");
  return v.map((s) => {
    if (typeof s !== "string") throw new TypeError("hash must be a base64 string");
    const h = fromBase64(s);
    if (h.length !== HASH_SIZE) throw new TypeError("hash must be 32 bytes");
    return h;
  });
}

export function hashesToJson(hs: readonly Hash[]): string[] {
  return hs.map(toBase64);
}

/** Two heads are the same statement (ignoring signatures). */
export function sameTreeHead(a: TreeHead, b: TreeHead): boolean {
  return a.treeSize === b.treeSize && a.timestampMs === b.timestampMs && bytesEqual(a.rootHash, b.rootHash);
}
