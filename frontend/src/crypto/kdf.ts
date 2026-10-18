/**
 * Krypt v1 key derivation (spec sections 4.1, 5.2, 5.3).
 *
 * All primitives come from Web Crypto (`globalThis.crypto.subtle`), which works
 * in browsers and in Node, so the same code runs in the app and in tests.
 */
import { sha256 } from "@krypt/shared";
import { LABELS, lp, u32, utf8 } from "./encoding";

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("Web Crypto (crypto.subtle) is not available");
  return s;
};

/**
 * Web Crypto's types want ArrayBuffer-backed views. Our arrays always are, so
 * this is a type-level cast, not a copy.
 */
export function bs(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return u as Uint8Array<ArrayBuffer>;
}

const ZERO32 = new Uint8Array(32);
const BYTE_01 = new Uint8Array([0x01]);
const BYTE_02 = new Uint8Array([0x02]);

/** HMAC-SHA-256(key, data). */
export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle().importKey("raw", bs(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, bs(data)));
}

/**
 * HKDF-SHA-256 (RFC 5869), extract-then-expand, returning `length` bytes.
 * An empty salt is equivalent to 32 zero bytes (RFC 5869 section 2.2).
 */
export async function hkdf(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  if (!Number.isInteger(length) || length <= 0 || length > 255 * 32) {
    throw new RangeError("hkdf: invalid output length");
  }
  const k = await subtle().importKey("raw", bs(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: bs(salt), info: bs(info) },
    k,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Root-step context: ctx(e, ek, ct) = lp(u32(e), H(ek), H(ct)). */
export async function rootContext(epoch: number, ek: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
  return lp(u32(epoch), await sha256(ek), await sha256(ct));
}

/**
 * KDF_RK(RK, ss, ctx) = HKDF(salt = RK, ikm = ss, info = lp("Krypt-RK", ctx), 64)
 * -> new root key (first 32 bytes) and a fresh chain key (last 32 bytes).
 */
export async function kdfRoot(
  rk: Uint8Array,
  ss: Uint8Array,
  ctx: Uint8Array,
): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
  if (rk.length !== 32 || ss.length !== 32) throw new RangeError("kdfRoot: rk and ss must be 32 bytes");
  const okm = await hkdf(rk, ss, lp(LABELS.root, ctx), 64);
  return { rk: okm.slice(0, 32), ck: okm.slice(32, 64) };
}

/** Chain step: mk = HMAC(CK, 0x01), CK' = HMAC(CK, 0x02). */
export async function kdfChain(ck: Uint8Array): Promise<{ mk: Uint8Array; ck: Uint8Array }> {
  if (ck.length !== 32) throw new RangeError("kdfChain: chain key must be 32 bytes");
  const [mk, next] = await Promise.all([hmacSha256(ck, BYTE_01), hmacSha256(ck, BYTE_02)]);
  return { mk, ck: next };
}

/**
 * key ‖ iv = HKDF(0^32, mk, "Krypt-MK", 44). Deriving the IV is safe because
 * every message has its own key; uniqueness then rests on never rolling the
 * chain back (spec section 7).
 */
export async function messageKeyAndIv(mk: Uint8Array): Promise<{ key: Uint8Array; iv: Uint8Array }> {
  if (mk.length !== 32) throw new RangeError("messageKeyAndIv: mk must be 32 bytes");
  const okm = await hkdf(ZERO32, mk, utf8(LABELS.messageKey), 44);
  return { key: okm.slice(0, 32), iv: okm.slice(32, 44) };
}

/**
 * Handshake key schedule: RK0 ‖ CK0 = HKDF(0^32, lp(ss1, ss2), lp("Krypt-X3K", H(T)), 64).
 * `ss2` is empty when no one-time prekey was used.
 */
export async function kdfHandshake(
  ss1: Uint8Array,
  ss2: Uint8Array,
  transcriptHash: Uint8Array,
): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
  const okm = await hkdf(ZERO32, lp(ss1, ss2), lp(LABELS.x3k, transcriptHash), 64);
  return { rk: okm.slice(0, 32), ck: okm.slice(32, 64) };
}

// ---------------------------------------------------------------------------
// AES-256-GCM with explicit key, IV and AAD (128-bit tag appended to the ciphertext).

async function aesKey(key: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  if (key.length !== 32) throw new RangeError("AES-256 key must be 32 bytes");
  return subtle().importKey("raw", bs(key), { name: "AES-GCM" }, false, [usage]);
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (iv.length !== 12) throw new RangeError("AES-GCM IV must be 12 bytes");
  const k = await aesKey(key, "encrypt");
  return new Uint8Array(
    await subtle().encrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(aad), tagLength: 128 }, k, bs(plaintext)),
  );
}

/** Throws (Web Crypto OperationError) if the tag does not verify. */
export async function aesGcmDecrypt(
  key: Uint8Array,
  iv: Uint8Array,
  body: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (iv.length !== 12) throw new RangeError("AES-GCM IV must be 12 bytes");
  if (body.length < 16) throw new RangeError("AES-GCM body shorter than the tag");
  const k = await aesKey(key, "decrypt");
  return new Uint8Array(
    await subtle().decrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(aad), tagLength: 128 }, k, bs(body)),
  );
}

