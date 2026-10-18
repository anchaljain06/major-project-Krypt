/**
 * Krypt v1 canonical encoding (spec section 1).
 *
 * Everything that is hashed, signed, fed to a KDF or used as AAD is built with
 * `lp(...)`: each field is prefixed by its 4-byte big-endian length. That makes
 * the encoding injective, so two different field lists can never collide and a
 * key of one type can never be reinterpreted as another.
 *
 * Base64url is only for the network edge, and its decoder is strict so every
 * byte string has exactly one accepted text form (a bit flip in the text can
 * never decode to the same bytes).
 *
 * The plain byte helpers (UTF-8, u32, concatenation, standard base64, hex,
 * SHA-256) come from @krypt/shared, so the whole repo has one copy of each.
 */
import { concatBytes, fromUtf8, readU32be, u32be, utf8 } from "@krypt/shared";

export { fromUtf8, utf8 };

/** u32(x) in the spec: 4-byte big-endian encoding of an integer in [0, 2^32). */
export const u32 = u32be;

/** Domain-separation labels. Never reuse a label for a second purpose. */
export const LABELS = {
  transcript: "Krypt-v1",
  x3k: "Krypt-X3K",
  init: "Krypt-init",
  spk: "Krypt-SPK",
  opk: "Krypt-OPK",
  root: "Krypt-RK",
  messageKey: "Krypt-MK",
  aad: "Krypt-AAD-v1",
  sessionAtRest: "krypt-session-v1",
  prekeysAtRest: "krypt-prekeys-v1",
} as const;

export const EMPTY = new Uint8Array(0);

/** A field is either raw bytes or a string (encoded as UTF-8). */
export type Field = Uint8Array | string;

/** lp(x1, ..., xk) = u32be(len(x1)) ‖ x1 ‖ ... (spec section 1). */
export function lp(...fields: Field[]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    const bytes = typeof f === "string" ? utf8(f) : f;
    parts.push(u32(bytes.length), bytes);
  }
  return concatBytes(...parts);
}

/**
 * Inverse of lp(): split bytes into exactly `count` fields (or any number when
 * count is undefined). Throws if the input is truncated or has trailing bytes.
 */
export function unlp(bytes: Uint8Array, count?: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  let off = 0;
  while (off < bytes.length) {
    if (off + 4 > bytes.length) throw new Error("lp: truncated length");
    const len = readU32be(bytes, off);
    off += 4;
    if (len > bytes.length - off) throw new Error("lp: truncated field");
    out.push(bytes.subarray(off, off + len));
    off += len;
  }
  if (count !== undefined && out.length !== count) {
    throw new Error(`lp: expected ${count} fields, got ${out.length}`);
  }
  return out;
}

/** Read a field produced by u32(). */
export function readU32(b: Uint8Array): number {
  if (b.length !== 4) throw new Error("u32 field must be 4 bytes");
  return readU32be(b, 0);
}

// ---------------------------------------------------------------------------
// Base64url (RFC 4648 section 5), no padding, strict.

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_REV = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

export function toBase64url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[v >> 18] + B64URL[(v >> 12) & 63] + B64URL[(v >> 6) & 63] + B64URL[v & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const v = bytes[i] << 16;
    out += B64URL[v >> 18] + B64URL[(v >> 12) & 63];
  } else if (rest === 2) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL[v >> 18] + B64URL[(v >> 12) & 63] + B64URL[(v >> 6) & 63];
  }
  return out;
}

/**
 * Strict base64url decoder. Rejects: characters outside the alphabet (including
 * '=' padding and whitespace), a length of 1 mod 4, and non-zero unused bits in
 * the last character. Together these make the encoding canonical.
 */
export function fromBase64url(s: string): Uint8Array {
  if (typeof s !== "string") throw new TypeError("base64url: not a string");
  if (s.length % 4 === 1) throw new Error("base64url: invalid length");
  const vals = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64URL_REV[c] : -1;
    if (v < 0) throw new Error("base64url: invalid character");
    vals[i] = v;
  }
  const full = Math.floor(s.length / 4);
  const rest = s.length % 4; // 0, 2 or 3
  const out = new Uint8Array(full * 3 + (rest === 0 ? 0 : rest - 1));
  let o = 0;
  for (let i = 0; i < full * 4; i += 4) {
    const v = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3];
    out[o++] = v >> 16;
    out[o++] = (v >> 8) & 255;
    out[o++] = v & 255;
  }
  const i = full * 4;
  if (rest === 2) {
    if (vals[i + 1] & 0x0f) throw new Error("base64url: non-canonical trailing bits");
    out[o++] = (vals[i] << 2) | (vals[i + 1] >> 4);
  } else if (rest === 3) {
    if (vals[i + 2] & 0x03) throw new Error("base64url: non-canonical trailing bits");
    out[o++] = (vals[i] << 2) | (vals[i + 1] >> 4);
    out[o++] = ((vals[i + 1] & 0x0f) << 4) | (vals[i + 2] >> 2);
  }
  return out;
}

// ---------------------------------------------------------------------------

/**
 * Constant-time equality for equal-length inputs. The length itself is not
 * secret anywhere we use this (hashes, tags, ids), so an early return on a
 * length mismatch leaks nothing useful.
 */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Lexicographic (bytewise, unsigned) comparison: -1, 0 or 1. Not constant time; use on public data only. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** Best-effort erase. JavaScript cannot guarantee no copies remain (spec section 9). */
export function wipe(...arrays: (Uint8Array | null | undefined)[]): void {
  for (const a of arrays) a?.fill(0);
}
