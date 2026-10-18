/**
 * Large-file transfer: manifest, chunk AAD and nonces (spec section 15).
 *
 * The sender makes one random 128-bit transferId, one fresh 256-bit file key
 * and one random 4-byte nonce prefix per file, and sends them in the manifest
 * INSIDE a normal Krypt v1 message (contentType "file"), so the ratchet
 * protects them. Chunks travel outside the ratchet as binary socket frames,
 * each sealed with AES-256-GCM under the file key:
 *
 *   nonce = noncePrefix ‖ uint64_be(nonceCounter)
 *   AAD   = lp("KRYPT-FILE-CHUNK-V1", transferId, sender, recipient,
 *            u32(chunkIndex), u32(chunkCount), u64(fileSize), u32(chunkSize),
 *            u32(chunkPlaintextLength), u64(nonceCounter))
 *
 * nonceCounter is a per-file encryption-attempt counter, not the chunk index:
 * it is reserved (and persisted) before every new encryption, so a crash can
 * only burn a counter, never reuse one.
 */
import { fromBase64url, lp, toBase64url, u32, utf8 } from "./encoding";

export const FILE_PROTOCOL = "KRYPT-FILE-V1";
const CHUNK_AAD_LABEL = "KRYPT-FILE-CHUNK-V1";

/** Plaintext bytes per chunk (plan 5.2). Not a cryptographic constant. */
export const FILE_CHUNK_SIZE = 1024 * 1024;
/** Accepted chunk sizes, so benchmarks can try 256 KiB and 4 MiB. */
export const MIN_CHUNK_SIZE = 64 * 1024;
export const MAX_CHUNK_SIZE = 4 * 1024 * 1024;
/** Largest file this release sends or accepts (tested up to this size class; see spec 15.6). */
export const MAX_FILE_BYTES = 256 * 1024 * 1024;
export const MAX_CHUNK_COUNT = 4096;
/** Upper bound on nonce counters (the relay checks the same bound). */
export const MAX_NONCE_COUNTER = 0xffffffff;
export const GCM_TAG_BYTES = 16;
export const MAX_FILE_NAME_CHARS = 255;
const MAX_MIME_CHARS = 100;

export interface FileManifestV1 {
  v: 1;
  type: "file-offer";
  /** 16 random bytes, base64url. */
  transferId: string;
  name: string;
  /** Untrusted, display only. */
  mime: string;
  size: number;
  chunkSize: number;
  /** max(1, ceil(size / chunkSize)): a zero-byte file is one empty chunk. */
  chunkCount: number;
  /** 32-byte AES-256-GCM key, base64url. Only ever inside an encrypted message or the sealed store. */
  fileKey: string;
  /** 4 bytes, base64url. */
  noncePrefix: string;
  protocol: typeof FILE_PROTOCOL;
}

export class FileManifestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FileManifestError";
  }
}

export function chunkCountFor(size: number, chunkSize: number): number {
  return Math.max(1, Math.ceil(size / chunkSize));
}

/** Plaintext length of chunk `index` (the last one is shorter; a zero-byte file has one empty chunk). */
export function chunkLength(m: Pick<FileManifestV1, "size" | "chunkSize" | "chunkCount">, index: number): number {
  if (!Number.isSafeInteger(index) || index < 0 || index >= m.chunkCount) throw new FileManifestError("chunk index out of range");
  return index < m.chunkCount - 1 ? m.chunkSize : m.size - m.chunkSize * (m.chunkCount - 1);
}

/** New manifest with a fresh transferId, file key and nonce prefix. */
export function createManifest(name: string, mime: string, size: number, chunkSize = FILE_CHUNK_SIZE): FileManifestV1 {
  const random = (n: number) => toBase64url(crypto.getRandomValues(new Uint8Array(n)));
  return parseManifest({
    v: 1,
    type: "file-offer",
    transferId: random(16),
    name,
    mime: mime || "application/octet-stream",
    size,
    chunkSize,
    chunkCount: chunkCountFor(size, chunkSize),
    fileKey: random(32),
    noncePrefix: random(4),
    protocol: FILE_PROTOCOL,
  });
}

function bytesOf(s: unknown, len: number): boolean {
  if (typeof s !== "string") return false;
  try {
    return fromBase64url(s).length === len;
  } catch {
    return false;
  }
}

export function isTransferId(s: unknown): s is string {
  return bytesOf(s, 16);
}

/** Strict check of a manifest (from a decrypted message, or our own). Returns a clean copy. */
export function parseManifest(x: unknown): FileManifestV1 {
  const o = x as Partial<FileManifestV1> | null;
  const fail = (why: string): never => {
    throw new FileManifestError(`file offer is malformed: ${why}`);
  };
  if (!o || typeof o !== "object") fail("not an object");
  const m = o as Partial<FileManifestV1>;
  if (m.v !== 1 || m.type !== "file-offer" || m.protocol !== FILE_PROTOCOL) fail("wrong version");
  if (!isTransferId(m.transferId)) fail("transferId");
  if (typeof m.name !== "string" || m.name.length === 0 || m.name.length > MAX_FILE_NAME_CHARS) fail("name");
  if (typeof m.mime !== "string" || m.mime.length > MAX_MIME_CHARS) fail("mime");
  const ints = [m.size, m.chunkSize, m.chunkCount];
  if (!ints.every((n) => typeof n === "number" && Number.isSafeInteger(n) && n >= 0)) fail("sizes");
  const size = m.size!;
  const chunkSize = m.chunkSize!;
  if (size > MAX_FILE_BYTES) fail("file too large");
  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) fail("chunk size");
  if (m.chunkCount !== chunkCountFor(size, chunkSize) || m.chunkCount! > MAX_CHUNK_COUNT) fail("chunk count");
  if (!bytesOf(m.fileKey, 32)) fail("file key");
  if (!bytesOf(m.noncePrefix, 4)) fail("nonce prefix");
  return {
    v: 1,
    type: "file-offer",
    transferId: m.transferId!,
    name: m.name!,
    mime: m.mime!,
    size,
    chunkSize,
    chunkCount: m.chunkCount!,
    fileKey: m.fileKey!,
    noncePrefix: m.noncePrefix!,
    protocol: FILE_PROTOCOL,
  };
}

/** 8-byte big-endian encoding of a safe non-negative integer. */
export function u64(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError("u64 needs a safe non-negative integer");
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setUint32(0, Math.floor(n / 2 ** 32));
  view.setUint32(4, n >>> 0);
  return out;
}

export function isNonceCounter(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && n <= MAX_NONCE_COUNTER;
}

/** nonce = noncePrefix ‖ uint64_be(nonceCounter): 12 bytes. */
export function chunkNonce(m: Pick<FileManifestV1, "noncePrefix">, nonceCounter: number): Uint8Array {
  if (!isNonceCounter(nonceCounter)) throw new FileManifestError("nonce counter out of range");
  const out = new Uint8Array(12);
  out.set(fromBase64url(m.noncePrefix), 0);
  out.set(u64(nonceCounter), 4);
  return out;
}

/** Canonical AAD for one chunk (plan 5.4). `from`/`to` are the sender's and recipient's usernames. */
export function chunkAad(m: FileManifestV1, from: string, to: string, index: number, nonceCounter: number): Uint8Array {
  return lp(
    CHUNK_AAD_LABEL,
    fromBase64url(m.transferId),
    utf8(from),
    utf8(to),
    u32(index),
    u32(m.chunkCount),
    u64(m.size),
    u32(m.chunkSize),
    u32(chunkLength(m, index)),
    u64(nonceCounter),
  );
}

// ---------------------------------------------------------------------------
// Control messages (plan 6). Each travels as the body of a normal Krypt v1
// message with contentType "file", so it is end-to-end authenticated.

export type FileControl =
  | { op: "offer"; manifest: FileManifestV1 }
  | { op: "accept" | "reject" | "complete" | "cancel"; transferId: string }
  /** `have`: base64url bitmap (bit i in byte i>>3, LSB first) of chunks the receiver has verified and stored. */
  | { op: "ack" | "resume"; transferId: string; have: string };

const SIMPLE_OPS = new Set(["accept", "reject", "complete", "cancel"]);

/** Bitmap length for `chunkCount` chunks. */
export const bitmapBytes = (chunkCount: number) => Math.ceil(chunkCount / 8);

export function parseFileControl(x: unknown): FileControl {
  const fail = (): never => {
    throw new FileManifestError("file control message is malformed");
  };
  const c = x as Record<string, unknown> | null;
  if (!c || typeof c !== "object" || typeof c.op !== "string") return fail();
  if (c.op === "offer") return { op: "offer", manifest: parseManifest(c.manifest) };
  if (!isTransferId(c.transferId)) return fail();
  const transferId = c.transferId as string;
  if (SIMPLE_OPS.has(c.op)) return { op: c.op as "accept", transferId };
  if (c.op === "ack" || c.op === "resume") {
    let have: Uint8Array | null = null;
    try {
      have = typeof c.have === "string" ? fromBase64url(c.have) : null;
    } catch {
      have = null;
    }
    if (!have || have.length === 0 || have.length > bitmapBytes(MAX_CHUNK_COUNT)) return fail();
    return { op: c.op, transferId, have: c.have as string };
  }
  return fail();
}

/**
 * Filename that is safe to hand to a download: no path separators, no control
 * or bidi-override characters, no leading dots, not empty.
 */
export function safeFileName(name: string): string {
  const unsafe = (c: number) =>
    c < 0x20 || (c >= 0x7f && c <= 0x9f) || c === 0x200e || c === 0x200f || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
  const cleaned = Array.from(name)
    .filter((ch) => !unsafe(ch.codePointAt(0)!))
    .join("")
    .replace(/[/\\:*?"<>|]/g, "_")
    .replace(/^[.\s]+/, "")
    .trim()
    .slice(0, MAX_FILE_NAME_CHARS);
  return cleaned || "download";
}
