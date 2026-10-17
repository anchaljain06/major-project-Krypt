/**
 * Attachments (plan 1.10).
 *
 * Each image or audio file gets a fresh random 32-byte key and is encrypted
 * once with AES-256-GCM (random 96-bit IV, AAD = lp("krypt-attachment-v1",
 * mime)). The key, IV, mime type, size and SHA-256 of the ciphertext travel
 * INSIDE the v1 message plaintext, so they are protected by the ratchet; the
 * ciphertext travels next to the envelope in the same socket frame.
 *
 * Size budget: the relay caps one socket frame at 16 MiB
 * (primary-backend MAX_SOCKET_MESSAGE_BYTES). The attachment is sent as
 * base64url, which expands by 4/3, and the envelope (init header up to ~12 KB
 * encoded, ratchet KEM fields, the small JSON plaintext) gets a 64 KiB
 * reserve:
 *
 *   MAX_ATTACHMENT_BYTES = floor((16 MiB - 64 KiB) * 3/4) - 16 (GCM tag)
 *                        = 12,533,744 bytes (about 11.95 MiB)
 *
 * The raw file is base64-encoded only once (v0 base64'd a data URL and then
 * base64'd its ciphertext again, which is where the old ~8.5 MB limit came
 * from). The sender also checks the final frame length before emitting.
 */
import { lp, toBase64url, fromBase64url, ctEqual } from "./encoding";
import { bs, sha256 } from "./kdf";

export const MAX_SOCKET_MESSAGE_BYTES = 16 * 1024 * 1024;
export const ENVELOPE_RESERVE_BYTES = 64 * 1024;
const GCM_TAG_BYTES = 16;
export const MAX_ATTACHMENT_BYTES =
  Math.floor(((MAX_SOCKET_MESSAGE_BYTES - ENVELOPE_RESERVE_BYTES) * 3) / 4) - GCM_TAG_BYTES;

export interface AttachmentMeta {
  /** base64url, 32 bytes. */
  key: string;
  /** base64url, 12 bytes. */
  iv: string;
  /** base64url SHA-256 of the attachment ciphertext. */
  sha256: string;
  mime: string;
  /** Plaintext length in bytes. */
  size: number;
}

export class AttachmentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttachmentError";
  }
}

const aad = (mime: string) => lp("krypt-attachment-v1", mime);

export function formatBytes(n: number): string {
  return n >= 1024 * 1024 ? `${(n / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(n / 1024)} KB`;
}

/** Throws AttachmentError if `size` bytes cannot fit in one relay frame. */
export function assertAttachmentFits(size: number, what = "File") {
  if (size > MAX_ATTACHMENT_BYTES) {
    throw new AttachmentError(
      `${what} is too large to send: ${formatBytes(size)} (limit ${formatBytes(MAX_ATTACHMENT_BYTES)}, set by the relay's 16 MB message cap).`,
    );
  }
}

export async function encryptAttachment(
  data: Uint8Array,
  mime: string,
): Promise<{ meta: AttachmentMeta; ciphertext: Uint8Array }> {
  assertAttachmentFits(data.length);
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", bs(rawKey), "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: bs(iv), additionalData: bs(aad(mime)) }, key, bs(data)),
  );
  const meta: AttachmentMeta = {
    key: toBase64url(rawKey),
    iv: toBase64url(iv),
    sha256: toBase64url(await sha256(ciphertext)),
    mime,
    size: data.length,
  };
  rawKey.fill(0);
  return { meta, ciphertext };
}

/** Strict shape check of metadata decrypted from a message. */
export function parseAttachmentMeta(x: unknown): AttachmentMeta {
  const m = x as Partial<AttachmentMeta> | null;
  if (
    !m ||
    typeof m !== "object" ||
    typeof m.key !== "string" ||
    typeof m.iv !== "string" ||
    typeof m.sha256 !== "string" ||
    typeof m.mime !== "string" ||
    m.mime.length === 0 ||
    m.mime.length > 100 ||
    typeof m.size !== "number" ||
    !Number.isSafeInteger(m.size) ||
    m.size < 0 ||
    m.size > MAX_ATTACHMENT_BYTES
  ) {
    throw new AttachmentError("attachment metadata is malformed");
  }
  try {
    if (fromBase64url(m.key).length !== 32 || fromBase64url(m.iv).length !== 12 || fromBase64url(m.sha256).length !== 32) {
      throw new Error();
    }
  } catch {
    throw new AttachmentError("attachment metadata is malformed");
  }
  return { key: m.key, iv: m.iv, sha256: m.sha256, mime: m.mime, size: m.size };
}

export async function decryptAttachment(ciphertext: Uint8Array, meta: AttachmentMeta): Promise<Uint8Array> {
  if (!ctEqual(await sha256(ciphertext), fromBase64url(meta.sha256))) {
    throw new AttachmentError("attachment does not match the hash in the message");
  }
  const key = await crypto.subtle.importKey("raw", bs(fromBase64url(meta.key)), "AES-GCM", false, ["decrypt"]);
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bs(fromBase64url(meta.iv)), additionalData: bs(aad(meta.mime)) },
        key,
        bs(ciphertext),
      ),
    );
  } catch {
    throw new AttachmentError("attachment failed authentication");
  }
  if (plain.length !== meta.size) throw new AttachmentError("attachment size does not match the message");
  return plain;
}
