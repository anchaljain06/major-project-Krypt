import { bytesToBase64, base64ToBytes, sha256Bytes } from "./utils";

/**
 * Project Krypt - Symmetric Encryption Engine
 *
 * NIST SP 800-38D AES-256-GCM (Authenticated Encryption with Associated Data)
 * via the browser's native Web Cryptography API.
 * - 256-bit symmetric encryption key derived from ML-KEM-1024 / symmetric hash ratchet
 * - Cryptographically random 96-bit (12-byte) initialization vector (IV/Nonce) per message
 * - 128-bit authentication tag for authenticated integrity protection (AEAD)
 *
 * There is no legacy decryption path. The old C/WASM AES-CBC code (c_source/) is not
 * used for live traffic: any ciphertext without the "GCM:" prefix is rejected.
 */

/**
 * Raised when a ciphertext is not in the only accepted format ("GCM:<base64>").
 */
export class CiphertextFormatError extends Error {
  constructor(message = 'Unsupported ciphertext format: expected "GCM:" prefix.') {
    super(message);
    this.name = "CiphertextFormatError";
  }
}

/**
 * Normalizes an arbitrary key string into a strict 32-byte (256-bit) AES key.
 */
async function get256BitKey(dynamicAesKey: string): Promise<Uint8Array> {
  const rawBytes = base64ToBytes(dynamicAesKey);
  if (rawBytes.length === 32) {
    return rawBytes;
  }
  // Hash with NIST FIPS 180-4 SHA-256 to ensure exact 256-bit entropy
  return await sha256Bytes(rawBytes);
}

/**
 * Encrypts a message or binary media string using NIST SP 800-38D AES-256-GCM.
 * Generates a fresh cryptographically random 12-byte IV for every message.
 * Produces an AEAD-authenticated ciphertext bundled with its authentication tag.
 *
 * @param message The plaintext text or Base64 data URL (images/audio)
 * @param dynamicAesKey The 256-bit session key (Base64)
 * @returns Prefixed Base64 string "GCM:<base64(iv + ciphertext + tag)>"
 */
export async function encryptAES(
  message: string,
  dynamicAesKey: string,
): Promise<string> {
  const keyBytes = await get256BitKey(dynamicAesKey);

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  // NIST SP 800-38D mandates a unique 96-bit (12-byte) nonce for every invocation
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);

  const ciphertextAndTag = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    encoded,
  );

  const combined = new Uint8Array(iv.length + ciphertextAndTag.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertextAndTag), iv.length);

  return "GCM:" + bytesToBase64(combined);
}

/**
 * Decrypts a ciphertext message using NIST SP 800-38D AES-256-GCM.
 * Verifies the 128-bit authentication tag before releasing decrypted plaintext.
 * Fails closed: anything that is not a well-formed "GCM:" payload throws.
 *
 * @param base64Ciphertext The encrypted string
 * @param decryptedAesKey The 256-bit session key (Base64)
 * @returns The original plaintext or media string
 * @throws CiphertextFormatError if the payload is not a well-formed "GCM:" payload
 */
export async function decryptAES(
  base64Ciphertext: string,
  decryptedAesKey: string,
): Promise<string> {
  if (typeof base64Ciphertext !== "string") {
    throw new CiphertextFormatError("Ciphertext must be a string.");
  }
  const trimmed = base64Ciphertext.trim();

  if (!trimmed.startsWith("GCM:")) {
    throw new CiphertextFormatError();
  }

  let combined: Uint8Array;
  try {
    combined = base64ToBytes(trimmed.substring(4));
  } catch {
    throw new CiphertextFormatError("Invalid AES-GCM ciphertext: not valid Base64.");
  }
  if (combined.length < 12 + 16) {
    throw new CiphertextFormatError(
      "Invalid AES-GCM ciphertext payload: length too short.",
    );
  }

  const iv = combined.subarray(0, 12);
  const ciphertext = combined.subarray(12);

  const keyBytes = await get256BitKey(decryptedAesKey);
  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource },
    cryptoKey,
    ciphertext as unknown as BufferSource,
  );

  return new TextDecoder().decode(decryptedBuffer);
}
