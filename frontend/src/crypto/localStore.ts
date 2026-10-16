import type { UserIdentityKeys } from "./mlkem";
import { bytesToBase64, base64ToBytes, sha256Bytes } from "./utils";

/**
 * Project Krypt - Local Device Storage Cryptographic Engine
 *
 * Implements:
 * - NIST SP 800-56C Rev. 2: Key Derivation using HKDF-SHA-256
 * - NIST SP 800-38D: AES-256-GCM Authenticated Encryption for local IndexedDB cache
 *
 * Encrypts messages and contacts before persisting to IndexedDB on the client device.
 * Derives local storage keys from the user's ML-KEM-1024 secret key with fallback
 * to legacy SHA-256 derivation for existing messages.
 */

let cachedLocalKey: CryptoKey | null = null;
let lastSourceKey: UserIdentityKeys | null = null;

const LOCAL_STORE_SALT = new TextEncoder().encode("KRYPT_LOCAL_STORE_SALT_V1");
const LOCAL_STORE_INFO = new TextEncoder().encode("KRYPT_LOCAL_STORAGE_ENCRYPTION_KEY_V1");

export async function getLocalKey(privateKey: UserIdentityKeys): Promise<CryptoKey> {
  if (cachedLocalKey && lastSourceKey === privateKey) {
    return cachedLocalKey;
  }

  // Derive local AES-256-GCM key using NIST SP 800-56C HKDF from KEM secret key
  const ikm = await window.crypto.subtle.importKey(
    "raw",
    privateKey.kemSecretKey as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveKey"],
  );

  cachedLocalKey = await window.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: LOCAL_STORE_SALT,
      info: LOCAL_STORE_INFO,
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  lastSourceKey = privateKey;

  return cachedLocalKey;
}

/**
 * Legacy key derivation helper for pre-upgrade IndexedDB entries.
 */
async function getLegacyLocalKey(privateKey: UserIdentityKeys): Promise<CryptoKey> {
  const hash = await sha256Bytes(privateKey.kemSecretKey);
  return await window.crypto.subtle.importKey(
    "raw",
    hash as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
}

export async function encryptLocal(
  plaintext: string,
  privateKey: UserIdentityKeys,
): Promise<string> {
  const key = await getLocalKey(privateKey);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded,
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return "LOC:" + bytesToBase64(combined);
}

/**
 * Raised when a local IndexedDB entry is not a valid "LOC:" ciphertext or fails
 * authentication. Callers must treat the entry as unreadable, never as plaintext.
 */
export class LocalStoreDecryptError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LocalStoreDecryptError";
  }
}

/**
 * Decrypts a "LOC:" entry. Fails closed: unprefixed (plaintext) input, malformed
 * payloads and authentication failures all throw LocalStoreDecryptError.
 */
export async function decryptLocal(
  ciphertextBase64: string,
  privateKey: UserIdentityKeys,
): Promise<string> {
  if (typeof ciphertextBase64 !== "string" || !ciphertextBase64.startsWith("LOC:")) {
    throw new LocalStoreDecryptError("Local entry is not encrypted; refusing to read it.");
  }

  let combined: Uint8Array;
  try {
    combined = base64ToBytes(ciphertextBase64.substring(4));
  } catch {
    throw new LocalStoreDecryptError("Local entry is corrupted (invalid Base64).");
  }

  if (combined.length < 12 + 16) {
    throw new LocalStoreDecryptError("Local entry is corrupted (too short).");
  }

  const iv = combined.subarray(0, 12);
  const ciphertext = combined.subarray(12);

  // 1. Attempt decryption with modern HKDF-derived key
  try {
    const key = await getLocalKey(privateKey);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      key,
      ciphertext as unknown as BufferSource,
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    // 2. Fallback: attempt decryption with legacy SHA-256 derived key
    try {
      const legacyKey = await getLegacyLocalKey(privateKey);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as unknown as BufferSource },
        legacyKey,
        ciphertext as unknown as BufferSource,
      );
      return new TextDecoder().decode(decrypted);
    } catch {
      throw new LocalStoreDecryptError(
        "Failed to decrypt local entry with current or legacy key.",
      );
    }
  }
}
