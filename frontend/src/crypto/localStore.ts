import type { UserIdentityKeys } from "./mlkem";
import { concatBytes, fromBase64, toBase64 } from "@krypt/shared";
import { EMPTY, fromUtf8, utf8 } from "./encoding";
import { bs } from "./kdf";
import { open, seal } from "./session-store";

/**
 * Project Krypt - Local Device Storage Cryptographic Engine
 *
 * Implements:
 * - NIST SP 800-56C Rev. 2: Key Derivation using HKDF-SHA-256
 * - NIST SP 800-38D: AES-256-GCM Authenticated Encryption for local IndexedDB cache
 *
 * Encrypts messages and contacts before persisting to IndexedDB on the client device.
 * Derives the local storage key from the user's ML-KEM-1024 secret key (HKDF).
 * Entries written under the older SHA-256-derived key fail closed.
 */

let cachedLocalKey: CryptoKey | null = null;
let lastSourceKey: UserIdentityKeys | null = null;

const LOCAL_STORE_SALT = utf8("KRYPT_LOCAL_STORE_SALT_V1");
const LOCAL_STORE_INFO = utf8("KRYPT_LOCAL_STORAGE_ENCRYPTION_KEY_V1");

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
      salt: bs(LOCAL_STORE_SALT),
      info: bs(LOCAL_STORE_INFO),
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  lastSourceKey = privateKey;

  return cachedLocalKey;
}

export async function encryptLocal(
  plaintext: string,
  privateKey: UserIdentityKeys,
): Promise<string> {
  // "LOC:" + base64(iv ‖ AES-GCM ciphertext), no AAD.
  const { iv, ct } = await seal(await getLocalKey(privateKey), EMPTY, utf8(plaintext));
  return "LOC:" + toBase64(concatBytes(iv, ct));
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
    combined = fromBase64(ciphertextBase64.substring(4));
  } catch {
    throw new LocalStoreDecryptError("Local entry is corrupted (invalid Base64).");
  }

  if (combined.length < 12 + 16) {
    throw new LocalStoreDecryptError("Local entry is corrupted (too short).");
  }

  try {
    const sealed = { iv: combined.subarray(0, 12), ct: combined.subarray(12) };
    return fromUtf8(await open(await getLocalKey(privateKey), EMPTY, sealed));
  } catch {
    throw new LocalStoreDecryptError("Failed to decrypt local entry.");
  }
}
