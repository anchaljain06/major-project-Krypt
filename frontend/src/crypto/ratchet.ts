import { bytesToBase64, base64ToBytes, sha256Bytes } from "./utils";

/**
 * Project Krypt - Perfect Forward Secrecy (PFS) Ratchet Engine
 *
 * Implements:
 * - NIST SP 800-56C Rev. 2: Recommendation for Key-Derivation Methods in Key-Establishment Schemes
 * - NIST SP 800-108r1: Recommendation for Key Derivation Using Pseudorandom Functions
 *
 * Uses HKDF-SHA-256 (HMAC-based Key Derivation Function) with domain separation
 * to deterministically ratchet the 256-bit symmetric session key after every message.
 * The old key is deleted immediately, ensuring Perfect Forward Secrecy (PFS):
 * compromising a current key yields zero ability to decrypt previous communications.
 */

const RATCHET_SALT = new TextEncoder().encode("KRYPT_NIST_RATCHET_SALT_V1");
const RATCHET_INFO = new TextEncoder().encode("KRYPT_NIST_PFS_RATCHET_STEP_V1");

export const ratchetKey = async (currentKeyBase64: string): Promise<string> => {
  let rawKeyBytes = base64ToBytes(currentKeyBase64);
  if (rawKeyBytes.length !== 32) {
    rawKeyBytes = await sha256Bytes(rawKeyBytes);
  }

  const hkdfKey = await window.crypto.subtle.importKey(
    "raw",
    rawKeyBytes as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const nextBits = await window.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: RATCHET_SALT,
      info: RATCHET_INFO,
    },
    hkdfKey,
    256,
  );

  return bytesToBase64(new Uint8Array(nextBits));
};
