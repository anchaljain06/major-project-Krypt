import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { bytesToBase64, base64ToBytes } from "./utils";

/**
 * Project Krypt - long-term identity keys and their storage formats.
 *
 * - ML-DSA-87 (FIPS 204): the identity signature key. Krypt v1 signs prekeys,
 *   handshakes (spec 3-4) and KT leaves with it, and derives the at-rest store
 *   key from it (services/protocol.ts).
 * - ML-KEM-1024 (FIPS 203): kept in the identity bundle because the server's
 *   `identityKey` JSON, the KT leaf (SHA-256 of it) and the local message
 *   store key (localStore.ts) use it. v1 sessions do not encapsulate to it;
 *   prekeys replace it.
 *
 * The v0 handshake (encapsulate to the identity KEM key, sign the ciphertext)
 * has been removed: all messaging goes through the v1 SessionManager.
 */

export { bytesToBase64, base64ToBytes };

export interface UserIdentityKeys {
  kemPublicKey: Uint8Array;
  kemSecretKey: Uint8Array;
  dsaPublicKey: Uint8Array;
  dsaSecretKey: Uint8Array;
}

export interface UserPublicIdentity {
  kemPublicKey: Uint8Array;
  dsaPublicKey: Uint8Array;
}

/** Generates the ML-KEM-1024 and ML-DSA-87 identity key pairs. */
export function generateUserIdentityKeys(): UserIdentityKeys {
  const kemKeys = ml_kem1024.keygen();
  const dsaKeys = ml_dsa87.keygen();
  return {
    kemPublicKey: kemKeys.publicKey,
    kemSecretKey: kemKeys.secretKey,
    dsaPublicKey: dsaKeys.publicKey,
    dsaSecretKey: dsaKeys.secretKey,
  };
}

/**
 * The public identity as stored by the server (`identityKey`): JSON with
 * standard base64 `kem` and `dsa` fields (spec 2).
 */
export function exportPublicIdentity(
  keys: UserIdentityKeys | UserPublicIdentity,
): string {
  return JSON.stringify({
    version: "ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)",
    kem: bytesToBase64(keys.kemPublicKey),
    dsa: bytesToBase64(keys.dsaPublicKey),
  });
}

/** Serializes private identity keys for the encrypted vault and session cache. */
export function exportPrivateIdentity(keys: UserIdentityKeys): string {
  return JSON.stringify({
    version: "ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)",
    kemPub: bytesToBase64(keys.kemPublicKey),
    kemSec: bytesToBase64(keys.kemSecretKey),
    dsaPub: bytesToBase64(keys.dsaPublicKey),
    dsaSec: bytesToBase64(keys.dsaSecretKey),
  });
}

/**
 * Deserializes private identity keys from encrypted storage. Very old vaults
 * hold only a raw base64 ML-KEM secret key; they load without ML-DSA keys and
 * cannot use Krypt v1.
 */
export function importPrivateIdentity(serialized: string): UserIdentityKeys {
  try {
    const parsed = JSON.parse(serialized);
    if (parsed.kemSec && parsed.kemPub) {
      return {
        kemPublicKey: base64ToBytes(parsed.kemPub),
        kemSecretKey: base64ToBytes(parsed.kemSec),
        dsaPublicKey: parsed.dsaPub ? base64ToBytes(parsed.dsaPub) : new Uint8Array(0),
        dsaSecretKey: parsed.dsaSec ? base64ToBytes(parsed.dsaSec) : new Uint8Array(0),
      };
    }
  } catch {
    // Fallback for raw base64 ML-KEM secret key
  }
  const kemSecretKey = base64ToBytes(serialized);
  const kemPublicKey = ml_kem1024.getPublicKey(kemSecretKey);
  return {
    kemPublicKey,
    kemSecretKey,
    dsaPublicKey: new Uint8Array(0),
    dsaSecretKey: new Uint8Array(0),
  };
}
