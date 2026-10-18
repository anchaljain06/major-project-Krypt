import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { fromBase64, toBase64 } from "@krypt/shared";

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
    kem: toBase64(keys.kemPublicKey),
    dsa: toBase64(keys.dsaPublicKey),
  });
}

/** Serializes private identity keys for the encrypted vault and session cache. */
export function exportPrivateIdentity(keys: UserIdentityKeys): string {
  return JSON.stringify({
    version: "ML-KEM-1024/ML-DSA-87 (NIST FIPS 203/204)",
    kemPub: toBase64(keys.kemPublicKey),
    kemSec: toBase64(keys.kemSecretKey),
    dsaPub: toBase64(keys.dsaPublicKey),
    dsaSec: toBase64(keys.dsaSecretKey),
  });
}

/**
 * Deserializes private identity keys from encrypted storage. Bundles from
 * builds before Krypt v1 (a raw ML-KEM secret key, or JSON without the ML-DSA
 * keys) are rejected: v1 cannot sign, publish prekeys or join KT without them.
 */
export function importPrivateIdentity(serialized: string): UserIdentityKeys {
  let parsed: { kemPub?: unknown; kemSec?: unknown; dsaPub?: unknown; dsaSec?: unknown };
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error("This identity file is not in the Krypt v1 format.");
  }
  const { kemPub, kemSec, dsaPub, dsaSec } = parsed ?? {};
  if (typeof kemPub !== "string" || typeof kemSec !== "string" || typeof dsaPub !== "string" || typeof dsaSec !== "string") {
    throw new Error("This identity file was made before Krypt v1 (no ML-DSA-87 keys) and cannot be used.");
  }
  return {
    kemPublicKey: fromBase64(kemPub),
    kemSecretKey: fromBase64(kemSec),
    dsaPublicKey: fromBase64(dsaPub),
    dsaSecretKey: fromBase64(dsaSec),
  };
}
