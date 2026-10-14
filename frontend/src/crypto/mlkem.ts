import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { bytesToBase64, base64ToBytes } from "./utils";

/**
 * Project Krypt - Post-Quantum Cryptographic Engine
 *
 * Implements:
 * 1. NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM-1024)
 *    - Security Category 5 (256-bit quantum security level)
 *    - IND-CCA2 secure key encapsulation
 * 2. NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA-87)
 *    - Security Category 5 (256-bit quantum security level)
 *    - EUF-CMA secure digital signatures for handshake origin authentication
 * 3. NIST SP 800-56C Rev. 2: Key Derivation using HKDF-SHA-256
 *    - Derives symmetric 256-bit Root AES keys from KEM shared secrets
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

/**
 * Generates an ML-KEM-1024 KeyPair for post-quantum key encapsulation
 * along with an ML-DSA-87 KeyPair for post-quantum handshake authentication.
 * Both primitives are Category 5 (highest NIST security level).
 */
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
 * Serializes the public identity certificate to a JSON string
 * for transmission to the blind router server / PostgreSQL database.
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

/**
 * Deserializes a public identity string from the server.
 * Supports both JSON bundles and legacy raw ML-KEM-1024 base64 public keys.
 */
export function importPublicIdentity(raw: string): UserPublicIdentity {
  try {
    const parsed = JSON.parse(raw);
    if (parsed.kem && parsed.dsa) {
      return {
        kemPublicKey: base64ToBytes(parsed.kem),
        dsaPublicKey: base64ToBytes(parsed.dsa),
      };
    }
    if (parsed.kem) {
      return {
        kemPublicKey: base64ToBytes(parsed.kem),
        dsaPublicKey: new Uint8Array(0),
      };
    }
  } catch {
    // Treat as raw base64 ML-KEM-1024 public key
  }
  return {
    kemPublicKey: base64ToBytes(raw),
    dsaPublicKey: new Uint8Array(0),
  };
}

/**
 * Serializes private identity keys for encrypted storage in .vault files or local cache.
 */
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
 * Deserializes private identity keys from encrypted storage.
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

/**
 * Derives a 256-bit symmetric Root Key from the ML-KEM shared secret
 * using HKDF-SHA-256 with domain context (NIST SP 800-56C Rev. 2).
 */
export async function deriveRootKeyFromKEM(sharedSecret: Uint8Array): Promise<string> {
  const ikm = await window.crypto.subtle.importKey(
    "raw",
    sharedSecret as unknown as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode("KRYPT_FIPS203_ROOT_SALT_V1"),
      info: new TextEncoder().encode("KRYPT_NIST_ROOT_AES256_KEY_V1"),
    },
    ikm,
    256,
  );

  return bytesToBase64(new Uint8Array(derivedBits));
}

/**
 * Initiator encapsulation (NIST FIPS 203):
 * Uses the recipient's ML-KEM-1024 public key to encapsulate a fresh 32-byte shared secret.
 * Returns the encapsulated ciphertext (1568 bytes Base64) to transmit over the wire
 * and the HKDF-derived 256-bit root AES key (Base64).
 */
export async function encapsulateSharedKey(recipientKemPublicKey: Uint8Array): Promise<{
  kemCiphertextBase64: string;
  rootBase64: string;
}> {
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(recipientKemPublicKey);
  const rootBase64 = await deriveRootKeyFromKEM(sharedSecret);
  return {
    kemCiphertextBase64: bytesToBase64(cipherText),
    rootBase64,
  };
}

/**
 * Receiver decapsulation (NIST FIPS 203):
 * Uses the receiver's ML-KEM-1024 secret key to decapsulate the received ciphertext.
 * Returns the exact same HKDF-derived 256-bit root AES key (Base64).
 */
export async function decapsulateSharedKey(
  kemCiphertextBase64: string,
  myKemSecretKey: Uint8Array,
): Promise<string> {
  const cipherText = base64ToBytes(kemCiphertextBase64);
  const sharedSecret = ml_kem1024.decapsulate(cipherText, myKemSecretKey);
  return await deriveRootKeyFromKEM(sharedSecret);
}

/**
 * Signs the ML-KEM handshake payload with the sender's ML-DSA-87 private key (NIST FIPS 204)
 * to prevent impersonation and guarantee sender authenticity.
 */
export function signHandshakePayload(
  sender: string,
  recipient: string,
  kemCiphertextBase64: string,
  dsaSecretKey: Uint8Array,
): string {
  if (dsaSecretKey.length === 0) {
    throw new Error("Cannot sign handshake: Missing ML-DSA-87 private key.");
  }
  const payloadToSign = new TextEncoder().encode(
    `ML-KEM-1024-AUTH:${sender}->${recipient}:${kemCiphertextBase64}`,
  );
  const signature = ml_dsa87.sign(payloadToSign, dsaSecretKey);
  return bytesToBase64(signature);
}

/**
 * Verifies the ML-DSA-87 signature of the received handshake payload (NIST FIPS 204).
 * Enforces strict verification: rejects any payload where signature is missing
 * or public key is empty.
 */
export function verifyHandshakeSignature(
  sender: string,
  recipient: string,
  kemCiphertextBase64: string,
  signatureBase64: string,
  senderDsaPublicKey: Uint8Array,
): boolean {
  if (!signatureBase64 || senderDsaPublicKey.length === 0) {
    return false;
  }
  try {
    const payloadToVerify = new TextEncoder().encode(
      `ML-KEM-1024-AUTH:${sender}->${recipient}:${kemCiphertextBase64}`,
    );
    const signature = base64ToBytes(signatureBase64);
    return ml_dsa87.verify(signature, payloadToVerify, senderDsaPublicKey);
  } catch (err) {
    console.error("ML-DSA-87 signature verification error:", err);
    return false;
  }
}
