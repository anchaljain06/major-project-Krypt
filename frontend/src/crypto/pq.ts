/**
 * Typed post-quantum wrappers for Krypt v1 (spec section 2).
 *
 * - ML-KEM-768 and X-Wing (ML-KEM-768 + X25519) for ratchet keys (`KemSuite`)
 * - ML-KEM-1024 for signed and one-time prekeys
 * - ML-DSA-87 for identity signatures
 *
 * Every function checks exact input lengths before calling into noble, so a
 * wrong-sized key or ciphertext fails loudly here instead of deep inside the
 * library. Nothing in this file logs or stringifies key material.
 */
import { ml_kem768, ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

/** Thrown when an input has the wrong type or length. Never contains key bytes. */
export class CryptoInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoInputError";
  }
}

function expectLen(what: string, b: Uint8Array, len: number): void {
  if (!(b instanceof Uint8Array)) throw new CryptoInputError(`${what}: expected Uint8Array`);
  if (b.length !== len) throw new CryptoInputError(`${what}: expected ${len} bytes, got ${b.length}`);
}

export interface KemKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Kem {
  readonly name: string;
  readonly lengths: { publicKey: number; secretKey: number; cipherText: number; sharedSecret: 32 };
  keygen(): KemKeyPair;
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
  /** FIPS 203 section 7.2 encapsulation-key input check (length + modulus). */
  checkEncapsulationKey(publicKey: Uint8Array): boolean;
  /** FIPS 203 section 7.3 decapsulation-key input check (length + H(ek) hash). */
  checkDecapsulationKey(secretKey: Uint8Array): boolean;
}

/** The subset of noble's KEM interface we rely on. */
interface NobleKem {
  lengths: { publicKey?: number; secretKey?: number; cipherText?: number };
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array, msg?: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

function wrapKem(name: string, impl: NobleKem): Kem & {
  /** Deterministic encapsulation with caller-supplied randomness. For known-answer tests only. */
  encapsulateDerand(publicKey: Uint8Array, m: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  /** Deterministic key generation from a seed. For known-answer tests only. */
  keygenDerand(seed: Uint8Array): KemKeyPair;
} {
  const lengths = {
    publicKey: impl.lengths.publicKey!,
    secretKey: impl.lengths.secretKey!,
    cipherText: impl.lengths.cipherText!,
    sharedSecret: 32 as const,
  };
  const checkSs = (ss: Uint8Array) => {
    expectLen(`${name} shared secret`, ss, 32);
    return ss;
  };
  return {
    name,
    lengths,
    keygen() {
      const { publicKey, secretKey } = impl.keygen();
      expectLen(`${name} public key`, publicKey, lengths.publicKey);
      expectLen(`${name} secret key`, secretKey, lengths.secretKey);
      return { publicKey, secretKey };
    },
    keygenDerand(seed) {
      return impl.keygen(seed);
    },
    encapsulate(publicKey) {
      expectLen(`${name} public key`, publicKey, lengths.publicKey);
      const { cipherText, sharedSecret } = impl.encapsulate(publicKey);
      expectLen(`${name} ciphertext`, cipherText, lengths.cipherText);
      return { cipherText, sharedSecret: checkSs(sharedSecret) };
    },
    encapsulateDerand(publicKey, m) {
      expectLen(`${name} public key`, publicKey, lengths.publicKey);
      const { cipherText, sharedSecret } = impl.encapsulate(publicKey, m);
      return { cipherText, sharedSecret: checkSs(sharedSecret) };
    },
    // noble performs both FIPS 203 input checks inside encapsulate/decapsulate
    // (it throws "wrong publicKey modulus" / "hash check failed"); these helpers
    // expose them as booleans. The X-Wing secret key is a seed, so only the
    // length can be checked for it.
    checkEncapsulationKey(publicKey) {
      if (!(publicKey instanceof Uint8Array) || publicKey.length !== lengths.publicKey) return false;
      try {
        impl.encapsulate(publicKey);
        return true;
      } catch {
        return false;
      }
    },
    checkDecapsulationKey(secretKey) {
      if (!(secretKey instanceof Uint8Array) || secretKey.length !== lengths.secretKey) return false;
      try {
        impl.decapsulate(new Uint8Array(lengths.cipherText), secretKey);
        return true;
      } catch {
        return false;
      }
    },
    decapsulate(cipherText, secretKey) {
      expectLen(`${name} ciphertext`, cipherText, lengths.cipherText);
      expectLen(`${name} secret key`, secretKey, lengths.secretKey);
      // ML-KEM uses implicit rejection: a tampered ciphertext yields a
      // pseudorandom secret rather than an error, so tampering surfaces later
      // as an AES-GCM failure.
      return checkSs(impl.decapsulate(cipherText, secretKey));
    },
  };
}

export const mlkem768 = wrapKem("ML-KEM-768", ml_kem768 as unknown as NobleKem);
export const mlkem1024 = wrapKem("ML-KEM-1024", ml_kem1024 as unknown as NobleKem);
/** X-Wing (draft-connolly-cfrg-xwing-kem). The secret key is a 32-byte seed. */
export const xwing = wrapKem("X-Wing", ml_kem768_x25519 as unknown as NobleKem);

/** Ratchet KEM suites. Prekeys are always ML-KEM-1024. */
export type KemSuite = "mlkem768" | "xwing";
export const KEM_SUITES: readonly KemSuite[] = ["mlkem768", "xwing"];

export function isKemSuite(x: unknown): x is KemSuite {
  return x === "mlkem768" || x === "xwing";
}

export function ratchetKem(suite: KemSuite): Kem {
  switch (suite) {
    case "mlkem768":
      return mlkem768;
    case "xwing":
      return xwing;
  }
}

/** Prekey KEM (signed and one-time prekeys). */
export const prekeyKem: Kem = mlkem1024;

// ---------------------------------------------------------------------------
// ML-DSA-87

export const MLDSA87 = {
  publicKey: 2592,
  secretKey: 4896,
  signature: 4627,
} as const;

export interface SigKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function mldsaKeygen(): SigKeyPair {
  const { publicKey, secretKey } = ml_dsa87.keygen();
  return { publicKey, secretKey };
}

/**
 * ML-DSA-87 sign (hedged, FIPS 204 "pure" mode). Krypt passes a message that
 * already starts with a domain label, and leaves `context` empty (spec 2).
 */
export function mldsaSign(secretKey: Uint8Array, message: Uint8Array, context?: Uint8Array): Uint8Array {
  expectLen("ML-DSA-87 secret key", secretKey, MLDSA87.secretKey);
  const sig = ml_dsa87.sign(message, secretKey, context ? { context } : undefined);
  expectLen("ML-DSA-87 signature", sig, MLDSA87.signature);
  return sig;
}

/**
 * ML-DSA-87 verify. Returns false (never throws) for a wrong-length key or
 * signature, because those come from untrusted input.
 */
export function mldsaVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context?: Uint8Array,
): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== MLDSA87.publicKey) return false;
  if (!(signature instanceof Uint8Array) || signature.length !== MLDSA87.signature) return false;
  if (context && context.length > 255) return false;
  try {
    return ml_dsa87.verify(signature, message, publicKey, context ? { context } : undefined);
  } catch {
    return false;
  }
}
