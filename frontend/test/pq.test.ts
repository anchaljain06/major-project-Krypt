import { describe, expect, it } from "vitest";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import {
  CryptoInputError,
  KEM_SUITES,
  MLDSA87,
  mldsaKeygen,
  mldsaSign,
  mldsaVerify,
  mlkem1024,
  prekeyKem,
  ratchetKem,
  xwing,
} from "../src/crypto/pq";

describe("KEM wrappers", () => {
  it("X-Wing is exported by noble's hybrid module with the draft's sizes", () => {
    expect(typeof ml_kem768_x25519.encapsulate).toBe("function");
    expect(xwing.lengths).toEqual({ publicKey: 1216, secretKey: 32, cipherText: 1120, sharedSecret: 32 });
  });

  it("prekeys are ML-KEM-1024", () => {
    expect(prekeyKem).toBe(mlkem1024);
    expect(mlkem1024.lengths).toEqual({ publicKey: 1568, secretKey: 3168, cipherText: 1568, sharedSecret: 32 });
  });

  for (const suite of KEM_SUITES) {
    it(`${suite}: round trip, implicit rejection, exact length checks`, () => {
      const kem = ratchetKem(suite);
      const { publicKey, secretKey } = kem.keygen();
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
      expect(kem.decapsulate(cipherText, secretKey)).toEqual(sharedSecret);

      // A modified ciphertext decapsulates to a different (pseudorandom) secret.
      const bad = cipherText.slice();
      bad[0] ^= 1;
      expect(kem.decapsulate(bad, secretKey)).not.toEqual(sharedSecret);

      expect(() => kem.encapsulate(publicKey.subarray(1))).toThrow(CryptoInputError);
      expect(() => kem.decapsulate(cipherText.subarray(1), secretKey)).toThrow(CryptoInputError);
      expect(() => kem.decapsulate(cipherText, secretKey.subarray(1))).toThrow(CryptoInputError);
    });
  }
});

describe("ML-DSA-87 wrapper", () => {
  const { publicKey, secretKey } = mldsaKeygen();
  const msg = new TextEncoder().encode("Krypt-test message");

  it("signs and verifies; context strings separate domains", () => {
    const sig = mldsaSign(secretKey, msg);
    expect(sig.length).toBe(MLDSA87.signature);
    expect(mldsaVerify(publicKey, msg, sig)).toBe(true);
    expect(mldsaVerify(publicKey, msg, sig, new Uint8Array([1]))).toBe(false);
    const ctxSig = mldsaSign(secretKey, msg, new Uint8Array([1]));
    expect(mldsaVerify(publicKey, msg, ctxSig, new Uint8Array([1]))).toBe(true);
  });

  it("returns false (never throws) for tampered or wrong-length inputs", () => {
    const sig = mldsaSign(secretKey, msg);
    const flipped = sig.slice();
    flipped[100] ^= 1;
    expect(mldsaVerify(publicKey, msg, flipped)).toBe(false);
    expect(mldsaVerify(publicKey, msg, sig.subarray(1))).toBe(false);
    expect(mldsaVerify(publicKey.subarray(1), msg, sig)).toBe(false);
    expect(mldsaVerify(publicKey, new Uint8Array([1]), sig)).toBe(false);
  });

  it("refuses to sign with a wrong-length secret key", () => {
    expect(() => mldsaSign(secretKey.subarray(1), msg)).toThrow(CryptoInputError);
  });
});
