/** Wycheproof vectors through the Web Crypto wrappers in src/crypto/kdf.ts. */
import { describe, expect, it } from "vitest";
import { aesGcmDecrypt, aesGcmEncrypt, hkdf, hmacSha256 } from "../../src/crypto/kdf";
import { hex, loadVectors, unhex } from "./vectors";

type Result = "valid" | "invalid" | "acceptable";

describe("Wycheproof hkdf_sha256_test", () => {
  const { tests } = loadVectors<{
    tests: { tcId: number; ikm: string; salt: string; info: string; size: number; okm: string; result: Result }[];
  }>("wycheproof-hkdf-sha256.json");
  it(`${tests.length} cases`, async () => {
    for (const t of tests) {
      const run = hkdf(unhex(t.salt), unhex(t.ikm), unhex(t.info), t.size);
      if (t.result === "invalid") {
        // The invalid cases ask for more than 255 * 32 bytes of output.
        await expect(run, `tc ${t.tcId}`).rejects.toThrow();
      } else {
        expect(hex(await run), `tc ${t.tcId}`).toBe(t.okm);
      }
    }
  });
});

describe("Wycheproof hmac_sha256_test", () => {
  const { tests } = loadVectors<{
    tests: { tcId: number; key: string; msg: string; tag: string; tagSize: number; result: Result }[];
  }>("wycheproof-hmac-sha256.json");
  it(`${tests.length} cases (full and 128-bit truncated tags)`, async () => {
    for (const t of tests) {
      const mac = await hmacSha256(unhex(t.key), unhex(t.msg));
      const matches = hex(mac.subarray(0, t.tagSize / 8)) === t.tag;
      expect(matches, `tc ${t.tcId}`).toBe(t.result === "valid");
    }
  });
});

describe("Wycheproof aes_gcm_test (256-bit key, 96-bit IV, 128-bit tag)", () => {
  const { tests } = loadVectors<{
    tests: { tcId: number; key: string; iv: string; aad: string; msg: string; ct: string; tag: string; result: Result }[];
  }>("wycheproof-aes-gcm-256.json");
  it(`${tests.length} cases`, async () => {
    for (const t of tests) {
      const body = unhex(t.ct + t.tag);
      const dec = aesGcmDecrypt(unhex(t.key), unhex(t.iv), body, unhex(t.aad));
      if (t.result === "valid") {
        expect(hex(await dec), `tc ${t.tcId}`).toBe(t.msg);
        const enc = await aesGcmEncrypt(unhex(t.key), unhex(t.iv), unhex(t.msg), unhex(t.aad));
        expect(hex(enc), `tc ${t.tcId}`).toBe(t.ct + t.tag);
      } else {
        await expect(dec, `tc ${t.tcId}`).rejects.toThrow();
      }
    }
  });
});
