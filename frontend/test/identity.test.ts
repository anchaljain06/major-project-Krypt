/** Identity bundle format (crypto/mlkem.ts): only the v1 JSON with ML-DSA keys loads. */
import { describe, expect, it } from "vitest";
import { toBase64 } from "@krypt/shared";
import { exportPrivateIdentity, generateUserIdentityKeys, importPrivateIdentity } from "../src/crypto/mlkem";

describe("private identity bundle", () => {
  it("round-trips all four keys", () => {
    const keys = generateUserIdentityKeys();
    expect(importPrivateIdentity(exportPrivateIdentity(keys))).toEqual(keys);
  });

  it("rejects pre-v1 bundles instead of loading them without ML-DSA keys", () => {
    const keys = generateUserIdentityKeys();
    const rawKemSecret = toBase64(keys.kemSecretKey);
    const kemOnly = JSON.stringify({ kemPub: toBase64(keys.kemPublicKey), kemSec: rawKemSecret });
    expect(() => importPrivateIdentity(rawKemSecret)).toThrow(/not in the Krypt v1 format/);
    expect(() => importPrivateIdentity(kemOnly)).toThrow(/before Krypt v1/);
  });
});
