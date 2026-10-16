import { randomBytes } from "crypto";
import { describe, expect, it } from "vitest";
import {
  acceptOrRejectBody,
  base64urlBytes,
  blockBody,
  loginVerifyBody,
  ML_DSA_87_SIGNATURE_BYTES,
  ML_KEM_1024_PUBLIC_KEY_BYTES,
  privateMessagePayload,
  registerBody,
  sendOrRevokeBody,
  uploadPrekeysBody,
  usernameSchema,
} from "../src/schemas.js";

const b64u = (n: number) => randomBytes(n).toString("base64url");
const prekey = (keyId: number) => ({
  keyId,
  publicKey: b64u(ML_KEM_1024_PUBLIC_KEY_BYTES),
  signature: b64u(ML_DSA_87_SIGNATURE_BYTES),
});

describe("usernameSchema", () => {
  it("trims and accepts normal names", () => {
    expect(usernameSchema.parse("  alice ")).toBe("alice");
  });
  it("rejects empty, too long, control chars and non-strings", () => {
    for (const bad of ["", "   ", "a".repeat(65), "al\u0000ice", "a\nb", 5, null, {}]) {
      expect(usernameSchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe("auth bodies", () => {
  it("accepts a well-formed registration", () => {
    const ok = registerBody.safeParse({
      username: "alice",
      publicKey: "pk",
      srpSalt: "ab12",
      srpVerifier: "ff00",
    });
    expect(ok.success).toBe(true);
  });
  it("rejects missing fields and non-hex SRP values", () => {
    expect(registerBody.safeParse({ username: "alice" }).success).toBe(false);
    expect(
      loginVerifyBody.safeParse({
        username: "a",
        clientEphemeralPublic: "zz",
        clientSessionProof: "00",
      }).success,
    ).toBe(false);
  });
});

describe("social bodies", () => {
  it("makes the acting-user field optional", () => {
    expect(sendOrRevokeBody.safeParse({ receiver: "bob" }).success).toBe(true);
    expect(acceptOrRejectBody.safeParse({ sender: "bob" }).success).toBe(true);
    expect(blockBody.safeParse({ blocked: "bob" }).success).toBe(true);
  });
  it("requires the target user", () => {
    expect(sendOrRevokeBody.safeParse({ sender: "alice" }).success).toBe(false);
    expect(acceptOrRejectBody.safeParse({ receiver: "alice" }).success).toBe(false);
    expect(blockBody.safeParse({ blocker: "alice" }).success).toBe(false);
  });
});

describe("privateMessagePayload", () => {
  it("requires `to` and passes other fields through", () => {
    const parsed = privateMessagePayload.parse({
      to: "bob",
      from: "spoofed",
      ciphertext: "GCM:abc",
      type: "text",
      eph: "x",
      header: { v: 1 },
    });
    expect(parsed).toMatchObject({ to: "bob", ciphertext: "GCM:abc", header: { v: 1 } });
  });
  it("rejects a missing or bad recipient", () => {
    expect(privateMessagePayload.safeParse({ ciphertext: "x" }).success).toBe(false);
    expect(privateMessagePayload.safeParse({ to: 42 }).success).toBe(false);
    expect(privateMessagePayload.safeParse("bob").success).toBe(false);
    expect(privateMessagePayload.safeParse(null).success).toBe(false);
  });
});

describe("prekey validation", () => {
  it("checks exact decoded length and canonical base64url", () => {
    const schema = base64urlBytes(4);
    expect(schema.safeParse(Buffer.from([1, 2, 3, 4]).toString("base64url")).success).toBe(true);
    expect(schema.safeParse("AQIDBA==").success).toBe(false); // padded
    expect(schema.safeParse("AQID+A").success).toBe(false); // base64, not base64url
    expect(schema.safeParse("AQID").success).toBe(false); // 3 bytes
    expect(schema.safeParse("AQIDBB").success).toBe(false); // non-canonical trailing bits
  });

  it("accepts ML-KEM-1024 keys with ML-DSA-87 signatures", () => {
    const ok = uploadPrekeysBody.safeParse({
      signedPrekey: prekey(1),
      oneTimePrekeys: [prekey(1), prekey(2)],
    });
    expect(ok.success).toBe(true);
  });

  it("rejects wrong sizes, duplicates and too many OPKs", () => {
    expect(
      uploadPrekeysBody.safeParse({ signedPrekey: { ...prekey(1), publicKey: b64u(1184) } })
        .success,
    ).toBe(false);
    expect(
      uploadPrekeysBody.safeParse({ oneTimePrekeys: [prekey(7), prekey(7)] }).success,
    ).toBe(false);
    const many = Array.from({ length: 201 }, (_, i) => prekey(i));
    expect(uploadPrekeysBody.safeParse({ oneTimePrekeys: many }).success).toBe(false);
    expect(
      uploadPrekeysBody.safeParse({ oneTimePrekeys: [{ ...prekey(1), keyId: -1 }] }).success,
    ).toBe(false);
  });
});
