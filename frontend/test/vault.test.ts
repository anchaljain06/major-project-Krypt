/**
 * At-rest formats in crypto/vault.ts and crypto/localStore.ts.
 *
 * - Vault files: only "ENC:v2:" (PBKDF2 600k -> AES-256-GCM) is read;
 *   plaintext and the older "ENC:" format fail closed.
 * - The fixtures were written by the code before both files moved onto
 *   session-store seal/open, so they pin the stored bytes as unchanged.
 */
import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { toBase64 } from "@krypt/shared";
import type { UserIdentityKeys } from "../src/crypto/mlkem";

vi.stubGlobal("window", globalThis);
const { decryptVaultData, encryptVaultData } = await import("../src/crypto/vault");
const { decryptLocal, encryptLocal } = await import("../src/crypto/localStore");

const OLD_VAULT =
  "ENC:v2:BwcHBwcHBwcHBwcHBwcHBwkJCQkJCQkJCQkJCUQUHAV0xGzZRGqXNS1rTSMwdHSs2JhZQV7RRXKnY2EcRuOqnW5OrHf0pTauNg==";
const OLD_LOCAL = "LOC:BQUFBQUFBQUFBQUFpZI0u2q3If5RD9uEu81CAz6fZHVjaTwfj4eLlqWtAg==";

describe("vault files", () => {
  it("round-trips under the password and rejects a wrong one", async () => {
    const file = await encryptVaultData('{"hello":"vault"}', "correct horse");
    expect(file.startsWith("ENC:v2:")).toBe(true);
    expect(await decryptVaultData(`${file}\n`, "correct horse")).toBe('{"hello":"vault"}');
    await expect(decryptVaultData(file, "wrong password")).rejects.toThrow(/Wrong password/);
  });

  it("reads a file written by the previous implementation", async () => {
    expect(await decryptVaultData(OLD_VAULT, "fixture password")).toBe('{"written":"by the old code"}');
  });

  it("rejects the pre-v2 ENC: format and unencrypted files", async () => {
    const old = "ENC:" + toBase64(new Uint8Array(64));
    await expect(decryptVaultData(old, "pw")).rejects.toThrow(/old format/);
    await expect(decryptVaultData('{"kemPub":"x"}', "pw")).rejects.toThrow(/not encrypted/);
  });
});

describe("local store entries", () => {
  const keys = { kemSecretKey: new Uint8Array(3168).fill(3) } as UserIdentityKeys;

  it("reads an entry written by the previous implementation and round-trips new ones", async () => {
    expect(await decryptLocal(OLD_LOCAL, keys)).toBe("old local entry");
    expect(await decryptLocal(await encryptLocal("new entry", keys), keys)).toBe("new entry");
  });

  it("fails closed on plaintext and on a flipped bit", async () => {
    await expect(decryptLocal("plain text", keys)).rejects.toThrow(/not encrypted/);
    const flipped = OLD_LOCAL.slice(0, -4) + (OLD_LOCAL.at(-4) === "A" ? "B" : "A") + OLD_LOCAL.slice(-3);
    await expect(decryptLocal(flipped, keys)).rejects.toThrow(/Failed to decrypt/);
  });
});
