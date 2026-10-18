/**
 * Vault files (crypto/vault.ts): only the ENC:v2: format (PBKDF2 600k ->
 * AES-256-GCM) is read; plaintext and the older "ENC:" format fail closed.
 */
import "fake-indexeddb/auto";
import { describe, expect, it, vi } from "vitest";
import { toBase64 } from "@krypt/shared";

vi.stubGlobal("window", globalThis);
const { decryptVaultData, encryptVaultData } = await import("../src/crypto/vault");

describe("vault files", () => {
  it("round-trips under the password and rejects a wrong one", async () => {
    const file = await encryptVaultData('{"hello":"vault"}', "correct horse");
    expect(file.startsWith("ENC:v2:")).toBe(true);
    expect(await decryptVaultData(`${file}\n`, "correct horse")).toBe('{"hello":"vault"}');
    await expect(decryptVaultData(file, "wrong password")).rejects.toThrow(/Wrong password/);
  });

  it("rejects the pre-v2 ENC: format and unencrypted files", async () => {
    const old = "ENC:" + toBase64(new Uint8Array(64));
    await expect(decryptVaultData(old, "pw")).rejects.toThrow(/old format/);
    await expect(decryptVaultData('{"kemPub":"x"}', "pw")).rejects.toThrow(/not encrypted/);
  });
});
