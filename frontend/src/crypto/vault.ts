import { db } from "../services/db";
import { concatBytes, fromBase64, toBase64 } from "@krypt/shared";
import { EMPTY, fromUtf8, utf8 } from "./encoding";
import { bs } from "./kdf";
import { open, seal } from "./session-store";

/**
 * Project Krypt - Vault & Backup Cryptographic Engine
 *
 * Implements:
 * - NIST SP 800-132: Recommendation for Password-Based Key Derivation (PBKDF2-HMAC-SHA256)
 * - NIST SP 800-38D: AES-256-GCM Authenticated Encryption with Associated Data
 *
 * Current standard:
 * - 600,000 iterations of PBKDF2-HMAC-SHA256 for password stretching
 * - 16-byte cryptographically random salt
 * - 12-byte cryptographically random IV for AES-256-GCM
 * - Header "ENC:v2:"; the older "ENC:" format (100,000 iterations) is rejected
 */

const PBKDF2_ITERATIONS = 600000;
const VAULT_HEADER = "ENC:v2:";

/** Minimum length for a vault (.vault export) password. */
export const MIN_VAULT_PASSWORD_LENGTH = 8;

/**
 * Checks a new vault password and its confirmation.
 * @returns an error message, or null if the password is acceptable
 */
export function validateVaultPassword(
  password: string,
  confirm: string,
): string | null {
  if (password.length < MIN_VAULT_PASSWORD_LENGTH) {
    return `Vault password must be at least ${MIN_VAULT_PASSWORD_LENGTH} characters.`;
  }
  if (password !== confirm) {
    return "Vault passwords do not match.";
  }
  return null;
}

/** PBKDF2-HMAC-SHA256 (600,000 iterations) from the password to an AES-256-GCM key. */
async function vaultKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey("raw", bs(utf8(password)), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: bs(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Encrypts data under a password (PBKDF2-HMAC-SHA256 -> AES-256-GCM).
 * A password is mandatory: unencrypted export is refused.
 * Format: "ENC:v2:" + base64(salt(16) ‖ iv(12) ‖ ciphertext), no AAD.
 */
export async function encryptVaultData(
  data: string,
  password: string,
): Promise<string> {
  if (!password) {
    throw new Error("A password is required. Unencrypted export is not allowed.");
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { iv, ct } = await seal(await vaultKey(password, salt), EMPTY, utf8(data));
  return VAULT_HEADER + toBase64(concatBytes(salt, iv, ct));
}

export async function decryptVaultData(
  data: string,
  password?: string,
): Promise<string> {
  const trimmed = data.trim();
  if (!trimmed.startsWith(VAULT_HEADER)) {
    // Fail closed: unencrypted vaults and the pre-v2 "ENC:" format (100,000
    // PBKDF2 iterations, written only by builds before protocol-v0) are rejected.
    throw new Error(
      trimmed.startsWith("ENC:")
        ? "This vault file uses an old format that is no longer supported."
        : "This file is not encrypted. Unencrypted vault and backup files are no longer accepted.",
    );
  }

  if (!password) {
    throw new Error("Password is required to decrypt this vault file.");
  }

  let combined: Uint8Array;
  try {
    combined = fromBase64(trimmed.substring(VAULT_HEADER.length));
  } catch {
    throw new Error("Invalid vault payload: corrupted or incomplete file.");
  }

  if (combined.length < 16 + 12 + 16) {
    throw new Error("Invalid vault payload: corrupted or incomplete file.");
  }

  const salt = combined.subarray(0, 16);
  const sealed = { iv: combined.subarray(16, 28), ct: combined.subarray(28) };
  try {
    return fromUtf8(await open(await vaultKey(password, salt), EMPTY, sealed));
  } catch {
    throw new Error("Failed to decrypt vault file. Wrong password or corrupted file.");
  }
}

export async function exportChatBackup(password: string): Promise<string> {
  const messages = await db.messages.toArray();
  const backupData = JSON.stringify({ messages });
  return await encryptVaultData(backupData, password);
}

export async function importChatBackup(
  backupContent: string,
  password: string,
): Promise<void> {
  const decrypted = await decryptVaultData(backupContent, password);
  const data = JSON.parse(decrypted);
  if (data.messages && Array.isArray(data.messages)) {
    // Only encrypted message rows. Ratchet state is never in a backup (spec 7 rule 3).
    const validMessages = data.messages.filter(
      (m: unknown): m is { payload: string } =>
        !!m && typeof m === "object" && typeof (m as { payload?: unknown }).payload === "string",
    );
    if (validMessages.length > 0) {
      await db.messages.bulkAdd(validMessages);
    } else {
      throw new Error("No valid messages found in backup.");
    }
  } else {
    throw new Error("Invalid backup file: No messages array found.");
  }
}
