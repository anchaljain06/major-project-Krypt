import { db } from "../services/db";
import { fromBase64, toBase64 } from "@krypt/shared";

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

/**
 * Encrypts data under a password (PBKDF2-HMAC-SHA256 -> AES-256-GCM).
 * A password is mandatory: unencrypted export is refused.
 */
export async function encryptVaultData(
  data: string,
  password: string,
): Promise<string> {
  if (!password) {
    throw new Error("A password is required. Unencrypted export is not allowed.");
  }

  const enc = new TextEncoder();
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    enc.encode(data),
  );

  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);

  return VAULT_HEADER + toBase64(combined);
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
  const iv = combined.subarray(16, 28);
  const ciphertext = combined.subarray(28);

  try {
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );
    const key = await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt as unknown as BufferSource,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    const plaintext = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      key,
      ciphertext as unknown as BufferSource,
    );
    return new TextDecoder().decode(plaintext);
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
