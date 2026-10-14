import { getWasmModule } from "../services/wasmLoader";
import { bytesToBase64, base64ToBytes, sha256Bytes } from "./utils";

/**
 * Project Krypt - Symmetric Encryption Engine
 *
 * Primary Engine: NIST SP 800-38D AES-256-GCM (Authenticated Encryption with Associated Data)
 * - 256-bit symmetric encryption key derived from ML-KEM-1024 / PFS ratchet
 * - Cryptographically random 96-bit (12-byte) initialization vector (IV/Nonce) per message
 * - 128-bit authentication tag for authenticated integrity protection (AEAD)
 * - Constant-time, hardware-accelerated execution via native Web Cryptography API
 *
 * Legacy Fallback: WASM-powered AES-CBC (for backward compatibility with pre-upgrade messages)
 */

const LEGACY_IV = "initialvector123";

/**
 * Normalizes an arbitrary key string into a strict 32-byte (256-bit) AES key.
 */
async function get256BitKey(dynamicAesKey: string): Promise<Uint8Array> {
  const rawBytes = base64ToBytes(dynamicAesKey);
  if (rawBytes.length === 32) {
    return rawBytes;
  }
  // Hash with NIST FIPS 180-4 SHA-256 to ensure exact 256-bit entropy
  return await sha256Bytes(rawBytes);
}

/**
 * Encrypts a message or binary media string using NIST SP 800-38D AES-256-GCM.
 * Generates a fresh cryptographically random 12-byte IV for every message.
 * Produces an AEAD-authenticated ciphertext bundled with its authentication tag.
 *
 * @param message The plaintext text or Base64 data URL (images/audio)
 * @param dynamicAesKey The 256-bit session key (Base64)
 * @returns Prefixed Base64 string "GCM:<base64(iv + ciphertext + tag)>"
 */
export async function encryptAES(
  message: string,
  dynamicAesKey: string,
): Promise<string> {
  const keyBytes = await get256BitKey(dynamicAesKey);

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes as unknown as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );

  // NIST SP 800-38D mandates a unique 96-bit (12-byte) nonce for every invocation
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(message);

  const ciphertextAndTag = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    encoded,
  );

  const combined = new Uint8Array(iv.length + ciphertextAndTag.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertextAndTag), iv.length);

  return "GCM:" + bytesToBase64(combined);
}

/**
 * Decrypts a ciphertext message using NIST SP 800-38D AES-256-GCM.
 * Verifies the 128-bit authentication tag before releasing decrypted plaintext.
 * If the ciphertext is in legacy format, gracefully falls back to the WASM CBC decryptor.
 *
 * @param base64Ciphertext The encrypted string
 * @param decryptedAesKey The 256-bit session key (Base64)
 * @returns The original plaintext or media string
 */
export async function decryptAES(
  base64Ciphertext: string,
  decryptedAesKey: string,
): Promise<string> {
  const trimmed = base64Ciphertext.trim();

  // Primary Path: NIST SP 800-38D AES-256-GCM
  if (trimmed.startsWith("GCM:")) {
    const combined = base64ToBytes(trimmed.substring(4));
    if (combined.length < 12 + 16) {
      throw new Error("Invalid AES-GCM ciphertext payload: length too short.");
    }

    const iv = combined.subarray(0, 12);
    const ciphertext = combined.subarray(12);

    const keyBytes = await get256BitKey(decryptedAesKey);
    const cryptoKey = await window.crypto.subtle.importKey(
      "raw",
      keyBytes as unknown as BufferSource,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      cryptoKey,
      ciphertext as unknown as BufferSource,
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  // Legacy Fallback Path: WASM AES-CBC engine (for pre-upgrade messages)
  return decryptLegacyWASM(trimmed, decryptedAesKey);
}

/**
 * Fallback decryptor for legacy pre-upgrade WASM CBC ciphertexts.
 */
async function decryptLegacyWASM(
  base64Ciphertext: string,
  decryptedAesKey: string,
): Promise<string> {
  try {
    const Module = await getWasmModule();
    const cipherBytes = base64ToBytes(base64Ciphertext);

    // Converts bytes to a C pointer in WASM memory
    const cipherPtr = Module._malloc(cipherBytes.length);
    Module.HEAPU8.set(cipherBytes, cipherPtr);

    const keyBytes = new TextEncoder().encode(decryptedAesKey);
    const keyPtr = Module._malloc(keyBytes.length);
    Module.HEAPU8.set(keyBytes, keyPtr);

    const ivBytes = new TextEncoder().encode(LEGACY_IV);
    const ivPtr = Module._malloc(ivBytes.length);
    Module.HEAPU8.set(ivBytes, ivPtr);

    const outLenPtr = Module._malloc(4);

    const outPtr = Module._decrypt_wrapper(
      cipherPtr,
      cipherBytes.length,
      keyPtr,
      keyBytes.length,
      ivPtr,
      outLenPtr,
    );

    if (!outPtr) {
      Module._free(cipherPtr);
      Module._free(keyPtr);
      Module._free(ivPtr);
      Module._free(outLenPtr);
      throw new Error("Legacy WASM decryption failed.");
    }

    const outLen = Module.HEAP32[outLenPtr >> 2];
    const decryptedBytes = new Uint8Array(Module.HEAPU8.buffer, outPtr, outLen);
    const plaintext = new TextDecoder().decode(decryptedBytes);

    Module._free(cipherPtr);
    Module._free(keyPtr);
    Module._free(ivPtr);
    Module._free(outLenPtr);
    Module._free_buffer(outPtr);

    return plaintext;
  } catch (err: any) {
    throw new Error(`Decryption failed: ${err.message || "Unknown error"}`);
  }
}
