/**
 * Project Krypt - Cryptographic Utilities
 * Compliant with NIST FIPS 180-4 (Secure Hash Standard) and NIST SP 800 series.
 */

/**
 * Converts a byte array to Base64 in safe chunks to avoid call stack limits
 * on large data payloads (e.g., encrypted media, high-resolution images).
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  const chunkSize = 8192;
  for (let i = 0; i < len; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunkSize, len)));
  }
  return (globalThis.btoa || btoa)(binary);
}

/**
 * Converts a Base64 string back to Uint8Array.
 * Handles trimmed input and standard padding.
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = (globalThis.atob || atob)(base64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts a byte array to a lowercase hexadecimal string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Computes a NIST FIPS 180-4 SHA-256 hash of a string and returns a hex string.
 * Uses native Web Crypto API for constant-time, hardware-accelerated execution.
 */
export async function sha256Hex(data: string): Promise<string> {
  const encoded = new TextEncoder().encode(data);
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", encoded);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Computes a NIST FIPS 180-4 SHA-256 hash of a byte array and returns a Uint8Array.
 */
export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const hashBuffer = await window.crypto.subtle.digest(
    "SHA-256",
    data as unknown as BufferSource,
  );
  return new Uint8Array(hashBuffer);
}
