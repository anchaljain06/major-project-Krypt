import { Dexie, type Table } from "dexie";
import { bytesToBase64, base64ToBytes } from "../crypto/utils";

/**
 * Refresh-survivable session cache for the private identity key bundle.
 *
 * What lives where (no password and no plaintext key is stored anywhere):
 * - IndexedDB "KryptSessionKeys" / keys[username]: a random AES-GCM-256 CryptoKey
 *   generated with extractable = false. Page script can encrypt/decrypt with it,
 *   but cannot read the key bytes out (structured clone keeps it non-extractable).
 * - localStorage `sessionCache_${user}`: "SC1:" + Base64(iv || AES-GCM(bundle JSON)),
 *   AAD "krypt-session-cache-v1". Useless without the CryptoKey above.
 * - sessionStorage `krypt_session_active` = "1": marks a live session in this tab.
 *   sessionStorage dies with the tab, so a new tab or browser restart finds no flag;
 *   the key and cache are then deleted and a fresh login is required.
 * - sessionStorage `krypt_token`: the server session token (services/authToken.ts).
 * - localStorage `encryptedPrivateKey_${user}`: the bundle encrypted under the login
 *   password (PBKDF2, crypto/vault.ts). Kept so a returning login on this device
 *   works without the .vault file; it is only opened when the user types the password.
 */

const ACTIVE_FLAG = "krypt_session_active";
const CACHE_PREFIX = "sessionCache_";
const CACHE_HEADER = "SC1:";
const AAD = new TextEncoder().encode("krypt-session-cache-v1");

interface SessionKeyRecord {
  id: string; // username
  key: CryptoKey;
}

class SessionKeyDatabase extends Dexie {
  keys!: Table<SessionKeyRecord, string>;

  constructor() {
    super("KryptSessionKeys");
    this.version(1).stores({ keys: "id" });
  }
}

const keyDb = new SessionKeyDatabase();

const cacheKey = (user: string) => `${CACHE_PREFIX}${user}`;

/**
 * Encrypts the private key bundle under a fresh non-extractable key and marks
 * this tab's session as active. Replaces any previous cache for `user`.
 */
export async function createSessionCache(user: string, bundle: string): Promise<void> {
  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: AAD },
    key,
    new TextEncoder().encode(bundle),
  );

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);

  await keyDb.keys.put({ id: user, key });
  localStorage.setItem(cacheKey(user), CACHE_HEADER + bytesToBase64(combined));
  sessionStorage.setItem(ACTIVE_FLAG, "1");
}

/**
 * Returns the cached bundle for `user` if this tab still has a live session,
 * otherwise wipes the cache and returns null (caller must require login).
 */
export async function restoreSessionCache(user: string): Promise<string | null> {
  if (sessionStorage.getItem(ACTIVE_FLAG) !== "1") {
    await clearSessionCache();
    return null;
  }

  const stored = localStorage.getItem(cacheKey(user));
  const record = await keyDb.keys.get(user);
  if (!stored || !stored.startsWith(CACHE_HEADER) || !record) {
    await clearSessionCache(user);
    return null;
  }

  try {
    const combined = base64ToBytes(stored.substring(CACHE_HEADER.length));
    const plaintext = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: combined.subarray(0, 12) as unknown as BufferSource,
        additionalData: AAD,
      },
      record.key,
      combined.subarray(12) as unknown as BufferSource,
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    await clearSessionCache(user);
    return null;
  }
}

/**
 * Deletes the session flag, the encrypted cache and the stored CryptoKey.
 * With no `user`, removes every user's cache and key.
 */
export async function clearSessionCache(user?: string): Promise<void> {
  sessionStorage.removeItem(ACTIVE_FLAG);
  if (user) {
    localStorage.removeItem(cacheKey(user));
    await keyDb.keys.delete(user).catch(() => {});
    return;
  }
  const staleKeys: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key && key.startsWith(CACHE_PREFIX)) staleKeys.push(key);
  }
  staleKeys.forEach((key) => localStorage.removeItem(key));
  await keyDb.keys.clear().catch(() => {});
}

/** Drops the whole KryptSessionKeys database (used by "Clear Browser Cache & Storage"). */
export async function deleteSessionKeyDatabase(): Promise<void> {
  sessionStorage.removeItem(ACTIVE_FLAG);
  await keyDb.delete();
}
