/**
 * One Krypt v1 SessionManager per logged-in user (plan 1.8-1.9).
 *
 * Storage
 * - Ratchet state: IndexedDB "krypt-sessions-v1:<user>" (IndexedDbSessionStore).
 * - Prekey private halves and the session-id memory: IndexedDB
 *   "krypt-prekeys-v1:<user>" (IndexedDbPrekeyStore).
 * - Resend outbox and seen message ids: IndexedDB "krypt-msgstate-v1:<user>"
 *   (IndexedDbMessageState, services/messageState.ts).
 * All are sealed with AES-256-GCM under ONE store key:
 *
 *   storeKey = HKDF-SHA-256(salt = "krypt-store-salt-v1",
 *                           ikm  = ML-DSA-87 identity secret key (4896 B),
 *                           info = lp("krypt-store-key-v1", username)) -> AES-GCM-256
 *
 * The key is imported with extractable = false, so page script can use it but
 * never read it. It is a pure function of the identity key, which lives in the
 * vault and in the per-tab session cache (services/sessionCache.ts). A refresh
 * restores the identity from that cache and re-derives the same store key, so
 * sessions survive a refresh without the key ever being written anywhere. The
 * label differs from every other HKDF use (local message store, vault), so the
 * store key is independent of them.
 *
 * Session state is never exported (vault and chat backups hold only identity,
 * contacts and messages; spec 7 rule 3).
 */
import { lp, utf8 } from "../crypto/encoding";
import { bs } from "../crypto/kdf";
import type { UserIdentityKeys } from "../crypto/mlkem";
import type { PrekeyBundleWire } from "../crypto/prekeys";
import { SessionManager, createMutexLock, type LockFn } from "../crypto/session";
import { IndexedDbPrekeyStore, IndexedDbSessionStore } from "../crypto/session-store";
import { apiFetch } from "./api";
import { KtClient } from "./kt";
import { IndexedDbMessageState } from "./messageState";
import { socket } from "./socket";
import { createTrustIdentity } from "./trust";

export type TrustFn = (username: string, dsaPub: Uint8Array) => Promise<boolean>;

const STORE_SALT = utf8("krypt-store-salt-v1");
const STORE_INFO_LABEL = "krypt-store-key-v1";

/** Derives the non-extractable AES-GCM key that seals sessions and prekeys at rest. */
export async function deriveStoreKey(keys: UserIdentityKeys, username: string): Promise<CryptoKey> {
  if (keys.dsaSecretKey.length === 0) throw new Error("Identity has no ML-DSA-87 secret key");
  const ikm = await crypto.subtle.importKey("raw", bs(keys.dsaSecretKey), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: bs(STORE_SALT), info: bs(lp(STORE_INFO_LABEL, username)) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

interface NavigatorLocks {
  request<T>(name: string, cb: () => Promise<T>): Promise<T>;
}

/** navigator.locks (shared by every tab of the origin) when present, else an in-process mutex. */
export const appLock: LockFn = (() => {
  const locks = (globalThis.navigator as { locks?: NavigatorLocks } | undefined)?.locks;
  if (locks && typeof locks.request === "function") {
    return <T,>(name: string, fn: () => Promise<T>) => locks.request<T>(name, () => fn());
  }
  return createMutexLock();
})();

export const sessionDbName = (user: string) => `krypt-sessions-v1:${user}`;
export const prekeyDbName = (user: string) => `krypt-prekeys-v1:${user}`;
export const messageStateDbName = (user: string) => `krypt-msgstate-v1:${user}`;

/** GET /api/bundle/:username. Claims one of the peer's one-time prekeys. */
async function fetchBundle(username: string): Promise<PrekeyBundleWire> {
  const res = await apiFetch(`/api/bundle/${encodeURIComponent(username)}`);
  if (res.status === 404) throw new Error(`${username} is not registered.`);
  if (!res.ok) throw new Error(`Could not fetch ${username}'s prekey bundle (HTTP ${res.status}).`);
  return (await res.json()) as PrekeyBundleWire;
}

/**
 * The peer's identityKey JSON via the read-only `request_public_key` socket
 * call. It never claims a one-time prekey (spec 4.2 step 5).
 */
export function fetchIdentity(username: string, timeoutMs = 10_000): Promise<string> {
  return new Promise((resolve, reject) => {
    socket
      .timeout(timeoutMs)
      .emit("request_public_key", username, (err: Error | null, res?: { success?: boolean; publicKey?: unknown; error?: string }) => {
        if (err) return reject(new Error(`Timed out fetching ${username}'s identity key.`));
        if (!res?.success || typeof res.publicKey !== "string") {
          return reject(new Error(res?.error || `Could not fetch ${username}'s identity key.`));
        }
        resolve(res.publicKey);
      });
  });
}

export class Protocol {
  readonly username: string;
  readonly keys: UserIdentityKeys;
  readonly sessions: IndexedDbSessionStore;
  readonly prekeys: IndexedDbPrekeyStore;
  readonly messageState: IndexedDbMessageState;
  readonly kt: KtClient;
  private readonly trust: TrustFn;
  private readonly manager: SessionManager;

  constructor(username: string, keys: UserIdentityKeys, storeKey: CryptoKey) {
    this.username = username;
    this.keys = keys;
    this.kt = new KtClient(username, keys);
    this.trust = createTrustIdentity(keys, this.kt);
    this.sessions = new IndexedDbSessionStore({ key: storeKey, dbName: sessionDbName(username) });
    this.prekeys = new IndexedDbPrekeyStore({ key: storeKey, dbName: prekeyDbName(username) });
    this.messageState = new IndexedDbMessageState({ key: storeKey, dbName: messageStateDbName(username), lock: appLock });
    this.manager = new SessionManager({
      self: {
        username: this.username,
        identity: { dsaPub: this.keys.dsaPublicKey, dsaSec: this.keys.dsaSecretKey },
      },
      store: this.sessions,
      prekeys: this.prekeys,
      fetchBundle,
      fetchIdentity: (u) => fetchIdentity(u),
      trustIdentity: this.trust,
      lock: appLock,
    });
  }

  /** The SessionManager. Every encrypt/decrypt goes through it. */
  get session(): SessionManager {
    return this.manager;
  }

  async close() {
    await Promise.allSettled([this.sessions.close(), this.prekeys.close(), this.messageState.close()]);
  }
}

/** Removes v0 ratchet keys (`session_<me>_<peer>`) left in localStorage by older builds. */
export function deleteLegacySessionKeys() {
  try {
    const stale: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("session_")) stale.push(k);
    }
    stale.forEach((k) => localStorage.removeItem(k));
  } catch {
    // Storage unavailable: nothing to delete.
  }
}

// ---------------------------------------------------------------------------
// Process-wide instance

let current: Protocol | null = null;
let starting: Promise<Protocol> | null = null;
let waiters: ((p: Protocol) => void)[] = [];

/** Creates (or returns) the Protocol for this user and identity. */
export function startProtocol(username: string, keys: UserIdentityKeys): Promise<Protocol> {
  if (current && current.username === username && current.keys === keys) return Promise.resolve(current);
  if (starting) return starting;
  starting = (async () => {
    if (current) await stopProtocol();
    deleteLegacySessionKeys();
    const p = new Protocol(username, keys, await deriveStoreKey(keys, username));
    current = p;
    waiters.forEach((w) => w(p));
    waiters = [];
    return p;
  })().finally(() => {
    starting = null;
  });
  return starting;
}

/** Resolves once a Protocol is running (incoming messages wait on this). */
export function protocolReady(): Promise<Protocol> {
  if (current) return Promise.resolve(current);
  return new Promise((resolve) => waiters.push(resolve));
}

export async function stopProtocol() {
  const p = current;
  current = null;
  if (p) await p.close();
}

function deleteDb(name: string): Promise<void> {
  return new Promise<void>((resolve) => {
    const r = indexedDB.deleteDatabase(name);
    r.onsuccess = r.onerror = r.onblocked = () => resolve();
  });
}

/**
 * Deletes this user's ratchet sessions on this device (Wipe Local Device
 * Cache), and with them the resend outbox and seen ids, which refer to those
 * sessions. Prekeys are kept.
 */
export async function deleteSessionDatabase(user: string) {
  if (current?.username === user) await Promise.allSettled([current.sessions.close(), current.messageState.close()]);
  await deleteDb(sessionDbName(user));
  await deleteDb(messageStateDbName(user));
}

/** Deletes every user's ratchet-session and message-state databases on this device (login screen "Clear" button). */
export async function deleteAllSessionDatabases() {
  try {
    const dbs = (await indexedDB.databases?.()) ?? [];
    const prefixes = ["krypt-sessions-v1:", "krypt-msgstate-v1:"];
    await Promise.all(
      dbs
        .map((d) => d.name)
        .filter((n): n is string => !!n && prefixes.some((p) => n.startsWith(p)))
        .map(deleteDb),
    );
  } catch {
    // indexedDB.databases() unsupported: nothing we can enumerate.
  }
}
