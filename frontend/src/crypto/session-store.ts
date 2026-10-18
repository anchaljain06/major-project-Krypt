/**
 * Session state types and persistence (spec sections 5.1 and 12).
 *
 * `SessionStore` keeps one record per peer: the live session (if any) plus
 * the ids of recently closed or replaced sessions (tombstones).
 *
 * Contract for every implementation: `load` returns a fresh copy the caller
 * may mutate, and `save` replaces the whole record atomically. The
 * SessionManager always calls them inside the per-peer lock.
 */
import { LABELS, fromBase64url, fromUtf8, lp, toBase64url, u32, utf8 } from "./encoding";
import type { KemField } from "./envelope";
import type { InitHeader } from "./handshake";
import { bs } from "./kdf";
import type { KemSuite } from "./pq";
import type { PrekeyRecord, PrekeyStore } from "./prekeys";

export interface SkippedKey {
  epoch: number;
  n: number;
  mk: Uint8Array;
  expiresAt: number;
}

/** Full ratchet state of one session (spec 5.1). */
export interface SessionState {
  v: 1;
  sessionId: Uint8Array;
  peer: string;
  role: "initiator" | "responder";
  suite: KemSuite;
  rk: Uint8Array;
  // Sending side
  sendEpoch: number;
  cks: Uint8Array | null;
  ns: number;
  pn: number;
  sendKem: KemField | null;
  init: InitHeader | null;
  peerAcked: boolean;
  ourEk: Uint8Array | null;
  ourDk: Uint8Array | null;
  peerEk: Uint8Array | null;
  // Receiving side
  recvEpoch: number;
  ckr: Uint8Array | null;
  nr: number;
  skipped: SkippedKey[];
  // Bookkeeping
  established: boolean;
  createdAt: number;
  lastRatchetAt: number;
}

export interface PeerRecord {
  session: SessionState | null;
  /** base64url ids of closed/replaced sessions, oldest first, at most MAX_TOMBSTONES. */
  closed: string[];
}

export const MAX_TOMBSTONES = 32;

export interface SessionStore {
  load(peer: string): Promise<PeerRecord | undefined>;
  save(peer: string, rec: PeerRecord): Promise<void>;
}

// ---------------------------------------------------------------------------
// Serialization: JSON with every Uint8Array written as {"$b": "<base64url>"}.

export function serializeRecord(rec: PeerRecord): string {
  return JSON.stringify(rec, (_key, value) => (value instanceof Uint8Array ? { $b: toBase64url(value) } : value));
}

export function deserializeRecord(text: string): PeerRecord {
  return JSON.parse(text, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const keys = Object.keys(value);
      if (keys.length === 1 && keys[0] === "$b" && typeof value.$b === "string") return fromBase64url(value.$b);
    }
    return value;
  }) as PeerRecord;
}

/**
 * In-memory store. It keeps the serialized text, not live objects, so it
 * behaves like real persistence: callers can never alias stored state, and
 * tests can compare records byte for byte.
 */
export class MemorySessionStore implements SessionStore {
  private records = new Map<string, string>();

  async load(peer: string): Promise<PeerRecord | undefined> {
    const t = this.records.get(peer);
    return t === undefined ? undefined : deserializeRecord(t);
  }
  async save(peer: string, rec: PeerRecord): Promise<void> {
    this.records.set(peer, serializeRecord(rec));
  }

  /** Serialized record, for "state unchanged" assertions in tests. */
  raw(peer: string): string | undefined {
    return this.records.get(peer);
  }
  /** Deep copy (used to model a stolen device snapshot or a second tab). */
  clone(): MemorySessionStore {
    const c = new MemorySessionStore();
    for (const [k, v] of this.records) c.records.set(k, v);
    return c;
  }
}

// ---------------------------------------------------------------------------
// Encrypted IndexedDB stores
//
// The helpers below are exported for other at-rest stores that use the same
// scheme (services/messageState.ts); they are not part of the protocol API.

export function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

export function openDb(factory: IDBFactory, name: string, stores: string[]): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = factory.open(name, 1);
    r.onupgradeneeded = () => {
      for (const s of stores) if (!r.result.objectStoreNames.contains(s)) r.result.createObjectStore(s);
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export interface Sealed {
  iv: Uint8Array;
  ct: Uint8Array;
}

/** AES-256-GCM with a random 96-bit IV; the AAD binds the record to its slot. */
export async function seal(key: CryptoKey, aad: Uint8Array, plaintext: Uint8Array): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: bs(aad) }, key, bs(plaintext)),
  );
  return { iv, ct };
}

export async function open(key: CryptoKey, aad: Uint8Array, sealed: Sealed): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bs(sealed.iv), additionalData: bs(aad) },
      key,
      bs(sealed.ct),
    ),
  );
}

export interface IndexedDbOptions {
  /** AES-GCM key from the vault (non-extractable is fine). */
  key: CryptoKey;
  dbName?: string;
  /** Defaults to globalThis.indexedDB; tests pass fake-indexeddb. */
  indexedDB?: IDBFactory;
}

/**
 * Session store in IndexedDB. Each record is encrypted with the caller's key,
 * AAD = lp("krypt-session-v1", peer), so a record copied into another peer's
 * slot fails to decrypt.
 */
export class IndexedDbSessionStore implements SessionStore {
  private db: Promise<IDBDatabase>;
  private key: CryptoKey;

  constructor(opts: IndexedDbOptions) {
    this.key = opts.key;
    const factory = opts.indexedDB ?? globalThis.indexedDB;
    this.db = openDb(factory, opts.dbName ?? "krypt-sessions-v1", ["sessions"]);
  }

  private aad(peer: string) {
    return lp(LABELS.sessionAtRest, peer);
  }

  async load(peer: string): Promise<PeerRecord | undefined> {
    const db = await this.db;
    const sealed = await req<Sealed | undefined>(db.transaction("sessions").objectStore("sessions").get(peer));
    if (!sealed) return undefined;
    return deserializeRecord(fromUtf8(await open(this.key, this.aad(peer), sealed)));
  }

  async save(peer: string, rec: PeerRecord): Promise<void> {
    const sealed = await seal(this.key, this.aad(peer), utf8(serializeRecord(rec)));
    const db = await this.db;
    const tx = db.transaction("sessions", "readwrite");
    tx.objectStore("sessions").put(sealed, peer);
    await done(tx);
  }

  async close(): Promise<void> {
    (await this.db).close();
  }
}

/**
 * Prekey private halves in IndexedDB, encrypted like sessions with
 * AAD = lp("krypt-prekeys-v1", kind, u32(keyId)). Accepted session ids are
 * public hashes and are stored unencrypted under "<spkId>/<sessionId>".
 */
export class IndexedDbPrekeyStore implements PrekeyStore {
  private db: Promise<IDBDatabase>;
  private key: CryptoKey;

  constructor(opts: IndexedDbOptions) {
    this.key = opts.key;
    const factory = opts.indexedDB ?? globalThis.indexedDB;
    this.db = openDb(factory, opts.dbName ?? "krypt-prekeys-v1", ["spk", "opk", "accepted"]);
  }

  private aad(kind: "spk" | "opk", keyId: number) {
    return lp(LABELS.prekeysAtRest, kind, u32(keyId));
  }

  private async put(kind: "spk" | "opk", recs: PrekeyRecord[]) {
    const sealed = await Promise.all(
      recs.map((r) =>
        seal(
          this.key,
          this.aad(kind, r.keyId),
          utf8(JSON.stringify({ keyId: r.keyId, publicKey: toBase64url(r.publicKey), secretKey: toBase64url(r.secretKey), createdAt: r.createdAt })),
        ),
      ),
    );
    const tx = (await this.db).transaction(kind, "readwrite");
    recs.forEach((r, i) => tx.objectStore(kind).put(sealed[i], r.keyId));
    await done(tx);
  }

  private async get(kind: "spk" | "opk", keyId: number): Promise<PrekeyRecord | undefined> {
    const sealed = await req<Sealed | undefined>((await this.db).transaction(kind).objectStore(kind).get(keyId));
    if (!sealed) return undefined;
    const o = JSON.parse(fromUtf8(await open(this.key, this.aad(kind, keyId), sealed)));
    return { keyId: o.keyId, publicKey: fromBase64url(o.publicKey), secretKey: fromBase64url(o.secretKey), createdAt: o.createdAt };
  }

  putSignedPrekey(rec: PrekeyRecord) {
    return this.put("spk", [rec]);
  }
  getSignedPrekey(keyId: number) {
    return this.get("spk", keyId);
  }
  async deleteSignedPrekey(keyId: number) {
    // One transaction: the SPK and its accepted-session memory go together.
    const tx = (await this.db).transaction(["spk", "accepted"], "readwrite");
    tx.objectStore("spk").delete(keyId);
    tx.objectStore("accepted").delete(IDBKeyRange.bound(`${keyId}/`, `${keyId}/￿`));
    await done(tx);
  }
  async listSignedPrekeyIds() {
    return (await req((await this.db).transaction("spk").objectStore("spk").getAllKeys())) as number[];
  }
  putOneTimePrekeys(recs: PrekeyRecord[]) {
    return this.put("opk", recs);
  }
  getOneTimePrekey(keyId: number) {
    return this.get("opk", keyId);
  }
  async deleteOneTimePrekey(keyId: number) {
    const tx = (await this.db).transaction("opk", "readwrite");
    tx.objectStore("opk").delete(keyId);
    await done(tx);
  }
  async countOneTimePrekeys() {
    return req((await this.db).transaction("opk").objectStore("opk").count());
  }
  async hasAcceptedSession(spkId: number, sessionId: string) {
    const v = await req((await this.db).transaction("accepted").objectStore("accepted").get(`${spkId}/${sessionId}`));
    return v !== undefined;
  }
  async recordAcceptedSession(spkId: number, sessionId: string) {
    const tx = (await this.db).transaction("accepted", "readwrite");
    tx.objectStore("accepted").put(1, `${spkId}/${sessionId}`);
    await done(tx);
  }

  async close(): Promise<void> {
    (await this.db).close();
  }
}
