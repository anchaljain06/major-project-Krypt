/**
 * Prekeys for Krypt-X3K (spec section 3).
 *
 * Bob publishes one signed prekey (SPK) and a pool of one-time prekeys (OPK),
 * all ML-KEM-1024, each signed by his ML-DSA-87 identity key under its own
 * label ("Krypt-SPK" / "Krypt-OPK"), so the relay cannot pass one kind off as
 * the other. Private halves live in an injectable `PrekeyStore`.
 */
import { fromBase64 } from "@krypt/shared";
import { LABELS, fromBase64url, lp, toBase64url, u32 } from "./encoding";
import { HandshakeError } from "./errors";
import { MLDSA87, mldsaSign, mldsaVerify, prekeyKem } from "./pq";

export type PrekeyKind = "spk" | "opk";

/** Wire shape of one prekey (base64url fields), shared with the backend. */
export interface PrekeyWire {
  keyId: number;
  publicKey: string;
  signature: string;
}

/** Body of `POST /prekeys`. */
export interface PrekeyUploadWire {
  signedPrekey: PrekeyWire;
  oneTimePrekeys: PrekeyWire[];
}

/** Response of `GET /bundle/:user`. */
export interface PrekeyBundleWire {
  username: string;
  /** Today's identity JSON from mlkem.ts: {"version", "kem": base64, "dsa": base64}. */
  identityKey: string;
  signedPrekey: PrekeyWire | null;
  oneTimePrekey: PrekeyWire | null;
}

/** A prekey's private record, as kept in a PrekeyStore. */
export interface PrekeyRecord {
  keyId: number;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  createdAt: number;
}

/** What the initiator gets out of a verified bundle. */
export interface VerifiedBundle {
  username: string;
  identityDsaPub: Uint8Array;
  signedPrekey: { keyId: number; publicKey: Uint8Array };
  oneTimePrekey: { keyId: number; publicKey: Uint8Array } | null;
}

/**
 * Private prekey storage plus Bob's memory of accepted session ids.
 *
 * Accepted session ids (= H(T)) are recorded under the SPK the handshake used,
 * for every handshake (with or without an OPK), and are forgotten when that SPK
 * is deleted. That is enough: any later init naming a deleted SPK fails with
 * UNKNOWN_PREKEY anyway (spec section 3.2).
 */
export interface PrekeyStore {
  putSignedPrekey(rec: PrekeyRecord): Promise<void>;
  getSignedPrekey(keyId: number): Promise<PrekeyRecord | undefined>;
  /** Deletes the SPK private key and its accepted-session memory. */
  deleteSignedPrekey(keyId: number): Promise<void>;
  listSignedPrekeyIds(): Promise<number[]>;

  putOneTimePrekeys(recs: PrekeyRecord[]): Promise<void>;
  getOneTimePrekey(keyId: number): Promise<PrekeyRecord | undefined>;
  deleteOneTimePrekey(keyId: number): Promise<void>;
  countOneTimePrekeys(): Promise<number>;

  hasAcceptedSession(spkId: number, sessionId: string): Promise<boolean>;
  recordAcceptedSession(spkId: number, sessionId: string): Promise<void>;
}

/** In-memory PrekeyStore (tests, and a template for persistent stores). */
export class MemoryPrekeyStore implements PrekeyStore {
  private spks = new Map<number, PrekeyRecord>();
  private opks = new Map<number, PrekeyRecord>();
  private accepted = new Map<number, Set<string>>();

  async putSignedPrekey(rec: PrekeyRecord) {
    this.spks.set(rec.keyId, copyRecord(rec));
  }
  async getSignedPrekey(keyId: number) {
    const r = this.spks.get(keyId);
    return r && copyRecord(r);
  }
  async deleteSignedPrekey(keyId: number) {
    this.spks.delete(keyId);
    this.accepted.delete(keyId);
  }
  async listSignedPrekeyIds() {
    return [...this.spks.keys()];
  }
  async putOneTimePrekeys(recs: PrekeyRecord[]) {
    for (const r of recs) this.opks.set(r.keyId, copyRecord(r));
  }
  async getOneTimePrekey(keyId: number) {
    const r = this.opks.get(keyId);
    return r && copyRecord(r);
  }
  async deleteOneTimePrekey(keyId: number) {
    this.opks.delete(keyId);
  }
  async countOneTimePrekeys() {
    return this.opks.size;
  }
  async hasAcceptedSession(spkId: number, sessionId: string) {
    return this.accepted.get(spkId)?.has(sessionId) ?? false;
  }
  async recordAcceptedSession(spkId: number, sessionId: string) {
    let set = this.accepted.get(spkId);
    if (!set) this.accepted.set(spkId, (set = new Set()));
    set.add(sessionId);
  }

  /** Deep copy, used by tests to snapshot and compare state. */
  clone(): MemoryPrekeyStore {
    const c = new MemoryPrekeyStore();
    for (const [k, v] of this.spks) c.spks.set(k, copyRecord(v));
    for (const [k, v] of this.opks) c.opks.set(k, copyRecord(v));
    for (const [k, v] of this.accepted) c.accepted.set(k, new Set(v));
    return c;
  }

  /** Stable text form of the whole store, for "state unchanged" assertions. */
  fingerprint(): string {
    const ids = (m: Map<number, unknown>) => [...m.keys()].sort((a, b) => a - b).join(",");
    const acc = [...this.accepted].map(([k, v]) => `${k}:${[...v].sort().join("|")}`).sort().join(";");
    return `spk[${ids(this.spks)}] opk[${ids(this.opks)}] accepted[${acc}]`;
  }
}

function copyRecord(r: PrekeyRecord): PrekeyRecord {
  return { keyId: r.keyId, publicKey: r.publicKey.slice(), secretKey: r.secretKey.slice(), createdAt: r.createdAt };
}

// ---------------------------------------------------------------------------
// Signing

const MAX_KEY_ID = 0x7fffffff;

export function isValidKeyId(x: unknown): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 1 && x <= MAX_KEY_ID;
}

/** The exact bytes signed for a prekey: lp(label, u32(keyId), publicKey). */
export function prekeySignedMessage(kind: PrekeyKind, keyId: number, publicKey: Uint8Array): Uint8Array {
  return lp(kind === "spk" ? LABELS.spk : LABELS.opk, u32(keyId), publicKey);
}

function randomKeyId(taken: Set<number>): number {
  for (;;) {
    const v = crypto.getRandomValues(new Uint32Array(1))[0] & MAX_KEY_ID;
    if (v !== 0 && !taken.has(v)) {
      taken.add(v);
      return v;
    }
  }
}

function makePrekey(
  kind: PrekeyKind,
  dsaSec: Uint8Array,
  keyId: number,
  now: number,
): { record: PrekeyRecord; wire: PrekeyWire } {
  const { publicKey, secretKey } = prekeyKem.keygen();
  const signature = mldsaSign(dsaSec, prekeySignedMessage(kind, keyId, publicKey));
  return {
    record: { keyId, publicKey, secretKey, createdAt: now },
    wire: { keyId, publicKey: toBase64url(publicKey), signature: toBase64url(signature) },
  };
}

/** Generates a new signed prekey, stores its private half, returns its wire form. */
export async function createSignedPrekey(dsaSec: Uint8Array, store: PrekeyStore, now = Date.now()): Promise<PrekeyWire> {
  const taken = new Set(await store.listSignedPrekeyIds());
  const { record, wire } = makePrekey("spk", dsaSec, randomKeyId(taken), now);
  await store.putSignedPrekey(record);
  return wire;
}

/** Generates `count` one-time prekeys, stores their private halves, returns wire forms. */
export async function createOneTimePrekeys(
  dsaSec: Uint8Array,
  store: PrekeyStore,
  count: number,
  now = Date.now(),
): Promise<PrekeyWire[]> {
  const taken = new Set<number>();
  const out: { record: PrekeyRecord; wire: PrekeyWire }[] = [];
  for (let i = 0; i < count; i++) {
    let id = randomKeyId(taken);
    while (await store.getOneTimePrekey(id)) id = randomKeyId(taken);
    out.push(makePrekey("opk", dsaSec, id, now));
  }
  await store.putOneTimePrekeys(out.map((o) => o.record));
  return out.map((o) => o.wire);
}

/** Initial upload: one SPK and `oneTimeCount` (default 100) OPKs. */
export async function createPrekeyUpload(
  dsaSec: Uint8Array,
  store: PrekeyStore,
  oneTimeCount = 100,
): Promise<PrekeyUploadWire> {
  return {
    signedPrekey: await createSignedPrekey(dsaSec, store),
    oneTimePrekeys: await createOneTimePrekeys(dsaSec, store, oneTimeCount),
  };
}

// ---------------------------------------------------------------------------
// Bundle verification (initiator side)

/**
 * Reads the ML-DSA-87 public key out of today's identity JSON (mlkem.ts
 * `exportPublicIdentity`): {"version": ..., "kem": base64, "dsa": base64}.
 */
export function parseIdentityKey(identityKey: string): Uint8Array {
  let parsed: unknown;
  try {
    parsed = JSON.parse(identityKey);
  } catch {
    throw new HandshakeError("BAD_BUNDLE", "identityKey is not JSON");
  }
  const dsa = (parsed as { dsa?: unknown } | null)?.dsa;
  if (typeof dsa !== "string") throw new HandshakeError("BAD_BUNDLE", "identityKey has no ML-DSA key");
  let key: Uint8Array;
  try {
    key = fromBase64(dsa);
  } catch {
    throw new HandshakeError("BAD_BUNDLE", "identityKey ML-DSA key is not base64");
  }
  if (key.length !== MLDSA87.publicKey) throw new HandshakeError("BAD_BUNDLE", "identityKey ML-DSA key has wrong length");
  return key;
}

function decodePrekey(kind: PrekeyKind, w: unknown, ik: Uint8Array): { keyId: number; publicKey: Uint8Array } {
  const p = w as Partial<PrekeyWire> | null;
  if (!p || typeof p !== "object" || !isValidKeyId(p.keyId) || typeof p.publicKey !== "string" || typeof p.signature !== "string") {
    throw new HandshakeError("BAD_BUNDLE", `${kind} has the wrong shape`);
  }
  let publicKey: Uint8Array, signature: Uint8Array;
  try {
    publicKey = fromBase64url(p.publicKey);
    signature = fromBase64url(p.signature);
  } catch {
    throw new HandshakeError("BAD_BUNDLE", `${kind} is not base64url`);
  }
  if (!prekeyKem.checkEncapsulationKey(publicKey)) throw new HandshakeError("BAD_BUNDLE", `${kind} is not an ML-KEM-1024 key`);
  if (!mldsaVerify(ik, prekeySignedMessage(kind, p.keyId, publicKey), signature)) {
    throw new HandshakeError("BAD_PREKEY_SIGNATURE", `${kind} signature does not verify`);
  }
  return { keyId: p.keyId, publicKey };
}

/**
 * Verifies a bundle for `expectedUsername`: shape, exact lengths, and each
 * prekey's signature under its own label. Identity-key trust (KT) is a
 * separate step done by the SessionManager.
 */
export function verifyBundle(bundle: unknown, expectedUsername: string): VerifiedBundle {
  const b = bundle as Partial<PrekeyBundleWire> | null;
  if (!b || typeof b !== "object" || typeof b.identityKey !== "string") throw new HandshakeError("BAD_BUNDLE", "bad shape");
  if (b.username !== expectedUsername) throw new HandshakeError("BAD_BUNDLE", "bundle is for a different user");
  if (!b.signedPrekey) throw new HandshakeError("NO_SIGNED_PREKEY");
  const ik = parseIdentityKey(b.identityKey);
  const signedPrekey = decodePrekey("spk", b.signedPrekey, ik);
  const oneTimePrekey = b.oneTimePrekey ? decodePrekey("opk", b.oneTimePrekey, ik) : null;
  return { username: b.username, identityDsaPub: ik, signedPrekey, oneTimePrekey };
}
