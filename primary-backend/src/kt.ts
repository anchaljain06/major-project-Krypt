import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import type { Prisma, PrismaClient } from "@prisma/client";
import {
  KtOp,
  MemoryNodeStore,
  MerkleLog,
  bytesEqual,
  decodeLeaf,
  fromBase64,
  hashLeaf,
  logIdFromPublicKey,
  ownerSignedMessage,
  sha256,
  signTreeHead,
  toBase64,
  type Hash,
  type KtLeaf,
  type NodeStore,
  type SignedTreeHead,
} from "./vendor/krypt-shared/index.js";

// Key transparency log (plan 2.21-2.22, strategy §5).
//
// The Merkle maths lives in shared/ (vendored, see scripts/vendor-shared.mjs).
// This module adds what the server needs around it:
//
//   - KtStorage: where leaves, subtree hashes and signed tree heads live.
//     prismaKtStorage() is the Postgres one; memoryKtStorage() is for tests.
//   - KtLog: appends (serialised by an in-process mutex AND a Postgres
//     advisory lock, so two server processes cannot interleave), lazy STH
//     publication, and the honest read view that the /kt/* endpoints serve.
//
// Appends are serialised because MerkleLog derives each new node from the
// tree size; two concurrent appends at the same size would corrupt the tree.

export const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
export const ML_DSA_87_SECRET_KEY_BYTES = 4896;
export const ML_DSA_87_SIG_BYTES = 4627;
export const ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;
/** Default minimum time between two published tree heads (plan 2.22). */
export const DEFAULT_STH_INTERVAL_MS = 5 * 60 * 1000;
/** Arbitrary constant naming the KT append lock among Postgres advisory locks. */
export const KT_ADVISORY_LOCK_KEY = 0x4b5254; // "KRT"

export interface StoredLeaf {
  index: number;
  leaf: Uint8Array;
  leafHash: Hash;
  userHash: Hash;
  keyVersion: number;
  ownerSig: Uint8Array;
}

/** Operations available while holding the append lock (inside one DB transaction). */
export interface KtTx {
  /** Number of leaves in the log, published or not. */
  size(): Promise<number>;
  nodes: NodeStore;
  /** The user's newest leaf with index < beforeSize (default: any). */
  latestLeafForUser(userHash: Hash, beforeSize?: number): Promise<StoredLeaf | null>;
  insertLeaf(row: StoredLeaf): Promise<void>;
  latestSth(): Promise<SignedTreeHead | null>;
  insertSth(sth: SignedTreeHead): Promise<void>;
}

export interface KtStorage extends KtTx {
  /** Runs fn holding the append lock, in one transaction where the backend has them. */
  locked<T>(fn: (tx: KtTx) => Promise<T>): Promise<T>;
  /** Leaves with from <= index < to, in index order. */
  leaves(from: number, to: number): Promise<StoredLeaf[]>;
  /** The published head of exactly this size, if any. */
  sthAt(size: number): Promise<SignedTreeHead | null>;
}

// ---------------------------------------------------------------------------
// Signing key

export interface LogKey {
  publicKey: Uint8Array;
  sign(msg: Uint8Array): Uint8Array;
  verify(msg: Uint8Array, sig: Uint8Array): boolean;
}

function keyFromSecret(secretKey: Uint8Array, publicKey: Uint8Array): LogKey {
  return {
    publicKey,
    sign: (msg) => ml_dsa87.sign(msg, secretKey),
    verify: (msg, sig) => ml_dsa87.verify(sig, msg, publicKey),
  };
}

/** Deterministic key from a 32-byte seed (FIPS 204 ML-DSA.KeyGen_internal). */
export function logKeyFromSeed(seed: Uint8Array): LogKey {
  const { secretKey, publicKey } = ml_dsa87.keygen(seed);
  return keyFromSecret(secretKey, publicKey);
}

/**
 * Loads the STH signing key from KT_LOG_SK: standard base64 of either a
 * 32-byte seed (preferred; `npm run kt:keygen` prints one) or a 4896-byte
 * ML-DSA-87 secret key. Without it, a random key is generated and a warning
 * logged: fine for development, useless for a witness, because the key (and
 * so the log identity) changes on every restart.
 */
export function loadLogKey(env: NodeJS.ProcessEnv = process.env): LogKey {
  const raw = env.KT_LOG_SK?.trim();
  if (!raw) {
    const key = logKeyFromSeed(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    console.warn(
      "[KT] WARNING: KT_LOG_SK is not set. Using a random tree-head signing key; " +
        "every restart creates a new log identity that no witness or client will accept. " +
        `Public key: ${toBase64(key.publicKey).slice(0, 24)}...`,
    );
    return key;
  }
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(raw);
  } catch {
    throw new Error("KT_LOG_SK must be standard padded base64.");
  }
  if (bytes.length === 32) return logKeyFromSeed(bytes);
  if (bytes.length === ML_DSA_87_SECRET_KEY_BYTES) {
    return keyFromSecret(bytes, ml_dsa87.getPublicKey(bytes));
  }
  throw new Error(
    `KT_LOG_SK must decode to a 32-byte seed or a ${ML_DSA_87_SECRET_KEY_BYTES}-byte ML-DSA-87 secret key, got ${bytes.length} bytes.`,
  );
}

// ---------------------------------------------------------------------------
// Errors and small helpers

/** A refused request: status and a message that is safe to show the client. */
export class KtError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Promise-chain mutex: serialises async critical sections within this process. */
export class Mutex {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.tail.then(fn, fn);
    this.tail = result.catch(() => undefined);
    return result;
  }
}

// ---------------------------------------------------------------------------
// Read views. The /kt/* endpoints serve whatever view they are given; the
// honest one comes from KtLog.honestView(). The evil relay builds others.

export interface KtView {
  /** The newest published head (publishing one first if it is due). */
  latestSth(): Promise<SignedTreeHead>;
  /** The published head of exactly this size, if any. */
  sthAt(size: number): Promise<SignedTreeHead | null>;
  /** Proof source for any size up to the latest head. */
  log(size: number): Promise<MerkleLog>;
  leaves(from: number, to: number): Promise<StoredLeaf[]>;
  latestLeafForUser(userHash: Hash, beforeSize: number): Promise<StoredLeaf | null>;
}

// ---------------------------------------------------------------------------
// The log service

export interface KtLogOptions {
  /** Minimum time between published heads. */
  sthIntervalMs?: number;
  now?: () => number;
}

/** Validates the append against the user's previous leaf; throws KtError to refuse. */
export type AppendCheck = (prev: StoredLeaf | null) => void | Promise<void>;

export class KtLog {
  readonly logId: Promise<Hash>;
  private readonly mutex = new Mutex();
  private readonly intervalMs: number;
  private readonly now: () => number;

  constructor(
    readonly storage: KtStorage,
    readonly key: LogKey,
    opts: KtLogOptions = {},
  ) {
    this.intervalMs = opts.sthIntervalMs ?? DEFAULT_STH_INTERVAL_MS;
    this.now = opts.now ?? Date.now;
    this.logId = logIdFromPublicKey(key.publicKey);
  }

  /**
   * Appends a leaf. `check` runs while the lock is held, with the user's
   * newest leaf, so a concurrent rotation cannot slip in between the check
   * and the append. Publishes a head if one is due.
   */
  append(leafBytes: Uint8Array, ownerSig: Uint8Array, check?: AppendCheck): Promise<StoredLeaf> {
    const leaf = decodeLeaf(leafBytes);
    return this.mutex.run(() =>
      this.storage.locked(async (tx) => {
        if (check) await check(await tx.latestLeafForUser(leaf.userHash));
        const size = await tx.size();
        const log = new MerkleLog(tx.nodes, size);
        const leafHash = await hashLeaf(leafBytes);
        const index = await log.append(leafHash);
        const row: StoredLeaf = {
          index,
          leaf: leafBytes,
          leafHash,
          userHash: leaf.userHash,
          keyVersion: leaf.keyVersion,
          ownerSig,
        };
        await tx.insertLeaf(row);
        await this.publishIfDue(tx, log);
        return row;
      }),
    );
  }

  /** The newest user leaf, published or not (for the owner's own status). */
  latestLeafForUser(userHash: Hash): Promise<StoredLeaf | null> {
    return this.storage.latestLeafForUser(userHash);
  }

  /**
   * The newest head. Publishes one first when none exists yet, or when the
   * log has grown and the last head is at least sthIntervalMs old.
   */
  async latestSth(): Promise<SignedTreeHead> {
    const [sth, size] = await Promise.all([this.storage.latestSth(), this.storage.size()]);
    if (sth && !this.isDue(sth, size)) return sth;
    return this.mutex.run(() =>
      this.storage.locked(async (tx) => {
        const size = await tx.size();
        const published = await this.publishIfDue(tx, new MerkleLog(tx.nodes, size));
        return published ?? (await tx.latestSth())!;
      }),
    );
  }

  /** Signs a tree head with the log key (also used by the evil relay's views). */
  sign(treeSize: number, rootHash: Hash, timestampMs: number): Promise<SignedTreeHead> {
    return signTreeHead({ treeSize, rootHash, timestampMs }, this.key.sign);
  }

  honestView(): KtView {
    const storage = this.storage;
    return {
      latestSth: () => this.latestSth(),
      sthAt: (size) => storage.sthAt(size),
      log: async (size) => new MerkleLog(storage.nodes, size),
      leaves: (from, to) => storage.leaves(from, to),
      latestLeafForUser: (userHash, beforeSize) => storage.latestLeafForUser(userHash, beforeSize),
    };
  }

  private isDue(sth: SignedTreeHead | null, size: number): boolean {
    if (!sth) return true;
    return size > sth.treeSize && this.now() - sth.timestampMs >= this.intervalMs;
  }

  /** Must hold the lock. Returns the new head, or null if none was due. */
  private async publishIfDue(tx: KtTx, log: MerkleLog): Promise<SignedTreeHead | null> {
    const prev = await tx.latestSth();
    if (!this.isDue(prev, log.size)) return null;
    // Timestamps never go backwards, even if the clock does.
    const ts = Math.max(this.now(), prev ? prev.timestampMs + 1 : 0);
    const sth = await this.sign(log.size, await log.root(), ts);
    await tx.insertSth(sth);
    return sth;
  }
}

// ---------------------------------------------------------------------------
// Identity keys as the frontend stores them in User.identityKeyPub
// (frontend/src/crypto/mlkem.ts exportPublicIdentity):
//   {"version": "...", "kem": base64(ML-KEM-1024 pk), "dsa": base64(ML-DSA-87 pk)}

export interface IdentityPublicKeys {
  mldsaPk: Uint8Array;
  mlkemPk: Uint8Array;
}

function decodeStdBase64(s: unknown, bytes: number): Uint8Array | null {
  if (typeof s !== "string") return null;
  try {
    const b = fromBase64(s.trim());
    return b.length === bytes ? b : null;
  } catch {
    return null;
  }
}

/** Parses identityKeyPub; null for legacy (KEM-only) or malformed values. */
export function parseIdentityKey(raw: string | null | undefined): IdentityPublicKeys | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const o = parsed as Record<string, unknown>;
  const mlkemPk = decodeStdBase64(o.kem, ML_KEM_1024_PUBLIC_KEY_BYTES);
  const mldsaPk = decodeStdBase64(o.dsa, ML_DSA_87_PUBLIC_KEY_BYTES);
  return mlkemPk && mldsaPk ? { mldsaPk, mlkemPk } : null;
}

// ---------------------------------------------------------------------------
// Validation of client-submitted leaves (POST /api/kt/register)

/** Owner timestamps further than this from the server clock are refused. */
export const MAX_LEAF_CLOCK_SKEW_MS = 10 * 60 * 1000;

export interface LeafSubmission {
  leaf: KtLeaf;
  ownerSig: Uint8Array;
  /** ML-DSA-87 key that made ownerSig: the previous key for a rotation. */
  signerPk: Uint8Array;
  /** The user's identity key that the leaf must name (register/rotate). */
  identity: IdentityPublicKeys;
}

/**
 * Checks a leaf against the user's newest leaf and verifies the owner
 * signature. Throws KtError. Rules:
 *
 *   register  only when the user has no leaf; key_version 1; signed by the new key
 *   rotate    previous leaf is not a revoke; key_version = previous + 1;
 *             signed by the previous key (signerPk must hash to its mldsaPkHash)
 *   revoke    names exactly the previous leaf's key and version; signed by it
 *
 * Register and rotate must name the user's identity key (ML-DSA and ML-KEM
 * fingerprints). A revoked key cannot be followed by anything yet: key reset
 * after a revoke or a lost key is future work.
 */
export async function checkSubmission(
  s: LeafSubmission,
  prev: StoredLeaf | null,
  now: number,
): Promise<void> {
  const { leaf } = s;
  if (Math.abs(leaf.timestampMs - now) > MAX_LEAF_CLOCK_SKEW_MS) {
    throw new KtError(400, "Leaf timestamp is too far from the server clock.");
  }
  const prevLeaf = prev ? decodeLeaf(prev.leaf) : null;
  if (prevLeaf?.op === KtOp.Revoke) {
    throw new KtError(409, "The current key is revoked; nothing can follow a revoke yet.");
  }

  if (leaf.op === KtOp.Register || leaf.op === KtOp.Rotate) {
    if (
      !bytesEqual(leaf.mldsaPkHash, await sha256(s.identity.mldsaPk)) ||
      !bytesEqual(leaf.mlkemPkHash, await sha256(s.identity.mlkemPk))
    ) {
      throw new KtError(400, "Leaf key fingerprints do not match the identity key.");
    }
  }

  switch (leaf.op) {
    case KtOp.Register:
      if (prevLeaf) throw new KtError(409, "A key is already registered; use rotate.");
      if (leaf.keyVersion !== 1) throw new KtError(400, "A first registration must have key_version 1.");
      break;
    case KtOp.Rotate:
      if (!prevLeaf) throw new KtError(409, "No key registered yet; use register.");
      if (leaf.keyVersion !== prevLeaf.keyVersion + 1) {
        throw new KtError(409, `Rotation must have key_version ${prevLeaf.keyVersion + 1}.`);
      }
      if (!bytesEqual(await sha256(s.signerPk), prevLeaf.mldsaPkHash)) {
        throw new KtError(400, "A rotation must be signed by the previous key (signerPk).");
      }
      break;
    case KtOp.Revoke:
      if (!prevLeaf) throw new KtError(409, "No key registered yet.");
      if (
        leaf.keyVersion !== prevLeaf.keyVersion ||
        !bytesEqual(leaf.mldsaPkHash, prevLeaf.mldsaPkHash) ||
        !bytesEqual(leaf.mlkemPkHash, prevLeaf.mlkemPkHash)
      ) {
        throw new KtError(409, "A revoke must name the current key and key_version.");
      }
      break;
  }

  // Same check as shared's verifyOwnerSig, inlined so the signer rules above
  // and the hash checks stay in one place.
  if (!bytesEqual(await sha256(s.ownerSig), leaf.ownerSigHash)) {
    throw new KtError(400, "ownerSig does not match the leaf's owner_sig hash.");
  }
  if (leaf.op !== KtOp.Rotate && !bytesEqual(await sha256(s.signerPk), leaf.mldsaPkHash)) {
    throw new KtError(400, "Owner signature must be made by the key the leaf names.");
  }
  let ok = false;
  try {
    ok = ml_dsa87.verify(s.ownerSig, ownerSignedMessage(leaf), s.signerPk);
  } catch {
    ok = false;
  }
  if (!ok) throw new KtError(400, "Invalid owner signature.");
}

// ---------------------------------------------------------------------------
// Storage: Postgres

type Db = PrismaClient | Prisma.TransactionClient;

const big = (n: number) => BigInt(n);
const num = (b: bigint) => Number(b);
const bytes = (b: Uint8Array) => new Uint8Array(b);

interface LeafRow {
  idx: bigint;
  leaf: Uint8Array;
  leafHash: Uint8Array;
  userHash: Uint8Array;
  keyVersion: number;
  ownerSig: Uint8Array;
}
interface SthRow {
  treeSize: bigint;
  rootHash: Uint8Array;
  timestamp: bigint;
  signature: Uint8Array;
}

const toLeaf = (r: LeafRow): StoredLeaf => ({
  index: num(r.idx),
  leaf: bytes(r.leaf),
  leafHash: bytes(r.leafHash),
  userHash: bytes(r.userHash),
  keyVersion: r.keyVersion,
  ownerSig: bytes(r.ownerSig),
});
const toSth = (r: SthRow): SignedTreeHead => ({
  treeSize: num(r.treeSize),
  rootHash: bytes(r.rootHash),
  timestampMs: num(r.timestamp),
  signature: bytes(r.signature),
});

/**
 * Nodes never change once written, so committed reads can be cached for the
 * life of the process. Writes made inside a transaction are only cached by
 * the caller after commit (see prismaKtStorage.locked), so a rolled-back
 * append never leaves a phantom node in the cache.
 */
export class NodeCache {
  private readonly map = new Map<string, Hash>();
  constructor(private readonly max = 200_000) {}
  get(level: number, index: number) {
    return this.map.get(`${level}:${index}`);
  }
  set(level: number, index: number, h: Hash) {
    if (this.map.size >= this.max) this.map.clear();
    this.map.set(`${level}:${index}`, h);
  }
  clear() {
    this.map.clear();
  }
}

/** NodeStore over the KtNode table. */
export function prismaNodeStore(
  db: Db,
  cache?: NodeCache,
  onPut?: (level: number, index: number, hash: Hash) => void,
): NodeStore {
  return {
    async get(level, index) {
      const hit = cache?.get(level, index);
      if (hit) return hit;
      const row = await db.ktNode.findUnique({
        where: { level_idx: { level, idx: big(index) } },
        select: { hash: true },
      });
      if (!row) return undefined;
      const h = bytes(row.hash);
      if (!onPut) cache?.set(level, index, h); // only cache committed reads
      return h;
    },
    async put(level, index, hash) {
      await db.ktNode.create({ data: { level, idx: big(index), hash: bytes(hash) } });
      onPut?.(level, index, hash);
    },
  };
}

function prismaTx(db: Db, nodes: NodeStore): KtTx {
  return {
    nodes,
    async size() {
      const r = await db.ktLeaf.aggregate({ _max: { idx: true } });
      return r._max.idx === null ? 0 : num(r._max.idx) + 1;
    },
    async latestLeafForUser(userHash, beforeSize) {
      const row = await db.ktLeaf.findFirst({
        where: {
          userHash: bytes(userHash),
          ...(beforeSize !== undefined ? { idx: { lt: big(beforeSize) } } : {}),
        },
        orderBy: { idx: "desc" },
      });
      return row ? toLeaf(row) : null;
    },
    async insertLeaf(r) {
      await db.ktLeaf.create({
        data: {
          idx: big(r.index),
          leaf: bytes(r.leaf),
          leafHash: bytes(r.leafHash),
          userHash: bytes(r.userHash),
          keyVersion: r.keyVersion,
          ownerSig: bytes(r.ownerSig),
        },
      });
    },
    async latestSth() {
      const row = await db.ktSth.findFirst({ orderBy: { treeSize: "desc" } });
      return row ? toSth(row) : null;
    },
    async insertSth(s) {
      await db.ktSth.create({
        data: {
          treeSize: big(s.treeSize),
          rootHash: bytes(s.rootHash),
          timestamp: big(s.timestampMs),
          signature: bytes(s.signature),
        },
      });
    },
  };
}

export function prismaKtStorage(prisma: PrismaClient, cache = new NodeCache()): KtStorage {
  const base = prismaTx(prisma, prismaNodeStore(prisma, cache));
  return {
    ...base,
    async locked(fn) {
      const written: [number, number, Hash][] = [];
      const result = await prisma.$transaction(
        async (tx) => {
          // Held until commit or rollback; serialises appends across processes.
          await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${KT_ADVISORY_LOCK_KEY})`);
          const nodes = prismaNodeStore(tx, cache, (l, i, h) => written.push([l, i, h]));
          return fn(prismaTx(tx, nodes));
        },
        { maxWait: 20_000, timeout: 30_000 },
      );
      for (const [l, i, h] of written) cache.set(l, i, h);
      return result;
    },
    async leaves(from, to) {
      const rows = await prisma.ktLeaf.findMany({
        where: { idx: { gte: big(from), lt: big(to) } },
        orderBy: { idx: "asc" },
      });
      return rows.map(toLeaf);
    },
    async sthAt(size) {
      const row = await prisma.ktSth.findUnique({ where: { treeSize: big(size) } });
      return row ? toSth(row) : null;
    },
  };
}

// ---------------------------------------------------------------------------
// Storage: memory (tests, and the evil relay's alternative views)

export function memoryKtStorage(): KtStorage & { nodeStore: MemoryNodeStore; sths: SignedTreeHead[]; rows: StoredLeaf[] } {
  const rows: StoredLeaf[] = [];
  const sths: SignedTreeHead[] = [];
  const nodeStore = new MemoryNodeStore();
  const tx: KtTx = {
    nodes: nodeStore,
    async size() {
      return rows.length;
    },
    async latestLeafForUser(userHash, beforeSize = rows.length) {
      for (let i = Math.min(beforeSize, rows.length) - 1; i >= 0; i--) {
        if (bytesEqual(rows[i]!.userHash, userHash)) return rows[i]!;
      }
      return null;
    },
    async insertLeaf(r) {
      if (r.index !== rows.length) throw new Error("memoryKtStorage: out-of-order insert");
      rows.push(r);
    },
    async latestSth() {
      return sths[sths.length - 1] ?? null;
    },
    async insertSth(s) {
      if (sths.some((x) => x.treeSize === s.treeSize)) throw new Error("duplicate STH size");
      sths.push(s);
    },
  };
  const lock = new Mutex();
  return {
    ...tx,
    nodeStore,
    sths,
    rows,
    locked: (fn) => lock.run(() => fn(tx)),
    async leaves(from, to) {
      return rows.slice(from, to);
    },
    async sthAt(size) {
      return sths.find((s) => s.treeSize === size) ?? null;
    },
  };
}
