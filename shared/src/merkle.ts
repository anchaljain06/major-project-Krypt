// RFC 9162 (Certificate Transparency 2.0) Merkle tree with SHA-256.
//
//   leaf hash  = SHA-256(0x00 || d)
//   node hash  = SHA-256(0x01 || left || right)
//   MTH({})    = SHA-256()            (empty string)
//
// The 0x00/0x01 prefixes are the domain separation that stops an attacker
// passing an interior node off as a leaf (second-preimage attack on the tree).
//
// Two ways to use this module:
//   * list functions (merkleTreeHash, inclusionProof, consistencyProof) take
//     every leaf in memory. Good for tests and small clients.
//   * MerkleLog keeps perfect-subtree hashes in a NodeStore keyed by
//     (level, index), so a server can append and prove without loading leaves.
// Both generate proofs with the same RFC 9162 PATH/SUBPROOF code; only the
// source of subtree hashes differs.

import { bytesEqual, sha256 } from "./bytes.ts";

export const HASH_SIZE = 32;
export type Hash = Uint8Array;

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

/** SHA-256(0x00 || data): RFC 9162 §2.1.1 leaf hash. */
export function hashLeaf(data: Uint8Array): Promise<Hash> {
  return sha256(LEAF_PREFIX, data);
}

/** SHA-256(0x01 || left || right): RFC 9162 §2.1.1 interior node hash. */
export function hashChildren(left: Hash, right: Hash): Promise<Hash> {
  return sha256(NODE_PREFIX, left, right);
}

/** MTH of the empty tree: SHA-256 of the empty string. */
export function emptyRoot(): Promise<Hash> {
  return sha256();
}

// ---------------------------------------------------------------------------
// Integer helpers. Sizes and indices are JS numbers (safe integers), so we use
// arithmetic instead of bitwise operators, which truncate to 32 bits.

function isSafeUint(v: number): boolean {
  return Number.isSafeInteger(v) && v >= 0;
}

function assertSafeUint(name: string, v: number): void {
  if (!isSafeUint(v)) throw new RangeError(`${name} must be a non-negative safe integer, got ${v}`);
}

/** Largest power of two strictly less than n (n >= 2): the RFC's split point k. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function isPowerOfTwo(n: number): boolean {
  if (n < 1) return false;
  while (n % 2 === 0) n /= 2;
  return n === 1;
}

function half(n: number): number {
  return Math.floor(n / 2);
}

function isOdd(n: number): boolean {
  return n % 2 === 1;
}

function popcount(n: number): number {
  let c = 0;
  while (n > 0) {
    c += n % 2;
    n = half(n);
  }
  return c;
}

function isHash(h: unknown): h is Hash {
  return h instanceof Uint8Array && h.length === HASH_SIZE;
}

// ---------------------------------------------------------------------------
// Proof generation, RFC 9162 §2.1.3.1 (PATH) and §2.1.4.1 (SUBPROOF).
//
// `SubtreeHash(start, end)` returns MTH(D[start:end]). The recursion only ever
// asks for ranges produced by the RFC's split, so every perfect range it asks
// for is aligned (start is a multiple of its size). A NodeStore can therefore
// answer those directly.

type SubtreeHash = (start: number, end: number) => Promise<Hash>;

/** PATH(m, D[start:end]) with m relative to start. */
async function path(sub: SubtreeHash, m: number, start: number, end: number): Promise<Hash[]> {
  const n = end - start;
  if (n === 1) return [];
  const k = splitPoint(n);
  if (m < k) {
    return [...(await path(sub, m, start, start + k)), await sub(start + k, end)];
  }
  return [...(await path(sub, m - k, start + k, end)), await sub(start, start + k)];
}

/** SUBPROOF(m, D[start:end], b). */
async function subproof(
  sub: SubtreeHash,
  m: number,
  start: number,
  end: number,
  b: boolean,
): Promise<Hash[]> {
  const n = end - start;
  if (m === n) {
    // The old tree is exactly this subtree. If it is the whole old tree (b) the
    // verifier already knows its hash, so it is left out of the proof.
    return b ? [] : [await sub(start, end)];
  }
  const k = splitPoint(n);
  if (m <= k) {
    return [...(await subproof(sub, m, start, start + k, b)), await sub(start + k, end)];
  }
  return [...(await subproof(sub, m - k, start + k, end, false)), await sub(start, start + k)];
}

function checkInclusionArgs(index: number, size: number): void {
  assertSafeUint("index", index);
  assertSafeUint("size", size);
  if (index >= size) throw new RangeError(`index ${index} is not below tree size ${size}`);
}

function checkConsistencyArgs(m: number, n: number): void {
  assertSafeUint("m", m);
  assertSafeUint("n", n);
  // A proof from the empty tree is meaningless: every tree extends it.
  if (m === 0) throw new RangeError("consistency proof from an empty tree is undefined");
  if (m > n) throw new RangeError(`old size ${m} is larger than new size ${n}`);
}

/** MTH over a slice of already-hashed leaves, by the RFC's recursive definition. */
function listSubtreeHash(leafHashes: Hash[]): SubtreeHash {
  const mth = async (start: number, end: number): Promise<Hash> => {
    const n = end - start;
    if (n === 1) return leafHashes[start]!;
    const k = splitPoint(n);
    return hashChildren(await mth(start, start + k), await mth(start + k, end));
  };
  return mth;
}

/** MTH(D[n]) of raw leaf entries (RFC 9162 §2.1.1). */
export async function merkleTreeHash(leaves: Uint8Array[]): Promise<Hash> {
  if (leaves.length === 0) return emptyRoot();
  const hashes = await Promise.all(leaves.map(hashLeaf));
  return listSubtreeHash(hashes)(0, hashes.length);
}

/** Inclusion proof PATH(index, D[n]) over raw leaf entries. */
export async function inclusionProof(leaves: Uint8Array[], index: number): Promise<Hash[]> {
  checkInclusionArgs(index, leaves.length);
  const hashes = await Promise.all(leaves.map(hashLeaf));
  return path(listSubtreeHash(hashes), index, 0, hashes.length);
}

/**
 * Consistency proof PROOF(m, D[n]) between the first m leaves and all of
 * `leaves`. Returns [] when m == n (nothing to prove).
 */
export async function consistencyProof(leaves: Uint8Array[], m: number): Promise<Hash[]> {
  checkConsistencyArgs(m, leaves.length);
  if (m === leaves.length) return [];
  const hashes = await Promise.all(leaves.map(hashLeaf));
  return subproof(listSubtreeHash(hashes), m, 0, hashes.length, true);
}

// ---------------------------------------------------------------------------
// Verification, exactly as RFC 9162 §2.1.3.2 and §2.1.4.2. Both return false
// (never throw) on any malformed input so callers can treat "false" as "the
// server lied or the data is corrupt" without a try/catch.

/** RFC 9162 §2.1.3.2: verify that leafHash is entry `index` of the tree of `size` with `root`. */
export async function verifyInclusion(
  index: number,
  size: number,
  leafHash: Hash,
  proof: Hash[],
  root: Hash,
): Promise<boolean> {
  if (!isSafeUint(index) || !isSafeUint(size)) return false;
  if (!isHash(leafHash) || !isHash(root) || !Array.isArray(proof) || !proof.every(isHash)) return false;

  // 1. leaf_index must be below tree_size.
  if (index >= size) return false;
  // 2. fn = leaf_index, sn = tree_size - 1.  3. r = hash.
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  // 4. Walk the path.
  for (const p of proof) {
    // 4a. More path elements than the tree is high: fail.
    if (sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      // 4b. We are a right child, or the rightmost node of a level whose
      // sibling was promoted: p is on the left.
      r = await hashChildren(p, r);
      // 4b.ii. Skip levels where this node has no right sibling.
      if (!isOdd(fn)) {
        while (!isOdd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      r = await hashChildren(r, p);
    }
    // 4c.
    fn = half(fn);
    sn = half(sn);
  }
  // 5. All levels consumed and the root matches.
  return sn === 0 && bytesEqual(r, root);
}

/**
 * RFC 9162 §2.1.4.2: verify that the tree of size n with newRoot extends the
 * tree of size m with oldRoot. The RFC defines verification for 0 < m < n; the
 * edge cases follow transparency-dev/merkle:
 *   m == n  valid iff the proof is empty and the roots are equal;
 *   m == 0  always false (nothing to prove; callers handle the empty tree);
 *   m >  n  always false.
 */
export async function verifyConsistency(
  m: number,
  n: number,
  oldRoot: Hash,
  newRoot: Hash,
  proof: Hash[],
): Promise<boolean> {
  if (!isSafeUint(m) || !isSafeUint(n)) return false;
  if (!isHash(oldRoot) || !isHash(newRoot) || !Array.isArray(proof) || !proof.every(isHash)) return false;
  if (m === 0 || m > n) return false;
  if (m === n) return proof.length === 0 && bytesEqual(oldRoot, newRoot);

  // 1. An empty proof cannot prove anything for m < n.
  if (proof.length === 0) return false;
  // 2. If m is a power of two the old root is itself a node of the new tree
  // and is omitted from the proof (SUBPROOF's b flag); put it back.
  const path = isPowerOfTwo(m) ? [oldRoot, ...proof] : proof;
  // 3. fn = first - 1, sn = second - 1.
  let fn = m - 1;
  let sn = n - 1;
  // 4. Skip the levels where the old tree's last leaf is a right child; those
  // nodes are inside the old tree's rightmost perfect subtree.
  while (isOdd(fn)) {
    fn = half(fn);
    sn = half(sn);
  }
  // 5. Seed both running hashes with the first path element.
  let fr = path[0]!;
  let sr = path[0]!;
  // 6. Fold in the remaining elements.
  for (const c of path.slice(1)) {
    // 6a.
    if (sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      // 6b. c is a left sibling: it belongs to both the old and new trees.
      fr = await hashChildren(c, fr);
      sr = await hashChildren(c, sr);
      if (!isOdd(fn)) {
        while (!isOdd(fn) && fn !== 0) {
          fn = half(fn);
          sn = half(sn);
        }
      }
    } else {
      // c is a right sibling: only the new tree contains it.
      sr = await hashChildren(sr, c);
    }
    // 6c.
    fn = half(fn);
    sn = half(sn);
  }
  // 7.
  return sn === 0 && bytesEqual(fr, oldRoot) && bytesEqual(sr, newRoot);
}

// ---------------------------------------------------------------------------
// Storage-backed log.

/**
 * Persistent store of perfect-subtree hashes. Node (level, index) is the root
 * of leaves [index * 2^level, (index + 1) * 2^level). Level 0 holds leaf
 * hashes. Because the log is append-only, a node never changes once written,
 * so it is valid for every later tree size. The server backs this with the
 * kt_nodes table; methods may be sync or async.
 */
export interface NodeStore {
  get(level: number, index: number): Promise<Hash | undefined> | Hash | undefined;
  put(level: number, index: number, hash: Hash): Promise<void> | void;
}

export class MemoryNodeStore implements NodeStore {
  private readonly nodes = new Map<string, Hash>();

  get(level: number, index: number): Hash | undefined {
    return this.nodes.get(`${level}:${index}`);
  }

  put(level: number, index: number, hash: Hash): void {
    this.nodes.set(`${level}:${index}`, hash);
  }

  /** Number of stored nodes (about 2n for n leaves). */
  get count(): number {
    return this.nodes.size;
  }
}

/**
 * An append-only RFC 9162 log over a NodeStore. The caller owns the current
 * size (e.g. `SELECT count(*) FROM kt_leaves`) and must serialise appends: two
 * concurrent appends at the same size would write conflicting nodes.
 */
export class MerkleLog {
  private _size: number;
  private readonly store: NodeStore;

  constructor(store: NodeStore, size = 0) {
    assertSafeUint("size", size);
    this.store = store;
    this._size = size;
  }

  get size(): number {
    return this._size;
  }

  /** Appends a leaf hash; returns its index. Writes the leaf and every perfect subtree it completes. */
  async append(leafHash: Hash): Promise<number> {
    if (!isHash(leafHash)) throw new TypeError("leafHash must be 32 bytes");
    const index = this._size;
    await this.store.put(0, index, leafHash);
    let h = leafHash;
    let level = 0;
    let i = index;
    // While the new node is a right child, its parent's subtree is now complete.
    while (isOdd(i)) {
      const left = await this.node(level, i - 1);
      h = await hashChildren(left, h);
      level += 1;
      i = half(i);
      await this.store.put(level, i, h);
    }
    this._size = index + 1;
    return index;
  }

  /** MTH of the first `size` leaves (any size up to the current one). */
  async root(size = this._size): Promise<Hash> {
    this.checkSize(size);
    if (size === 0) return emptyRoot();
    return this.subtreeHash(0, size);
  }

  /** Inclusion proof for leaf `index` in the tree of `size` leaves. */
  async inclusionProof(index: number, size = this._size): Promise<Hash[]> {
    this.checkSize(size);
    checkInclusionArgs(index, size);
    return path(this.subtreeHash, index, 0, size);
  }

  /** Consistency proof between tree sizes m and n (n defaults to the current size). */
  async consistencyProof(m: number, n = this._size): Promise<Hash[]> {
    this.checkSize(n);
    checkConsistencyArgs(m, n);
    if (m === n) return [];
    return subproof(this.subtreeHash, m, 0, n, true);
  }

  /** Compact range (right border) of the tree of `size` leaves; see CompactRange. */
  async compactRange(size = this._size): Promise<CompactRange> {
    this.checkSize(size);
    const hashes: Hash[] = [];
    // Perfect subtrees from left to right, one per set bit of size, largest first.
    let start = 0;
    let p = 1;
    while (p * 2 <= size) p *= 2;
    for (; p >= 1; p /= 2) {
      if (start + p <= size) {
        hashes.push(await this.subtreeHash(start, start + p));
        start += p;
      }
    }
    return CompactRange.fromHashes(size, hashes);
  }

  private checkSize(size: number): void {
    assertSafeUint("size", size);
    if (size > this._size) throw new RangeError(`size ${size} is beyond the log size ${this._size}`);
  }

  private async node(level: number, index: number): Promise<Hash> {
    const h = await this.store.get(level, index);
    // A missing node means the store is corrupt or out of sync with the size we
    // were given. Failing loudly beats publishing a wrong root.
    if (!h) throw new Error(`NodeStore is missing node (${level}, ${index})`);
    return h;
  }

  // Arrow function so it can be passed to path/subproof unbound.
  private readonly subtreeHash: SubtreeHash = async (start, end) => {
    const n = end - start;
    if (isPowerOfTwo(n) && start % n === 0) {
      let level = 0;
      for (let s = n; s > 1; s /= 2) level++;
      return this.node(level, start / n);
    }
    const k = splitPoint(n);
    return hashChildren(await this.subtreeHash(start, start + k), await this.subtreeHash(start + k, end));
  };
}

// ---------------------------------------------------------------------------
// Compact range: the O(log n) state needed to keep appending and computing
// roots without the leaves. Clients use it to authenticate a batch of leaves
// fetched from /kt/leaves: start from the range at the old size (checked
// against the old signed root), append the new leaves, compare with the new
// signed root.

export class CompactRange {
  /** Number of leaves covered. */
  readonly size: number;
  /** Roots of the perfect subtrees covering [0, size), left to right, largest first. */
  readonly hashes: readonly Hash[];

  private constructor(size: number, hashes: Hash[]) {
    this.size = size;
    this.hashes = hashes;
  }

  static empty(): CompactRange {
    return new CompactRange(0, []);
  }

  /**
   * Builds a range from its hashes, e.g. as served by the log. Pass
   * `expectedRoot` (from a verified STH of the same size) to authenticate it:
   * the hashes fold to that root only if they are the real ones.
   */
  static async fromHashes(size: number, hashes: Hash[], expectedRoot?: Hash): Promise<CompactRange> {
    assertSafeUint("size", size);
    if (hashes.length !== popcount(size) || !hashes.every(isHash)) {
      throw new RangeError(`a compact range of size ${size} has ${popcount(size)} hashes`);
    }
    const range = new CompactRange(size, [...hashes]);
    if (expectedRoot !== undefined && !bytesEqual(await range.root(), expectedRoot)) {
      throw new Error("compact range does not match the expected root");
    }
    return range;
  }

  /** Returns a new range with one more leaf. Ranges are immutable values. */
  async append(leafHash: Hash): Promise<CompactRange> {
    if (!isHash(leafHash)) throw new TypeError("leafHash must be 32 bytes");
    const hashes = [...this.hashes];
    let h = leafHash;
    // Each trailing 1 bit of the old size is a perfect subtree the new leaf completes.
    for (let s = this.size; isOdd(s); s = half(s)) {
      h = await hashChildren(hashes.pop()!, h);
    }
    hashes.push(h);
    return new CompactRange(this.size + 1, hashes);
  }

  async root(): Promise<Hash> {
    if (this.hashes.length === 0) return emptyRoot();
    let r = this.hashes[this.hashes.length - 1]!;
    for (let i = this.hashes.length - 2; i >= 0; i--) r = await hashChildren(this.hashes[i]!, r);
    return r;
  }
}
