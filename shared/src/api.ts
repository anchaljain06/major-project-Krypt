// JSON shapes of the KT endpoints (plan 2.23), plus parsers that turn
// untrusted JSON into typed values. Bytes are standard padded base64; integers
// are JSON numbers (all below 2^53). Parsers only check shape; the caller still
// verifies signatures and proofs (monitor.ts).
//
//   GET /kt/sth
//     -> SignedTreeHeadJson   { treeSize, rootHash, timestamp, signature }
//
//   GET /kt/consistency?from=<m>&to=<n>        1 <= m <= n, n a published STH size
//     -> ConsistencyResponseJson { from, to, proof: [hash...] }
//
//   GET /kt/proof?user=<username>[&size=<n>]
//     Latest leaf for the user in the tree of size n (default: latest STH).
//     -> LookupResponseJson { sth, leafIndex, leaf, ownerSig, proof: [hash...] }
//     404 if the user has no leaf.
//
//   GET /kt/leaves?from=<m>&to=<n>             0 <= m <= n, n a published STH size
//     Every leaf with m <= index < n, unfiltered (clients must not ask the
//     server to filter by user: it could hide entries). The server may cap
//     n - m and return fewer; the client then pages using `to`.
//     -> LeavesResponseJson { from, to, compactRange: [hash...], leaves: [{ index, leaf, ownerSig }] }
//     compactRange is CompactRange.hashes at size m; the client authenticates
//     it against the root it already holds for size m.

import { fromBase64 } from "./bytes.ts";
import { KT_LEAF_SIZE } from "./leaf.ts";
import type { Hash } from "./merkle.ts";
import { hashesFromJson, sthFromJson, type SignedTreeHead, type SignedTreeHeadJson } from "./sth.ts";

export interface ConsistencyResponseJson {
  from: number;
  to: number;
  proof: string[];
}

export interface LookupResponseJson {
  sth: SignedTreeHeadJson;
  leafIndex: number;
  /** The 153-byte KT leaf. */
  leaf: string;
  /** Full owner signature; its SHA-256 is in the leaf. */
  ownerSig: string;
  proof: string[];
}

export interface LeafEntryJson {
  index: number;
  leaf: string;
  ownerSig: string;
}

export interface LeavesResponseJson {
  from: number;
  to: number;
  compactRange: string[];
  leaves: LeafEntryJson[];
}

export interface ConsistencyResponse {
  from: number;
  to: number;
  proof: Hash[];
}

export interface LookupResponse {
  sth: SignedTreeHead;
  leafIndex: number;
  leaf: Uint8Array;
  ownerSig: Uint8Array;
  proof: Hash[];
}

export interface LeafEntry {
  index: number;
  leaf: Uint8Array;
  ownerSig: Uint8Array;
}

export interface LeavesResponse {
  from: number;
  to: number;
  compactRange: Hash[];
  leaves: LeafEntry[];
}

function obj(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new TypeError(`${what} must be an object`);
  return v as Record<string, unknown>;
}

function uint(o: Record<string, unknown>, k: string): number {
  const v = o[k];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new TypeError(`${k} must be a non-negative integer`);
  return v;
}

function bytes(o: Record<string, unknown>, k: string): Uint8Array {
  const v = o[k];
  if (typeof v !== "string") throw new TypeError(`${k} must be a base64 string`);
  return fromBase64(v);
}

function leafBytes(o: Record<string, unknown>): Uint8Array {
  const leaf = bytes(o, "leaf");
  if (leaf.length !== KT_LEAF_SIZE) throw new TypeError(`leaf must be ${KT_LEAF_SIZE} bytes`);
  return leaf;
}

export function parseConsistencyResponse(v: unknown): ConsistencyResponse {
  const o = obj(v, "consistency response");
  const from = uint(o, "from");
  const to = uint(o, "to");
  if (from > to) throw new RangeError("from > to");
  return { from, to, proof: hashesFromJson(o.proof) };
}

export function parseLookupResponse(v: unknown): LookupResponse {
  const o = obj(v, "lookup response");
  return {
    sth: sthFromJson(o.sth),
    leafIndex: uint(o, "leafIndex"),
    leaf: leafBytes(o),
    ownerSig: bytes(o, "ownerSig"),
    proof: hashesFromJson(o.proof),
  };
}

export function parseLeavesResponse(v: unknown): LeavesResponse {
  const o = obj(v, "leaves response");
  const from = uint(o, "from");
  const to = uint(o, "to");
  if (from > to) throw new RangeError("from > to");
  if (!Array.isArray(o.leaves)) throw new TypeError("leaves must be an array");
  const leaves = o.leaves.map((e, i) => {
    const eo = obj(e, "leaf entry");
    const index = uint(eo, "index");
    // Leaves must be contiguous from `from`, so a gap cannot hide an entry.
    if (index !== from + i) throw new RangeError(`leaf ${i} has index ${index}, expected ${from + i}`);
    return { index, leaf: leafBytes(eo), ownerSig: bytes(eo, "ownerSig") };
  });
  if (leaves.length !== to - from) throw new RangeError(`expected ${to - from} leaves, got ${leaves.length}`);
  return { from, to, compactRange: hashesFromJson(o.compactRange), leaves };
}
