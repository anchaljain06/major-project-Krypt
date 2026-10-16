// Client-side KT checks. Every function here assumes the server is the
// adversary: it reports what failed instead of trusting any field.
//
// Typical client flows:
//
//   Lookup (Alice wants Bob's key):
//     r = parseLookupResponse(GET /kt/proof?user=bob)
//     verifyLookup({ username: "bob", response: r, verifySth, mldsaPk, mlkemPk, minKeyVersion })
//     checkSthChain(lastSeenSth, r.sth, GET /kt/consistency?from=last&to=r.sth.treeSize)
//     and compare against the witness's cosigned head (witness/latest.json).
//
//   Self-monitoring (Bob on login):
//     verify the new STH, checkSthChain(last, new, proof)
//     page through GET /kt/leaves?from=last.treeSize&to=new.treeSize
//     verifyLeafRange(compactRangeAtLast, leaves, newSth)   (authenticates the batch)
//     selfMonitor(myUserHash, myKnownKeys, decoded leaves)  (alerts on keys Bob never made)

import { bytesEqual, sha256 } from "./bytes.ts";
import type { LeafEntry, LookupResponse } from "./api.ts";
import { KtOp, decodeLeaf, hashUsername, verifyOwnerSig, type KtLeaf, type VerifySigFn } from "./leaf.ts";
import { CompactRange, emptyRoot, hashLeaf, verifyConsistency, verifyInclusion, type Hash } from "./merkle.ts";
import { verifyTreeHead, type SignedTreeHead, type TreeHead, type VerifyFn } from "./sth.ts";

export type CheckResult = { ok: true } | { ok: false; kind: ChainFailure; reason: string };

/**
 * shrank:       next is smaller than prev (rollback or stale head).
 * fork:         same size, different root: two signed heads prove equivocation.
 * inconsistent: the consistency proof does not link prev to next.
 */
export type ChainFailure = "shrank" | "fork" | "inconsistent";

/**
 * Checks that `next` extends `prev` (both already signature-checked by the
 * caller). `prev = null` is first contact and is accepted as is. Timestamps
 * are not compared: freshness is a separate policy decision.
 */
export async function checkSthChain(
  prev: TreeHead | null,
  next: TreeHead,
  consistencyProof: Hash[],
): Promise<CheckResult> {
  if (prev === null) return { ok: true };
  if (next.treeSize < prev.treeSize) {
    return { ok: false, kind: "shrank", reason: `tree size went from ${prev.treeSize} to ${next.treeSize}` };
  }
  if (next.treeSize === prev.treeSize) {
    if (!bytesEqual(prev.rootHash, next.rootHash)) {
      return { ok: false, kind: "fork", reason: `two different roots for tree size ${next.treeSize}` };
    }
    return { ok: true };
  }
  if (prev.treeSize === 0) {
    // Every tree extends the empty tree, but a size-0 head must carry the empty root.
    if (!bytesEqual(prev.rootHash, await emptyRoot())) {
      return { ok: false, kind: "fork", reason: "size-0 head with a non-empty root" };
    }
    return { ok: true };
  }
  const ok = await verifyConsistency(prev.treeSize, next.treeSize, prev.rootHash, next.rootHash, consistencyProof);
  if (!ok) {
    return {
      ok: false,
      kind: "inconsistent",
      reason: `consistency proof ${prev.treeSize} -> ${next.treeSize} does not verify`,
    };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------

/** A key the owner knows they published (kept in the owner's local state). */
export interface KnownKey {
  keyVersion: number;
  mldsaPkHash: Uint8Array;
  mlkemPkHash: Uint8Array;
  /** True once the owner has revoked this key themselves. */
  revoked?: boolean;
}

export type MonitorAlertKind = "unknown-key" | "unexpected-revoke";

export interface MonitorAlert {
  kind: MonitorAlertKind;
  index: number;
  leaf: KtLeaf;
  message: string;
}

/**
 * Scans leaves the owner has not seen yet. Any register/rotate leaf for the
 * owner's name with a key they do not know is a rogue key (the attack KT
 * exists to expose). A revoke they did not perform is also flagged: it is a
 * denial-of-service on their identity even if not a key swap.
 */
export function selfMonitor(
  myUserHash: Uint8Array,
  myKnownKeys: readonly KnownKey[],
  newLeaves: readonly { index: number; leaf: KtLeaf }[],
): MonitorAlert[] {
  const alerts: MonitorAlert[] = [];
  for (const { index, leaf } of newLeaves) {
    if (!bytesEqual(leaf.userHash, myUserHash)) continue;
    const known = myKnownKeys.find(
      (k) =>
        k.keyVersion === leaf.keyVersion &&
        bytesEqual(k.mldsaPkHash, leaf.mldsaPkHash) &&
        bytesEqual(k.mlkemPkHash, leaf.mlkemPkHash),
    );
    if (leaf.op === KtOp.Revoke) {
      if (!known?.revoked) {
        alerts.push({
          kind: "unexpected-revoke",
          index,
          leaf,
          message: `leaf ${index} revokes key version ${leaf.keyVersion}, which you did not revoke`,
        });
      }
    } else if (!known) {
      alerts.push({
        kind: "unknown-key",
        index,
        leaf,
        message: `leaf ${index} publishes key version ${leaf.keyVersion} for your name, which you did not create`,
      });
    }
  }
  return alerts.sort((a, b) => a.index - b.index);
}

// ---------------------------------------------------------------------------

export type LeafRangeResult =
  | { ok: true; range: CompactRange; leaves: { index: number; leaf: KtLeaf; ownerSig: Uint8Array }[] }
  | { ok: false; reason: string };

/**
 * Authenticates a batch from /kt/leaves: starting from the compact range at
 * `start.size` (already trusted), appending the batch must give exactly the
 * signed root of `sth`. The batch must therefore end at sth.treeSize. A
 * server that hides, adds or reorders a leaf fails here.
 */
export async function verifyLeafRange(
  start: CompactRange,
  entries: readonly LeafEntry[],
  sth: TreeHead,
): Promise<LeafRangeResult> {
  if (start.size + entries.length !== sth.treeSize) {
    return { ok: false, reason: `batch covers ${start.size}..${start.size + entries.length}, head is ${sth.treeSize}` };
  }
  let range = start;
  const leaves: { index: number; leaf: KtLeaf; ownerSig: Uint8Array }[] = [];
  for (const [i, e] of entries.entries()) {
    if (e.index !== start.size + i) return { ok: false, reason: `leaf ${i} has index ${e.index}` };
    let leaf: KtLeaf;
    try {
      leaf = decodeLeaf(e.leaf);
    } catch (err) {
      return { ok: false, reason: `leaf ${e.index} is malformed: ${(err as Error).message}` };
    }
    if (!bytesEqual(await sha256(e.ownerSig), leaf.ownerSigHash)) {
      return { ok: false, reason: `leaf ${e.index}: ownerSig does not match the hash in the leaf` };
    }
    range = await range.append(await hashLeaf(e.leaf));
    leaves.push({ index: e.index, leaf, ownerSig: e.ownerSig });
  }
  if (!bytesEqual(await range.root(), sth.rootHash)) {
    return { ok: false, reason: "leaves do not hash to the signed root" };
  }
  return { ok: true, range, leaves };
}

// ---------------------------------------------------------------------------

export interface VerifyLookupOptions {
  /** The name the client asked for. */
  username: string;
  response: LookupResponse;
  /** Verifies the log's signature (ML-DSA-87 with the log key shipped in the build). */
  verifySth: VerifyFn;
  /** Full keys served alongside the proof (e.g. in the prekey bundle). Checked against the leaf if given. */
  mldsaPk?: Uint8Array;
  mlkemPk?: Uint8Array;
  /** Reject a key older than one already pinned for this contact (Phase 1 cannot prove "latest"). */
  minKeyVersion?: number;
  /** If given, a register leaf's self-signature is checked with mldsaPk. */
  verifySig?: VerifySigFn;
}

export type LookupResult = { ok: true; leaf: KtLeaf; sth: SignedTreeHead } | { ok: false; reason: string };

/**
 * Verifies a key lookup: STH signature, leaf format and owner, key hashes,
 * version pin and inclusion in the signed tree. The caller must still check
 * the returned STH against its last seen head and the witness (checkSthChain).
 */
export async function verifyLookup(opts: VerifyLookupOptions): Promise<LookupResult> {
  const { response: r } = opts;
  if (!(await verifyTreeHead(r.sth, opts.verifySth))) return { ok: false, reason: "bad STH signature" };

  let leaf: KtLeaf;
  try {
    leaf = decodeLeaf(r.leaf);
  } catch (err) {
    return { ok: false, reason: `malformed leaf: ${(err as Error).message}` };
  }
  if (!bytesEqual(leaf.userHash, await hashUsername(opts.username))) {
    return { ok: false, reason: "leaf belongs to a different user" };
  }
  if (leaf.op === KtOp.Revoke) return { ok: false, reason: `key version ${leaf.keyVersion} is revoked` };
  if (!bytesEqual(await sha256(r.ownerSig), leaf.ownerSigHash)) {
    return { ok: false, reason: "ownerSig does not match the hash in the leaf" };
  }
  if (opts.mldsaPk && !bytesEqual(await sha256(opts.mldsaPk), leaf.mldsaPkHash)) {
    return { ok: false, reason: "ML-DSA key does not match the logged key" };
  }
  if (opts.mlkemPk && !bytesEqual(await sha256(opts.mlkemPk), leaf.mlkemPkHash)) {
    return { ok: false, reason: "ML-KEM key does not match the logged key" };
  }
  if (opts.minKeyVersion !== undefined && leaf.keyVersion < opts.minKeyVersion) {
    return { ok: false, reason: `key version ${leaf.keyVersion} is older than pinned ${opts.minKeyVersion}` };
  }
  if (opts.verifySig && opts.mldsaPk && leaf.op === KtOp.Register) {
    if (!(await verifyOwnerSig(leaf, r.ownerSig, opts.mldsaPk, opts.verifySig))) {
      return { ok: false, reason: "register leaf is not signed by its own key" };
    }
  }
  const included = await verifyInclusion(r.leafIndex, r.sth.treeSize, await hashLeaf(r.leaf), r.proof, r.sth.rootHash);
  if (!included) return { ok: false, reason: "inclusion proof does not verify against the signed root" };
  return { ok: true, leaf, sth: r.sth };
}
