# @krypt/shared

Key transparency building blocks shared by the Krypt frontend, backend and witness (plan step 2.20).

- RFC 9162 Merkle tree with SHA-256, proofs and verifiers.
- KT leaf encoding (strategy §5.2).
- Signed tree heads and witness cosignatures.
- JSON shapes for the `/kt/*` endpoints.
- Client checks: STH chain, self-monitoring, lookup verification.

There are no runtime dependencies. Hashing uses `globalThis.crypto.subtle`, so the same code runs in browsers and in Node 20 or later. Signing goes through callbacks, so the package never imports ML-DSA itself.

```
npm install
npm test        # tsc typecheck + vitest
npm run build   # emits dist/ (JS + .d.ts) for the witness copy
```

## How to consume it

| Consumer | How |
|---|---|
| frontend (Vite) | Import the TS sources directly. Add the alias `"@krypt/shared": path.resolve(__dirname, "../shared/src/index.ts")` in `vite.config.ts` and the same path in `tsconfig` `paths`. Vite compiles the `.ts` imports. |
| primary-backend (tsc, `rootDir: ./src`) | Uses a vendored TS copy in `primary-backend/src/vendor/krypt-shared/`, because Render builds from `primary-backend/` alone. Refresh it with `npm run vendor:shared` in `primary-backend/`; `test/vendor.test.ts` fails if the copy is stale. |
| witness | Uses a vendored JS copy (built from `dist/`) in `witness/lib/krypt-shared/`, because the witness will move to its own repository. Refresh it with `node witness/scripts/vendor-shared.mjs`. |

The sources import each other with explicit `.ts` extensions and use only erasable TypeScript syntax. They therefore also run under Node's type stripping (Node 22.18 or later) without a build.

## API

All hashes are 32-byte `Uint8Array`s. Sizes, indices and timestamps are JS numbers and must be safe integers. Functions that hash are async, because Web Crypto is async.

### merkle.ts

```ts
hashLeaf(data): Promise<Hash>                     // SHA-256(0x00 || data)
hashChildren(left, right): Promise<Hash>          // SHA-256(0x01 || left || right)
emptyRoot(): Promise<Hash>                        // SHA-256("")
merkleTreeHash(leaves: Uint8Array[]): Promise<Hash>
inclusionProof(leaves: Uint8Array[], index): Promise<Hash[]>       // RFC 9162 PATH
consistencyProof(leaves: Uint8Array[], m): Promise<Hash[]>         // PROOF(m, D[n]); [] if m == n
verifyInclusion(index, size, leafHash, proof, root): Promise<boolean>        // §2.1.3.2
verifyConsistency(m, n, oldRoot, newRoot, proof): Promise<boolean>           // §2.1.4.2

interface NodeStore { get(level, index); put(level, index, hash) }  // sync or async
class MemoryNodeStore implements NodeStore
class MerkleLog {             // server side: no leaves in memory
  constructor(store: NodeStore, size = 0)
  size: number
  append(leafHash): Promise<number>
  root(size?): Promise<Hash>
  inclusionProof(index, size?): Promise<Hash[]>
  consistencyProof(m, n?): Promise<Hash[]>
  compactRange(size?): Promise<CompactRange>
}
class CompactRange {          // O(log n) right border; client side
  static empty(); static fromHashes(size, hashes, expectedRoot?)
  append(leafHash): Promise<CompactRange>; root(): Promise<Hash>
}
```

How the verifiers handle edge cases (they never throw):

| Case | Result |
|---|---|
| `m == n` | `true` only if the proof is empty and the roots are equal |
| `m == 0` | always `false` (`checkSthChain` handles the empty tree) |
| `m > n` | always `false` |
| any hash that is not 32 bytes | always `false` |

The last rule is stricter than upstream in one probe. The test file documents it.

Proof generators throw a `RangeError` on bad arguments. Node `(level, index)` covers leaves `[index·2^level, (index+1)·2^level)`. Nodes never change once written. `MerkleLog` callers must serialise appends.

### leaf.ts

```ts
KT_LEAF_SIZE = 153; KtOp = { Register: 1, Rotate: 2, Revoke: 3 }
normalizeUsername(u)            // NFC(lower(u))
hashUsername(u): Promise<Hash>  // SHA-256("krypt-user\0" || NFC(lower(u)))
encodeLeaf(leaf: KtLeaf): Uint8Array; decodeLeaf(bytes): KtLeaf   // decode throws on any deviation
ownerSignedMessage(body): Uint8Array
ownerSigner(op): "new-key" | "previous-key" | "revoked-key"
buildLeafBody(input): Promise<KtLeafBody>; attachOwnerSig(body, sig): Promise<KtLeaf>
ktLeafHash(leaf): Promise<Hash>
verifyOwnerSig(leaf, ownerSig, signerPk, verify): Promise<boolean>
```

Leaf layout (big-endian):

```
"KRYPT-KT-v1\0"(12) op(1) user_hash(32) key_version u32(4)
SHA-256(mldsa_pk)(32) SHA-256(mlkem_pk)(32) timestamp_ms u64(8) SHA-256(owner_sig)(32)
```

**What owner_sig signs:**

```
ML-DSA-87.Sign(sk, "KRYPT-KT-OWNER-v1\0" || op || user_hash || u32 key_version
               || SHA-256(mldsa_pk) || SHA-256(mlkem_pk) || u64 timestamp_ms)
```

The signing key depends on the operation:

| Operation | Signing key |
|---|---|
| register | the new key |
| rotate | the previous key (version − 1) |
| revoke | the key being revoked |

If a user registers again after earlier leaves, it is a key reset. Clients must show it as a safety-number change.

### sth.ts

```ts
encodeTreeHead(th) / decodeTreeHead(bytes)        // "KRYPT-STH-v1" || u64 size || root || u64 ts_ms (60 B)
signTreeHead(th, sign) / verifyTreeHead(sth, verify)
logIdFromPublicKey(pk)                            // SHA-256(log pk)
cosignatureMessage(witness, tsMs, logId, th)      // "KRYPT-COSIG-v1\0" || u8 len || name || u64 ts || log_id || tree head
cosignTreeHead(th, logId, witness, tsMs, sign) / verifyCosignature(th, logId, cosig, verify)
sthToJson / sthFromJson, cosignatureToJson / cosignatureFromJson, hashesToJson / hashesFromJson
type SignFn = (msg) => Uint8Array | Promise<Uint8Array>
type VerifyFn = (msg, sig) => boolean | Promise<boolean>
```

The log signs with ML-DSA-87 and witnesses sign with ML-DSA-44. Both use FIPS 204 with an empty context string. Domain separation comes from the tags in the messages.

### api.ts: endpoint shapes for plan 2.23

Bytes are standard padded base64. Integers are JSON numbers.

```
GET /kt/sth                         -> { treeSize, rootHash, timestamp, signature }
GET /kt/consistency?from=m&to=n     -> { from, to, proof: [b64] }               1 <= m <= n
GET /kt/proof?user=<name>[&size=n]  -> { sth, leafIndex, leaf, ownerSig, proof } latest leaf for user; 404 if none
GET /kt/leaves?from=m&to=n          -> { from, to, compactRange: [b64], leaves: [{ index, leaf, ownerSig }] }
```

For `/kt/leaves`:

- Leaves must be contiguous from `m`.
- The server may cap the page size and return a smaller `to`.
- `compactRange` is `MerkleLog.compactRange(m).hashes`.
- Never filter by user.

Each endpoint has a parser: `parseConsistencyResponse`, `parseLookupResponse` and `parseLeavesResponse`.

### monitor.ts

```ts
checkSthChain(prev: TreeHead | null, next: TreeHead, proof): Promise<{ok:true} | {ok:false, kind:"shrank"|"fork"|"inconsistent", reason}>
selfMonitor(myUserHash, myKnownKeys: KnownKey[], newLeaves: {index, leaf}[]): MonitorAlert[]   // "unknown-key" | "unexpected-revoke"
verifyLeafRange(start: CompactRange, entries: LeafEntry[], sth): Promise<{ok, range, leaves} | {ok:false, reason}>
verifyLookup({ username, response, verifySth, mldsaPk?, mlkemPk?, minKeyVersion?, verifySig? }): Promise<{ok, leaf, sth} | {ok:false, reason}>
```

**Owner on login:**

1. Verify the new STH.
2. Run `checkSthChain(last, new, proof)`.
3. Fetch `/kt/leaves` pages and authenticate the starting compact range with `CompactRange.fromHashes(m, hashes, lastRoot)`.
4. Run `verifyLeafRange`, then `selfMonitor`.

**Lookup:** run `verifyLookup`, then `checkSthChain` against the last seen head and the witness's `latest.json`.

## Tests

| Source | What it covers |
|---|---|
| transparency-dev/merkle (Apache-2.0, commit in `test/vectors/*.json`) | hasher values, the RFC 6962 reference tree and its compact ranges, the proof-shape tables from `proof_test.go`, and all 196 `testdata` inclusion and consistency probes. Regenerate with `scripts/import-tdm-vectors.mjs`. |
| fast-check | inclusion and consistency proofs for sizes 1..300 verify, and tampered proofs, roots, indices and sizes fail. |
| exhaustive | every proof for n ≤ 40. |
| leaf round-trip | layout, domain separation, ML-DSA-87 owner signatures. |
| sth and monitor | signed tree heads, cosignatures, monitor flows. |
