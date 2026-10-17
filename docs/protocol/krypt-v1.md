# Krypt v1 protocol specification

Status: implemented in `frontend/src/crypto/` (branch `wt/protocol-core`).
This document is the source of truth. If the code and this document disagree,
the code has a bug or this document needs a reviewed change (see section 13).

Design rationale lives in `Krypt_Major_Project_Strategy.md` sections 4.2-4.9.
This document fixes every byte.

| Module | Role |
|---|---|
| `encoding.ts` | Length-prefixed encoding, labels, strict base64url, constant-time compare |
| `kdf.ts` | SHA-256, HMAC-SHA-256, HKDF-SHA-256 (Web Crypto), root/chain/message-key KDFs |
| `pq.ts` | ML-KEM-768, ML-KEM-1024, X-Wing, ML-DSA-87 wrappers with exact length checks |
| `prekeys.ts` | Prekey generation, signing, wire shapes, bundle verification, `PrekeyStore` |
| `handshake.ts` | Krypt-X3K `initiate` / `respond`, transcript `T` |
| `envelope.ts` | Header and envelope types, canonical header bytes, JSON and binary codecs |
| `session.ts` | `SessionManager`: the KEM ratchet state machine |
| `session-store.ts` | `SessionStore` (memory + encrypted IndexedDB), IndexedDB `PrekeyStore` |

---

## 1. Notation and encoding

- `‖` is concatenation. **Every** composite input in this protocol is encoded
  with `lp(...)`, never by raw concatenation:

  ```
  lp(x1, ..., xk) = u32be(len(x1)) ‖ x1 ‖ ... ‖ u32be(len(xk)) ‖ xk
  ```

  Length prefixes make the encoding injective: two different field lists can
  never produce the same bytes, so a key of one type can never be read as a key
  of another type (the PQXDH encoding fix).
- `u32(x)` is the 4-byte big-endian encoding of an integer `0 ≤ x < 2^32`.
  Inside `lp` it is a 4-byte field like any other.
- `ε` is the empty byte string. An absent optional field is encoded as `ε`
  (its length prefix is `00 00 00 00`). Because key ids are never 0 and keys are
  never empty, `ε` is unambiguous.
- Strings (usernames, labels, suite names, content types) are UTF-8 bytes.
- `H(x)` = SHA-256. `HMAC(k, m)` = HMAC-SHA-256. `HKDF(salt, ikm, info, L)` =
  HKDF-SHA-256 (RFC 5869) via Web Crypto. `0^32` is 32 zero bytes.
- Base64url (RFC 4648 section 5, **no padding**) is used only at the network
  edge. Decoding is strict: characters outside `[A-Za-z0-9_-]`, padding,
  length `≡ 1 (mod 4)`, and non-zero unused trailing bits are all rejected, so
  every byte string has exactly one accepted encoding.

### 1.1 Labels

| Label (ASCII) | Used in |
|---|---|
| `Krypt-v1` | First field of the handshake transcript `T` |
| `Krypt-X3K` | Handshake HKDF info |
| `Krypt-init` | Initiator signature `σ_A` |
| `Krypt-SPK` | Signed prekey signature |
| `Krypt-OPK` | One-time prekey signature |
| `Krypt-RK` | Root KDF info |
| `Krypt-MK` | Message key + IV HKDF info |
| `Krypt-AAD-v1` | AES-GCM associated data |
| `krypt-session-v1` | Associated data for session state encrypted at rest |
| `mlkem768`, `xwing` | Ratchet suite identifiers |

## 2. Algorithms and key hierarchy

| Use | Algorithm | Sizes (bytes) |
|---|---|---|
| Identity signature `IK` | ML-DSA-87 (FIPS 204) | pk 2592, sk 4896, sig 4627 |
| Signed prekey `SPK`, one-time prekeys `OPK` | ML-KEM-1024 (FIPS 203) | ek 1568, dk 3168, ct 1568, ss 32 |
| Ratchet keys, suite `mlkem768` | ML-KEM-768 | ek 1184, dk 2400, ct 1088, ss 32 |
| Ratchet keys, suite `xwing` | X-Wing (ML-KEM-768 + X25519), `ml_kem768_x25519` | ek 1216, dk 32 (seed), ct 1120, ss 32 |
| Symmetric | HKDF/HMAC-SHA-256, AES-256-GCM (96-bit IV, 128-bit tag) | |

ML-DSA signatures sign a domain-separated message (`lp(label, ...)`) with the
FIPS 204 context string left empty. The label already separates every use; an
empty context keeps the signatures verifiable by any FIPS 204 implementation.

```text
IK (ML-DSA-87, long-term) ──signs──> SPK, OPK[i] (ML-KEM-1024)
                          ──signs──> σ_A over H(T) (initiator only)

ss1 = KEM(SPK), ss2 = KEM(OPK) ──HKDF "Krypt-X3K"──> RK0 ‖ CK0       (epoch 0)

RK ──KDF_RK(RK, ss, ctx)──> RK' ‖ CK_e     (one root step per new epoch e)

CK ──HMAC 0x02──> CK'    (chain step)
CK ──HMAC 0x01──> mk ──HKDF "Krypt-MK"──> key(32) ‖ iv(12)   (one per message)
```

The identity key used today is the ML-DSA-87 key in the account's existing
identity bundle (`mlkem.ts`): the server's `identityKey` field is the JSON
string `{"version": ..., "kem": <base64>, "dsa": <base64>}` (standard base64
with padding). Krypt v1 reads only `dsa`; the long-term ML-KEM-1024 `kem` key is
not used by v1 (prekeys replace it).

## 3. Prekeys

Bob generates and uploads, once and then on refill:

- one **signed prekey** `SPK` (ML-KEM-1024), rotated weekly;
- `N` (default 100) **one-time prekeys** `OPK[i]` (ML-KEM-1024).

Each prekey has a `keyId`: a random integer in `[1, 2^31 - 1]` (fits a Postgres
`int4` and a JSON number). Signatures:

```
sig_SPK = Sign(IK_B, lp("Krypt-SPK", u32(keyId), ek_SPK))
sig_OPK = Sign(IK_B, lp("Krypt-OPK", u32(keyId), ek_OPK))
```

### 3.1 Wire shapes (shared with the backend, `POST /prekeys`, `GET /bundle/:user`)

```jsonc
// upload
{ "signedPrekey":   { "keyId": 123, "publicKey": "<b64url>", "signature": "<b64url>" },
  "oneTimePrekeys": [ { "keyId": 456, "publicKey": "<b64url>", "signature": "<b64url>" } ] }

// bundle (one OPK row is claimed and deleted atomically by the server)
{ "username": "bob",
  "identityKey": "{\"version\":...,\"kem\":\"...\",\"dsa\":\"...\"}",
  "signedPrekey":  { "keyId": 123, "publicKey": "...", "signature": "..." } | null,
  "oneTimePrekey": { "keyId": 456, "publicKey": "...", "signature": "..." } | null }

// DELETE /prekeys/one-time (owner only): withdraw the listed OPKs, or all if keyIds is omitted
{ "keyIds": [456, 789] }            // -> { "success": true, "oneTimeRemaining": 0 }
```

`verifyBundle` (initiator) rejects the bundle unless: `signedPrekey` is present,
every base64url field decodes strictly to the exact length, each public key
passes the FIPS 203 modulus check, and each signature verifies under the `dsa`
key parsed from `identityKey` **with its own label** (`Krypt-SPK` for the signed
prekey, `Krypt-OPK` for the one-time prekey).
A missing `oneTimePrekey` is allowed (empty pool: SPK-only fallback, section 4.3).
Identity-key trust (key transparency, step 3.1 of the plan) is a separate hook:
`SessionManager` calls `trustIdentity(username, dsaPub)` before using any key.

### 3.2 Private halves and lifecycle (`PrekeyStore`)

- **Separate keyId namespaces.** SPK ids and OPK ids are independent: the
  store keeps them in separate tables, and the init header names them in
  separate fields (`spkId`, `opkId`). An `opkId` is only ever looked up among
  OPKs, so an id collision between the two kinds is harmless. Together with the
  distinct signature labels, the relay cannot make one kind stand in for the
  other.
- OPK private keys are deleted after the first successful handshake that used
  them (after AES-GCM verified the first message, section 4.2).
- **Stale OPKs.** Every OPK still on the server must have its private half on
  the device (the device may hold more: OPKs claimed by a peer whose init has
  not arrived yet). If the server lists more OPKs than the device holds, or an
  init names an OPK the device does not hold (`UNKNOWN_PREKEY`), the private
  halves were lost: the client withdraws all of its server OPKs and uploads a
  fresh batch, at most once an hour (such an init is unauthenticated, so the
  limit stops forged ones from forcing churn). OPK private halves generated
  for an upload that failed are deleted again.
- SPK private keys stay until rotation plus a grace period (recommended: delete
  the previous SPK two weeks after its replacement is uploaded) so that inits
  already in flight still work.
- **Session-id memory.** For **every** accepted handshake (with or without an
  OPK) Bob records `sessionId = H(T)` under the id of the SPK it used, and
  rejects any later init whose `sessionId` is already recorded
  (`INIT_REPLAY`). The memory for an SPK is deleted together with the SPK;
  after that, any init naming that SPK fails with `UNKNOWN_PREKEY`, so the
  memory never needs to outlive the key. This is what makes a repeated init
  header recognisable after the OPK private key is gone.
- **The SPK rotation interval is a security parameter.** A session started
  without an OPK has no forward secrecy for its epoch-0 messages until the SPK
  private key is deleted: anyone who later steals `dk_SPK` can decrypt them.
  Weekly rotation (plus the grace period) bounds that window to about three
  weeks. Later epochs are protected by the ratchet regardless.

## 4. Handshake: Krypt-X3K

### 4.1 Initiator (Alice)

1. `bundle = fetchBundle("bob")`; `verifyBundle(bundle)`; `trustIdentity("bob", IK_B)`.
2. `(ct1, ss1) = Encaps_1024(SPK_B)`.
3. If the bundle has an OPK: `(ct2, ss2) = Encaps_1024(OPK_B)`; else `ct2 = ss2 = ε`.
4. `(ek_A¹, dk_A¹) = KeyGen_suite()` (first ratchet key, suite `mlkem768` or `xwing`).
5. Transcript:

   ```
   T = lp("Krypt-v1", suite, "alice", "bob", IK_A, IK_B,
          u32(spkId), SPK_B, u32(opkId) | ε, OPK_B | ε,
          ct1, ct2 | ε, ek_A¹)
   ```

6. `RK0 ‖ CK0 = HKDF(0^32, lp(ss1, ss2 | ε), lp("Krypt-X3K", H(T)), 64)`
7. `σ_A = Sign(IK_A, lp("Krypt-init", H(T)))`
8. `sessionId = H(T)` (32 bytes).

Alice's state: `RK = RK0`, `CKs = CK0` (epoch 0), no receiving chain, her
pending ratchet pair `(ek_A¹, dk_A¹)`. The **init header**
`{spkId, opkId, ct1, ct2, ek = ek_A¹, sig = σ_A}` is attached to **every**
epoch-0 message until a message from Bob is received (lost first message,
section 4.4).

### 4.2 Responder (Bob)

Everything below runs inside the per-peer lock for `from` (section 7). Bob
first looks the `sessionId` up, and only then does any public-key work:

1. `sessionId` equals the live session's id → this is a **repeated init
   header**: ordinary chain processing (section 5.5), no handshake.
2. `sessionId` is tombstoned → `SESSION_CLOSED`. No `init` field → `UNKNOWN_SESSION`.
3. Check `pn = 0` and no `kem` field (epoch 0 is enforced by the parser).
4. Simultaneous-initiation tie-break (section 4.5).
5. `IK_A = fetchIdentity(from)`; `trustIdentity(from, IK_A)`. (Bob does **not**
   fetch Alice's bundle: that would consume one of her OPKs.)
6. Load `SPK_B[spkId]`; missing → `UNKNOWN_PREKEY`.
7. `sessionId` already in the session-id memory of that SPK → `INIT_REPLAY`.
8. If `opkId` is set, load `OPK_B[opkId]` (OPK namespace only); missing →
   `UNKNOWN_PREKEY`.
9. Rebuild `T` from his own copies of `SPK_B`, `OPK_B`, `IK_B` and the header's
   `ct1, ct2, ek`; verify `σ_A` under `IK_A` (`BAD_SIGNATURE`), then require
   `H(T) = sessionId`.
10. `ss1 = Decaps(dk_SPK, ct1)`, `ss2 = Decaps(dk_OPK, ct2)` or `ε`; derive `RK0 ‖ CK0`.
11. Set `RK = RK0`, `CKr = CK0` (epoch 0), `CKs = ⊥`, peer ratchet key `ek_A¹`.
12. Decrypt the message on `CK0`. **Only if AES-GCM verifies**, commit in this
    order: persist the session, delete `dk_OPK`, record `sessionId` in the SPK's
    session-id memory.

**Atomicity of the session-id test-and-insert.** Steps 1-12 run under one
lock, so the check in steps 1/7 and the insert in step 12 cannot interleave
with another delivery of the same init. The lock is per peer, which is enough:
`T` contains the initiator's username, so two inits with the same `sessionId`
always come from the same `from` and therefore take the same lock. (An init
whose `from` was changed fails at step 9.) The formal model's injective
agreement result relies on this. The commit order is crash-safe: if Bob
crashes after persisting the session, a repeat of the init hits step 1.

Why Alice signs: a KEM authenticates only the receiver. The cost is
deniability: Bob can prove that Alice started the session.

### 4.3 Empty one-time pool

If the server has no OPK left, the bundle's `oneTimePrekey` is `null` and the
handshake uses `ss1` only. Such a session has **no forward secrecy for epoch 0
until the SPK rotates**: epoch-0 messages are exposed if `dk_SPK` leaks before
it is deleted, which is why the rotation interval is a security parameter
(section 3.2). Later epochs are protected by the ratchet. Replays of an
SPK-only init are rejected by the session-id memory.

### 4.4 Lost first message and repeated init headers

Every epoch-0 message from Alice carries the same init header (until she
receives anything from Bob). If message 0 is lost, Bob starts the session from
whichever epoch-0 message arrives first and caches skipped keys for the earlier
numbers. A repeated init header whose `sessionId` matches Bob's live session is
the **same** session: it goes down the normal chain path and never resets state.

### 4.5 Session replacement and simultaneous initiation

There is at most one live session per peer. Each peer record also keeps the ids
of the last 32 closed or replaced sessions (tombstones). When an init header
with session id `X` arrives from peer `P` and the live session is `S`:

| Condition | Action |
|---|---|
| `S.sessionId = X` | Same session; normal chain processing |
| `X` is tombstoned | Reject `SESSION_CLOSED` (covers replays of closed sessions) |
| `X` is in the session-id memory | Reject `INIT_REPLAY` (an old session whose tombstone has rolled over, or whose record was lost) |
| No `S` | Respond (section 4.2) |
| `S` was initiated by us and **unconfirmed** (nothing received from `P` on it yet) | Simultaneous initiation. Keep the session whose id is **bytewise smaller**. If `X < S.sessionId`: respond to `X`, tombstone `S`. Otherwise reject `SESSION_SUPERSEDED`, keep `S`, and **tombstone `X`** if the init authenticates (see below) |
| Otherwise (`S` confirmed, or we are `S`'s responder) | The peer started over (lost state, new device). Respond to `X`, tombstone `S` |

Both sides know both ids, so they apply the same comparison and converge on
the same session without any extra round trip. The comparison is on the raw
32-byte ids, not on their base64url strings: the base64url alphabet is not in
ASCII order, so string comparison can pick the other session. The rule uses
the transcript hash, not usernames, so the relay cannot choose the winner.
Messages already sent on the losing session cannot be decrypted by the peer
(`SESSION_SUPERSEDED`); the application should re-send them.

All of these actions happen only after the incoming init passes every check in
section 4.2, including AES-GCM verification of its message.

**Tombstoning the losing init.** When Bob rejects `X` with
`SESSION_SUPERSEDED`, he still runs steps 5-12 of section 4.2 on it. If the
init authenticates (signature, `H(T) = sessionId`, AES-GCM of its message),
then, under the same per-peer lock and before throwing, he:

1. tombstones `X` (the live session `S` is saved unchanged),
2. deletes the OPK it used, and
3. records `X` in the SPK's session-id memory,

in that order, as for an accepted init. The decrypted message is discarded.
Without this, nothing would be left of `X`: once `S` is confirmed, a late or
relay-replayed copy of `X` would match the "peer started over" row, replace
the agreed session, and leave both sides with `SESSION_CLOSED` (the peer has
already tombstoned `X` itself). With it, every later copy is refused with
`SESSION_CLOSED` (or `INIT_REPLAY` once the tombstone rolls over). If the
losing init does **not** authenticate, Bob still answers `SESSION_SUPERSEDED`
and records nothing, so forged inits cannot fill the tombstone list. A genuine
new handshake from the peer has a new transcript and therefore a new
`sessionId`, so it is not affected. This is the single exception to the
"no state change on error" rule of section 10.

## 5. The KEM ratchet

### 5.1 State

| Field | Meaning |
|---|---|
| `sessionId`, `peer`, `role`, `suite` | Fixed at the handshake |
| `rk` | Root key |
| `sendEpoch`, `cks`, `ns`, `pn` | Current sending chain: epoch (`-1` = none), chain key (`⊥` = none), next message number, length of the previous sending chain |
| `sendKem` | `(ct, ek)` attached to headers of the current sending chain (epoch ≥ 1) |
| `init` | Init header (initiator, epoch 0, until confirmed) |
| `peerAcked` | The peer has proved it holds our current chain's ratchet data |
| `ourEk`, `ourDk` | Our pending ratchet pair; the peer's next epoch encapsulates to it |
| `peerEk` | The peer's newest `ek` that we have not yet encapsulated to |
| `recvEpoch`, `ckr`, `nr` | Current receiving chain |
| `skipped` | Cached message keys `(epoch, n) → mk` with an expiry time |
| `established` | Something from the peer has been authenticated on this session |

Epoch parity is fixed: the initiator sends on even epochs (0, 2, 4, ...), the
responder on odd epochs (1, 3, 5, ...). An epoch number therefore names exactly
one chain and its direction.

### 5.2 Chain step and message encryption

```
mk  = HMAC(CK, 0x01)
CK' = HMAC(CK, 0x02)
key ‖ iv = HKDF(0^32, mk, "Krypt-MK", 44)        // key = 32 bytes, iv = 12 bytes
body = AES-256-GCM(key, iv, plaintext, AAD)     // ciphertext ‖ 16-byte tag
```

Each `mk` is used once. The IV is derived because the key is unique per
message; the pair (key, IV) can repeat only if chain state is rolled back
(section 7).

### 5.3 Root step and the epoch rule

```
ctx(e, ek, ct)    = lp(u32(e), H(ek), H(ct))
KDF_RK(RK, ss, c) = HKDF(salt = RK, ikm = ss, info = lp("Krypt-RK", c), 64) → RK' ‖ CK
```

**Epoch rule:** every root step uses the epoch number of the chain it creates.
`ctx` binds the KEM output to the exact key and ciphertext (`H(ek)`), so the
protocol stays safe even with a KEM that does not bind its public key.

### 5.4 Sending (`encrypt`)

1. If there is no session: run the handshake (section 4.1). `CKs = CK0`, `sendEpoch = 0`.
2. **Send step** if `CKs = ⊥` (Bob's bootstrap) or (`peerEk` is set and
   `ns ≥ K`, see 5.6):
   - `(ct, ss) = Encaps_suite(peerEk)`; `(ek', dk') = KeyGen_suite()`
   - `e' = recvEpoch + 1` (the epoch after the chain that delivered `peerEk`)
   - `(RK, CKs) = KDF_RK(RK, ss, ctx(e', peerEk, ct))`
   - `pn = ns` (0 if there was no sending chain), `ns = 0`, `sendEpoch = e'`,
     `sendKem = (ct, ek')`, `ourEk, ourDk = ek', dk'`, `peerEk = ⊥`,
     `peerAcked = false`, `init = ⊥`.
3. Chain step on `CKs`; the header gets `n = ns`, `pn`, and:
   - `kem = sendKem` and/or `init` **while `peerAcked = false`**;
   - nothing extra once `peerAcked = true` (only reachable when K > 1).
4. **Persist** the advanced state (`CKs'`, `ns + 1`) **before** encrypting and
   returning the envelope. If persisting fails, nothing is encrypted.

**Bob's bootstrap** is step 2 with `CKs = ⊥`: his first send encapsulates to
`ek_A¹` and creates epoch 1 with `ctx(1, ek_A¹, ct_B)`.

Alice's send step happens lazily at her next `encrypt`, not at the moment she
receives Bob's new key. The bytes on the wire are identical to the eager
description in the strategy; lazy evaluation means a state snapshot taken
between receive and send holds no fresh `dk` yet.

### 5.5 Receiving (`decrypt`)

All work happens on a copy of the state. **The copy is committed only after
AES-GCM verifies**; on any error the stored state is unchanged.

1. Validate the envelope strictly (section 8); `to` must be us.
2. If `sessionId` is not the live session's id: tombstoned → `SESSION_CLOSED`;
   otherwise with `init` go to section 4.2 / 4.5, without → `UNKNOWN_SESSION`.
3. `suite` must equal the session's suite. `epoch` must have the peer's parity.
4. If `(epoch, n)` is in the skipped cache: use that `mk` (removed on success).
5. Else if `epoch = recvEpoch`: `n < nr` → `DUPLICATE`; `n - nr > MAX_SKIP` →
   `TOO_MANY_SKIPPED`; otherwise cache `mk` for `nr..n-1` and use `mk_n`.
6. Else if `epoch > recvEpoch` (a new chain from the peer):
   - require `epoch = sendEpoch + 1`, our `dk` present and a `kem` field;
     otherwise `BAD_EPOCH`;
   - finish the previous receiving chain: `pn < nr` → `BAD_HEADER`;
     cache `mk` for `nr..pn-1` (gap capped by `MAX_SKIP`);
   - **receive step:** `ss = Decaps(ourDk, kem.ct)`;
     `(RK, CKr) = KDF_RK(RK, ss, ctx(epoch, ourEk, kem.ct))`; erase `ourDk`;
   - cache `mk` for `0..n-1` of the new chain, use `mk_n`;
   - `peerEk = kem.ek`, `peerAcked = true`, `init = ⊥`, drop skipped keys of
     epochs older than `epoch - 2`.
7. Else (`epoch < recvEpoch`, key not cached) → `STALE_EPOCH`.
8. AES-GCM decrypt with the header as AAD. Failure → `AUTH_FAILED`.
9. Commit: `established = true`, store the new skipped keys, persist.

Why there are no ratchet collisions: a root step fires only when a **new peer
key** arrives, never because of arrival timing, and epochs alternate by parity,
so both sides apply root updates in the same order.

### 5.6 Sparse mode (`ratchetEveryK`, experiment E7)

`K = 1` (default) is the alternating ratchet: every message of a new epoch
carries `(ct, ek)`, and a party ratchets on its first send after receiving the
peer's new key. With `K > 1` a party keeps sending on its current chain until it
has sent `K` messages on it, and only then performs the send step. Once the peer
has acknowledged the chain's ratchet data (`peerAcked`), headers stop carrying
it, which is where the bandwidth saving comes from. Larger `K` means fewer
ratchet steps and therefore slower healing (section 9).

What sparse mode saves is mainly KEM work and epochs, not always header bytes:
a chain's ratchet data is acknowledged only when the peer ratchets, which with
strictly alternating traffic happens after the peer's own `K` sends, so about
half of the headers still carry `(ct, ek)`. One-sided bursts benefit more.
Experiment E7 should report both numbers.

## 6. Skipped keys and limits

| Limit | Value | Enforced |
|---|---|---|
| `MAX_SKIP` | 1000 keys per chain per message | Gap in the current chain, the `pn` catch-up, and the new chain's `n` |
| `MAX_SKIPPED_TOTAL` | 2000 keys per session | Oldest entries evicted first |
| `SKIPPED_TTL` | 7 days | Expired keys deleted on every operation |
| Epoch window | Current and previous receiving epoch | Keys of older epochs deleted at each receive step |
| Usernames | 1-64 UTF-8 bytes | Envelope parser |
| `contentType` | 1-64 UTF-8 bytes | Envelope parser |
| `body` | 16 bytes to 64 MiB + 16 | Envelope parser |
| `epoch`, `n`, `pn` | `0 ≤ x < 2^32` | Envelope parser; encrypt refuses to wrap `n` |
| Tombstones | 32 per peer | Session store |

Skipped keys are created only when a message authenticates, so an attacker who
cannot produce valid ciphertexts cannot fill the cache.

## 7. No-rollback rules (nonce safety)

A rolled-back chain would reuse `mk` (and so the AES-GCM key and IV) for a new
plaintext, which breaks GCM completely. Three rules prevent it:

1. **Persist before send.** `encrypt` saves the advanced chain before it encrypts.
2. **One writer.** Every `encrypt`/`decrypt`/`closeSession` runs inside
   `lock("krypt-session:" + self + ":" + peer, ...)`. The default lock is
   `navigator.locks` (shared across tabs of the origin) when present, else an
   in-process mutex. The state is reloaded from the store inside the lock, so a
   second tab never works from a stale copy. The same lock makes the
   session-id test-and-insert of section 4.2 atomic.
3. **No ratchet state in backups.** Session state is never exported in vault or
   chat backups (enforced at integration, `vault.ts`).

## 8. Wire format

### 8.1 Header (canonical bytes, used as AAD)

```
header = lp(u32(1), suite, sessionId, from, to, contentType,
            u32(epoch), u32(n), u32(pn), kemField, initField)

kemField  = lp(kem.ct, kem.ek)                                  or ε
initField = lp(u32(spkId), u32(opkId) | ε, ct1, ct2 | ε, ek, sig)  or ε

AAD = lp("Krypt-AAD-v1", header)
```

Every field of the header, including `contentType`, `from`, `to`, `sessionId`
(= `H(T)`), `epoch`, `n`, `pn` and all KEM material, is authenticated.

### 8.2 JSON envelope (what the relay carries)

```jsonc
{
  "v": 1,
  "suite": "mlkem768",              // or "xwing"
  "sessionId": "<b64url 32 B>",
  "from": "alice",
  "to": "bob",
  "contentType": "text",            // "text" | "image" | "audio" | any 1-64 byte string
  "epoch": 2,
  "n": 0,
  "pn": 3,
  "kem":  { "ct": "<b64url>", "ek": "<b64url>" },                 // optional
  "init": { "spkId": 123, "opkId": 456, "ct1": "...", "ct2": "...",
            "ek": "...", "sig": "..." },                           // optional, epoch 0 only; opkId/ct2 may be null
  "body": "<b64url ciphertext ‖ tag>"
}
```

The parser is strict: unknown keys, missing keys, wrong JSON types, non-integer
numbers, out-of-range values, non-canonical base64url, and wrong byte lengths
(per suite) are all `MALFORMED`. `kem` and `init` are omitted, never `null`.

### 8.3 Binary envelope

`binary = lp(header, body)`. It carries exactly the same information as the
JSON form and is provided for the bandwidth experiment (E5).

### 8.4 Sizes at K = 1 (suite `mlkem768`)

| Message | KEM material in header |
|---|---|
| Alice, epoch 0 | init: 2 × 1568 (ct1, ct2) + 1184 (ek) + 4627 (sig) ≈ 8.9 KB |
| Any later message | kem: 1088 (ct) + 1184 (ek) = 2272 B |

## 9. Security properties (claims, stated precisely)

| Property | Claim | Not claimed |
|---|---|---|
| Confidentiality | IND-CCA KEM + HKDF + AES-GCM; PQ against harvest-now-decrypt-later | Security if the device is owned |
| Forward secrecy | A compromise at time t does not reveal messages whose keys were already erased | Messages whose skipped keys are still cached (hence the cap and TTL) |
| Post-compromise security | Against a **passive** attacker holding party P's full state: secrecy returns at P's next ratchet step, the first message P sends after receiving the peer's next new `ek`. Messages in P's current epoch and in the peer's next epoch stay exposed (the peer encapsulates to P's stolen `dk`) | Against an **active** attacker who uses the stolen state to inject keys (impossible for any ratchet) |
| Authentication | Injective agreement on the handshake transcript, given Bob's session-id memory with an atomic test-and-insert (section 4.2) | Deniability (the initiator signs) |
| Ordering | Any delivery order inside MAX_SKIP decrypts; replays are rejected | Unbounded gaps |

DH ratchets also need a round trip to heal both directions. What KEMs cost is
bandwidth. With sparse mode (`K > 1`) P's "next ratchet step" happens only after
P has sent `K` messages on its current chain, so healing is delayed accordingly.

Further limits that an examiner should hear from us first:

- noble's ML-KEM / ML-DSA make no constant-time claim; X-Wing mode hedges this
  with X25519.
- Liveness is not claimed against a malicious relay: it can drop messages, and
  by reordering a simultaneous-initiation race it can make the two sides keep
  different sessions (both then report `SESSION_CLOSED`/`SESSION_SUPERSEDED`;
  the app recovers with `closeSession` and a new handshake). It cannot read,
  forge or replay messages.
- JavaScript cannot guarantee that erased keys are gone from memory.

## 10. Error policy

`decrypt` throws `DecryptError` with a `code`; nothing is returned and **no
state changes** (stored session, prekeys, replay cache) happen on any error.
The one exception is an authenticated init that loses the
simultaneous-initiation tie-break: its id is tombstoned before
`SESSION_SUPERSEDED` is thrown (section 4.5).
A failed message does not close the session: otherwise any unauthenticated
garbage could kill a conversation. The app drops the message and may show a
neutral warning.

| Code | Meaning |
|---|---|
| `MALFORMED` | Envelope failed strict parsing or length checks |
| `UNSUPPORTED_VERSION` | `v ≠ 1` |
| `NOT_FOR_ME` | `to` is not our username |
| `UNKNOWN_SESSION` | No such session and no init header |
| `SESSION_CLOSED` | Session id is tombstoned (closed or replaced) |
| `SESSION_SUPERSEDED` | Init lost the simultaneous-initiation tie-break (tombstoned if it authenticated) |
| `UNKNOWN_PREKEY` | SPK or OPK private key not found (OPK already used) |
| `INIT_REPLAY` | Init whose `sessionId` is in the session-id memory of its SPK |
| `BAD_SIGNATURE` | `σ_A` does not verify, or `H(T) ≠ sessionId` |
| `UNTRUSTED_IDENTITY` | `trustIdentity` refused the peer's key |
| `BAD_EPOCH` | Epoch has the wrong parity, skips ahead, lacks ratchet data, or suite mismatch |
| `BAD_HEADER` | Header fields contradict state (e.g. `pn < nr`) |
| `DUPLICATE` | `n` already received in the current chain |
| `STALE_EPOCH` | Message from an old epoch with no cached key |
| `TOO_MANY_SKIPPED` | Gap larger than `MAX_SKIP` |
| `AUTH_FAILED` | AES-GCM verification failed |

Handshake-side failures while encrypting (bad bundle) throw `HandshakeError`
with codes `NO_SIGNED_PREKEY`, `BAD_BUNDLE`, `BAD_PREKEY_SIGNATURE`,
`UNTRUSTED_IDENTITY`.

## 11. `SessionManager` API

```ts
new SessionManager({
  self: { username: string, identity: { dsaPub: Uint8Array, dsaSec: Uint8Array } },
  store: SessionStore,
  prekeys: PrekeyStore,
  fetchBundle: (username: string) => Promise<PrekeyBundleWire>,
  fetchIdentity: (username: string) => Promise<string>,  // identityKey JSON (as in the bundle)
  trustIdentity?: (username: string, dsaPub: Uint8Array) => Promise<boolean>, // default: accept
  suite?: 'mlkem768' | 'xwing',          // ratchet suite for sessions we initiate (default mlkem768)
  ratchetEveryK?: number,                // sparse mode, default 1
  lock?: <T>(name: string, fn: () => Promise<T>) => Promise<T>,
  now?: () => number,                    // ms clock, for TTL tests
})

encrypt(peer, plaintext: Uint8Array, contentType: string): Promise<EnvelopeV1>
decrypt(env: unknown): Promise<{ peer, plaintext, contentType, sessionId, epoch, n }>
getStatus(peer): Promise<SessionStatus | null>
closeSession(peer): Promise<void>
```

The responder's suite is whatever the initiator chose (it is bound in `T`);
both suites are always accepted.

```ts
type DecryptResult = { peer: string; plaintext: Uint8Array; contentType: string;
                       sessionId: string /* b64url */; epoch: number; n: number };
type SessionStatus = { sessionId: string; role: 'initiator' | 'responder'; suite: KemSuite;
                       established: boolean; epoch: number; sendEpoch: number;
                       recvEpoch: number; lastRatchetAt: number; createdAt: number };
```

### 11.1 Prekeys (`prekeys.ts`)

```ts
createPrekeyUpload(dsaSec, store: PrekeyStore, oneTimeCount = 100): Promise<PrekeyUploadWire>
createSignedPrekey(dsaSec, store, now?): Promise<PrekeyWire>          // rotation
createOneTimePrekeys(dsaSec, store, count, now?): Promise<PrekeyWire[]> // refill
verifyBundle(bundle: unknown, expectedUsername: string): VerifiedBundle // throws HandshakeError
parseIdentityKey(identityKey: string): Uint8Array                      // ML-DSA-87 public key

interface PrekeyStore {
  putSignedPrekey(rec); getSignedPrekey(keyId); deleteSignedPrekey(keyId); listSignedPrekeyIds();
  putOneTimePrekeys(recs); getOneTimePrekey(keyId); deleteOneTimePrekey(keyId); countOneTimePrekeys();
  hasAcceptedSession(spkId, sessionId); recordAcceptedSession(spkId, sessionId);
}
// implementations: MemoryPrekeyStore, IndexedDbPrekeyStore({ key, dbName?, indexedDB? })
```

### 11.2 Session store (`session-store.ts`)

```ts
interface SessionStore {
  load(peer: string): Promise<PeerRecord | undefined>;  // fresh copy
  save(peer: string, rec: PeerRecord): Promise<void>;    // atomic replace
}
type PeerRecord = { session: SessionState | null; closed: string[] };
// implementations: MemorySessionStore, IndexedDbSessionStore({ key: CryptoKey, dbName?, indexedDB? })
```

## 12. Session state at rest

`SessionStore` stores one record per peer: `{ session, closed[] }`. The
IndexedDB implementation serialises the record to JSON (bytes as base64url) and
encrypts it with a caller-provided AES-GCM `CryptoKey` (derived from the vault
key at integration): random 12-byte IV, `AAD = lp("krypt-session-v1", peer)`,
so a record cannot be moved to another peer's slot. The same scheme protects
prekey private keys in `IndexedDbPrekeyStore` (AAD label `krypt-prekeys-v1`).
The app layer's re-send outbox and seen message ids (section 4.5) use the same
key and scheme with AAD labels `krypt-outbox-v1` and `krypt-seen-v1`.

## 13. Changes relative to the strategy document

The strategy (sections 4.2-4.9) is the design; these are the places where this
spec had to choose or tighten something:

1. **Transcript fields.** `T` also binds the suite id, both usernames and both
   prekey ids (handoff section 11: algorithm ids, role ordering, identities).
   Absent OPK fields are `ε`.
2. **OPK signature label.** OPKs are signed under `Krypt-OPK`, not `Krypt-SPK`,
   and the bundle verifier checks each prekey under its own label, so the server
   cannot present a one-time key as a signed prekey or vice versa.
3. **Composite KDF inputs are length-prefixed** too: `info` of the handshake,
   root and AAD, and the handshake IKM `lp(ss1, ss2)`.
4. **AAD.** The strategy's `AD = H(T) ‖ header` is `lp("Krypt-AAD-v1", header)`
   with `H(T)` carried inside the header as `sessionId`.
5. **Lazy send step** (section 5.4): wire-identical, smaller window for a
   snapshot to capture a fresh `dk`.
6. **Responder identity lookup** via `fetchIdentity`, so Bob never consumes
   Alice's OPKs to check `σ_A`.
7. **`pn` and the previous chain** are specified (Double-Ratchet style): the
   header's `pn` lets the receiver cache keys left in its previous receiving
   chain when a new epoch arrives.
8. **Session-id memory for all handshakes.** The strategy's SPK-only `H(T)`
   replay cache is generalised: every accepted `sessionId` is remembered under
   its SPK until that SPK is deleted, and it is looked up **before** any
   decapsulation, under the per-peer lock (formal-model requirement). Tombstones
   additionally reject inits of closed sessions without any public-key work.
9. **Session replacement and simultaneous initiation** (section 4.5) were not
   specified; the handoff's chain labels (`KRYPT/CK/v1`, ...) and hash-derived
   nonce are superseded by the strategy's `0x01`/`0x02` chain step and the
   HKDF-derived IV.
10. **ML-DSA context string** is empty; domain separation is in the message.
11. **Separate SPK/OPK keyId namespaces** in storage and in the init header, in
    addition to the separate signature labels (formal-model requirement).
12. **SPK rotation interval** is stated as a security parameter: it bounds the
    epoch-0 exposure of SPK-only sessions.
13. **Losing inits are tombstoned** (section 4.5, found during integration).
    An init that authenticates but loses the simultaneous-initiation tie-break
    is tombstoned, its OPK deleted and its id recorded in the session-id
    memory, so a late or replayed copy cannot later take the "peer started
    over" path and replace the agreed session. This is a liveness rule: it
    changes no secrecy or authentication property.
