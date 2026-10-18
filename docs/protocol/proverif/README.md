# Krypt v1 in ProVerif

Symbolic models of the Krypt-X3K handshake and the alternating KEM ratchet, checked against the claims in `Krypt_Major_Project_Strategy.md` §4.7. Plan reference: Phase 2 track P, steps 2.1-2.5.

**Bottom line.** Every query on the fixed spec gives the expected result (`handshake.pv`, `ratchet.pv`, `binding_weak.pv`, `binding_fixed.pv`; ProVerif 2.05). Three spec changes came out of this work:

1. OPK signatures need their own label.
2. Bob must remember the sessionId of every accepted session, OPK sessions included.
3. The PCS claim holds exactly as reworded in §4.7.

```
make check     # builds the Docker image on first use, runs all 8 models
```

`results/<model>.txt` is the full ProVerif output, including attack traces. Its first line is the ProVerif version and its last line is `# exit=… wall_ms=…`. `results/summary.txt` lists every `RESULT` line.

## Files

| File | What it is | Spec |
|---|---|---|
| `handshake.pv` | Krypt-X3K, **fixed spec** (main model) | §4.3 |
| `handshake_samelabel.pv` | ablation: OPKs signed with the SPK label (old spec text) | §4.3 |
| `handshake_nocache.pv` | ablation: no sessionId replay cache | §4.3 |
| `ratchet.pv` | handshake + 5 unrolled ratchet epochs, FS and PCS | §4.4, §4.7 |
| `binding_weak.pv` | non-binding KEM, root ctx **without** `H(ek)` | §4.8 |
| `binding_fixed.pv` | non-binding KEM, root ctx **with** `H(ek)` (Krypt v1) | §4.8 |
| `binding_weak_unauth.pv` | ablation: also no `H(ct)`, header not in AEAD AD | §4.8 |
| `binding_fixed_unauth.pv` | same ablation, `H(ek)` added back | §4.8 |
| `Dockerfile`, `Makefile` | `ocaml/opam` + `opam install proverif.2.05` | |

Variant files differ from their base only in lines marked `ABLATION` or `>>> VARIANT <<<`. `handshake_nocache.pv` keeps the processes and changes only the queries.

## What is modelled

**Handshake** (`handshake.pv`):

- Unbounded clients, sessions, SPKs and OPKs.
- The relay is the attacker, and every bundle passes through it.
- The KT log is a trusted table (C2 is assumed to work).

Compromise oracles, each fired at a time the attacker chooses:

- `CompromiseIK(c)`: the ML-DSA identity key of client c.
- `CompromiseSPK(c, spk)`: an SPK secret.
- `CompromiseOPK(c, opk)`: an OPK secret, only while it is still on the server. One input either reveals the OPK or consumes it, which models deletion.

In phase 1, after all sessions, every identity key and every SPK leaks. OPKs do not, because they were deleted.

**Ratchet** (`ratchet.pv`):

- One honest Alice–Bob session, unrolled message by message: m0 (epoch 0), m1 (1, Bob's send-only bootstrap), m2 (2).
- Phase 1 opens with a full leak of Alice's state: RK₂, CKs after m2, CKr after m1, and the pending dk_A2. Both identity keys and Bob's SPK leak too.
- Then come m2b (2), m3 (3), m4 (4) and m5 (5).
- The attacker is active in phase 0. In phase 1 it is passive: it sees every message but delivery goes through a table it cannot write. §4.7 claims PCS only against a passive attacker.

**Binding** (`binding_*.pv`):

- The same ratchet, epochs 0-3, active attacker, no state leak.
- The attacker gets Bob's ratchet key dk_B1 as soon as it exists, plus any KEM keys of its own.
- The KEM theory is the deliberately non-binding one from the PQXDH models (Inria-Prosecco/pqxdh-analysis, revision1): `ct = kem_enc(ek, ss)` with ss chosen independently of ek. Anyone who learns ss can re-encapsulate it to any other ek.

## Abstractions

- **Symbolic Dolev-Yao model with perfect primitives.**
  - ML-KEM is a binding equational theory, `kem_dec(sk, kem_ct(pk(sk), r)) = kem_ss(pk(sk), r)`. Implicit rejection is modelled as failure.
  - ML-DSA is a signature that reveals its message.
  - HKDF, HMAC and SHA-256 are random oracles. Each HKDF output half is its own function.
  - AES-GCM is a perfect AEAD. `key‖iv = HKDF(mk)` is folded into mk.
- No computational bounds, timing or side channels, and no KyberSlash.
- Encodings are injective (`[data]`), which matches the length-prefixed encoding of §4.2.
- Prekey ids are not modelled; a prekey is identified by its public key.
- The ratchet is bounded: one session, 5 epochs, one or two messages per chain.
- Not modelled: `pn`, skipped-key store, MAX_SKIP/TTL, the ratchet threshold K, state rollback, Bob-side state leak. The KEM is abstract, so the model covers the ML-KEM-1024 ratchet (the only suite) without change.

## Results (from `make check`, Apple M5, Docker, 2026-10-17)

"false" for a reachability query means "reachable", which is what a sanity check wants. Every secrecy result depends on the run actually completing.

### Handshake: `handshake.pv` (fixed spec), 1.9 s

| # | Query | §4.7 claim | Expected | Actual |
|---|---|---|---|---|
| Q0 | Bob accepts an OPK / SPK-only handshake (sanity) | – | reachable | reachable / reachable |
| Q1 | Alice's m0 secret unless IK_B leaked *before*, or (SPK leaked any time and (no OPK or OPK leaked pre-use)) | confidentiality, FS, KCI | true | **true** |
| Q2 | OPK handshake: m0 secret even though IK_B and SPK leak later (phase 1) | FS | true | **true** |
| Q3 | SPK-only handshake: m0 secret against a later SPK leak | documented limitation | false | **false** (attack: decapsulate ct1 with the leaked SPK) |
| Q4 | Bob's m0 secret unless IK_A leaked before, or SPK-only and SPK leaked | confidentiality, KCI | true | **true** (needs `preciseActions`, see below) |
| Q5a | `inj-event(BobAccepts) ⇒ inj-event(AliceInit)` on (a, b, H(T), RK0), OPK path | authentication | true | **true** |
| Q5b | same, non-injective, both paths | authentication | true | **true** |
| Q5c | two `AliceInit` with the same H(T) are the same event | sessionId uniqueness | true | **true** |

Q1, Q4 and Q5 never mention IK_A for Alice, IK_B for Bob, or SPK for authentication. So those compromises are proven harmless:

- KCI holds.
- An SPK compromise does not let anyone impersonate Alice. In PQXDH it does, because there the initiator does not sign.

### Handshake ablations

| Model | Query | Expected | Actual | What the ablation breaks |
|---|---|---|---|---|
| `handshake_samelabel.pv` (1, 3.3 s) | Q1 | false | **false** | Initiator FS. The relay swaps slots: an OPK goes in the SPK slot and another of Bob's SPKs in the OPK slot. Alice records "OPK used", but her "OPK" is an SPK that leaks later. |
| | Q2 | false | **false** | Same trace. Alice's FS guarantee for OPK sessions is gone. |
| | Q3, Q4, Q5a-c | as main | as main | Bob-side properties and authentication are unaffected: Bob's OPK path never matches a swapped key. |
| `handshake_nocache.pv` (0.7 s) | Q6: injective agreement on the SPK-only path, no cache | false | **false** | Replay. The relay re-sends Alice's init and Bob accepts one Alice session twice. ProVerif confirms the non-injective version still holds. |

**How the replay cache is handled.** ProVerif cannot model an atomic test-and-insert. Restrictions may not mention time variables (2.05 rejects `CacheInsert(h)@i && CacheInsert(h)@j ==> i = j`), and table get/insert is neither atomic nor precise. So `handshake.pv` proves the two facts the cache relies on instead:

- Q5b: everything Bob accepts traces back to an Alice session with the same H(T).
- Q5c: each H(T) belongs to exactly one Alice session.

A cache that accepts each `sessionId = H(T)` at most once therefore gives injective agreement. That last step is an argument, not a ProVerif result. `handshake_nocache.pv` shows the attack the cache must stop.

### Ratchet: `ratchet.pv`, 170 s

| Query | Claim | Expected | Actual |
|---|---|---|---|
| run reaches Alice receiving m5 | sanity | reachable | reachable |
| m0 (epoch 0) | FS: OPK deleted, long-term keys leaked | true | **true** |
| m1 (epoch 1, received before the leak) | FS | true | **true** |
| m2 (epoch 2, sent before the leak) | FS within a chain (`CK' = HMAC(CK, 0x02)`) | true | **true** |
| m2b (Alice's current epoch, after the leak) | PCS: "P's current epoch stays exposed" | false | **false** |
| m3 (Bob's next epoch; Bob encapsulates to the stolen dk_A2) | PCS: "the peer's next epoch stays exposed" | false | **false** |
| m4 (Alice's first send after Bob's reply with ek_B3) | PCS: "secrecy returns at P's next ratchet step" | true | **true** |
| m5 (Bob's following epoch) | PCS | true | **true** |

This confirms the reworded §4.7 PCS row exactly, for a passive attacker and a leak of Alice's state taken right after she sent her first epoch-2 message.

### Binding experiment (non-binding KEM, attacker holds dk_B1)

| Model | root ctx | ct, ek in AD | m0-m3 secret | root agreement | same RK ⇒ same ek | Time |
|---|---|---|---|---|---|---|
| `binding_weak.pv` | e ‖ H(ct) | yes | true | **true** | **true** | 1.7 s |
| `binding_fixed.pv` | e ‖ H(ek) ‖ H(ct) | yes | true | **true** | **true** | 1.8 s |
| `binding_weak_unauth.pv` | e | no | true | **false** | **false** | 0.9 s |
| `binding_fixed_unauth.pv` | e ‖ H(ek) | no | true | **true** | **true** | 0.6 s |

**ProVerif finds no attack on the weak variant as specified.** Three things block re-encapsulation there:

1. **The AEAD-authenticated header.** The attacker cannot change the ek that Alice encapsulates to.
2. **`H(ct)` in ctx.** Symbolically a ciphertext names its target key, so a re-encapsulated `ct'` changes the context.
3. **The chained root key as HKDF salt.** Knowing one ss (here via dk_B1) never yields RK′.

The ablation removes (1) and (2). Then ProVerif finds the re-encapsulation attack:

- The attacker swaps ek_B1 for its own key in Bob's epoch-1 header.
- Alice encapsulates to the attacker's key.
- The attacker decapsulates, then re-encapsulates the same ss to ek_B1.
- Alice and Bob end with the same RK₂, but disagree on the ek. The binding query fails, and so does root agreement.

Adding `H(ek)` back is enough to restore both, so `H(ek)` is exactly the defence that matters once the KEM stops binding. Secrecy holds in every variant because of (3). The attack does not need the compromised dk_B1, because the attacker uses its own key.

## Changes the models forced on the spec

1. **OPK signature label.** The old §4.3 text said OPKs are "each signed the same way" as the SPK. With one label, a signature on an OPK is also a valid SPK signature, and the reverse. `handshake_samelabel.pv` breaks Alice's FS this way. **Adopted fix:** OPKs are signed under `"Krypt-OPK"`, SPKs keep `"Krypt-SPK"`, and the implementation should keep the SPK and OPK id namespaces separate.
2. **sessionId cache for every session.** The lost-first-message rule makes Alice repeat the init header until Bob replies. For an OPK session, Bob has already deleted the OPK and cannot decapsulate the repeat. He has to recognise the sessionId *before* decapsulating. **Adopted fix:** Bob remembers H(T) for every accepted session and accepts each at most once.
3. **The cache check must be atomic.** Q5b + Q5c only give injectivity if test-and-insert is atomic across tabs and workers, for example inside the same Web Lock that serialises ratchet state (§4.4).
4. **`H(ek)` in the root ctx is defence in depth for ML-KEM, not a fix for an attack on v1 as written.** The slide should say: "with a non-binding KEM, H(ek) is what prevents the re-encapsulation attack once the header is not authenticated; v1 has both".
5. **SPK-only sessions are not forward secret** until the SPK is deleted (Q3), and an SPK leak at any time exposes Bob's side of them (Q4). Rotation frequency is therefore a security parameter, not just hygiene.

## Limitations

- Symbolic results only. They say nothing about ML-KEM/ML-DSA/AES-GCM strength, implementation bugs, side channels or the computational binding properties of real KEMs.
- The ratchet is bounded: one session, 5 epochs, a leak at one point (Alice, after m2). Leaks at other points, a Bob-side leak and several sessions per pair are not checked.
- PCS is checked against a passive attacker only, which matches the claim. An active attacker with stolen state breaks any ratchet.
- No skipped-key store, so the FS caveat "messages whose skipped keys are still cached" is not modelled.
- The replay cache is argued from Q5b + Q5c, not modelled directly (see above).
- `preciseActions` was needed in `handshake.pv`. Without it ProVerif's abstraction forgets that one input receives one message. It then lets an OPK be both revealed and consumed, and Q4 comes back "cannot be proved" (a false attack).
- The KT log is trusted. A malicious log is C2's problem and is not modelled here.

**Session replacement and the losing-init tombstone are outside the symbolic model.** Spec §4.5 adds a rule found during integration testing: when an init loses the simultaneous-initiation tie-break but authenticates, the responder tombstones its `sessionId`, deletes its OPK and records it in the session-id memory, so a late or relay-replayed copy cannot later replace the agreed session through the "peer started over" path. None of these models has more than one session per pair, a tie-break, tombstones or session replacement, and ProVerif checks secrecy and authentication, not liveness. The rule is a liveness fix: it only makes Bob refuse more inits and adds no key material, so it cannot weaken any result above, but it is also not proved by them. It is checked by the unit tests in `frontend/test/app-layer.test.ts` ("session race recovery").
