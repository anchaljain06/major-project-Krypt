**Krypt — Cryptographic Security & Implementation Handoff**

_A precise engineering handoff for hardening the existing E2EE architecture while preserving Krypt's core identity_

**Repository reviewed:** anchaljain06/major-project-Krypt  
Prepared: 16 October 2026

# 1\. Executive Summary

Krypt should remain a client-side, end-to-end encrypted messaging system with a blind relay: the client owns plaintext and secret key material; the backend authenticates/routs opaque protocol objects; PostgreSQL stores account/social metadata but never message plaintext or long-term private keys.

The repository currently documents SRP-6a authentication, physical .vault identities, ML-KEM-1024 for post-quantum key establishment, ML-DSA-87 for handshake authentication, AES-256-GCM for message encryption, client-side IndexedDB persistence, and a SHA-256 one-way key ratchet. The README calls this a "SHA-256 Double-Ratchet," but the described mechanism is not a full Double Ratchet: it has a symmetric hash chain and no independent asymmetric ratchet. The most important handoff requirement is therefore to correct the protocol terminology and implement a real two-chain ratchet plus a carefully designed periodic KEM ratchet if post-compromise recovery is a project goal.

The recommended target is:

Identity authentication → authenticated ML-KEM session establishment → HKDF-SHA-256 root derivation → independent send/receive HMAC-SHA-256 chains → AES-256-GCM per-message keys → replay/order protection → periodic fresh ML-KEM ratchet → authenticated state transitions.

The implementation should be state-machine driven. Do not let React component state itself become the cryptographic protocol state. A dedicated session manager should own ratchet state, sequence numbers, replay windows, skipped-message keys, and zeroization.

# 2\. Current Repository Baseline

The repository structure is:

frontend/src/components: UI

frontend/src/hooks: useAuth, useSocketListeners, useChat, useSocial, useRatchet

frontend/src/crypto: aes_wasm.ts, mlkem.ts, ratchet.ts

frontend/src/services: socket.ts, db.ts, wasmLoader.ts

primary-backend/src: api.ts, server.ts, db.ts

The README describes React/Vite/TypeScript on Vercel, Node/Express/TypeScript plus Socket.io on Render, Prisma/PostgreSQL on Neon, SRP authentication, ML-KEM-1024, ML-DSA-87, AES-256-GCM, Dexie/IndexedDB, and a pure-memory routing model.

Current documented handshake:

1\. Alice requests Bob's public identity.

2\. Alice encapsulates to Bob's ML-KEM public key.

3\. Alice obtains a KEM ciphertext and a 32-byte shared secret.

4\. Alice signs the handshake with ML-DSA-87.

5\. Bob verifies the signature and decapsulates.

6\. Both derive the same root AES material.

7\. Messages use AES-GCM.

8\. The current key is SHA-256 hashed after a message and the old key is deleted.

Important correction: the KEM ciphertext is public protocol data. The shared secret is secret key material. The actual message ciphertext is a separate AES-GCM output.

# 3\. Security Objectives

O1 Confidentiality: the relay must never obtain plaintext, message keys, root keys, or private identity keys.

O2 Integrity/authenticity: a message must be accepted only if it is authenticated under the correct session key and belongs to the expected peer/session.

O3 Forward secrecy: compromise of current message state must not reveal already-erased message keys.

O4 Post-compromise recovery: after a compromise, future messages should become secure again after a fresh asymmetric ratchet succeeds. A simple SHA-256 chain does NOT provide this property.

O5 Replay resistance: old valid packets must not be accepted as new messages.

O6 Ordering robustness: delayed/out-of-order WebSocket delivery must not desynchronize the session.

O7 Identity binding: ML-KEM keys used for a session must be bound to the intended user's authenticated identity and not silently replaced.

O8 Key separation: authentication, root derivation, sending, receiving, media, and message encryption keys must never be reused for different purposes.

O9 Availability: malformed ciphertexts and protocol abuse must fail closed without crashing the client or exhausting browser memory.

O10 Minimal server knowledge: the relay may know routing metadata required for delivery, but never receives decryption keys.

# 4\. Recommended Cryptographic Stack

Identity/authentication:

- SRP-6a remains the password-authentication mechanism already used by Krypt.
- ML-DSA-87 remains the long-term post-quantum identity signature key, subject to the exact implementation/library being FIPS 204 compatible.

Key establishment:

- ML-KEM-1024 remains the primary post-quantum KEM.
- Encaps(public_key) returns (kem_ciphertext, shared_secret).
- The ciphertext is transmitted; the shared secret is not.

Key derivation:

- Replace "SHA-256(current_key)" as the sole key schedule with HKDF-SHA-256 for root/epoch derivation.
- Use HMAC-SHA-256 with explicit labels for chain advancement.

Message encryption:

- AES-256-GCM remains the message/media AEAD.
- Generate a unique 96-bit nonce for every AES-GCM encryption under a given key.
- Never reuse a nonce with the same AES-GCM key.
- Prefer deterministic nonce construction from a unique session/epoch/message counter if the implementation can guarantee monotonic uniqueness; otherwise use a CSPRNG and persist enough state to prevent reuse.

Identity:

- Long-term private keys remain client-side in the vault.
- Do not use a password directly as an AES key for vault encryption. Derive a vault key with a memory-hard password KDF such as Argon2id where the platform/library permits; otherwise document the selected KDF and parameters explicitly.

Browser boundary:

- Keep secret cryptographic state outside ordinary React render state.
- Use Web Crypto/native vetted implementations where possible.
- Keep the C++ WASM engine limited to well-defined symmetric operations; do not implement novel cryptography in WASM unless there is a strong reason and extensive testing.

# 5\. Target Dataflow

Registration:

User password → SRP client calculation → SRP verifier/salt registration

Client CSPRNG → ML-KEM-1024 key pair

Client CSPRNG → ML-DSA-87 key pair

Public keys → backend

Private keys → encrypted .vault only

Session setup:

Alice authenticated → fetch Bob identity bundle → verify identity/pinned ML-DSA key → create session transcript → ML-KEM encapsulate to Bob → obtain KEM ciphertext + 32-byte secret → derive root key with HKDF → initialize independent send/receive chains → sign transcript/handshake → send opaque handshake envelope.

Message:

plaintext → message key from sending chain → AES-256-GCM → {version, session_id, epoch, message_number, nonce, ciphertext, tag, authenticated header} → relay → recipient → validate envelope → locate session → derive/lookup message key → AES-GCM verify/decrypt → advance receive chain → delete one-time message key.

KEM ratchet:

Generate fresh ephemeral ML-KEM key pair → authenticate the new public key under long-term ML-DSA identity and/or bind it into the session transcript → peer encapsulates to it → KEM ciphertext returned → owner decapsulates → combine fresh KEM secret with current root using HKDF → replace root and regenerate chains → increment epoch → discard old asymmetric/session secrets as appropriate.

The server should route envelopes without parsing plaintext. It may parse routing headers required for delivery, but should not need cryptographic secrets.

# 6\. Target Key Hierarchy

Use explicit labels and separate keys:

IK_sig = long-term ML-DSA signing private key

IK_kem = long-term ML-KEM decapsulation private key

RK_0 = session root key

CKs_0 = Alice→Bob sending chain

CKr_0 = Bob→Alice receiving chain

For every message:

CK_next = HMAC-SHA-256(CK, "KRYPT/CK/v1" || 0x01)

MK = HMAC-SHA-256(CK, "KRYPT/MK/v1" || 0x02)

Use MK exactly once and erase it.

For a KEM ratchet:

K_new = ML-KEM shared secret

RK' = HKDF-Extract(salt=RK, IKM=K_new || context)

OKM = HKDF-Expand(RK', "KRYPT/RATCHET/v1" || session_id || epoch, 64)

RK' = first 32 bytes

CK_seed = last 32 bytes

Then derive fresh independent sending and receiving chains from CK_seed using labeled HKDF-Expand operations.

Do not derive the message key directly as SHA-256(RootKey). The root key should never be used directly as an AES key. This gives cleaner key separation and makes the protocol easier to audit.

# 7\. Precise Message Key Schedule

Define a fixed byte-level protocol.

HKDF:

HKDF-Extract(Hash=SHA-256, salt=old_root, IKM=fresh_kem_secret || transcript_hash)

HKDF-Expand(PRK, info, 64)

new_root = OKM\[0:32\]

chain_seed = OKM\[32:64\]

Chain initialization:

send_chain = HKDF-Expand(root, "KRYPT/SEND/v1" || initiator_id || responder_id, 32)

recv_chain = HKDF-Expand(root, "KRYPT/RECV/v1" || initiator_id || responder_id, 32)

Message derivation:

next_chain = HMAC-SHA-256(chain_key, "KRYPT/CHAIN/v1" || 0x01)

message_key = HMAC-SHA-256(chain_key, "KRYPT/MESSAGE/v1" || 0x02)

AES:

AES-256-GCM(key=message_key, nonce=unique_12_bytes, plaintext, AAD=canonical_header)

AAD must include at least:

protocol_version

session_id

sender_id

recipient_id

epoch

message_number

message_type

nonce

and any immutable media metadata.

The recipient must authenticate the header before accepting the plaintext.

# 8\. Wire Envelope

Use a versioned envelope so protocol changes are explicit.

Conceptual JSON representation:

{

"v": 1,

"type": "msg",

"sessionId": "opaque-id",

"epoch": 4,

"sender": "Alice",

"recipient": "Bob",

"messageNumber": 17,

"nonce": "base64url(12 bytes)",

"ciphertext": "base64url(...)",

"tag": "base64url(16 bytes)"

}

For a KEM-ratchet envelope:

{

"v": 1,

"type": "kem-ratchet",

"sessionId": "...",

"epoch": 5,

"sender": "...",

"recipient": "...",

"kemPublicKey": "base64url(...)",

"kemCiphertext": "base64url(...)",

"signature": "base64url(...)",

"transcriptHash": "base64url(...)"

}

For production efficiency, binary framing should eventually replace JSON/Base64 for large media and cryptographic payloads. Base64 increases payload size by about one third and causes extra allocations. Keep JSON during development if it simplifies debugging, but benchmark binary framing separately.

# 9\. Session State Machine

Do not make "currentKey" a loose React variable. Create a SessionState object owned by a dedicated crypto/session module.

Suggested fields:

sessionId

peerId

role

epoch

sendMessageNumber

receiveMessageNumber

rootKey

sendingChainKey

receivingChainKey

peerKemPublicKey

ourEphemeralKemPrivateKey

ourEphemeralKemPublicKey

skippedMessageKeys

lastPeerRatchet

established

closed

State transitions:

NEW → HANDSHAKING → ESTABLISHED → RATCHETING → ESTABLISHED

ESTABLISHED → CLOSED

Any authentication/decryption failure → ERROR/CLOSED according to policy.

Every transition should be atomic from the protocol's perspective. Never advance a chain before the corresponding message has been successfully authenticated/decrypted unless the protocol deliberately supports skipped-message derivation.

# 10\. Out-of-Order and Replay Handling

Socket.io does not guarantee that a real-world distributed messaging protocol will behave like a perfectly ordered local function call. Add explicit message numbers.

For each receiving chain:

expected = n

If incoming n == expected: derive one message key and decrypt.

If incoming n > expected: derive and temporarily cache skipped keys up to n, with a strict maximum such as 64 or 128 skipped messages; then decrypt n.

If incoming n < expected: check the skipped-key cache. If absent, reject as duplicate/replay.

Never allow an attacker to request an unbounded skipped-key derivation. Cap the gap and cache size. Expire skipped keys after a bounded lifetime or after a newer epoch is established.

A message must be authenticated before it is committed to the local database.

# 11\. Handshake Authentication

The long-term ML-DSA identity key must authenticate the KEM key being used.

Do not sign only the KEM ciphertext. Sign a canonical transcript containing:

protocol version

algorithm identifiers

Alice identity fingerprint

Bob identity fingerprint

Alice/Bob role ordering

Bob KEM public-key fingerprint

Alice ephemeral KEM public key if present

KEM ciphertext if this handshake binds it

session identifier

initial epoch

all negotiated options

Canonicalization must be deterministic. Never sign a JSON object whose field order is accidental.

Bob verifies the signature against Alice's previously trusted/pinned ML-DSA public identity key before accepting the handshake.

When a user's long-term identity key changes, show a security event and require explicit re-verification rather than silently replacing it.

# 12\. Simultaneous Handshake / Collision Handling

The current README uses alphabetical username comparison to choose a winner during simultaneous initiation. Keep deterministic tie-breaking as a UX fallback, but do not use usernames alone as cryptographic entropy or identity authentication.

Prefer:

1\. Compare canonical identity fingerprints, not display names.

2\. Choose a deterministic session initiator from the two authenticated identity IDs.

3\. Include the chosen initiator and both identity fingerprints in the signed transcript.

4\. Bind the resulting sessionId to the transcript hash.

5\. Reject a second handshake that conflicts with an established session unless it is explicitly a rekey/ratchet operation.

This removes ambiguity and prevents a routing-level attacker from creating arbitrary session collisions.

# 13\. ML-KEM Ratchet Design

A pure SHA-256 chain cannot provide post-compromise recovery. Add a fresh KEM event periodically.

Recommended one-sided KEM ratchet:

1\. Sender generates a fresh ephemeral ML-KEM-1024 key pair.

2\. Sender sends the ephemeral KEM public key plus a signature binding it to the existing session transcript and next epoch.

3\. Receiver verifies the signature and encapsulates a fresh secret to that public key.

4\. Receiver sends the KEM ciphertext back, authenticated by the current message key or by the ratchet transcript.

5\. Sender decapsulates.

6\. Both derive a new root from the fresh KEM secret and the old root.

7\. Both reset send/receive chains for the new epoch.

8\. Erase the old root, old chain keys, and old ephemeral private key after the new state is committed.

This can be performed periodically, e.g. every 50–100 messages or every few minutes, depending on performance goals. Do not rotate on every message: ML-KEM-1024 is substantially heavier and its ciphertext is large.

For stronger bidirectional recovery, alternate which party publishes the next ephemeral KEM public key, or define an explicit two-sided ratchet state machine. The protocol must specify exactly who is expected to act next; never infer this from packet arrival timing.

# 14\. AES-GCM Requirements

AES-256-GCM is appropriate for the bulk message/media layer, but nonce management is non-negotiable.

Never reuse (key, nonce).

Recommended deterministic nonce:

nonce = Truncate96(SHA-256("KRYPT/NONCE/v1" || sessionId || epoch || direction || uint64(messageNumber)))

This makes uniqueness depend on unique session/epoch/direction/messageNumber tuples. If you instead use random nonces, use a CSPRNG and enforce state so accidental reuse cannot occur.

Use a fresh message key for every message, so nonce uniqueness is easier to reason about.

AAD must authenticate routing-independent protocol fields that the recipient must not allow an attacker to modify.

Do not expose plaintext or message keys to console logs, telemetry, exceptions, or React devtools in production.

# 15\. Vault and Local Storage

The current repository stores vault material in local/session browser storage for refresh recovery. This is a sensitive area.

Preferred hierarchy:

- sessionStorage: short-lived unlock state only if the threat model accepts it.
- IndexedDB: encrypted application data and encrypted private-key material.
- .vault: encrypted export for recovery.
- Never store plaintext private keys in localStorage.
- Never store the plaintext vault password in persistent storage.

Vault encryption should use an authenticated encryption scheme with a password-derived key. Use a memory-hard KDF such as Argon2id if the selected browser/library supports it securely. Include KDF parameters, salt, algorithm version, and vault format version in the vault header.

Nuclear logout should:

1\. stop sockets,

2\. destroy session manager state,

3\. wipe in-memory references where practical,

4\. delete IndexedDB records,

5\. delete localStorage/sessionStorage application secrets,

6\. revoke/close active sessions,

7\. clear UI state.

Browser memory cannot be guaranteed to be physically zeroized by JavaScript. The design should state "best-effort logical zeroization" rather than claiming guaranteed forensic erasure.

# 16\. Media Encryption

Keep the current architecture: large media is encrypted client-side and the relay sees only opaque encrypted data.

For each media object:

1\. Generate a random 32-byte media key.

2\. Encrypt the media using AES-256-GCM with unique nonces.

3\. Wrap the media key inside the already-authenticated message envelope using the message key, or derive a media subkey from the message key using HKDF.

4\. Send encrypted media and metadata through the relay.

5\. Delete temporary plaintext buffers as soon as practical.

Avoid transmitting large Base64 strings when performance matters. Base64 costs bandwidth and memory. Introduce binary WebSocket frames for media after the cryptographic protocol is stable.

# 17\. Backend Blind Router Changes

The backend should not receive or store:

plaintext

message keys

root keys

chain keys

vault private keys

ML-KEM decapsulation keys

ML-DSA signing keys

The backend may store:

username/account identifiers

SRP salt/verifier

public identity keys

friend/request metadata

revocation metadata

non-secret routing state

The Socket.io server should validate message envelope size, recipient authorization, protocol version, and basic schema before forwarding. It does not need to decrypt the payload.

Add strict maximum sizes for:

text ciphertext

media envelope

KEM ciphertext

signature

header

total frame

Reject oversized frames before buffering them fully where feasible.

# 18\. API / Database Changes

Add or verify these public-key fields:

kemPublicKey

signaturePublicKey

keyVersion

identityFingerprint

createdAt

revokedAt

For sessions, do not store secret session keys server-side. If a session record is necessary, store only:

sessionId

participant IDs

public-key fingerprints

current protocol version

revocation/status metadata

timestamps

If the backend stores public-key history, preserve old public keys for verification of historical signed envelopes but mark them revoked. Never silently overwrite an identity key.

A key change must produce an auditable security event visible to the clients.

# 19\. Frontend File-Level Implementation Plan

frontend/src/crypto/mlkem.ts

- Keep all ML-KEM API wrappers here.
- Expose typed functions:

generateKemIdentity()

generateKemEphemeral()

encapsulate(publicKey)

decapsulate(privateKey, ciphertext)

- Return Uint8Array/ArrayBuffer, not Base64 internally.
- Convert to Base64URL only at the network boundary.
- Validate exact key/ciphertext lengths before use.
- Do not log secret outputs.

frontend/src/crypto/ratchet.ts

Replace the current raw SHA-256 key step with:

hkdfExtract()

hkdfExpand()

deriveInitialChains()

deriveMessageKey()

advanceChain()

deriveNextRoot()

All functions must be deterministic and unit-testable.

frontend/src/hooks/useRatchet.ts

Turn this into a thin React adapter around a SessionManager. It should not implement cryptographic arithmetic or own the authoritative protocol state.

NEW frontend/src/crypto/session.ts

Create the authoritative session state machine:

createSession()

processHandshake()

encryptMessage()

decryptMessage()

initiateKemRatchet()

processKemRatchet()

closeSession()

frontend/src/hooks/useChat.ts

Call SessionManager methods. UI state should contain only displayable data and operation status.

frontend/src/hooks/useSocketListeners.ts

Treat incoming frames as untrusted input. Validate envelope → dispatch to SessionManager → persist only after authentication/decryption.

frontend/src/crypto/aes_wasm.ts

Keep the WASM boundary small. Require explicit key/nonce/AAD parameters. Ensure the wrapper checks output lengths and authentication failures. Prefer Web Crypto AES-GCM for ordinary messages and benchmark WASM for media before deciding where each is used.

frontend/src/services/db.ts

Persist encrypted message records and non-secret session metadata. Never persist plaintext session keys.

# 20\. Reference TypeScript Interfaces

\`\`\`ts

type SessionState = {

version: 1;

sessionId: string;

peerId: string;

role: "initiator" | "responder";

epoch: number;

sendNumber: bigint;

receiveNumber: bigint;

rootKey: Uint8Array;

sendChainKey: Uint8Array;

receiveChainKey: Uint8Array;

peerKemPublicKey: Uint8Array;

skipped: Map&lt;string, Uint8Array&gt;;

status: "handshaking" | "established" | "closed";

};

type MessageEnvelope = {

v: 1;

type: "msg";

sessionId: string;

epoch: number;

sender: string;

recipient: string;

n: string;

nonce: string;

ciphertext: string;

tag: string;

};

type KemRatchetEnvelope = {

v: 1;

type: "kem-ratchet";

sessionId: string;

epoch: number;

sender: string;

recipient: string;

kemPublicKey: string;

signature: string;

transcriptHash: string;

};

\`\`\`

Use \`Uint8Array\` internally and Base64URL only at the transport boundary. Keep counters as integers/BigInt internally so they cannot silently overflow.

# 21\. Reference Pseudocode

\`\`\`ts

async function establishSession(peer: PeerIdentity): Promise&lt;SessionState&gt; {

assertTrustedIdentity(peer);

const { publicKey: peerKemKey } = peer;

const { ciphertext, sharedSecret } =

await mlkem.encapsulate(peerKemKey);

const transcript = canonicalHandshake({

version: 1,

algorithms: \["ML-KEM-1024", "ML-DSA-87", "HKDF-SHA-256", "AES-256-GCM"\],

initiator: localIdentityFingerprint,

responder: peer.identityFingerprint,

peerKemFingerprint: sha256(peerKemKey),

kemCiphertext: ciphertext,

});

const signature = await mldsa.sign(identityPrivateKey, transcript);

const root = await deriveInitialRoot(sharedSecret, transcript);

secureErase(sharedSecret);

return createInitialSession(root, peer, transcript);

}

async function encryptMessage(state: SessionState, plaintext: Uint8Array) {

const { nextChain, messageKey } =

deriveMessageKey(state.sendChainKey);

const nonce = deriveUniqueNonce(

state.sessionId, state.epoch, "send", state.sendNumber

);

const header = canonicalHeader(state, nonce);

const { ciphertext, tag } =

await aesGcm.encrypt(messageKey, nonce, plaintext, header);

secureErase(messageKey);

state.sendChainKey = nextChain;

state.sendNumber++;

return encodeEnvelope(header, ciphertext, tag);

}

\`\`\`

Receiving must verify the envelope, derive/obtain the correct message key, perform AES-GCM authentication, and only then commit the plaintext to the local message database.

# 22\. Critical Security Corrections

1\. Do not call the current SHA-256 chain a "Double Ratchet." It is a one-way symmetric hash ratchet unless an independent asymmetric ratchet is implemented.

2\. Do not claim full post-compromise security from SHA-256 alone. A current-key compromise lets an attacker compute future SHA-chain keys.

3\. Do not use the raw ML-KEM shared secret directly as an AES key. Feed it into a KDF with protocol context.

4\. Do not reuse an AES-GCM nonce with a key.

5\. Do not use the same chain key for both directions.

6\. Do not let message arrival order determine ratchet state.

7\. Do not accept a new public identity key silently.

8\. Do not sign ambiguous/unstable JSON. Canonicalize the signed transcript.

9\. Do not expose private keys/shared secrets in logs.

10\. Do not claim "zero footprint" as an absolute browser guarantee. A web application can minimize server persistence and perform logical deletion, but cannot guarantee physical memory erasure or prevent OS/browser screenshots, crash dumps, backups, or compromised devices.

11\. Verify the exact ML-KEM/ML-DSA library against NIST-compatible known-answer tests before calling the implementation production secure.

12\. Prefer established cryptographic libraries over custom cryptographic primitives. The custom WASM engine should be treated as an optimization component, not a new cryptographic standard.

# 23\. Testing and Verification

Cryptographic correctness tests:

- ML-KEM key generation/encapsulation/decapsulation round trip.
- Assert AliceSecret == BobSecret.
- Modified KEM ciphertext must not produce an accepted session.
- Wrong private key must fail.
- ML-DSA valid signature succeeds.
- Modified transcript/signature/key identity fails.
- HKDF test vectors.
- HMAC chain test vectors.
- AES-GCM known-answer tests.
- AES-GCM tampered ciphertext/tag/AAD/nonce rejection.

State-machine tests:

- duplicate message
- out-of-order message
- skipped message
- excessive message gap
- old epoch
- future epoch
- simultaneous handshake
- peer key rotation
- session restart
- lost KEM-ratchet packet
- duplicate KEM-ratchet packet
- stale ratchet packet

Adversarial tests:

- malformed Base64
- wrong lengths
- huge payload
- invalid UTF-8 where applicable
- counter overflow
- replay from another session
- ciphertext copied between sessions
- header modification
- recipient modification
- epoch modification
- signature copied to a different transcript

Performance tests:

- ML-KEM key generation
- ML-KEM encapsulation
- ML-KEM decapsulation
- HKDF
- chain-key derivation
- AES-GCM small-message throughput
- AES-GCM media throughput
- Base64 encode/decode
- binary-frame throughput
- memory peak during media encryption

Do not benchmark only the cryptographic primitive. Measure the full protocol cost, including serialization, Base64, WebSocket transfer, and memory allocation.

# 24\. Migration Order

Phase A — Freeze the current protocol

1\. Tag the existing version as protocol v0/legacy.

2\. Add a protocol version field.

3\. Stop changing cryptographic semantics while implementing the new state machine.

Phase B — Key schedule

1\. Implement HKDF-SHA-256.

2\. Implement labeled HMAC chain derivation.

3\. Split send/receive chains.

4\. Add epoch and message numbers.

5\. Add deterministic nonce construction.

6\. Unit-test all KDF functions.

Phase C — Session manager

1\. Create session.ts.

2\. Move ratchet state out of React.

3\. Implement encrypt/decrypt through SessionManager.

4\. Add replay/out-of-order handling.

5\. Add strict state transitions.

Phase D — Authenticated handshake

1\. Canonicalize handshake transcript.

2\. Sign transcript with ML-DSA.

3\. Verify identity fingerprint.

4\. Derive initial root using HKDF.

5\. Bind sessionId to transcript hash.

Phase E — KEM ratchet

1\. Implement ephemeral ML-KEM generation.

2\. Implement signed ephemeral public-key envelope.

3\. Implement encapsulation response.

4\. Derive new root and fresh chains.

5\. Add epoch handling.

6\. Add retransmission/duplicate handling.

7\. Test compromise-and-recovery scenarios.

Phase F — Storage hardening

1\. Audit IndexedDB/localStorage/sessionStorage.

2\. Remove plaintext secret persistence.

3\. Improve vault KDF/format.

4\. Implement best-effort logical zeroization.

Phase G — Performance

1\. Benchmark Web Crypto AES vs WASM AES.

2\. Keep WASM for workloads where it actually wins.

3\. Replace large Base64 media frames with binary WebSocket frames.

4\. Measure memory peaks.

Phase H — Security validation

1\. KATs.

2\. Fuzz envelope parser.

3\. Mutation tests for signatures/ciphertexts.

4\. Replay tests.

5\. Race/simultaneous-handshake tests.

6\. Dependency audit.

7\. External cryptographic review before real high-stakes deployment.

# 25\. Recommended Feature Roadmap

High-value cryptographic features:

- Security-number/fingerprint verification screen.
- Identity-key-change warning.
- Session/epoch security status.
- "New device" re-verification.
- Automatic KEM rekey after a configurable message/time threshold.
- Key-compromise recovery indicator.
- Encrypted attachment keys derived separately from message keys.
- Disappearing-message cryptographic deletion policy.
- Encrypted local search index only if absolutely necessary.
- Binary protocol framing.
- Optional offline message queue containing ciphertext only.
- Formal protocol specification with byte-level wire format.
- Automated known-answer and interoperability tests.
- Security audit checklist in CI.

Avoid feature creep into custom cryptography. Krypt's strongest identity is not "we invented encryption"; it is "a blind, client-side E2EE architecture built from standardized primitives with an explicit, testable key lifecycle."

# 26\. Final Target Architecture

KRYPT CLIENT A

|

+---------------------+---------------------+

| | |

UI/Chat Session Manager Vault/Storage

|

+---------------------+---------------------+

| | |

ML-DSA ML-KEM-1024 HKDF/HMAC

Identity/Auth Session/Ratchet Key Schedule

|

AES-256-GCM

|

Opaque Envelope

|

WebSocket / TLS

|

+---------v----------+

| BLIND ROUTER |

| Express + Socket.io|

| no plaintext |

| no secret keys |

+---------+----------+

|

Opaque Envelope

|

+---------v----------+

| KRYPT CLIENT B |

+--------------------+

The server remains a router, not a cryptographic participant. Public identity keys may be stored server-side; private keys and session secrets remain client-side.

# 27\. Definition of Done

The handoff is complete when all of the following are true:

- \[ \] ML-KEM-1024 round trip passes known-answer/interoperability tests.
- \[ \] ML-DSA identity signatures authenticate session transcripts.
- \[ \] Initial shared secret is fed through HKDF before use.
- \[ \] Separate send/receive chains exist.
- \[ \] Each message gets a one-time message key.
- \[ \] AES-GCM nonce uniqueness is guaranteed.
- \[ \] Message header is authenticated as AAD.
- \[ \] Replay and out-of-order handling is bounded.
- \[ \] KEM ratchet state is versioned and authenticated.
- \[ \] Old root/chain/message keys are logically erased.
- \[ \] React UI does not own authoritative secret state.
- \[ \] Server never receives message plaintext or private keys.
- \[ \] No plaintext cryptographic material appears in logs.
- \[ \] Protocol versioning is implemented.
- \[ \] Fuzzing and negative tests pass.
- \[ \] Performance is measured end-to-end.
- \[ \] Documentation accurately distinguishes forward secrecy from post-compromise security.
- \[ \] Claims such as "military-grade" and "perfect forward secrecy" are replaced with precise, testable security properties.

# 28\. Engineering Notes for the Next Developer

Preserve Krypt's existing visual/product identity, blind-router architecture, vault concept, SRP authentication, ML-KEM-1024, ML-DSA-87, AES-256-GCM, and client-side storage model.

The cryptographic redesign should be incremental rather than a rewrite. The safest path is to isolate protocol logic in frontend/src/crypto/session.ts and make useChat/useRatchet call it. Keep mlkem.ts as a thin provider adapter and ratchet.ts as a pure key-schedule module. This allows the UI, social wall, Socket.io routing, and database features to remain largely unchanged.

Most importantly, treat the protocol as a state machine with a written wire format. Cryptographic failures should fail closed. Every new cryptographic feature should have positive, negative, replay, concurrency, and performance tests before being connected to the UI.