# 🛡️ Project Krypt: Detailed System Lifecycle

This document provides a technical walkthrough of the **Project Krypt** lifecycle, detailing the cryptographic operations and state transitions behind its password-less server storage (SRP-6a augmented PAKE), post-quantum key establishment, and v0 symmetric hash ratchet. It describes protocol **v0**; the v1 plan is in [`Krypt_Implementation_Plan.md`](Krypt_Implementation_Plan.md).

---

## 1. User Registration (Identity Genesis)
**Goal:** Create a globally unique identity without the server ever knowing the password.

1.  **SRP Setup**: Client generates a random 32-byte salt and computes a `verifier` using the **SRP-6a** protocol.
2.  **Identity Keypair**: Client generates a permanent **ML-KEM-1024** KeyPair and **ML-DSA-87** KeyPair (implementing the FIPS 203/204 algorithms). The public bundle is the user's post-quantum "Identity Certificate."
3.  **Submission**: Client sends `username`, `salt`, `verifier`, and `publicKey` to the server, which replies with a short-lived session token.
4.  **Vault Export (mandatory)**: Before the chat dashboard opens, a blocking screen makes the user download the Private Identity Keys as a `.vault` file encrypted under a vault password (min 8 characters, confirmed; PBKDF2-HMAC-SHA-256 → AES-256-GCM). Unencrypted export is not possible.
    *   **Security Principle**: The server never sees the Private Keys. It is the user's responsibility to guard this file.

## 2. Authentication & Session Restoration
**Goal:** Prove identity to the server and restore the local cryptographic environment.

### A. Full Login (New Device/Fresh Tab)
1.  **SRP Handshake**:
    *   Client requests a challenge. Server sends `salt` and `B` (server ephemeral).
    *   Client derives the session from the password and sends `A` (client ephemeral) + `M1` (client proof).
    *   Server validates `M1` and returns `M2` (server proof) plus a short-lived session token.
    *   Client verifies `M2`; if it is missing or wrong, the login is aborted (mutual authentication).
    *   The token is sent as `Authorization: Bearer <token>` on every REST call and in the Socket.io handshake (`auth.token`). A rejected token (HTTP 401 or socket `unauthorized`) logs the user out with "Session expired".
2.  **Identity Restoration**:
    *   On a new device the user uploads their `.vault` file and enters its password; on a known device the password-encrypted key cache in `localStorage` is used instead.
    *   The **Private Identity Keys** are imported into RAM (never saved to browser storage in plaintext).
3.  **Session Caching**: No password is stored. The client generates a random **non-extractable** AES-256-GCM `CryptoKey`, stores the key object in IndexedDB (`KryptSessionKeys`), encrypts the private key bundle under it into `localStorage`, and sets a per-tab `sessionStorage` flag.

### B. Auto-Restoration (Page Refresh)
1.  **Trigger**: User refreshes the tab.
2.  **Process**:
    *   The app checks for the tab's session flag and token in `sessionStorage`.
    *   It loads the non-extractable key from IndexedDB and decrypts the cached bundle in RAM.
    *   **Result**: Seamless UX without re-uploading the vault file.
3.  **New tab / browser restart**: the `sessionStorage` flag is gone, so the stored key and cache are deleted and the password is required again.

## 3. The Social Handshake (Establishment of Trust)
**Goal:** Establish an E2EE channel between Alice and Bob.

1.  **Friend Request**: Alice sends a request to Bob via the server.
2.  **Acceptance**: Bob accepts. The server creates a bidirectional "Friend" relationship.
3.  **Revocation**: If Alice cancels a pending request, a **Socket Event** (`request_revoked`) is emitted to Bob, immediately clearing the UI and updating the database.

## 4. Message Exchange (ML-KEM-1024 Handshake & Ratchet)
**Goal:** Transmit data with post-quantum key establishment, per-message key evolution, and identity authentication. (v0 does not claim perfect forward secrecy; see the ratchet limits below.)

1.  **Authenticated Post-Quantum Handshake (ML-KEM-1024 + ML-DSA-87)**:
    *   Alice requests Bob's Public Identity Certificate from the server and validates against local TOFU cache.
    *   **Initiator**: Alice encapsulates a fresh 32-byte shared secret against Bob's ML-KEM-1024 public key (`encapsulate(Bob_KEM_Public)`).
    *   **Root Key**: The 32-byte post-quantum shared secret directly forms the **Root AES Key**.
    *   **Signature**: Alice computes an authenticating digital signature over the handshake payload using her **ML-DSA-87 Private Key** (`sign(payload, Alice_DSA_Private)`).
    *   **Transmission**: Alice sends the encrypted message payload along with `kemCiphertext` (1568 bytes) and `signature`.
    *   **Receiver**: Bob receives the message, verifies the `signature` using Alice's **ML-DSA-87 Public Key**, and decapsulates the **Root AES Key** from `kemCiphertext` using his **ML-KEM-1024 Secret Key** (`decapsulate(kemCiphertext, Bob_KEM_Secret)`).
2.  **Encryption**:
    *   Payload (Text, Image, or Audio) is encrypted with **AES-256-GCM** via the browser's Web Crypto API.
    *   Decryption fails closed: anything not in the `GCM:` format is rejected.
3.  **The Symmetric Hash Ratchet (v0)**:
    *   Immediately after sending/receiving, both parties derive the next key from the current one with **HKDF-SHA-256**.
    *   The old key is deleted. The derived key is used for the next message.
    *   **Limits**: one chain is shared by both directions and the root key is encapsulated to the peer's static identity key, so leaking that key exposes recorded traffic. v1 replaces this with a KEM-based double ratchet.

4.  **Handshake Collision Resolution (Race Condition Fix)**:
    *   If Alice and Bob send their first message at the exact same time, both act as initiators.
    *   **Rule**: The user with the lexicographically smaller username ("Alice" < "Bob") wins the tie-break.
    *   **Winner**: Decrypts the incoming message using the loser's key but maintains their own session.
    *   **Loser**: Discards their own session and adopts the winner's key.
    *   **Result**: Seamless synchronization without any extra server-side logic.

## 5. Media & Files (Memory Routing)
**Goal:** Handle large binary data with no plaintext or keys server-side.

1.  **Client Encryption**: Images/audio are encrypted on the client with Web Crypto AES-256-GCM (the old C/WASM AES-CBC prototype is not used for live traffic).
2.  **Base64 Pipeline**: Encrypted blobs are transmitted as Base64 strings directly over the WebSocket within the message payload.
3.  **Blind Routing**: The "Blind Router" (Server) forwards ciphertext to an online receiver from RAM. If the receiver is offline it is queued in an offline mailbox and deleted on delivery.
    *   **Security Principle**: No plaintext or keys server-side; ciphertext deleted on delivery. There is no `uploads/` folder for media files.

## 6. Termination (Nuclear Logout)
**Goal:** Best-effort wipe of session secrets from the device.

1.  **Wipe**: The user can choose to wipe the **Local Device Cache** (IndexedDB messages and contacts).
2.  **Purge**: the session token, the session flag, the encrypted refresh cache and its non-extractable key are deleted. Browser storage wipes are best-effort.
3.  **Server Disconnect**: The socket is disconnected and the user is removed from the `onlineUsers` map.
