# 🛡️ Project Krypt: Detailed System Lifecycle

This document provides a technical walkthrough of the **Project Krypt** lifecycle, detailing the cryptographic operations and state transitions that ensure zero-knowledge security, post-quantum resilience, and perfect forward secrecy.

---

## 1. User Registration (Identity Genesis)
**Goal:** Create a globally unique identity without the server ever knowing the password.

1.  **SRP Setup**: Client generates a random 32-byte salt and computes a `verifier` using the **SRP-6a** protocol.
2.  **Identity Keypair**: Client generates a permanent **ML-KEM-1024** (NIST FIPS 203) KeyPair and **ML-DSA-87** (NIST FIPS 204) KeyPair. The public bundle is the user's post-quantum "Identity Certificate."
3.  **Submission**: Client sends `username`, `salt`, `verifier`, and `publicKey` to the server.
4.  **Vault Export**: The Private Identity Keys are exported as an encrypted `.vault` file.
    *   **Security Principle**: The server never sees the Private Keys. It is the user's responsibility to guard this file.

## 2. Authentication & Session Restoration
**Goal:** Prove identity to the server and restore the local cryptographic environment.

### A. Full Login (New Device/Fresh Tab)
1.  **SRP Handshake**:
    *   Client requests a challenge. Server sends `salt` and `B` (server ephemeral).
    *   Client solves the mathematical challenge using the password and sends `A` (client ephemeral) + `M1` (proof).
    *   Server validates `M1`. If successful, the user is authenticated.
2.  **Identity Restoration**:
    *   The user must upload their `.vault` file.
    *   The **Private Identity Keys** are imported into RAM (never saved to `localStorage` in plaintext).
3.  **Session Caching**: The password is saved to **`sessionStorage`** (volatile tab memory). The private key bundle is encrypted with the password and saved to a **Secure Cache** in `localStorage`.

### B. Auto-Restoration (Page Refresh)
1.  **Trigger**: User refreshes the tab.
2.  **Process**:
    *   The app detects the `sessionPassword` in `sessionStorage`.
    *   It fetches the encrypted Private Keys from the `localStorage` cache.
    *   The key bundle is decrypted in RAM using the session password.
    *   **Result**: Seamless UX without re-uploading the vault file.

## 3. The Social Handshake (Establishment of Trust)
**Goal:** Establish an E2EE channel between Alice and Bob.

1.  **Friend Request**: Alice sends a request to Bob via the server.
2.  **Acceptance**: Bob accepts. The server creates a bidirectional "Friend" relationship.
3.  **Revocation**: If Alice cancels a pending request, a **Socket Event** (`request_revoked`) is emitted to Bob, immediately clearing the UI and updating the database.

## 4. Message Exchange (ML-KEM-1024 Handshake & Ratchet)
**Goal:** Transmit data with Quantum-Resistant Secrecy, Perfect Forward Secrecy, and Identity Authentication.

1.  **Authenticated Post-Quantum Handshake (ML-KEM-1024 + ML-DSA-87)**:
    *   Alice requests Bob's Public Identity Certificate from the server and validates against local TOFU cache.
    *   **Initiator**: Alice encapsulates a fresh 32-byte shared secret against Bob's ML-KEM-1024 public key (`encapsulate(Bob_KEM_Public)`).
    *   **Root Key**: The 32-byte post-quantum shared secret directly forms the **Root AES Key**.
    *   **Signature**: Alice computes an authenticating digital signature over the handshake payload using her **ML-DSA-87 Private Key** (`sign(payload, Alice_DSA_Private)`).
    *   **Transmission**: Alice sends the encrypted message payload along with `kemCiphertext` (1568 bytes) and `signature`.
    *   **Receiver**: Bob receives the message, verifies the `signature` using Alice's **ML-DSA-87 Public Key**, and decapsulates the **Root AES Key** from `kemCiphertext` using his **ML-KEM-1024 Secret Key** (`decapsulate(kemCiphertext, Bob_KEM_Secret)`).
2.  **Encryption**:
    *   Payload (Text, Image, or Audio) is encrypted using **WASM-powered AES-256-GCM**.
3.  **The Symmetric Ratchet**:
    *   Immediately after sending/receiving, both parties run the Root Key through a **SHA-256 hash function**.
    *   The old key is deleted. The hash becomes the key for the next message.
    *   **Result**: Perfect Forward Secrecy (PFS) is achieved.

4.  **Handshake Collision Resolution (Race Condition Fix)**:
    *   If Alice and Bob send their first message at the exact same time, both act as initiators.
    *   **Rule**: The user with the lexicographically smaller username ("Alice" < "Bob") wins the tie-break.
    *   **Winner**: Decrypts the incoming message using the loser's key but maintains their own session.
    *   **Loser**: Discards their own session and adopts the winner's key.
    *   **Result**: Seamless synchronization without any extra server-side logic.

## 5. Media & Files (Pure Memory Routing)
**Goal:** Handle large binary data without persistent storage or disk footprint.

1.  **WASM Engine**: High-speed C++ compiled WebAssembly handles the heavy lifting of encrypting multi-megabyte images/audio on the client side.
2.  **Base64 Pipeline**: Encrypted blobs are transmitted as Base64 strings directly over the WebSocket within the message payload.
3.  **Zero-Footprint Routing**: The "Blind Router" (Server) receives the encrypted string in RAM and immediately forwards it to the receiver's socket. 
    *   **Security Principle**: No files are ever written to the server's disk. There is no `uploads/` folder and no temporary storage, ensuring that even a physical server compromise yields zero historical media data.

## 6. Termination (Nuclear Logout)
**Goal:** Leave zero traces on the device.

1.  **Wipe**: The user can choose to wipe the **Local Device Cache** (IndexedDB).
2.  **Purge**: `sessionStorage` and `localStorage` cache are cleared.
3.  **Server Disconnect**: The socket is disconnected and the user is removed from the `onlineUsers` map.
