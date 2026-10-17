# Krypt v1: implementation status

Last updated 2026-10-17. Branch `major/v1-protocol` (local only, not pushed). The v0 baseline is tag `protocol-v0`.

**Where things stand:** Phase 0 security fixes are in the app. The v1 protocol (handshake, KEM ratchet, session manager) is built and tested as a library, but **the chat screens still send v0 messages**. Wiring v1 into the hooks is the next step and is paused mid-way. Key transparency, the ProVerif proofs and the benchmark harness are done as standalone pieces.

See every change: `git log --oneline protocol-v0..major/v1-protocol` (53 commits) or `git diff --stat protocol-v0..major/v1-protocol`.

## Progress against the plan

Step numbers refer to `Krypt_Implementation_Plan.md`.

| Phase | Done | Not done yet |
|---|---|---|
| 0. Foundation | 0.1, 0.2 (backend CI), 0.4-0.13 | 0.3 v0 attack matrix (harness exists, not yet run against two real clients); frontend CI |
| 1. Protocol core | 1.1-1.8, 1.11, 1.20-1.26 | 1.9-1.10 hooks and media on v1 (paused) |
| 2. Proofs + transparency | 2.1-2.5 ProVerif; 2.20 Merkle library; 2.24 witness | 2.21-2.23, 2.25 server endpoints (built on a paused branch, not merged) |
| 3. Integration + measurement | 3.20-3.22, 3.24 as quick-mode samples | 3.1-3.5 client KT, security UI, hybrid toggle; 3.23 E7; 3.25 v1 attack matrix |
| 4. Sealed sender | | Not started |
| 5. Write and defend | | Not started |

## What changed, by area

### 1. Backend security (`primary-backend/`)

| Before (v0) | Now | Where |
|---|---|---|
| SRP login issued no session; any client could act as anyone | HMAC-SHA-256 bearer token issued on login and registration; every REST route requires it | `src/auth.ts`, `src/api.ts` |
| REST routes trusted usernames from the body (BOLA) | Identity comes only from the token; a mismatch returns 403 | `src/auth.ts` (`requireSelf`), `src/api.ts` |
| Any socket could claim any username and read that user's mailbox | Sockets authenticate with the token; the server overwrites `from` | `src/auth.ts` (`socketAuth`), `src/sockets.ts` |
| Offline mailbox could lose messages and let live ones overtake queued ones | Flush before going online, delete exact row ids, 7-day TTL, 500-message quota | `src/mailbox.ts`, `src/sockets.ts` |
| No payload validation; 1 MB socket limit vs 10 MB audio | `zod` schemas on every input, 16 MB socket limit, no internal error details leaked | `src/schemas.ts`, `src/server.ts` |
| No prekeys | Signed + one-time ML-KEM-1024 prekey upload; bundle endpoint claims one OPK atomically | `src/prekeys.ts`, migration `20261017000300_prekeys` |
| No way to test attacks | `EVIL_MODE` malicious relay: replay, reorder, drop, duplicate, tamper, flip type, key swap | `src/evil.ts` |
| Friend/block tables keyed by mutable usernames | Keyed by `User.id`, with a backfill migration | migration `20261017000100_social_fks_to_user_id` |

Tests: 68 (vitest). CI: `.github/workflows/ci-backend.yml`. Database steps: `primary-backend/MIGRATING.md`.

### 2. Frontend security (`frontend/`)

| Before (v0) | Now | Where |
|---|---|---|
| Client never checked the server's SRP proof | Login aborts unless `M2` verifies | `src/hooks/useAuth.ts` |
| Plaintext password in `sessionStorage` | Non-extractable AES-GCM key in IndexedDB encrypts the refresh cache | `src/services/sessionCache.ts` |
| Non-`GCM:` data went to a broken AES-CBC WASM decryptor | Fails closed with `CiphertextFormatError` | `src/crypto/aes_wasm.ts` |
| Unencrypted local data and vaults accepted as plaintext | Rejected | `src/crypto/localStore.ts`, `src/crypto/vault.ts` |
| Vault password optional; download optional | Password required (8+ chars); download forced after registration | `src/components/VaultBackupModal.tsx` |
| README overclaimed ("military-grade", "double ratchet") | Reworded; v1 roadmap added | `README.md`, `flow.md` |

### 3. v1 protocol core (`frontend/src/crypto/`, `docs/protocol/krypt-v1.md`)

The spec is `docs/protocol/krypt-v1.md`. The code implements it as a UI-independent library.

| File | What it does |
|---|---|
| `encoding.ts` | Length-prefixed canonical encoding, strict base64url |
| `kdf.ts` | HKDF and HMAC chains, message key + IV derivation |
| `pq.ts` | ML-KEM-768/1024, X-Wing hybrid, ML-DSA-87 wrappers with FIPS 203 key checks |
| `prekeys.ts` | Signed (`Krypt-SPK`) and one-time (`Krypt-OPK`) prekeys, bundle verification |
| `handshake.ts` | Krypt-X3K: Alice encapsulates to SPK + OPK, signs the transcript |
| `envelope.ts` | v1 wire format; the whole header is authenticated as AAD |
| `session.ts` | `SessionManager`: KEM ratchet, epochs, skipped keys, replay rejection, commit-after-verify, sparse mode |
| `session-store.ts` | Encrypted IndexedDB and in-memory session stores |

Tests: 143 unit and property tests, all passing for both suites (`mlkem768`, `xwing`). Known-answer tests: 15 pass, 2 skipped until `npm run vectors:fetch` downloads the large vector files. The vectors are NIST ACVP (ML-KEM, ML-DSA) and Wycheproof (ML-KEM, ML-DSA, HKDF, HMAC, AES-GCM).

### 4. Key transparency (`shared/`, `witness/`)

| Part | What it does | Tests |
|---|---|---|
| `shared/src/merkle.ts` | RFC 9162 Merkle tree, inclusion and consistency proofs, verifiers | 294 total in `shared/`, including all 196 transparency-dev/merkle probes |
| `shared/src/leaf.ts` | 153-byte KT leaf, owner signatures | |
| `shared/src/sth.ts` | Signed tree heads, witness cosignatures | |
| `shared/src/monitor.ts` | Client checks: tree-head chain, self-monitoring, lookups | |
| `witness/` | GitHub Actions witness: checks the log only grows, cosigns with ML-DSA-44, publishes to Pages | 8 |

### 5. Formal model (`docs/protocol/proverif/`)

8 ProVerif 2.05 models, run in Docker with `make check`. Results are in `results/`, and the README explains them.

| Model | Result |
|---|---|
| `handshake.pv` (final design) | Secrecy, forward secrecy, KCI and injective agreement all hold |
| `ratchet.pv` | Forward secrecy holds; post-compromise recovery happens exactly when the strategy doc (section 4.7) says it does |
| `handshake_samelabel.pv` (ablation) | Attack found: a shared prekey label lets the relay remove forward secrecy |
| `handshake_nocache.pv` (ablation) | Attack found: without the session-id cache, a replay breaks injective agreement |
| `binding_*.pv` | `H(ek)` is defence in depth: the attack appears only once other bindings are removed |

### 6. Evaluation (`evaluation/`)

A cross-origin-isolated benchmark page, a Playwright runner (Chromium, Firefox, WebKit), a Node runner, aggregation scripts and matplotlib plots. A quick-mode sample run from one Mac is committed in `evaluation/results/sample-2026-10-17/`, with its figures in `figures/`.

| ML-KEM-768 encaps, median (quick mode) | noble (current) | liboqs WASM | Native Web Crypto |
|---|---:|---:|---:|
| Chromium | 211 µs | 18.7 µs | 5.8 µs |
| Firefox | 297 µs | 22.5 µs | unsupported |
| WebKit | 414 µs | 22.0 µs | unsupported |

These are pipeline-check numbers, not final data. Final runs need full mode, real Safari and an Android phone.

## Behaviour changes to know before deploying

1. **Deploy backend and frontend together.** The old frontend cannot talk to the new backend (no token).
2. **Set `AUTH_TOKEN_SECRET` on Render.** Without it, every user is logged out whenever the server restarts.
3. **Run the database migrations on a Neon branch first.** Follow `primary-backend/MIGRATING.md`. Never run `prisma migrate dev` against Neon.
4. **Refresh vs new tab.** A refresh in the same tab stays logged in. A new tab or a browser restart asks for the password again.
5. **Old unencrypted `.vault` and backup files are rejected.** Export a new encrypted vault before deploying.
6. **Never set `EVIL_MODE` in production.**

## How to check it yourself

```bash
cd frontend && npm install && npm run build && npm test && npm run test:kat
cd ../primary-backend && npm install && npm run build && npm test
cd ../shared && npm install && npm test
cd ../witness && npm install && npm test
cd ../docs/protocol/proverif && make check     # needs Docker; ratchet.pv takes about 3 minutes
```

## Paused work (not merged yet)

| Branch | Contents | State |
|---|---|---|
| `wt/kt-server` | `/kt/*` endpoints, KT database tables, server-signed tree heads | Endpoints and 87 tests done; malicious-server KT attacks, prekey rate limit and byte quota still to do |
| `wt/integration` | Chat hooks on `SessionManager`, prekey upload, client KT checks, security screen, hybrid toggle, two-user Playwright test | Not started (reading done) |
| `wt/eval-e7` | Sparse-ratchet bandwidth vs recovery experiment | Not started (reading done) |

## Open issues

1. **Prekey draining.** Any logged-in user can use up another user's one-time prekeys by fetching their bundle repeatedly. The fix is the rate limit on `wt/kt-server`.
2. **Audio size limit.** 10 MB of audio exceeds the 16 MB socket limit once encoded and encrypted. The client should cap it at about 8.5 MB (part of the integration work).
3. **Simultaneous first messages.** When both users start a session at the same moment, one side's messages must be resent. Integration handles this.
4. **Mailbox quota counts messages, not bytes.** The byte quota is on `wt/kt-server`.
5. **Frontend lint.** 20 pre-existing errors remain in hooks the integration step rewrites.
