# Krypt frontend

React 19 + Vite 7. All messaging uses the Krypt v1 protocol (`docs/protocol/krypt-v1.md`).

```bash
npm install
npm run dev        # VITE_API_URL=http://localhost:3000 by default (.env.example)
npm run build
npm run lint
npm test           # unit, protocol and property tests (Vitest)
npm run test:kat   # NIST ACVP + Wycheproof vectors
npm run test:e2e   # Playwright, two users over a running relay: see e2e/README.md
```

## Environment

| Variable | Required | Meaning |
|---|---|---|
| `VITE_API_URL` | yes | Backend origin (REST, socket.io and `/kt/*`) |
| `VITE_KT_LOG_PUBKEY` | no | Base64 ML-DSA-87 key of the KT log's tree heads. Pinned at build time, never fetched. Unset: KT runs in **disabled** mode (trust on first use only) and the sidebar shows a "KT disabled" badge |
| `VITE_KT_WITNESS_URL` | no | The witness's `latest.json` (see `witness/README.md`) |
| `VITE_KT_WITNESS_PUBKEY` | with the URL | Base64 ML-DSA-44 witness key. Without it the witness URL is ignored |

## Where things live

| Path | Role |
|---|---|
| `src/crypto/` | Protocol core (`session.ts`, `handshake.ts`, `prekeys.ts`, ...), attachments (`media.ts`), message codec (`appMessage.ts`), safety numbers |
| `src/services/protocol.ts` | One `SessionManager` per logged-in user, its encrypted IndexedDB stores and the store key |
| `src/services/prekeyMaintenance.ts` | Prekey upload, refill, weekly signed-prekey rotation with a 2-week grace period |
| `src/services/messaging.ts` | Send and receive pipeline, error toasts, re-send after a session race |
| `src/services/trust.ts` | `trustIdentity`: KT lookup, then the TOFU pin and the key-change dialog |
| `src/services/kt.ts` | KT client: lookup proofs, STH consistency, witness, self-monitoring, gossip |

### Store key

Ratchet sessions and prekey private keys are sealed in IndexedDB with AES-256-GCM under

```
HKDF-SHA-256(salt = "krypt-store-salt-v1", ikm = ML-DSA-87 identity secret key,
             info = lp("krypt-store-key-v1", username))
```

imported as a non-extractable `CryptoKey`. The identity key comes from the vault, or from the per-tab session cache after a refresh, so the same store key is re-derived without ever being stored.

### Shared KT library

`@krypt/shared` is an alias for `../shared/src/index.ts`, set in `vite.config.ts`, `tsconfig.app.json` and `vitest.config.ts`, as `shared/README.md` recommends. Vite compiles the TypeScript sources directly, so there is no vendored copy to keep in sync. Builds therefore need the whole repository checked out, not only `frontend/`.
