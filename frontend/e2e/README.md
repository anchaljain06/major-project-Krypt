# End-to-end test: two users over Krypt v1

`two-users.spec.ts` drives two Chromium contexts (Alice and Bob) through the real relay:

| Step | What it checks |
|---|---|
| Register both | Identity keys made, prekeys uploaded, vault gate passed |
| Befriend | Request, accept, socket notification |
| 10 texts each way | v1 handshake (Krypt-X3K) and ratchet, both directions |
| Image and audio | Per-attachment key, AES-GCM file, metadata inside the v1 message |
| Safety numbers | Both sides show the same 60 digits; the Security panel shows the ML-KEM-1024 ratchet |
| Bob offline | Messages wait in the mailbox; Bob logs in again (password only, no vault file) and decrypts them |
| Alice refreshes | Session cache restores the identity, the store key is re-derived, ratchet state survives |
| Final check | Every message is present, no decrypt-error toast, no `[Krypt]` warning in the console |

`files.spec.ts` covers large-file transfer (spec 14) between two users:

| Step | What it checks |
|---|---|
| 20 MB file | Offer, accept, 20 chunks of 1 MiB as binary `file:chunk` frames, both sides reach "Done", downloaded bytes match (SHA-256) |
| Zero-byte file named `../../empty.html` | One empty authenticated chunk; the download is saved as `_.._empty.html`, never opened |
| Cancel | Alice cancels before Bob answers; both cards show Cancelled and Bob can no longer accept |

Key transparency runs in **disabled** mode here unless the frontend is started with `VITE_KT_LOG_PUBKEY`.

`bench-files.spec.ts` is a benchmark, not a test: Playwright skips it unless `BENCH` is set, and `evaluation/files-bench/run.mjs` runs it (see `evaluation/README.md`, "File transfer"). The attack specs are skipped the same way unless `ATTACK` is set.

## Run it

Use a throwaway database. Do not use `primary-backend/.env`.

```bash
# 1. Postgres
docker run -d --name krypt-pg-int -e POSTGRES_PASSWORD=pg -p 55433:5432 postgres:16
export DATABASE_URL=postgresql://postgres:pg@localhost:55433/postgres
export DIRECT_URL=$DATABASE_URL

# 2. Backend on port 3100
cd primary-backend
npm install            # postinstall runs prisma generate, which needs the two URLs above
npx prisma migrate deploy
npx tsc
PORT=3100 FRONTEND_URL=http://localhost:5199 AUTH_TOKEN_SECRET=e2e-only-secret-0123456789abcdef \
  node dist/server.js

# 3. Frontend on port 5199 (another terminal)
cd frontend
VITE_API_URL=http://localhost:3100 npx vite --port 5199 --strictPort

# 4. The test (another terminal)
cd frontend
npx playwright install chromium   # once
npx playwright test               # E2E_BASE_URL overrides http://localhost:5199
```

Each run uses fresh usernames, so the database does not need to be reset between runs.

## With key transparency

This needs a backend that serves `/kt/*` (`major/v1-protocol` after the KT merge).

1. Run `node scripts/kt-keygen.mjs` in `primary-backend`.
2. Start the backend with `KT_LOG_SK=<seed>` and `KT_STH_INTERVAL_SECONDS=0`, so new leaves appear at once.
3. Start Vite with `VITE_KT_LOG_PUBKEY=<public key>`.
4. Run the test:

   ```bash
   E2E_EXPECT_KT=1 npx playwright test
   ```

The test then requires the "KT verified" badge and a "Verified" KT status for both contacts.
