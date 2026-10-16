# krypt-witness

A GitHub Actions witness for the Krypt key transparency log (plan step 2.24). Every 15 minutes it:

1. fetches the log's signed tree head (STH),
2. checks it is consistent with the last head it cosigned,
3. refuses forks,
4. publishes its ML-DSA cosignature on GitHub Pages.

The Krypt server (Render) cannot change what GitHub Pages serves. That is why clients compare their view against the witness.

This directory is meant to become its own repository (`krypt-witness`). It carries a vendored build of `shared/` in `lib/krypt-shared/` for that reason. After changing `shared/`, run `node scripts/vendor-shared.mjs`. Run `node scripts/vendor-shared.mjs --check` to detect a stale copy.

## Setup

1. **Create the repository.** Copy this directory to the root of a new **public** repository called `krypt-witness`. Pages and Actions minutes are free for public repositories. Commit `package-lock.json`.
2. **Generate the witness key.** Run `npm ci && node scripts/keygen.mjs`. It prints two values:
   - `WITNESS_SK`, a base64 32-byte seed. The full key is derived from it on every run.
   - The ML-DSA-44 public key.

   Ship the public key in the Krypt frontend build.
3. **Add the secret.** Go to Settings → Secrets and variables → Actions → *New repository secret*. Name it `WITNESS_SK` and paste the seed.
4. **Add repository variables** on the *Variables* tab of the same page:
   - `KRYPT_LOG_URL`: the backend base URL, for example `https://krypt-api.onrender.com`.
   - `KRYPT_LOG_PUBKEY`: the log's ML-DSA-87 STH public key, in base64.
   - `KRYPT_WITNESS_NAME` (optional): defaults to `krypt-witness`.
5. **Enable Pages.** Go to Settings → Pages → Source and choose **GitHub Actions**.
6. **First run.** Go to Actions → *witness* → *Run workflow*. Then check that `https://<user>.github.io/krypt-witness/latest.json` is served.

### Environment variables

`witness.mjs` reads these. The workflow sets them from the secret and variables above.

| Variable | Meaning |
|---|---|
| `KRYPT_LOG_URL` | Log base URL. The witness calls `/kt/sth` and `/kt/consistency?from=&to=`. |
| `KRYPT_LOG_PUBKEY` or `KRYPT_LOG_PUBKEY_FILE` | Log ML-DSA-87 public key (2592 bytes), base64 or a file containing base64. |
| `WITNESS_SK` | Witness seed, base64 32 bytes. |
| `KRYPT_WITNESS_NAME` | Name included in each cosignature. Default `krypt-witness`. |
| `KRYPT_WITNESS_DIR` | Where `state/` and `public/` live. Default: this directory. |
| `KRYPT_WITNESS_REFRESH_MINUTES` | How old the last cosignature must be before the witness re-cosigns an unchanged head. Default 360. This avoids a commit every 15 minutes. |
| `KRYPT_FETCH_TIMEOUT_MS` | Per-request timeout. Default 90000, because the Render free tier can take about a minute to wake. There are 3 attempts. |

### Files

| File | Content |
|---|---|
| `public/latest.json` | `{ log: { id, url }, witness: { name, algorithm, publicKey }, sth, cosignature }`. Clients fetch this. |
| `state/last.json` | The last cosigned head. This is the witness's memory, kept in git history. |
| `state/ALERT.json` | Written only when an inconsistency is proven. It holds both signed heads, the log key, and the failing proof (`{ from, to, proof }`). Anyone can check it offline. |

### Exit codes

| Code | Meaning | Workflow behaviour |
|---|---|---|
| 0 | Cosigned, or nothing new | Commit and deploy Pages |
| 1 | Fork or history rewrite proven, or halted by an earlier alert | Commit the evidence, fail the job (GitHub emails the owner) |
| 2 | Refused without evidence: log unreachable, bad signature, stale or future-dated head, misconfiguration | Warning only |

The alert is **sticky**. While `state/ALERT.json` exists the witness cosigns nothing. A human must review the evidence and delete the file.

## Why ML-DSA-44

C2SP tlog-cosignature recommends ML-DSA-44 for new deployments.

| | ML-DSA-44 (witness) | ML-DSA-87 (log STH) |
|---|---|---|
| Signature size | 2420 B | 4627 B |
| Public key size | 1312 B | 2592 B |
| NIST security category | 2 | 5 |

A cosignature is a short-lived freshness statement that clients re-fetch. Category 2 is still post-quantum. The smaller signature and key keep `latest.json` and the key pinned in the frontend small. The log keeps ML-DSA-87, because its signed heads are long-term evidence.

## Things to know

- **60-day inactivity.** GitHub disables scheduled workflows in public repositories after 60 days without repository activity. It is not documented whether the witness's own bot commits count as activity, and they stop when the log does not change. **Push a commit by hand at least once a month,** or re-enable the workflow under Actions if GitHub disables it.
- **Schedules are best effort.** GitHub may delay or skip `*/15` runs under load. Clients should accept a cosignature that is a few hours old. They should treat one older than about a day as "witness stale", not as an attack.
- **Trust on first use.** The very first head the witness sees is accepted without a consistency proof. Start the witness before real users register.

## Threat model

The witness checks one thing: **every head it cosigns extends every head it cosigned before.** It does not read or judge the leaves. Detecting rogue keys is the owners' job (self-monitoring).

| Protects against | Does not protect against |
|---|---|
| History rewrites and forks shown to the witness: the cosignature chain cannot follow both branches | A log that shows the witness one view and some clients another, **if** those clients never compare their head with `latest.json`. Clients must check |
| The log changing published evidence: it has no write access to this repository or to Pages | The log colluding with every witness. There is one witness here, so its operator is trusted not to cosign a fork |
| A network attacker feeding junk: unsigned or badly signed heads are refused, not cosigned | Theft of `WITNESS_SK`: the thief can cosign anything. Rotate the key and re-pin it in the frontend |
| Replay of an older head: refused as stale, or flagged as a fork if inconsistent | A compromised GitHub account or Actions runner; denial of service (the log can simply be unreachable, which is exit 2, not an alert) |

## Development

```
npm ci
npm test                 # node --test against a fake log on localhost (no network)
```

The tests cover:

- first run,
- normal growth (consistency proofs fetched and checked),
- the refresh window,
- a history rewrite (ALERT written, nothing cosigned, sticky halt),
- a same-size fork,
- a stale head versus an inconsistent older head,
- bad, future-dated and wrong-key signatures,
- CLI exit codes.
