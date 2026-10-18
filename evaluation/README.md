# Krypt evaluation harness (C3)

This package measures the cost of Krypt's cryptography in real browsers and in Node. It covers experiments E1–E5, E7 and E10 from strategy section 6.1. Where an experiment measures Krypt's own protocol code, it imports that code from `frontend/src/crypto/` instead of copying it: the E4 ratchet ops use `kdf.ts`, and E7 drives the shipped `SessionManager` in Node (see [E7](#e7-sparse-kem-ratchet-bandwidth-vs-healing)). The library benchmarks (E1–E3) call the libraries directly. Nothing imports from `primary-backend/`.

```
evaluation/
├─ bench/index.html, bench.ts   page controller: worker or main thread, results on window.__results
├─ bench/worker.ts              dedicated Web Worker that runs the suite
├─ src/e7-ratchet.ts            E7 driver: Alice/Bob over the real SessionManager, KEM op counters, attacker Eve
├─ src/harness.ts               batch timer (method rules below)
├─ src/stats.ts                 median, p5/p95, IQR, bootstrap CI
├─ src/experiments.ts           E1–E4 op definitions and self-checks
├─ scripts/run-bench.ts         Playwright: Chromium, Firefox, WebKit × N fresh launches
├─ scripts/run-node.ts          E10: node:crypto vs WebCrypto-in-Node vs noble vs liboqs
├─ scripts/e5-bytes.ts          E5 byte accounting (no timing)
├─ scripts/e7.ts                E7 runner: suite × K × traffic grid → results/e7-<date>/
├─ scripts/aggregate.ts         JSON → long.csv, summary.csv, env.csv, headline.md
├─ plots/plot.py                figures (PNG + SVG)
├─ plots/e7_plot.py             E7 figures (same style and palette)
└─ results/e7-2026-10-17/       E7 full grid: summary, per-snapshot results, figures
```

## Quick start (laptop)

```bash
cd eval
npm install
npx playwright install chromium firefox webkit

npm run bench:quick                         # 1 run × 3 browsers, quick config (about 1 min)
npm run bench                               # 5 fresh launches × 3 browsers, full method
npm run bench:node -- --quick               # E10 in Node (needs Node ≥ 24.7 for native ML-KEM)
npm run bytes                               # E5 → results/<date>/e5-bytes.csv
npm run aggregate -- results/<date>         # → summary.csv, long.csv, env.csv, headline.md

python3 -m venv .venv && .venv/bin/pip install -r plots/requirements.txt
npm run plot -- results/<date>              # → results/<date>/figures/*.png|svg

npm --prefix ../frontend install            # E7 imports frontend/src/crypto and its @noble deps
npm run e7                                  # E7 full grid (about 2 min) → results/e7-<date>/
npm run plot:e7 -- results/e7-<date>        # → results/e7-<date>/figures/e7_*.png|svg
```

Runner options:

```
tsx scripts/run-bench.ts --browsers chromium,webkit --runs 3 --mode main \
    --filter 'E1/ML-KEM-768' --batches 50 --headed --out results/my-run --no-build
```

Raw results go to `results/<YYYY-MM-DD>/<browser>-<run>.json`, which is gitignored. Only `results/sample-*` is committed.

## Method

These are the rules from strategy section 6.1, and where each one is enforced.

| Rule | How |
|---|---|
| Cross-origin isolation, so `performance.now()` resolves to about 5 µs instead of about 100 µs | `vite.config.ts` sends `COOP: same-origin` and `COEP: require-corp` in both dev and preview. Every result records `crossOriginIsolated` and a measured timer step (`timerResolutionUs`). |
| Discard 50–200 warm-up calls | Full mode: 100 calls. Quick mode: 50. |
| Batches of at least 10 ms | The batch size doubles until one batch takes ≥ 10 ms. Sample = batch time ÷ calls. |
| 30+ batches | Full mode: 30. Quick mode: 12, which deliberately breaks the rule; use it only for smoke tests. |
| Median, p95, IQR, bootstrap 95% CI; never the mean alone | `src/stats.ts`: type-7 quantiles, 10,000-resample percentile bootstrap of the median, seeded PRNG |
| Off the main thread | Default `mode=worker`. `?mode=main` measures the main thread for comparison. |
| Fresh state per run | Each of the N runs is a new browser launch |

`tinybench` also runs as a per-call cross-check in full mode (`tinybench_p50_ns` in `long.csv`). The batch timer is the number to report.

Every op checks itself before it is timed. Decaps must equal the encaps secret and verify must return true. Two cross-library checks also run: noble decapsulates liboqs ciphertexts, and noble verifies liboqs signatures. A backend that is missing is recorded as `status: "unsupported"` with the reason. It does not fail the run.

## What each experiment measures

| Exp | Ops | Backends |
|---|---|---|
| E1 | ML-KEM-512/768/1024 keygen, encaps, decaps; X-Wing (`ml_kem768_x25519`) keygen, encaps, decaps, as a comparison only (not a Krypt suite, spec §2.1) | noble 0.7.1, `@oqs/liboqs-js` 0.15.1 (WASM), native WebCrypto |
| E2 | ML-DSA-44/65/87 keygen, sign, verify (64-byte message) | noble, liboqs-js, native WebCrypto |
| E3 | X25519 keygen and derive; Ed25519 keygen, sign, verify | native WebCrypto, `@noble/curves` |
| E4 | AES-256-GCM encrypt/decrypt at 64 B, 1 KB, 16 KB, 256 KB, 1 MB (MB/s); ratchet `chain-step` (`kdfChain` + `messageKeyAndIv`, spec 5.3); `root-step` (`kdfRoot`, spec 5.2); `seal` = chain step + `aesGcmEncrypt` of 1 KB with a 256 B AAD. All three call `frontend/src/crypto/kdf.ts` | native WebCrypto |
| E5 | Bytes per handshake (bundle fetch + first message) and per steady-state message, each as raw vs binary vs Socket.io JSON/base64. v1 (ML-KEM-1024) is measured from a real handshake through the shipped `SessionManager`, `encodeBinaryEnvelope` and `buildWirePayload`. v1-mlkem768 and v1-xwing are the same real envelopes with the ratchet `ek`/`ct` resized (comparisons only, spec §2.1). v0 is hand-modelled, because its code exists only at tag `protocol-v0` | none (byte accounting; sizes checked against noble) |
| E10 | The same suite in Node, plus a `node-crypto` backend (`generateKeyPairSync('ml-kem-768')`, `crypto.encapsulate/decapsulate`, `crypto.sign/verify`) | noble, liboqs, Node WebCrypto, node:crypto |
| E7 | Sparse KEM ratchet interval K: bytes per message, KEM ops and CPU per message, messages-to-heal after a state compromise. See [E7](#e7-sparse-kem-ratchet-bandwidth-vs-healing) | the v1 `SessionManager` (noble ML-KEM-1024; results below are from the earlier ML-KEM-768 / X-Wing build), Node |

**Native WebCrypto detection.** The detection follows the WICG Modern Algorithms draft. The harness records what `SubtleCrypto.supports(op, alg)` reports, and whether `crypto.subtle.encapsulateBits` exists. It then makes a real `generateKey` call, because early implementations can disagree with `supports()`. The probes are stored under `env.nativeWebCrypto`.

**PQ ÷ classical** (`pq_vs_classical`) compares noble ML-KEM-768 and ML-DSA-65 against X25519 and Ed25519. Krypt itself now uses ML-KEM-1024 and ML-DSA-87 (spec §2); their E1/E2 numbers are slower. The classical side uses native WebCrypto where the runtime supports it. The pairings are:

- KEM keygen vs X25519 keygen
- encaps and decaps vs one X25519 derive
- ML-DSA vs Ed25519, op for op

## Figures (`plots/plot.py`)

| File | Strategy 6.1 figure |
|---|---|
| `e1e2_ops_by_browser` | ops/s by algorithm and browser: log scale, median bar, p5–p95 whiskers (noble) |
| `backend_comparison` | noble vs liboqs-js vs native per runtime (ML-KEM-768, ML-DSA-65); `n/a` = unsupported |
| `pq_vs_classical` | PQ ÷ classical bars, with a parity line |
| `aes_throughput` | AES-256-GCM MB/s vs size, log-log |
| `e5_bytes` | stacked bytes per handshake and per message, by component and encoding |
| `e10_node` | Node: native vs WASM vs JS |
| `heatmap_device_op` | device × operation median latency |

The colours are fixed per entity and identical in every figure:

- Browsers: Chromium blue, Firefox orange, WebKit aqua, Node pink.
- Backends: noble green, liboqs yellow, WebCrypto red, node:crypto violet.

Both sets passed a CVD and contrast palette validator (adjacent-pair ΔE ≥ 8). The bandwidth and heal vs K figures are E7's (`plots/e7_plot.py`, below). The other figures from 6.1 (latency CDF, attack matrix, KAT table) need E6, the evil relay and the KAT suite. Those experiments live elsewhere.

## E7: sparse KEM ratchet, bandwidth vs healing

E7 measures the research knob of contribution C1: the sparse interval `ratchetEveryK` (spec §5.6). Larger K means fewer KEM ratchet steps and smaller headers. It also means a stolen device state stays useful for longer.

### Method

`scripts/e7.ts` runs the grid and `src/e7-ratchet.ts` holds the driver. The run uses Node and `tsx`, not the browser page.

- **Code under test.** The driver imports `SessionManager` straight from `../frontend/src/crypto/session.ts`. Nothing is copied and nothing in `frontend/` is changed. Alice and Bob each have a `MemorySessionStore` and a `MemoryPrekeyStore`. They share an in-memory bundle directory, modelled on `frontend/test/helpers.ts`.
- **Grid.**
  - Suite: `mlkem1024`, the only ratchet suite since commit `4cab620`. The 2026-10-17 results below were run before that, with `mlkem768` and `xwing`.
  - K ∈ {1, 2, 5, 10, 50, 100}.
  - Four traffic patterns, 1,000 messages each, with 100-byte plaintexts.
  - Message 0 is always Alice's handshake.

  | Traffic | Script | Seeds |
  |---|---|---|
  | `alternate` | A B A B … | 1 |
  | `burst5` | 5 from A, then 5 from B | 1 |
  | `oneSided90` | each message is Alice's with p = 0.9 | 3 |
  | `poisson` | two Poisson processes, 1 msg/s per side. Relay latency is 0.15 s + Exp(0.35 s), capped at 3 s, FIFO per direction, so messages **cross in flight** | 3 |

  The first three deliver each message before the next one is sent.
- **Per message** (`messages.csv`, kept local because it is about 12 MB):
  - exact canonical header bytes, body bytes, binary frame `lp(header, body)` and JSON wire bytes;
  - whether `kem` or `init` rode on the header;
  - ratchet-KEM keygen, encaps and decaps on the sender and on the receiver. These are counted by wrapping the `mlkem1024` object's methods at runtime. Prekeys use the same object, so prekey operations are told apart by key fingerprint and counted separately;
  - encrypt and decrypt wall time, with the session-store time measured separately and subtracted. `cpu_*` is crypto plus state machine only.
- **CPU timing is single-call wall time** inside a stateful transcript. The batch rule of the browser harness cannot apply to stateful ops. A 60-message warm-up per suite runs first. Look at the mean and the root-step vs chain-step split (`cpu_root_ms_median`, `cpu_chain_ms_median`). The median alone hides a bimodal distribution.
- **Bytes** are reported excluding messages that carry the epoch-0 `init` header (`*_steady`). The all-message means are also in `summary.csv`. The binary frame here includes the `lp` length prefixes and the usernames, so K = 1 gives 2,516 B (ML-KEM-768). E5 derives its v1 rows from the same encoder, so its binary overhead plus the 100 B plaintext matches E7 exactly (3,381 / 2,516 / 2,577 B for ML-KEM-1024 / ML-KEM-768 / X-Wing).

### Threat model and attacker

The attacker is **passive** (spec §9, strategy §4.7).

- At compromise point k, Eve copies Alice's entire session store: `MemorySessionStore.clone()`, taken just before message k is sent.
- She sees every envelope on the wire from then on.
- She never injects, drops or modifies anything, and she never gets fresh randomness from Alice.

There are 20 compromise points per run, k = 100 + 23j. They cover both turn parities and every phase of a 5-message burst, and leave at least 463 messages after each one.

- **Bob → Alice.** Eve is a `SessionManager` over the cloned store. She `decrypt`s a copy of each of Bob's envelopes, in Alice's delivery order.
- **Alice → Bob.** Eve walks the stolen sending chain `cks` forward.
- **Exposure rule checked per message** (spec §9):
  - Alice→Bob is exposed iff `epoch = sendEpoch` at the snapshot.
  - Bob→Alice is exposed iff `epoch ≤ recvEpoch`, or `epoch = sendEpoch + 1` while Alice's `ourDk` was pending.

  `predicate_mismatches` counts every message where what Eve actually read differs from this rule.
- **Messages to heal** = messages from k up to and including Eve's last readable one (0 if she reads nothing).
  - A run is *healed* when the last post-k message in **each** direction is unreadable. Epochs only grow, so this means Eve is out for good.
  - Otherwise the value is a lower bound (`heal_censored`, hollow markers in the plots).
- **Forward secrecy.** For every message Alice had already sent or decrypted before k, Eve tries:
  - the snapshot's skipped keys;
  - both chain keys walked forward;
  - a `decrypt` on a separate clone.

  `fs_opened` must be 0. Bob's messages still in flight at k belong to Alice's future, not her past. They are counted as `exposed_in_flight`.

### Results (`results/e7-2026-10-17/`, Node 25.8.2, Apple-silicon MacBook)

> These results are from the build before commit `4cab620`, which had the `mlkem768` and `xwing` suites. They stay as the comparison behind spec §2.1. A quick ML-KEM-1024 run gave 3,381 B/msg at K = 1 and 1,959 at K = 10. The full ML-KEM-1024 grid at K = 1, 4, 8, 16 is still to run.

Strict alternation:

| K | bytes/msg, binary (mlkem768 / xwing) | JSON (mlkem768) | headers with `(ct, ek)` | KEM ops/msg | CPU ms/msg, mean (mlkem768 / xwing) | messages to heal, median (min–max) |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2,516 / 2,577 | 3,375 | 100% | 3.00 | 1.19 / 3.22 | 0.5 (0–1) |
| 2 | 1,945 / 1,990 | 2,611 | 75% | 1.50 | 0.65 / 1.66 | 1.5 (0–3) |
| 5 | 1,603 / 1,638 | 2,152 | 60% | 0.60 | 0.36 / 0.77 | 4.5 (0–9) |
| 10 | 1,489 / 1,521 | 1,999 | 55% | 0.30 | 0.25 / 0.46 | 9.5 (0–19) |
| 50 | 1,398 / 1,427 | 1,877 | 51% | 0.06 | 0.17 / 0.21 | 50.5 (0–93) |
| 100 | 1,386 / 1,416 | 1,862 | 50.5% | 0.03 | 0.15 / 0.17 | 89.5 (1–185) |

A header without ratchet data costs 236 B (binary), so the floor for any K is 236 B.

**Checks.**
- What Eve could read matched the §9 exposure rule on every message, for all 48 cells and 1,920 snapshots (`predicate_mismatches = 0`).
- No snapshot opened any earlier message (`fs_opened = 0`).
- Heal counts are identical for the two suites, because the KEM choice does not change the state machine.

**Findings.**
- **Alternating traffic keeps about half of the headers carrying `(ct, ek)` at large K**, as spec §5.6 predicts (50.5% at K = 100). The saving is mostly KEM work: 3 ops/msg at K = 1 against 0.03 at K = 100. Bytes drop only 45%.
- **Under strict alternation, K = 1 heals in at most one message.** With bursts or one-sided traffic it takes up to 9 or 57 messages. This is because the send step is lazy (spec §13.5). A snapshot taken while Alice holds Bob's new key but has not yet sent contains no fresh `dk`. Her next message heals both directions at once (heal = 0). Only a snapshot taken while her `dk` is pending exposes Bob's one reply (heal = 1).
- **Bursts of 5 get no byte saving until K > 5.** Every burst starts a new epoch.
- **One-sided traffic heals slowly.** A send step needs both K sends on one's own chain *and* a fresh key from the peer. So healing is paced by the *quieter* party's K sends. At 90/10 and K ≥ 50, 40 of 60 (K = 50) and 59 of 60 (K = 100) compromise points were still exposed at message 1,000.
- **Where §9's short form ("secrecy returns at P's next ratchet step") fails, and why that is expected:**
  - With crossing messages (`poisson`, even at K = 1), Bob can send on an exposed epoch after Alice's healing message has left but before it arrives. Across the 60 K = 1 Poisson snapshots, 41 messages were readable after Alice's ratchet.
  - With K > 1, Bob keeps sending up to K messages on his exposed chain after Alice ratchets.

  All of these messages are covered by §9's full statement ("messages in P's current epoch and in the peer's next epoch stay exposed"), and the per-message rule above predicts them exactly. The short form holds only for turn-taking traffic at K = 1.
- **X-Wing costs about 2.7× ML-KEM-768 per ratchet step in noble** (root-step median 3.2 ms vs 1.2 ms, encrypt plus decrypt). The X25519 part is pure JS. It adds 64 B of ratchet data to every header that carries `(ct, ek)`: 61 B net per message, because the suite name is 3 B shorter.

**Not covered.** Message loss and reordering are not covered: delivery is FIFO, so `skipped_peak` is 0 everywhere. CPU numbers are Node on one laptop, not browsers.

### Rerun

```bash
npm --prefix ../frontend install && npm install
npm run e7                                    # full grid, about 2 minutes on an M-series Mac
npm run e7 -- --quick                         # 200 messages, K ∈ {1, 10}, 4 snapshots: smoke test
npm run e7 -- --ks 1,4,8,16 --traffic alternate,poisson --seeds 1,2,3,4,5 --out results/my-e7
npm run plot:e7 -- results/e7-<date>
```

Outputs in `results/e7-<date>/`:

| File | Contents |
|---|---|
| `summary.csv` / `summary.json` | one row per (suite, K, traffic), seeds pooled |
| `snapshots.csv` | one row per compromise point: Alice's epochs at k, what Eve read, heal, FS check |
| `messages.csv` | one row per message (gitignored) |
| `env.json` | the configuration |
| `figures/` | `e7_bandwidth_vs_healing` (the key C1 figure: two stacked panels sharing K), `e7_bytes_vs_K`, `e7_heal_vs_K`, `e7_cpu_vs_K` |

## Running on real Safari (macOS / iOS)

WebKit in Playwright is not Safari. It has a different JIT tier policy, no Safari-specific power management, and a different build. To run on real Safari:

1. `npm run build && npx vite preview --config vite.config.ts --host` (serves on `:4174`, COOP/COEP on).
2. Open `http://<laptop-ip>:4174/?mode=worker` in Safari. For the full method, leave out `quick=1`.
3. Check that the header line says `crossOriginIsolated=true`. Wait for `done`, then press **Copy JSON** or **Download JSON**.
4. Save the file as `results/<date>/safari-<n>.json`. Add `"runner": {"browser": "safari", "browserVersion": "<x>", "run": n}` so that `aggregate.ts` labels it.

Note: on a LAN IP over plain HTTP, `crypto.subtle` is unavailable, because it is not a secure context. Use `localhost` on the Mac itself. For iOS, put it behind HTTPS (for example `npx vite preview --https` with a mkcert certificate, or a tunnel).

## Running on an Android phone (Chrome, USB)

1. Turn on USB debugging on the phone and connect it. Open `chrome://inspect/#devices` on the laptop.
2. Use **Port forwarding**: map `4174` → `localhost:4174`, then run `npx vite preview --config vite.config.ts`.
3. On the phone, open `http://localhost:4174/?mode=worker`. Over the forwarded port, `localhost` counts as a secure context.
4. Collect the results in one of two ways. Either use DevTools (**inspect** → Console → `copy(JSON.stringify(window.__results))`), or use the Download button. Label the file `android-<n>.json` with a `runner` block, as for Safari.
5. Record the model, the battery level and whether the phone was charging. Let it cool between runs.

## Caveats (say these in the report)

- **WebKit ≠ Safari.** Playwright's WebKit is a close build of the engine. It is not the shipping browser.
- **No cycle counters in browsers.** Report ns/op only. For a native reference, run liboqs `speed_kem` / `speed_sig` on the same laptop.
- **Timer resolution varies.** Under COOP/COEP, Chromium gives 5 µs and Firefox and WebKit give 20 µs, as measured in the sample. The ≥ 10 ms batches keep quantisation below 0.2%.
- **Thermal state and power.** Run on mains power with other apps closed. Do not run browsers in parallel. The runner launches them one after another. A laptop that is already warm reads slower.
- **Order effects.** Ops run in a fixed order inside one worker, and fresh launches across runs average out JIT history. If an order effect matters, randomise it with `--filter` subsets.
- **Async ops include promise overhead.** WebCrypto calls are awaited one at a time. This is the latency the app sees, not peak throughput. For example, AES at 64 B is dominated by about 1–9 µs of fixed per-call cost.
- **noble ML-DSA sign uses rejection sampling.** Its latency is heavy-tailed, so look at p95 and IQR, not only the median.
- **Native PQ in Chromium is very new.** Playwright's Chromium 156 exposed native ML-KEM-768/1024 and ML-DSA without flags. ML-KEM-512 was rejected (`Unrecognized name`). Confirm this on stable Chrome before claiming it for users.
- **The fixed AES IV** in the E4 throughput loop is only for benchmarking. The protocol derives a fresh IV per message key.

## Sample results (quick run, data not kept)

These are quick-mode numbers from one Mac. They show that the pipeline works and are not final data, so the raw files were not committed; Phase E re-runs everything on the final code: 12 batches (fewer than the 30 the method requires), 50 warm-up calls, and one run per source on an Apple-silicon MacBook (10 cores) on 2026-10-17. Sources were Chromium 156.0.8078.4, Firefox 157.0, WebKit 27.2 and Node v25.8.2. For the report, rerun with `npm run bench` (5 × 3, full method) plus real Safari and an Android phone.

ML-KEM-768 encaps, median:

| | noble | liboqs-js (WASM) | native WebCrypto | node:crypto |
|---|---:|---:|---:|---:|
| Chromium | 211 µs | 18.7 µs | 5.8 µs | – |
| Firefox | 297 µs | 22.5 µs | unsupported | – |
| WebKit | 414 µs | 22.0 µs | unsupported | – |
| Node 25 | 252 µs | 19.4 µs | 23.8 µs | 16.4 µs |

On bytes (E5 on the current code, ML-KEM-1024 ratchet), v1 at K = 1 costs 3,232 B raw (4,490 B JSON/base64) of overhead per message, against 40 B for v0. A full v1 handshake (bundle + first message) is about 26 KB raw (35 KB JSON), against about 10 KB for v0.
