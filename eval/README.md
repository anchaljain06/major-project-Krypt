# Krypt evaluation harness (C3)

This package measures the cost of Krypt's cryptography in real browsers and in Node. It covers experiments E1–E5 and E10 from strategy section 6.1, and has a hook for E7. It is a standalone package: it does not import from `frontend/` or `primary-backend/`.

```
eval/
├─ bench/index.html, bench.ts   page controller: worker or main thread, results on window.__results
├─ bench/worker.ts              dedicated Web Worker that runs the suite
├─ bench/e7-ratchet.ts          E7 stub: what to measure once session.ts lands
├─ src/harness.ts               batch timer (method rules below)
├─ src/stats.ts                 median, p5/p95, IQR, bootstrap CI
├─ src/experiments.ts           E1–E4 op definitions and self-checks
├─ scripts/run-bench.ts         Playwright: Chromium, Firefox, WebKit × N fresh launches
├─ scripts/run-node.ts          E10: node:crypto vs WebCrypto-in-Node vs noble vs liboqs
├─ scripts/e5-bytes.ts          E5 byte accounting (no timing)
├─ scripts/aggregate.ts         JSON → long.csv, summary.csv, env.csv, headline.md
├─ plots/plot.py                figures (PNG + SVG)
└─ results/sample-2026-10-17/   committed sample. QUICK mode, one Mac, NOT final data
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
| E1 | ML-KEM-512/768/1024 keygen, encaps, decaps; X-Wing (`ml_kem768_x25519`) keygen, encaps, decaps | noble 0.7.1, `@oqs/liboqs-js` 0.15.1 (WASM), native WebCrypto |
| E2 | ML-DSA-44/65/87 keygen, sign, verify (64-byte message) | noble, liboqs-js, native WebCrypto |
| E3 | X25519 keygen and derive; Ed25519 keygen, sign, verify | native WebCrypto, `@noble/curves` |
| E4 | AES-256-GCM encrypt/decrypt at 64 B, 1 KB, 16 KB, 256 KB, 1 MB (MB/s); ratchet `chain-step` (HMAC×2 + HKDF 44 B, strategy 4.4); `root-step` (HKDF 64 B); `seal` = chain step + AES-GCM of 1 KB | native WebCrypto |
| E5 | Bytes per handshake (bundle fetch + first message) and per steady-state message for v0, v1 (ML-KEM-768 ratchet) and v1-xwing, each as raw vs length-prefixed binary vs Socket.io JSON/base64 | none (pure accounting from FIPS 203/204 sizes, checked against noble) |
| E10 | The same suite in Node, plus a `node-crypto` backend (`generateKeyPairSync('ml-kem-768')`, `crypto.encapsulate/decapsulate`, `crypto.sign/verify`) | noble, liboqs, Node WebCrypto, node:crypto |
| E7 | Not implemented. See `bench/e7-ratchet.ts` for the exact protocol. It needs `frontend/src/crypto/session.ts` on main. | |

**Native WebCrypto detection.** The detection follows the WICG Modern Algorithms draft. The harness records what `SubtleCrypto.supports(op, alg)` reports, and whether `crypto.subtle.encapsulateBits` exists. It then makes a real `generateKey` call, because early implementations can disagree with `supports()`. The probes are stored under `env.nativeWebCrypto`.

**PQ ÷ classical** (`pq_vs_classical`) compares noble ML-KEM-768 and ML-DSA-65, which is what Krypt ships, against X25519 and Ed25519. The classical side uses native WebCrypto where the runtime supports it. The pairings are:

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

Both sets passed a CVD and contrast palette validator (adjacent-pair ΔE ≥ 8). The other figures from 6.1 (latency CDF, bandwidth and heal vs K, attack matrix, KAT table) need E6, E7, the evil relay and the KAT suite. Those experiments live elsewhere.

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

## Sample results (`results/sample-2026-10-17/`)

These are quick-mode numbers from one Mac. They show that the pipeline works and are not final data: 12 batches (fewer than the 30 the method requires), 50 warm-up calls, and one run per source on an Apple-silicon MacBook (10 cores) on 2026-10-17. Sources were Chromium 156.0.8078.4, Firefox 157.0, WebKit 27.2 and Node v25.8.2. For the report, rerun with `npm run bench` (5 × 3, full method) plus real Safari and an Android phone.

ML-KEM-768 encaps, median:

| | noble | liboqs-js (WASM) | native WebCrypto | node:crypto |
|---|---:|---:|---:|---:|
| Chromium | 211 µs | 18.7 µs | 5.8 µs | – |
| Firefox | 297 µs | 22.5 µs | unsupported | – |
| WebKit | 414 µs | 22.0 µs | unsupported | – |
| Node 25 | 252 µs | 19.4 µs | 23.8 µs | 16.4 µs |

See `headline.md` in the sample folder for ML-KEM-768 and ML-DSA-65 across all ops. The other files there are:

- `summary.csv`: every op
- `e5-bytes.csv`: bytes per component
- `figures/`: the plots

On bytes, v1 at K = 1 costs 2,345 B raw (3,260 B JSON/base64) per message, against 40 B for v0. A full v1 handshake is about 24 KB raw (32 KB JSON), against about 10 KB for v0.
