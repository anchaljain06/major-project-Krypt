// E7 hook: sparse KEM ratchet interval (strategy 4.4 "Sparse mode", plan step 3.23).
//
// STATUS: stub. This depends on the v1 SessionManager in frontend/src/crypto/session.ts, which
// has not landed on main yet (on 2026-10-17 wt/protocol-core has pq.ts, kdf.ts and
// ratchet.ts, but no session.ts). This file is deliberately not imported by bench.ts or
// worker.ts, so the page builds without it.
//
// TODO(E7): once session.ts is on main, implement runE7() below and wire it into run.ts
// behind `?exp=E7`. Exactly what to measure:
//
// Setup
//   - Import SessionManager straight from '../../frontend/src/crypto/session.ts' (no copy),
//     so the benchmark exercises the shipped code. Add a Vite `server.fs.allow` entry for
//     '../frontend'.
//   - Two in-memory peers, Alice and Bob, wired back-to-back (no socket), with an
//     in-memory store instead of IndexedDB so storage I/O is not timed.
//   - For each KEM suite in {"mlkem768", "xwing"} (plan step 3.5, KEM_SUITE flag) and each
//     K in {1, 10, 50, 100}: set the sparse interval to K, then run a fixed conversation
//     script of 1,000 messages with realistic turn-taking (alternate runs of 1-5
//     messages per side, seeded PRNG) plus one 200-message monologue to exercise the
//     "repeat (ct, ek) until reply" rule.
//
// Measure per (suite, K)
//   1. bytes/message: exact encoded size of every envelope under the binary frame and
//      under the JSON/base64 frame (reuse the encoders from scripts/e5-bytes.ts or the
//      session's own serializer). Report the mean, the p95 and the share of messages that
//      carry (ct, ek). At K = 1 the expectation is about 2.3 KB/message (E5 gives
//      2,345 B raw / 3,260 B JSON for ML-KEM-768 with a 100 B plaintext).
//   2. CPU/message: encrypt+send and receive+decrypt time per message with the
//      harness.ts batch rules. Split the cost into root-step messages (Encaps/Decaps +
//      keygen + HKDF) and chain-step-only messages, because the mean hides a
//      bimodal distribution.
//   3. messages-to-heal (post-compromise security):
//        a. at message k (k = 100, 300, 600) deep-copy Alice's full ratchet state:
//           the "attacker snapshot";
//        b. the attacker passively follows the transcript: it advances its copy using
//           only public headers and the snapshot, never fresh randomness from Alice;
//        c. count the messages after k that the attacker can still decrypt; healing
//           happens at the first message whose key depends on a KEM secret that was
//           generated after the snapshot;
//        d. also confirm that messages before k stay closed: forward secrecy means the
//           snapshot cannot decrypt earlier ciphertexts once their mk has been erased.
//      Report the median and max over the three k values and 20 seeded conversations.
//   4. skipped-key store size: peak number of cached keys under 5% random loss and
//      reordering (MAX_SKIP = 1000 per chain, so this must stay bounded).
//
// Output: append { exp: 'E7', suite, K, bytesPerMsg, cpuPerMsg, healMsgs, skippedPeak }
// rows to the results document. aggregate.ts passes unknown exps through unchanged.
// plot.py needs a new figure: bytes/message and messages-to-heal as two stacked
// small multiples sharing the x axis K (log). This is the key C1 figure. Never use a
// dual y axis.

export interface E7Row {
  exp: 'E7';
  suite: 'mlkem768' | 'xwing';
  K: number;
  bytesPerMsgBinary: { mean: number; p95: number };
  bytesPerMsgJson: { mean: number; p95: number };
  shareWithRatchetData: number;
  cpuPerMsgNs: { rootStep: number; chainOnly: number; overall: number };
  healMsgs: { median: number; max: number };
  forwardSecrecyHeld: boolean;
  skippedPeak: number;
}

export async function runE7(): Promise<E7Row[]> {
  throw new Error('E7 not implemented: needs frontend/src/crypto/session.ts (v1 SessionManager) on main');
}
