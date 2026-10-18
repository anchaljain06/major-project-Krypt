// E7 runner: suites x K x traffic x seeds, 1,000 messages each, passive-attacker snapshots.
//
//   npm run e7                       # full grid -> results/e7-<date>/
//   npm run e7 -- --quick            # 200 messages, K in {1, 10}, one seed (smoke test)
//   npm run e7 -- --out results/x --messages 1000 --ks 1,2,5 --traffic alternate
//
// Writes:
//   messages.csv   one row per message (bytes, ratchet data, KEM ops, timings)   [not committed]
//   snapshots.csv  one row per compromise point (what Eve could read, heal, FS check)
//   summary.csv / summary.json   one row per (suite, K, traffic), seeds pooled
//   env.json       runtime and configuration
import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  TRAFFIC,
  analyseSnapshot,
  runConversation,
  type MsgRecord,
  type SnapshotResult,
  type Traffic,
} from "../src/e7-ratchet.ts";
import type { KemSuite } from "../../frontend/src/crypto/pq.ts";
import { toCsv } from "../src/csv.ts";
import { mean, quantileOf } from "../src/stats.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const opt = (name: string, def: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : def;
};
const quick = flag("quick");
const date = new Date().toISOString().slice(0, 10);
const outDir = path.resolve(opt("out", path.join(here, "..", "results", `e7-${date}${quick ? "-quick" : ""}`)));
const messages = Number(opt("messages", quick ? "200" : "1000"));
const Ks = opt("ks", quick ? "1,10" : "1,2,5,10,50,100").split(",").map(Number);
const suites = opt("suites", "mlkem1024").split(",") as KemSuite[];
const traffics = opt("traffic", TRAFFIC.join(",")).split(",") as Traffic[];
// Deterministic scripts need one seed; random ones get three.
const randomSeeds = opt("seeds", quick ? "1" : "1,2,3").split(",").map(Number);
// Compromise points: 20 values from 100 with step 23, so they cover both parities and every
// phase of a 5-message burst; all leave at least 463 messages to watch healing.
const snapshotsAt = Array.from({ length: quick ? 4 : 20 }, (_, j) => Math.floor(messages / 10) + 23 * j).filter(
  (k) => k < messages,
);

mkdirSync(outDir, { recursive: true });

const q = quantileOf;
const r3 = (x: number) => (Number.isFinite(x) ? Math.round(x * 1000) / 1000 : x);
const csv = (rows: readonly object[]) => toCsv(rows as Record<string, unknown>[], 3);

// Warm-up: JIT the KEMs, HKDF and AES paths before anything is timed.
for (const suite of suites) {
  await runConversation({ suite, K: 1, traffic: "alternate", seed: 99, messages: 60, snapshotsAt: [] });
}

const msgRows: Record<string, unknown>[] = [];
const snapRows: SnapshotResult[] = [];
const summary: Record<string, unknown>[] = [];
const t0 = performance.now();

for (const suite of suites) {
  for (const K of Ks) {
    for (const traffic of traffics) {
      const seeds = traffic === "alternate" || traffic === "burst5" ? [1] : randomSeeds;
      const cellMsgs: MsgRecord[] = [];
      const cellSnaps: SnapshotResult[] = [];
      const epochs: number[] = [];
      for (const seed of seeds) {
        const c = await runConversation({ suite, K, traffic, seed, messages, snapshotsAt });
        for (const m of c.msgs) {
          msgRows.push({
            suite, K, traffic, seed,
            idx: m.idx, from: m.from, sendT: m.sendT, deliverT: m.deliverT, deliverSeq: m.deliverSeq,
            epoch: m.epoch, n: m.n, pn: m.pn, ratchetData: m.ratchetData, kind: m.kind,
            headerBytes: m.headerBytes, bodyBytes: m.bodyBytes, binaryBytes: m.binaryBytes, jsonBytes: m.jsonBytes,
            encKeygen: m.encKem.keygen, encEncaps: m.encKem.encaps, encDecaps: m.encKem.decaps,
            decKeygen: m.decKem.keygen, decEncaps: m.decKem.encaps, decDecaps: m.decKem.decaps,
            prekeyKemOps: m.prekeyKemOps,
            encMs: m.encMs, encStoreMs: m.encStoreMs, decMs: m.decMs, decStoreMs: m.decStoreMs,
            skippedAlice: m.skippedAlice, skippedBob: m.skippedBob,
          });
        }
        cellMsgs.push(...c.msgs);
        epochs.push(Math.max(...c.msgs.map((m) => m.epoch)));
        for (const snap of c.snapshots) cellSnaps.push(await analyseSnapshot(c, snap));
      }
      snapRows.push(...cellSnaps);

      const steady = cellMsgs.filter((m) => m.ratchetData !== "init");
      const timed = cellMsgs.filter((m) => m.kind !== "handshake");
      const cpu = (m: MsgRecord) => m.encMs - m.encStoreMs + (m.decMs - m.decStoreMs);
      const kemOps = (m: MsgRecord) =>
        m.encKem.keygen + m.encKem.encaps + m.encKem.decaps + m.decKem.keygen + m.decKem.encaps + m.decKem.decaps;
      const heal = cellSnaps.map((s) => s.healMsgs);
      const row = {
        suite, K, traffic,
        seeds: seeds.length,
        messages: cellMsgs.length,
        maxEpoch_mean: mean(epochs),
        sendSteps: cellMsgs.filter((m) => m.encKem.encaps > 0).length,
        share_ratchet_data: cellMsgs.filter((m) => m.ratchetData !== "none").length / cellMsgs.length,
        share_init: cellMsgs.filter((m) => m.ratchetData === "init").length / cellMsgs.length,
        share_kem_steady: steady.filter((m) => m.ratchetData === "kem").length / steady.length,
        header_mean: mean(cellMsgs.map((m) => m.headerBytes)),
        binary_mean: mean(cellMsgs.map((m) => m.binaryBytes)),
        binary_p95: q(cellMsgs.map((m) => m.binaryBytes), 0.95),
        json_mean: mean(cellMsgs.map((m) => m.jsonBytes)),
        json_p95: q(cellMsgs.map((m) => m.jsonBytes), 0.95),
        header_mean_steady: mean(steady.map((m) => m.headerBytes)),
        body_mean: mean(cellMsgs.map((m) => m.bodyBytes)),
        binary_mean_steady: mean(steady.map((m) => m.binaryBytes)),
        json_mean_steady: mean(steady.map((m) => m.jsonBytes)),
        kem_ops_per_msg: mean(timed.map(kemOps)),
        keygen_per_msg: mean(timed.map((m) => m.encKem.keygen + m.decKem.keygen)),
        encaps_per_msg: mean(timed.map((m) => m.encKem.encaps + m.decKem.encaps)),
        decaps_per_msg: mean(timed.map((m) => m.encKem.decaps + m.decKem.decaps)),
        cpu_ms_mean: mean(timed.map(cpu)),
        cpu_ms_median: q(timed.map(cpu), 0.5),
        cpu_ms_p95: q(timed.map(cpu), 0.95),
        cpu_root_ms_median: q(timed.filter((m) => m.kind === "root").map(cpu), 0.5),
        cpu_chain_ms_median: q(timed.filter((m) => m.kind === "chain").map(cpu), 0.5),
        share_root_msgs: timed.filter((m) => m.kind === "root").length / timed.length,
        enc_ms_median: q(timed.map((m) => m.encMs - m.encStoreMs), 0.5),
        enc_ms_p95: q(timed.map((m) => m.encMs - m.encStoreMs), 0.95),
        root_steps_per_100: (100 * cellMsgs.filter((m) => m.encKem.encaps > 0).length) / cellMsgs.length,
        dec_ms_median: q(timed.map((m) => m.decMs - m.decStoreMs), 0.5),
        store_ms_mean: mean(timed.map((m) => m.encStoreMs + m.decStoreMs)),
        handshake_cpu_ms: mean(cellMsgs.filter((m) => m.kind === "handshake").map(cpu)),
        skipped_peak: Math.max(...cellMsgs.map((m) => Math.max(m.skippedAlice, m.skippedBob))),
        snapshots: cellSnaps.length,
        heal_median: q(heal, 0.5),
        heal_p90: q(heal, 0.9),
        heal_max: Math.max(...heal),
        heal_min: Math.min(...heal),
        heal_censored: cellSnaps.filter((s) => !s.healed).length,
        exposed_median: q(cellSnaps.map((s) => s.exposedAfter), 0.5),
        exposed_max: Math.max(...cellSnaps.map((s) => s.exposedAfter)),
        exposed_in_flight: cellSnaps.reduce((a, s) => a + s.exposedInFlight, 0),
        predicate_mismatches: cellSnaps.reduce((a, s) => a + s.predicateMismatches, 0),
        exposed_after_alice_ratchet: cellSnaps.reduce((a, s) => a + s.exposedAfterAliceRatchet, 0),
        fs_checked: cellSnaps.reduce((a, s) => a + s.fsChecked, 0),
        fs_opened: cellSnaps.reduce((a, s) => a + s.fsOpened, 0),
      };
      summary.push(row);
      const el = ((performance.now() - t0) / 1000).toFixed(0);
      console.log(
        `[e7 ${el}s] ${suite} K=${K} ${traffic}: ${r3(row.binary_mean_steady)} B/msg, ` +
          `heal med ${row.heal_median} max ${row.heal_max} (censored ${row.heal_censored}/${row.snapshots}), ` +
          `cpu ${r3(row.cpu_ms_median)} ms, mismatches ${row.predicate_mismatches}, fs opened ${row.fs_opened}`,
      );
    }
  }
}

writeFileSync(path.join(outDir, "messages.csv"), csv(msgRows));
writeFileSync(path.join(outDir, "snapshots.csv"), csv(snapRows));
writeFileSync(path.join(outDir, "summary.csv"), csv(summary));
writeFileSync(path.join(outDir, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
writeFileSync(
  path.join(outDir, "env.json"),
  JSON.stringify(
    {
      exp: "E7",
      date,
      quick,
      node: process.version,
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
      cpu: os.cpus()[0]?.model,
      cores: os.cpus().length,
      messages,
      Ks,
      suites,
      traffics,
      randomSeeds,
      snapshotsAt,
      plaintextBytes: 100,
      poisson: "1 msg/s per side; latency 0.15 s + Exp(0.35 s), cap 3 s, FIFO per direction",
      store: "MemorySessionStore (JSON round trip), timed separately and subtracted from cpu_*",
      seconds: Math.round((performance.now() - t0) / 1000),
    },
    null,
    2,
  ) + "\n",
);
console.log(`[e7] wrote ${outDir}`);

// Correctness, not just numbers: Eve's reads must match the spec 9 exposure rule, and no
// message from before a compromise may open. CI relies on this exit code.
const broken = summary.filter((r) => Number(r.predicate_mismatches) > 0 || Number(r.fs_opened) > 0);
if (broken.length) {
  for (const r of broken) console.error(`[e7] FAIL ${r.suite} K=${r.K} ${r.traffic}: mismatches ${r.predicate_mismatches}, fs opened ${r.fs_opened}`);
  process.exit(1);
}
