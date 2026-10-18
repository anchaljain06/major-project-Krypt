/**
 * Phase E browser benchmarks (plan E.4, new-plan section 12): file chunk sizes,
 * resume after a disconnect, and one full first session + 100 messages + a file.
 *
 * Starts the real relay once. For each frontend build (one per chunk size, made
 * with VITE_FILE_CHUNK_SIZE) it serves a production build with `vite preview`
 * and runs frontend/e2e/bench-files.spec.ts in Chromium. Raw JSON per benchmark,
 * then summary.csv and headline.md, go to OUT_DIR.
 *
 * Usage:
 *   node evaluation/files-bench/run.mjs [--quick]
 * Env:
 *   DATABASE_URL, DIRECT_URL   throwaway Postgres (required)
 *   OUT_DIR                     default evaluation/results/files-<date>
 *   BACKEND_PORT=3100 VITE_PORT=5199
 * Needs primary-backend built (npx tsc) and migrated, and Playwright's Chromium.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os, { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { FRONTEND, ROOT, sleep, spawnProc, waitForHttp, waitForPort } from "../attacks/lib.mjs";

const QUICK = process.argv.includes("--quick");
const BACKEND_PORT = Number(process.env.BACKEND_PORT ?? 3100);
const VITE_PORT = Number(process.env.VITE_PORT ?? 5199);
const API_URL = `http://localhost:${BACKEND_PORT}`;
const BASE_URL = `http://localhost:${VITE_PORT}`;
const today = new Date().toISOString().slice(0, 10);
const OUT_DIR = resolve(process.env.OUT_DIR ?? join(ROOT, "evaluation", "results", `files-${today}`));
const KiB = 1024;
const CHUNK_SIZES = [256 * KiB, 1024 * KiB, 4096 * KiB];
const DEFAULT_CHUNK = 1024 * KiB;
const PLAN = QUICK
  ? { chunks: { runs: 1, mib: 16 }, resume: { runs: 1, mib: 16 }, session: { runs: 1, mib: 4 } }
  : { chunks: { runs: 5, mib: 100 }, resume: { runs: 5, mib: 64 }, session: { runs: 3, mib: 10 } };

if (!process.env.DATABASE_URL || !process.env.DIRECT_URL) {
  console.error("DATABASE_URL and DIRECT_URL must point at a throwaway Postgres.");
  process.exit(1);
}
mkdirSync(OUT_DIR, { recursive: true });

/** Production build with the given chunk size (undefined = the app default), served by vite preview. */
async function serveBuild(chunkSize) {
  const outDir = mkdtempSync(join(tmpdir(), "krypt-bench-"));
  const env = { ...process.env, VITE_API_URL: API_URL };
  if (chunkSize) env.VITE_FILE_CHUNK_SIZE = String(chunkSize);
  else delete env.VITE_FILE_CHUNK_SIZE;
  const b = spawnSync("npx", ["vite", "build", "--outDir", outDir, "--emptyOutDir", "--logLevel", "warn"], { cwd: FRONTEND, env, stdio: "inherit" });
  if (b.status !== 0) throw new Error("vite build failed");
  const preview = spawnProc("npx", ["vite", "preview", "--outDir", outDir, "--port", String(VITE_PORT), "--strictPort"], {
    cwd: FRONTEND,
    env: {},
    label: "preview",
  });
  await waitForHttp(`${BASE_URL}/`);
  return {
    stop: async () => {
      await preview.stop();
      rmSync(outDir, { recursive: true, force: true });
    },
  };
}

function runBench(bench, file, { runs, mib }, extra = {}) {
  const r = spawnSync("npx", ["playwright", "test", "bench-files.spec.ts", "--project", "chromium"], {
    cwd: FRONTEND,
    stdio: "inherit",
    env: {
      ...process.env,
      BENCH: bench,
      BENCH_OUT: join(OUT_DIR, file),
      BENCH_RUNS: String(runs),
      BENCH_FILE_MIB: String(mib),
      VITE_API_URL: API_URL,
      E2E_BASE_URL: BASE_URL,
      ...extra,
    },
  });
  if (r.status !== 0) console.error(`!! ${bench} (${file}) failed; see the output above`);
  return r.status === 0;
}

/** Machine and power state for env.json (E.4 records power state with every result). */
function machine() {
  let power = "unknown";
  try {
    if (process.platform === "darwin") power = execFileSync("pmset", ["-g", "batt"], { encoding: "utf8" }).trim().replace(/\s+/g, " ");
  } catch {
    /* not available */
  }
  return {
    date: new Date().toISOString(),
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    cpu: os.cpus()[0]?.model,
    cores: os.cpus().length,
    memGiB: Math.round(os.totalmem() / 2 ** 30),
    node: process.version,
    power,
    plan: PLAN,
  };
}

// ---------------------------------------------------------------------------
// Summary

const med = (xs) => {
  const s = xs.filter(Number.isFinite).sort((a, b) => a - b);
  if (!s.length) return NaN;
  const m = (s.length - 1) / 2;
  return (s[Math.floor(m)] + s[Math.ceil(m)]) / 2;
};
const range = (xs) => `${Math.min(...xs).toFixed(0)}-${Math.max(...xs).toFixed(0)}`;
const mb = (b) => (b / (1024 * 1024)).toFixed(1);
const read = (f) => {
  try {
    return JSON.parse(readFileSync(join(OUT_DIR, f), "utf8"));
  } catch {
    return null;
  }
};

/** "Now drawing from 'Battery Power' ... 64%; discharging ..." -> "Battery Power, 64%". */
const powerShort = (p) => [/'([^']+)'/.exec(p)?.[1], /(\d+%)/.exec(p)?.[1]].filter(Boolean).join(", ") || p;

function summarize() {
  const rows = [];
  const md = [`# Phase E file benchmarks (${today})`, ""];
  const chunkRuns = CHUNK_SIZES.map((c) => [c, read(`chunks-${c / KiB}k.json`)]).filter(([, d]) => d);
  const env = chunkRuns[0]?.[1]?.env ?? read("resume.json")?.env ?? read("session.json")?.env;
  const m = read("env.json");
  if (env) md.push(`Chromium ${env.browserVersion}, production build, local relay and Postgres on one machine${m ? ` (${m.cpu}, ${powerShort(m.power)})` : ""}. Median over fresh user pairs (range in brackets).`, "");

  if (chunkRuns.length) {
    md.push(
      `## Chunk size (${chunkRuns[0][1].env.fileMiB} MiB file, ${chunkRuns[0][1].env.runs} runs each)`,
      "",
      "| Chunk | Accept to done, ms | MiB/s | Retries | Peak heap growth, MiB (sender / receiver) | Peak buffer growth, MiB (sender / receiver) | Long tasks (sender / receiver) | Longest task, ms | Bytes match |",
      "|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    );
    for (const [c, d] of chunkRuns) {
      const r = d.runs;
      const g = (side, k) => med(r.map((x) => x.heap[side][`peak${k}`] - x.heap[side][`base${k}`]));
      const row = {
        bench: "chunks",
        chunk_bytes: c,
        runs: r.length,
        ms_median: med(r.map((x) => x.ms)),
        mib_per_s_median: med(r.map((x) => x.mibPerS)),
        retries_total: r.reduce((n, x) => n + x.retries, 0),
        heap_growth_sender_bytes: g("alice", "Js"),
        heap_growth_receiver_bytes: g("bob", "Js"),
        buffer_growth_sender_bytes: g("alice", "Buffers"),
        buffer_growth_receiver_bytes: g("bob", "Buffers"),
        long_tasks_sender: med(r.map((x) => x.longTasks.alice.count)),
        long_tasks_receiver: med(r.map((x) => x.longTasks.bob.count)),
        longest_task_ms: Math.max(...r.map((x) => Math.max(x.longTasks.alice.maxMs, x.longTasks.bob.maxMs))),
        bytes_match: r.every((x) => x.bytesMatch),
      };
      rows.push(row);
      md.push(
        `| ${c / KiB} KiB | ${row.ms_median.toFixed(0)} (${range(r.map((x) => x.ms))}) | ${row.mib_per_s_median.toFixed(1)} | ${row.retries_total} | ` +
          `${mb(row.heap_growth_sender_bytes)} / ${mb(row.heap_growth_receiver_bytes)} | ${mb(row.buffer_growth_sender_bytes)} / ${mb(row.buffer_growth_receiver_bytes)} | ` +
          `${row.long_tasks_sender} / ${row.long_tasks_receiver} | ${row.longest_task_ms.toFixed(0)} | ${row.bytes_match ? "yes" : "**no**"} |`,
      );
    }
    md.push("");
  }

  const resume = read("resume.json");
  if (resume) {
    const r = resume.runs;
    const row = {
      bench: "resume",
      chunk_bytes: DEFAULT_CHUNK,
      runs: r.length,
      completed: r.filter((x) => x.completed && x.bytesMatch).length,
      resume_ms_median: med(r.map((x) => x.resumeMs)),
      chunks_resent_median: med(r.map((x) => x.chunksResent)),
      retransmitted_bytes_median: med(r.map((x) => x.retransmittedBytes)),
      one_counter_per_chunk: r.every((x) => x.oneCounterPerChunk),
      identical_resends: r.every((x) => x.identicalResends),
      counter_reused: r.some((x) => x.counterReused),
      sender_paused: r.filter((x) => x.alicePausedDuringOutage).length,
    };
    rows.push(row);
    md.push(
      `## Resume (${resume.env.fileMiB} MiB, 1 MiB chunks, receiver offline ${resume.downMs} ms after half the chunks)`,
      "",
      "| Completed, bytes match | Sender paused | Reconnect to done, ms | Chunks re-sent | Re-sent bytes | One nonce counter per chunk | Re-sends byte-identical | Counter reused |",
      "|---:|---:|---:|---:|---:|---|---|---|",
      `| ${row.completed}/${row.runs} | ${row.sender_paused}/${row.runs} | ${row.resume_ms_median.toFixed(0)} (${range(r.map((x) => x.resumeMs))}) | ` +
        `${row.chunks_resent_median} (${range(r.map((x) => x.chunksResent))}) | ${mb(row.retransmitted_bytes_median)} MiB | ` +
        `${row.one_counter_per_chunk ? "yes" : "**no**"} | ${row.identical_resends ? "yes" : "**no**"} | ${row.counter_reused ? "**yes**" : "no"} |`,
      "",
    );
  }

  const session = read("session.json");
  if (session) {
    const r = session.runs;
    md.push(
      `## Entire experience (${r.length} runs; file ${session.env.fileMiB} MiB)`,
      "",
      "| Phase | Time, ms | Up, KiB (WS + HTTP) | Down, KiB (WS + HTTP) |",
      "|---|---:|---:|---:|",
    );
    const names = [...Object.keys(r[0].phases), "total"];
    for (const name of names) {
      const get = (x) => (name === "total" ? x.total : x.phases[name]);
      const row = {
        bench: "session",
        phase: name,
        runs: r.length,
        ms_median: med(r.map((x) => get(x).ms)),
        up_bytes_median: med(r.map((x) => get(x).wsUp + get(x).httpUp)),
        down_bytes_median: med(r.map((x) => get(x).wsDown + get(x).httpDown)),
        bytes_match: r.every((x) => x.bytesMatch),
      };
      rows.push(row);
      md.push(`| ${name} | ${row.ms_median.toFixed(0)} | ${(row.up_bytes_median / KiB).toFixed(0)} | ${(row.down_bytes_median / KiB).toFixed(0)} |`);
    }
    md.push("");
  }

  const cols = [...new Set(rows.flatMap((x) => Object.keys(x)))];
  const cell = (v) => (v === undefined || (typeof v === "number" && !Number.isFinite(v)) ? "" : typeof v === "number" ? String(Number(v.toFixed(3))) : String(v));
  writeFileSync(join(OUT_DIR, "summary.csv"), [cols.join(","), ...rows.map((x) => cols.map((c) => cell(x[c])).join(","))].join("\n") + "\n");
  writeFileSync(join(OUT_DIR, "headline.md"), md.join("\n"));
  console.log("\n" + md.join("\n"));
}

// ---------------------------------------------------------------------------

async function main() {
  if (process.argv.includes("--summary-only")) return summarize();
  writeFileSync(join(OUT_DIR, "env.json"), JSON.stringify(machine(), null, 1) + "\n");
  const backend = spawnProc("node", ["dist/server.js"], {
    cwd: join(ROOT, "primary-backend"),
    env: { PORT: String(BACKEND_PORT), FRONTEND_URL: BASE_URL, AUTH_TOKEN_SECRET: "files-bench-only-secret-0123456789abcdef" },
    label: "backend",
  });
  try {
    await waitForHttp(`${API_URL}/api/health`).catch(() => waitForPort(BACKEND_PORT));
    await sleep(1000);
    for (const c of CHUNK_SIZES) {
      console.log(`\n== chunks: ${c / KiB} KiB ==`);
      const srv = await serveBuild(c === DEFAULT_CHUNK ? undefined : c);
      try {
        runBench("chunks", `chunks-${c / KiB}k.json`, PLAN.chunks);
        if (c === DEFAULT_CHUNK) {
          console.log("\n== resume ==");
          runBench("resume", "resume.json", PLAN.resume, { BENCH_CHUNK_BYTES: String(DEFAULT_CHUNK) });
          console.log("\n== session ==");
          runBench("session", "session.json", PLAN.session);
        }
      } finally {
        await srv.stop();
        await sleep(500);
      }
    }
  } finally {
    await backend.stop();
  }
  summarize();
  console.log(`\nResults in ${OUT_DIR}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
