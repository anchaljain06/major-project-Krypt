/**
 * Attack-matrix runner, v1 side (this branch).
 *
 * For each attack it starts a fresh v1 backend with the matching EVIL_MODE, a
 * Vite dev server, runs frontend/e2e/attacks.spec.ts for that one attack, then
 * tears the servers down. KT attacks start the backend with a KT log key and
 * Vite with VITE_KT_LOG_PUBKEY pinned. impersonation/bola are checked in Node
 * against a plain (honest) backend.
 *
 * Usage:
 *   node evaluation/attacks/run-v1.mjs [attackId ...]
 * Env:
 *   DATABASE_URL, DIRECT_URL   throwaway Postgres (required)
 *   OUT_DIR                     results dir (required)
 *   BACKEND_PORT=3100 VITE_PORT=5199
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATTACKS } from "./attacks.mjs";
import { checkBola, checkImpersonation, spawnProc, waitForHttp, waitForPort, sleep } from "./lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const BACKEND = join(ROOT, "primary-backend");
const FRONTEND = join(ROOT, "frontend");
const FRONTEND_NM = join(FRONTEND, "node_modules");

const BACKEND_PORT = Number(process.env.BACKEND_PORT ?? 3100);
const VITE_PORT = Number(process.env.VITE_PORT ?? 5199);
const API_URL = `http://localhost:${BACKEND_PORT}`;
const BASE_URL = `http://localhost:${VITE_PORT}`;
const OUT_DIR = process.env.OUT_DIR ?? join(ROOT, "evaluation", "results", "attack-matrix-dev", "v1");
mkdirSync(OUT_DIR, { recursive: true });

if (!process.env.DATABASE_URL || !process.env.DIRECT_URL) {
  console.error("DATABASE_URL and DIRECT_URL must point at a throwaway Postgres.");
  process.exit(1);
}

const AUTH_SECRET = "attack-matrix-only-secret-0123456789abcdef";

// A KT log key pair (seed + public key), generated once for the KT runs.
let KT = null;
function ktKeys() {
  if (KT) return KT;
  const out = execFileSync("node", ["scripts/kt-keygen.mjs"], { cwd: BACKEND, encoding: "utf8" });
  const b64 = out.match(/[A-Za-z0-9+/]{40,}={0,2}/g) ?? [];
  const sk = b64.find((s) => s.length < 80); // 32-byte seed -> 44 chars
  const pk = b64.find((s) => s.length > 2000); // 2592-byte ML-DSA-87 pk
  if (!sk || !pk) throw new Error("could not parse KT keygen output");
  KT = { sk, pk };
  return KT;
}

function resolveEnv(env, names) {
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    out[k] = v === "__MALLORY__" ? names.mallory : v === "__BOB__" ? names.bob : v;
  }
  return out;
}

async function startServers(attack, names) {
  const kt = attack.kt;
  const evilEnv = resolveEnv(attack.env ?? {}, names);
  const backendEnv = {
    PORT: String(BACKEND_PORT),
    FRONTEND_URL: BASE_URL,
    AUTH_TOKEN_SECRET: AUTH_SECRET,
    DATABASE_URL: process.env.DATABASE_URL,
    DIRECT_URL: process.env.DIRECT_URL,
    ...evilEnv,
  };
  if (kt) {
    backendEnv.KT_LOG_SK = ktKeys().sk;
    backendEnv.KT_STH_INTERVAL_SECONDS = "0";
  }
  const backend = spawnProc("node", ["dist/server.js"], { cwd: BACKEND, env: backendEnv, label: "backend" });

  const viteEnv = { VITE_API_URL: API_URL };
  if (kt) viteEnv.VITE_KT_LOG_PUBKEY = ktKeys().pk;
  const vite = spawnProc("npx", ["vite", "--port", String(VITE_PORT), "--strictPort"], {
    cwd: FRONTEND,
    env: viteEnv,
    label: "vite",
  });

  const stop = async () => {
    await backend.stop();
    await vite.stop();
  };
  try {
    await waitForHttp(`${API_URL}/api/health`).catch(() => waitForPort(BACKEND_PORT));
    await waitForHttp(`${BASE_URL}/`);
  } catch (e) {
    await stop();
    throw e;
  }
  await sleep(1500);
  return { stop };
}

function runPlaywright(attack, names) {
  const r = spawnSync("npx", ["playwright", "test", "attacks.spec.ts", "--project", "chromium"], {
    cwd: FRONTEND,
    stdio: "inherit",
    env: {
      ...process.env,
      ATTACK: attack.id,
      OUT_DIR,
      VITE_API_URL: API_URL,
      E2E_BASE_URL: BASE_URL,
      E2E_EXPECT_KT: attack.kt ? "1" : "0",
      ALICE_NAME: names.alice,
      BOB_NAME: names.bob,
      MALLORY_NAME: names.mallory,
    },
  });
  return r.status === 0;
}

async function runPlainChecks(ids) {
  // One honest backend for impersonation + bola.
  const backend = spawnProc("node", ["dist/server.js"], {
    cwd: BACKEND,
    env: {
      PORT: String(BACKEND_PORT),
      FRONTEND_URL: BASE_URL,
      AUTH_TOKEN_SECRET: AUTH_SECRET,
      DATABASE_URL: process.env.DATABASE_URL,
      DIRECT_URL: process.env.DIRECT_URL,
    },
    label: "backend",
  });
  await waitForHttp(`${API_URL}/api/health`).catch(() => waitForPort(BACKEND_PORT));
  await sleep(800);
  try {
    if (ids.includes("impersonation")) {
      const r = await checkImpersonation({ apiUrl: API_URL, flavor: "v1", victim: "victim" });
      writeFileSync(
        join(OUT_DIR, "impersonation.json"),
        JSON.stringify({ attack: "impersonation", flavor: "v1", ...r, observed: r.observed, refused: !r.hijacked }, null, 2),
      );
      console.log(`  impersonation: ${r.observed}`);
    }
    if (ids.includes("bola")) {
      const r = await checkBola({ apiUrl: API_URL, sender: "someone", receiver: "victim" });
      writeFileSync(join(OUT_DIR, "bola.json"), JSON.stringify({ attack: "bola", flavor: "v1", ...r }, null, 2));
      console.log(`  bola: ${r.observed}`);
    }
  } finally {
    await backend.stop();
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const requested = argv.length ? argv : ATTACKS.map((a) => a.id);

  const plain = requested.filter((id) => id === "impersonation" || id === "bola");
  const browser = requested.filter((id) => id !== "impersonation" && id !== "bola");

  process.env.KRYPT_FRONTEND_NM = FRONTEND_NM;
  if (plain.length) {
    console.log(`== v1 plain checks: ${plain.join(", ")} ==`);
    await runPlainChecks(plain);
  }

  for (const id of browser) {
    const attack = ATTACKS.find((a) => a.id === id);
    if (!attack) {
      console.error(`unknown attack ${id}`);
      continue;
    }
    // Fresh, fixed usernames per attack, shared by the backend env and the spec,
    // so EVIL_SWAP_WITH / EVIL_KT_VICTIM name the accounts the spec registers.
    const suffix = `${id}_${Date.now().toString(36).slice(-5)}`.toLowerCase().replace(/[^a-z0-9_]/g, "");
    const names = { alice: `alice_${suffix}`, bob: `bob_${suffix}`, mallory: `mallory_${suffix}` };
    console.log(`\n== v1 attack: ${id} (EVIL_MODE=${attack.env?.EVIL_MODE ?? "none"}${attack.kt ? ", KT on" : ""}) ==`);
    const srv = await startServers(attack, names);
    try {
      const ok = runPlaywright(attack, names);
      if (!ok && !existsSync(join(OUT_DIR, `${id}.json`))) {
        writeFileSync(join(OUT_DIR, `${id}.json`), JSON.stringify({ attack: id, observed: "spec failed (no result)", error: true }, null, 2));
      }
    } finally {
      await srv.stop();
      await sleep(500);
    }
  }
  console.log(`\nResults in ${OUT_DIR}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
