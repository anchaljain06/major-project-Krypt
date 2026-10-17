/**
 * Attack-matrix runner, v0 side (tag protocol-v0, scratch copy).
 *
 * Layout per attack:
 *   v0 backend (scratch dist/server.js)  on V0_BACKEND_PORT
 *   evil proxy (evil-proxy.mjs, EVIL_MODE set)  on PROXY_PORT  -> v0 backend
 *   v0 frontend (scratch, VITE_API_URL=proxy)  on V0_VITE_PORT
 *   frontend/e2e/attacks-v0.spec.ts drives it.
 *
 * impersonation and bola are checked in Node directly against the v0 backend
 * (no token system at all in v0).
 *
 * Usage: node evaluation/attacks/run-v0.mjs [attackId ...]
 * Env:   V0_DIR (scratch copy, required), DATABASE_URL/DIRECT_URL (v0 DB), OUT_DIR
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATTACKS } from "./attacks.mjs";
import { checkBolaV0, checkMailboxDrainV0, spawnProc, waitForHttp, sleep } from "./lib.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const FRONTEND = join(ROOT, "frontend");
const FRONTEND_NM = join(FRONTEND, "node_modules");
const BACKEND_NM = join(ROOT, "primary-backend", "node_modules");
const EVIL_JS = join(ROOT, "primary-backend", "dist", "evil.js");
const PROXY = join(HERE, "evil-proxy.mjs");

const V0_DIR = process.env.V0_DIR;
if (!V0_DIR || !existsSync(V0_DIR)) {
  console.error("V0_DIR must point at the extracted protocol-v0 copy.");
  process.exit(1);
}
const V0_BACKEND_DIR = join(V0_DIR, "primary-backend");
const V0_FRONTEND_DIR = join(V0_DIR, "frontend");

const V0_BACKEND_PORT = Number(process.env.V0_BACKEND_PORT ?? 3301);
const PROXY_PORT = Number(process.env.PROXY_PORT ?? 3300);
const V0_VITE_PORT = Number(process.env.V0_VITE_PORT ?? 5299);
const PROXY_URL = `http://localhost:${PROXY_PORT}`;
const V0_BACKEND_URL = `http://localhost:${V0_BACKEND_PORT}`;
const BASE_URL = `http://localhost:${V0_VITE_PORT}`;
const OUT_DIR = process.env.OUT_DIR ?? join(ROOT, "evaluation", "results", "attack-matrix-dev", "v0");
mkdirSync(OUT_DIR, { recursive: true });

if (!process.env.DATABASE_URL || !process.env.DIRECT_URL) {
  console.error("DATABASE_URL and DIRECT_URL (v0 throwaway DB) required.");
  process.exit(1);
}
const DB = { DATABASE_URL: process.env.DATABASE_URL, DIRECT_URL: process.env.DIRECT_URL };

function startV0Backend() {
  return spawnProc("node", ["dist/server.js"], {
    cwd: V0_BACKEND_DIR,
    env: { PORT: String(V0_BACKEND_PORT), FRONTEND_URL: BASE_URL, ...DB },
    label: "v0-backend",
  });
}

function startProxy(attack, names) {
  const evilEnv = {};
  for (const [k, v] of Object.entries(attack.env ?? {}))
    evilEnv[k] = v === "__MALLORY__" ? names.mallory : v === "__BOB__" ? names.bob : v;
  return spawnProc("node", [PROXY], {
    cwd: HERE,
    env: {
      ...evilEnv,
      PROXY_PORT: String(PROXY_PORT),
      V0_BACKEND_URL,
      KRYPT_EVIL_JS: EVIL_JS,
      KRYPT_BACKEND_NM: BACKEND_NM,
      KRYPT_FRONTEND_NM: FRONTEND_NM,
    },
    label: "evil-proxy",
  });
}

function startV0Vite() {
  return spawnProc("npx", ["vite", "--port", String(V0_VITE_PORT), "--strictPort"], {
    cwd: V0_FRONTEND_DIR,
    env: { VITE_API_URL: PROXY_URL },
    label: "v0-vite",
  });
}

function runPlaywright(attack, names) {
  const r = spawnSync("npx", ["playwright", "test", "attacks-v0.spec.ts", "--project", "chromium"], {
    cwd: FRONTEND,
    stdio: "inherit",
    env: {
      ...process.env,
      ATTACK: attack.id,
      OUT_DIR,
      E2E_BASE_URL: BASE_URL,
      PROXY_URL,
      ALICE_NAME: names.alice,
      BOB_NAME: names.bob,
      MALLORY_NAME: names.mallory,
    },
  });
  return r.status === 0;
}

async function main() {
  const argv = process.argv.slice(2);
  // v0 has no KT; skip kt_* attacks.
  const applicable = ATTACKS.filter((a) => !a.kt).map((a) => a.id);
  const requested = (argv.length ? argv : applicable).filter((id) => applicable.includes(id));
  process.env.KRYPT_FRONTEND_NM = FRONTEND_NM;

  const plain = requested.filter((id) => id === "impersonation" || id === "bola");
  const browser = requested.filter((id) => id !== "impersonation" && id !== "bola");

  if (plain.length) {
    console.log(`== v0 plain checks: ${plain.join(", ")} ==`);
    const backend = startV0Backend();
    await waitForHttp(`${V0_BACKEND_URL}/api/users/search?q=x&current_user=x`).catch(() => sleep(2000));
    await sleep(800);
    try {
      const tag = Date.now().toString(36).slice(-5);
      if (plain.includes("impersonation")) {
        // Seed a victim with a queued message, then drain it as an impostor.
        const r = await checkMailboxDrainV0({ apiUrl: V0_BACKEND_URL, sender: `alice_imp_${tag}`, victim: `bob_imp_${tag}` });
        writeFileSync(
          join(OUT_DIR, "impersonation.json"),
          JSON.stringify({ attack: "impersonation", flavor: "v0", ...r }, null, 2),
        );
        console.log(`  impersonation: ${r.observed} (hijacked=${r.hijacked})`);
      }
      if (plain.includes("bola")) {
        const r = await checkBolaV0({ apiUrl: V0_BACKEND_URL, attacker: `mallory_bola_${tag}`, victim: `bob_bola_${tag}` });
        writeFileSync(join(OUT_DIR, "bola.json"), JSON.stringify({ attack: "bola", flavor: "v0", ...r }, null, 2));
        console.log(`  bola: ${r.observed} (refused=${r.refused})`);
      }
    } finally {
      await backend.stop();
      await sleep(400);
    }
  }

  for (const id of browser) {
    const attack = ATTACKS.find((a) => a.id === id);
    const suffix = `${id}_${Date.now().toString(36).slice(-5)}`.toLowerCase().replace(/[^a-z0-9_]/g, "");
    const names = { alice: `alice_${suffix}`, bob: `bob_${suffix}`, mallory: `mallory_${suffix}` };
    console.log(`\n== v0 attack: ${id} (EVIL_MODE=${attack.env?.EVIL_MODE ?? "none"}) ==`);
    const backend = startV0Backend();
    await waitForHttp(`${V0_BACKEND_URL}/api/users/search?q=x&current_user=x`).catch(() => sleep(2000));
    const proxy = startProxy(attack, names);
    const vite = startV0Vite();
    await waitForHttp(`${PROXY_URL}/api/users/search?q=x&current_user=x`).catch(() => sleep(1500));
    await waitForHttp(`${BASE_URL}/`);
    await sleep(1500);
    try {
      const ok = runPlaywright(attack, names);
      if (!ok && !existsSync(join(OUT_DIR, `${id}.json`)))
        writeFileSync(join(OUT_DIR, `${id}.json`), JSON.stringify({ attack: id, flavor: "v0", observed: "spec failed (no result)", error: true }, null, 2));
    } finally {
      await vite.stop();
      await proxy.stop();
      await backend.stop();
      await sleep(500);
    }
  }
  console.log(`\nResults in ${OUT_DIR}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
