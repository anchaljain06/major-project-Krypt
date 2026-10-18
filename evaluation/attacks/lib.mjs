/**
 * Shared helpers for the attack-matrix runners: spawn/stop servers, wait for a
 * port, run one attack spec, and the abuse checks done in Node (impersonation
 * and BOLA) for v1 and v0.
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import net from "node:net";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const FRONTEND = join(ROOT, "frontend");
export const FRONTEND_NM = join(FRONTEND, "node_modules");

/** Attacks checked in Node against an honest server; the rest need two browsers. */
const NODE_CHECKS = new Set(["impersonation", "bola"]);
export const splitPlain = (ids) => ({
  plain: ids.filter((id) => NODE_CHECKS.has(id)),
  browser: ids.filter((id) => !NODE_CHECKS.has(id)),
});

/** Fresh usernames per attack, shared by the relay env and the spec. */
export function namesFor(id) {
  const suffix = `${id}_${Date.now().toString(36).slice(-5)}`.toLowerCase().replace(/[^a-z0-9_]/g, "");
  return { alice: `alice_${suffix}`, bob: `bob_${suffix}`, mallory: `mallory_${suffix}` };
}

/** Replace the __MALLORY__ / __BOB__ placeholders in an attack's env with real usernames. */
export function resolveEnv(env, names) {
  const out = {};
  for (const [k, v] of Object.entries(env ?? {})) out[k] = v === "__MALLORY__" ? names.mallory : v === "__BOB__" ? names.bob : v;
  return out;
}

/** Run one Playwright spec in Chromium for one attack; true if it passed. */
export function runSpec(spec, attack, names, env) {
  const r = spawnSync("npx", ["playwright", "test", spec, "--project", "chromium"], {
    cwd: FRONTEND,
    stdio: "inherit",
    env: {
      ...process.env,
      ATTACK: attack.id,
      ALICE_NAME: names.alice,
      BOB_NAME: names.bob,
      MALLORY_NAME: names.mallory,
      ...env,
    },
  });
  return r.status === 0;
}

/** If a spec failed without writing its result, record that so the matrix shows it. */
export function writeFailure(outDir, id, extra = {}) {
  const file = join(outDir, `${id}.json`);
  if (!existsSync(file)) writeFileSync(file, JSON.stringify({ attack: id, ...extra, observed: "spec failed (no result)", error: true }, null, 2));
}

// socket.io-client is not a dependency of evaluation/, so load it from the
// frontend's node_modules (KRYPT_FRONTEND_NM, set by the runners).
function loadIoClient() {
  const nm = process.env.KRYPT_FRONTEND_NM;
  if (!nm) throw new Error("KRYPT_FRONTEND_NM (frontend/node_modules path) is not set");
  const require = createRequire(pathToFileURL(nm + "/"));
  return require("socket.io-client").io;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function waitForPort(port, host = "127.0.0.1", timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = () => {
      const sock = net.connect(port, host);
      sock.once("connect", () => {
        sock.destroy();
        resolve();
      });
      sock.once("error", () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`port ${port} not up in ${timeoutMs}ms`));
        else setTimeout(tick, 400);
      });
    };
    tick();
  });
}

export function waitForHttp(url, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tick = async () => {
      try {
        await fetch(url);
        resolve();
      } catch {
        if (Date.now() > deadline) reject(new Error(`${url} not up`));
        else setTimeout(tick, 400);
      }
    };
    tick();
  });
}

/** Spawn a child, prefix its output, and return a handle with a stop() that waits for exit. */
export function spawnProc(cmd, args, { cwd, env, label }) {
  const child = spawn(cmd, args, { cwd, env: { ...process.env, ...env } });
  const tag = label ?? cmd;
  const line = (buf) => {
    for (const l of buf.toString().split("\n")) if (l.trim()) process.stdout.write(`  [${tag}] ${l}\n`);
  };
  child.stdout.on("data", line);
  child.stderr.on("data", line);
  return {
    child,
    stop: () =>
      new Promise((resolve) => {
        if (child.exitCode !== null || child.signalCode) return resolve();
        child.once("exit", () => resolve());
        child.kill("SIGINT");
        setTimeout(() => {
          if (child.exitCode === null) child.kill("SIGKILL");
          resolve();
        }, 4000);
      }),
  };
}

/**
 * v1 impersonation: a socket with no auth token tries to come online. The
 * server must refuse it (connect_error), because identity comes from the token.
 * v0 is checked end to end by checkMailboxDrainV0 instead.
 */
export async function checkImpersonation({ apiUrl }) {
  const ioClient = loadIoClient();
  return await new Promise((resolve) => {
    let settled = false;
    const done = (observed, hijacked) => {
      if (settled) return;
      settled = true;
      try {
        s.close();
      } catch {
        /* ignore */
      }
      resolve({ observed, hijacked });
    };
    const s = ioClient(apiUrl, { auth: {}, reconnection: false, transports: ["websocket", "polling"] });
    s.on("connect_error", (e) => done(`connect_error: ${e.message}`, false));
    s.on("connect", () => done("connected_without_token (UNEXPECTED)", true));
    setTimeout(() => done("timeout (no connect, no error)", false), 9000);
  });
}

/**
 * v0 mailbox drain, end to end:
 *   1. a sender socket queues a message for the (offline) victim;
 *   2. an impostor socket emits register_socket(victim) with no credentials;
 *   3. if the impostor receives the queued payload, the hijack worked, and the
 *      server has purged it, so the real victim will never see it.
 */
export async function checkMailboxDrainV0({ apiUrl, sender, victim }) {
  const ioClient = loadIoClient();
  const marker = `queued-for-${victim}-${Date.now()}`;
  // 1. queue
  await new Promise((resolve) => {
    const s = ioClient(apiUrl, { reconnection: false, transports: ["websocket"] });
    s.on("connect", () => {
      s.emit("register_socket", sender);
      s.emit("private_message", { to: victim, from: sender, ciphertext: marker, type: "text" }, () => {
        s.close();
        resolve();
      });
    });
    s.on("connect_error", () => resolve());
    setTimeout(resolve, 5000);
  });
  // 2. impersonate
  return await new Promise((resolve) => {
    const got = [];
    const s = ioClient(apiUrl, { reconnection: false, transports: ["websocket"] });
    const done = () => {
      s.close();
      const drained = got.some((m) => m && m.ciphertext === marker);
      resolve({
        observed: drained
          ? `impostor socket registered as ${victim} with no credentials and received the victim's queued message (mailbox drained)`
          : `impostor received ${got.length} message(s); queued message not obtained`,
        hijacked: drained,
        refused: !drained,
      });
    };
    s.on("connect", () => {
      s.on("receive_message", (m) => got.push(m));
      s.emit("register_socket", victim);
      setTimeout(done, 3000);
    });
    s.on("connect_error", (e) => resolve({ observed: `connect_error: ${e.message}`, hijacked: false, refused: true }));
  });
}

/**
 * v0 BOLA, end to end: Mallory sends Bob a friend request and then accepts it
 * on Bob's behalf, with no credentials at all. Success = Mallory appears in
 * Bob's friend list without Bob doing anything.
 */
export async function checkBolaV0({ apiUrl, attacker, victim }) {
  const post = (path, body) =>
    fetch(`${apiUrl}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const reg = (u) => post("/api/register", { username: u, publicKey: "x", srpSalt: "x", srpVerifier: "x" });
  await reg(attacker);
  await reg(victim);
  await post("/api/request/send", { sender: attacker, receiver: victim });
  const acc = await post("/api/request/accept", { sender: attacker, receiver: victim });
  const friends = await fetch(`${apiUrl}/api/friends/${victim}`).then((r) => r.json()).catch(() => ({}));
  const isFriend = Array.isArray(friends.friends) && friends.friends.includes(attacker);
  return {
    observed: `POST /api/request/accept on ${victim}'s behalf (no token) -> HTTP ${acc.status}; ${attacker} ${isFriend ? "IS" : "is not"} in ${victim}'s friend list`,
    refused: !isFriend,
    status: acc.status,
  };
}

/**
 * v1 BOLA: accept a friend request on someone else's behalf with no
 * Authorization header. Expect 401: v1 takes the acting user from the token only.
 * v0 is checked end to end by checkBolaV0 instead.
 */
export async function checkBola({ apiUrl, sender, receiver }) {
  try {
    const res = await fetch(`${apiUrl}/api/request/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, receiver }),
    });
    const refused = res.status === 401;
    let body = "";
    try {
      body = JSON.stringify(await res.json());
    } catch {
      /* ignore */
    }
    return { observed: `HTTP ${res.status} ${body}`, refused, status: res.status };
  } catch (e) {
    return { observed: `fetch failed: ${e.message}`, refused: false, status: -1 };
  }
}
