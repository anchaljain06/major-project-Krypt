/**
 * Shared helpers for the attack-matrix runners: spawn/stop servers, wait for a
 * port, and the two protocol-independent abuse checks (socket impersonation and
 * BOLA) that are the same idea against v0 and v1.
 */
import { spawn } from "node:child_process";
import net from "node:net";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

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
 * Impersonation: a socket that is not the victim tries to come online as them.
 *  - v1: connect with no auth token; the server must refuse (connect_error).
 *  - v0: connect, then emit register_socket("<victim>") and listen for any of
 *        the victim's messages / mailbox. If anything is received, the hijack worked.
 */
export async function checkImpersonation({ apiUrl, flavor, victim }) {
  const ioClient = loadIoClient();
  return await new Promise((resolve) => {
    const got = [];
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
    s.on("receive_message", (m) => got.push(m));
    s.on("online_users", (u) => got.push({ online_users: u }));
    s.on("connect", () => {
      if (flavor === "v0") {
        s.emit("register_socket", victim);
        setTimeout(
          () =>
            done(
              got.length ? `registered as ${victim}; received ${got.length} event(s) incl. mailbox/presence` : "connected, no events",
              got.length > 0,
            ),
          4000,
        );
      } else {
        // v1 should never reach here without a token.
        done("connected_without_token (UNEXPECTED)", true);
      }
    });
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
 * BOLA: accept a friend request on someone else's behalf, no/!own token.
 *  - v0: POST /api/request/accept {sender, receiver} with no auth at all.
 *  - v1: same call with no Authorization header (expect 401) — and the route
 *        also requires the token user to be the receiver (403 otherwise).
 */
export async function checkBola({ apiUrl, sender, receiver }) {
  try {
    const res = await fetch(`${apiUrl}/api/request/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender, receiver }),
    });
    const refused = res.status === 401 || res.status === 403;
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
