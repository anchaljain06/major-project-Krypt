#!/usr/bin/env node
// Krypt KT witness (plan 2.24). One run:
//
//   1. GET ${KRYPT_LOG_URL}/kt/sth and verify the log's ML-DSA-87 signature.
//   2. Compare with the last head this witness cosigned (state/last.json):
//        same size, same root  -> nothing new (re-cosign only if the last
//                                 cosignature is older than the refresh window)
//        same size, other root -> FORK: two signed heads for one size
//        bigger                -> GET /kt/consistency?from=last&to=new, verify
//        smaller               -> GET /kt/consistency?from=new&to=last; consistent
//                                 means a stale head (refuse, no alert), otherwise FORK
//   3. On any proven inconsistency: write state/ALERT.json with both signed
//      heads and the proof, cosign nothing, exit 1. The alert is sticky: later
//      runs refuse to cosign until a human removes it.
//   4. Otherwise cosign with the witness's ML-DSA-44 key and write
//      public/latest.json (served on GitHub Pages) and state/last.json.
//
// Exit codes: 0 cosigned or nothing to do; 1 alert (fork/rewrite) or halted;
// 2 refused for a reason that is not evidence (log unreachable, bad
// signature, stale or future head, misconfiguration).

import { ml_dsa44, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  checkSthChain,
  cosignTreeHead,
  cosignatureToJson,
  fromBase64,
  hashesToJson,
  logIdFromPublicKey,
  parseConsistencyResponse,
  sthFromJson,
  sthToJson,
  toBase64,
  verifyTreeHead,
} from "./lib/krypt-shared/index.js";

export const EXIT = { OK: 0, ALERT: 1, REFUSED: 2 };

const HERE = dirname(fileURLToPath(import.meta.url));
const ML_DSA87_PK_BYTES = 2592;
// A head stamped further in the future than this is refused: a log could
// otherwise pre-date heads to make stale views look fresh to clients.
const MAX_FUTURE_SKEW_MS = 10 * 60 * 1000;

/** Reads configuration from the environment. Throws a readable error on anything missing. */
export function configFromEnv(env = process.env) {
  const need = (k) => {
    const v = env[k]?.trim();
    if (!v) throw new Error(`${k} is not set`);
    return v;
  };
  const logPublicKey = env.KRYPT_LOG_PUBKEY_FILE
    ? fromBase64(readFileSync(env.KRYPT_LOG_PUBKEY_FILE, "utf8").trim())
    : fromBase64(need("KRYPT_LOG_PUBKEY"));
  return {
    logUrl: need("KRYPT_LOG_URL").replace(/\/+$/, ""),
    logPublicKey,
    witnessSeed: fromBase64(need("WITNESS_SK")),
    witnessName: env.KRYPT_WITNESS_NAME?.trim() || "krypt-witness",
    dir: resolve(env.KRYPT_WITNESS_DIR || HERE),
    refreshMinutes: Number(env.KRYPT_WITNESS_REFRESH_MINUTES || 360),
    fetchTimeoutMs: Number(env.KRYPT_FETCH_TIMEOUT_MS || 90_000),
  };
}

function writeJsonAtomic(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n");
  renameSync(tmp, path);
}

function readJson(path) {
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : null;
}

/** GET with a long timeout and a few retries: Render's free tier takes ~1 min to wake up. */
async function getJson(url, { fetchImpl, timeoutMs, attempts = 3 }) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: "application/json" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      lastErr = err;
      if (i + 1 < attempts) await new Promise((r) => setTimeout(r, 1000 * 2 ** i));
    }
  }
  throw new Error(`GET ${url} failed: ${lastErr?.message ?? lastErr}`);
}

/**
 * Runs the witness once. Returns { code, status, message }; never calls
 * process.exit so tests can drive it in-process.
 */
export async function runWitness(cfg, { fetchImpl = globalThis.fetch, now = () => Date.now(), log = console.log } = {}) {
  const statePath = join(cfg.dir, "state", "last.json");
  const alertPath = join(cfg.dir, "state", "ALERT.json");
  const latestPath = join(cfg.dir, "public", "latest.json");
  const done = (code, status, message) => {
    log(`[witness] ${status}: ${message}`);
    return { code, status, message };
  };

  if (existsSync(alertPath)) {
    return done(EXIT.ALERT, "halted", `${alertPath} exists; a human must review it before this witness cosigns again`);
  }
  if (cfg.logPublicKey.length !== ML_DSA87_PK_BYTES) {
    return done(EXIT.REFUSED, "config", `log public key must be an ML-DSA-87 key (${ML_DSA87_PK_BYTES} bytes)`);
  }
  if (cfg.witnessSeed.length !== 32) return done(EXIT.REFUSED, "config", "WITNESS_SK must be a base64 32-byte seed");

  const logId = await logIdFromPublicKey(cfg.logPublicKey);
  const logIdB64 = toBase64(logId);
  const witnessKey = ml_dsa44.keygen(cfg.witnessSeed);
  const verifyLog = (msg, sig) => ml_dsa87.verify(sig, msg, cfg.logPublicKey);
  const http = { fetchImpl, timeoutMs: cfg.fetchTimeoutMs };

  // 1. Fetch and authenticate the offered head.
  let offered;
  try {
    offered = sthFromJson(await getJson(`${cfg.logUrl}/kt/sth`, http));
  } catch (err) {
    return done(EXIT.REFUSED, "unreachable", err.message);
  }
  if (!(await verifyTreeHead(offered, verifyLog))) {
    // Unsigned junk proves nothing about the log (it may be a network attacker), so no alert.
    return done(EXIT.REFUSED, "bad-signature", `STH of size ${offered.treeSize} has an invalid log signature`);
  }
  if (offered.timestampMs > now() + MAX_FUTURE_SKEW_MS) {
    return done(EXIT.REFUSED, "future", `STH timestamp ${offered.timestampMs} is in the future`);
  }

  // 2. Compare with the last cosigned head.
  const state = readJson(statePath);
  let last = null;
  if (state) {
    if (state.logId !== logIdB64) {
      return done(EXIT.REFUSED, "config", "state/last.json belongs to a different log key; refusing to mix logs");
    }
    last = sthFromJson(state.sth);
  }

  const raiseAlert = (kind, reason, proof) => {
    writeJsonAtomic(alertPath, {
      detectedAt: new Date(now()).toISOString(),
      kind,
      reason,
      logUrl: cfg.logUrl,
      logId: logIdB64,
      logPublicKey: toBase64(cfg.logPublicKey),
      // Both heads carry the log's signature: together they are publicly verifiable evidence.
      previous: state.sth,
      previousCosignature: state.cosignature,
      offered: sthToJson(offered),
      proof,
    });
    return done(EXIT.ALERT, kind, reason);
  };

  if (last) {
    const fetchProof = async (from, to) => {
      const r = parseConsistencyResponse(
        await getJson(`${cfg.logUrl}/kt/consistency?from=${from}&to=${to}`, http),
      );
      if (r.from !== from || r.to !== to) throw new Error(`asked for ${from}->${to}, got ${r.from}->${r.to}`);
      return r.proof;
    };

    if (offered.treeSize < last.treeSize) {
      // Rollback: fine only if the offered head is an older view of the same log.
      let proof = [];
      if (offered.treeSize > 0) {
        try {
          proof = await fetchProof(offered.treeSize, last.treeSize);
        } catch (err) {
          return done(EXIT.REFUSED, "unreachable", err.message);
        }
      }
      const chk = await checkSthChain(offered, last, proof);
      if (!chk.ok) {
        return raiseAlert(chk.kind === "fork" ? "fork" : "inconsistent", `older head is not a prefix of the cosigned one: ${chk.reason}`, {
          from: offered.treeSize,
          to: last.treeSize,
          proof: hashesToJson(proof),
        });
      }
      return done(EXIT.REFUSED, "stale", `log served size ${offered.treeSize}, already cosigned ${last.treeSize}`);
    }

    let proof = [];
    if (offered.treeSize > last.treeSize && last.treeSize > 0) {
      try {
        proof = await fetchProof(last.treeSize, offered.treeSize);
      } catch (err) {
        return done(EXIT.REFUSED, "unreachable", err.message);
      }
    }
    const chk = await checkSthChain(last, offered, proof);
    if (!chk.ok) {
      return raiseAlert(chk.kind, chk.reason, { from: last.treeSize, to: offered.treeSize, proof: hashesToJson(proof) });
    }

    if (offered.treeSize === last.treeSize) {
      const ageMin = (now() - state.cosignature.timestamp) / 60_000;
      if (ageMin < cfg.refreshMinutes) {
        return done(EXIT.OK, "unchanged", `size ${offered.treeSize} already cosigned ${ageMin.toFixed(0)} min ago`);
      }
    }
  }

  // 3. Cosign and publish.
  const cosig = await cosignTreeHead(offered, logId, cfg.witnessName, now(), (m) =>
    ml_dsa44.sign(m, witnessKey.secretKey),
  );
  const sthJson = sthToJson(offered);
  const cosigJson = cosignatureToJson(cosig);
  writeJsonAtomic(latestPath, {
    log: { id: logIdB64, url: cfg.logUrl },
    witness: { name: cfg.witnessName, algorithm: "ML-DSA-44", publicKey: toBase64(witnessKey.publicKey) },
    sth: sthJson,
    cosignature: cosigJson,
  });
  writeJsonAtomic(statePath, { logId: logIdB64, sth: sthJson, cosignature: cosigJson });
  const what = last ? (offered.treeSize === last.treeSize ? "refreshed" : `grew ${last.treeSize} -> ${offered.treeSize}`) : "first head (trust on first use)";
  return done(EXIT.OK, "cosigned", `size ${offered.treeSize}, ${what}`);
}

// CLI entry point.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let cfg;
  try {
    cfg = configFromEnv();
  } catch (err) {
    console.error(`[witness] config: ${err.message}`);
    process.exit(EXIT.REFUSED);
  }
  const { code } = await runWitness(cfg);
  process.exit(code);
}
