// Evil relay test harness (plans 0.3 and 1.23).
//
// When EVIL_MODE is set (comma-separated attack names) the server acts as a
// malicious relay, so the client's protocol can be tested against it:
//
//   replay     re-send the previous message of the same sender->recipient pair
//              right after the next one
//   reorder    hold one message and release it after the following one
//   drop       drop every Nth message per pair (N = EVIL_DROP_EVERY, default 3)
//   duplicate  deliver every message twice
//   tamper     flip one bit in one random base64 field of the payload
//   flip_type  set payload.type to "image" (the outer, unauthenticated field)
//   flip_content_type
//              set payload.envelope.contentType, the v1 header field inside
//              the AAD, to "image" ("text" if it already is "image")
//   swap_key   request_public_key and GET /api/bundle/:username return the keys
//              of EVIL_SWAP_WITH instead of the requested user
//
// Key transparency attacks (plan 2.25). Each must be caught by clients or
// the witness; none of them is possible through the honest code paths.
//
//   kt_rogue_leaf  POST /kt/evil/rogue-leaf?victim=<name> appends a leaf that
//                  binds the victim's name to EVIL_SWAP_WITH's identity key,
//                  with a forged owner signature. /api/kt/register also stops
//                  checking leaves. The victim's self-monitoring must alert.
//   kt_fork        requests whose User-Agent contains EVIL_FORK_UA, or that
//                  carry ?fork=1 or "X-Krypt-Fork: 1", see a forked log: the
//                  latest head plus one rogue leaf for EVIL_KT_VICTIM that
//                  nobody else sees. The witness or gossip must expose it.
//   kt_rewrite     every /kt/* request sees history rewritten: the leaf at
//                  EVIL_KT_REWRITE_INDEX (default 0) is swapped for one with
//                  EVIL_SWAP_WITH's key (or a flipped bit) and every head is
//                  re-signed. Consistency with any earlier head must fail.
//
// Example: EVIL_MODE=replay,tamper EVIL_SWAP_WITH=mallory npm run dev
//
// The transforms are pure functions (randomness is injected) so they can be
// unit-tested; createEvilRelay holds the little per-pair state they need.

import {
  KtError,
  ML_DSA_87_SIG_BYTES,
  parseIdentityKey,
  type KtLog,
  type KtView,
  type StoredLeaf,
} from "./kt.js";
import {
  KtOp,
  MemoryNodeStore,
  MerkleLog,
  bytesEqual,
  decodeLeaf,
  encodeLeaf,
  hashLeaf,
  hashUsername,
  sha256,
  type KtLeaf,
  type NodeStore,
  type SignedTreeHead,
} from "./vendor/krypt-shared/index.js";

export const ATTACKS = [
  "replay",
  "reorder",
  "drop",
  "duplicate",
  "tamper",
  "flip_type",
  "flip_content_type",
  "swap_key",
  "kt_rogue_leaf",
  "kt_fork",
  "kt_rewrite",
] as const;
export type Attack = (typeof ATTACKS)[number];

export interface EvilConfig {
  attacks: Set<Attack>;
  dropEvery: number;
  swapWith: string | null;
  /** kt_fork: whose name the forked view's extra leaf claims. */
  ktVictim: string | null;
  /** kt_fork: User-Agent substring (case-insensitive) of the client to fork. */
  forkUserAgent: string | null;
  /** kt_rewrite: index of the leaf to rewrite. */
  rewriteIndex: number;
}

export type RelayMessage = Record<string, unknown> & { to: string; from: string };
export type Rng = () => number;

/** Parse EVIL_* env vars. Returns null when evil mode is off. */
export function parseEvilConfig(env: NodeJS.ProcessEnv): EvilConfig | null {
  const raw = env.EVIL_MODE?.trim();
  if (!raw) return null;
  const attacks = new Set<Attack>();
  const unknown: string[] = [];
  for (const name of raw.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    if ((ATTACKS as readonly string[]).includes(name)) attacks.add(name as Attack);
    else unknown.push(name);
  }
  if (unknown.length > 0) {
    throw new Error(
      `Unknown EVIL_MODE attack(s): ${unknown.join(", ")}. Valid: ${ATTACKS.join(", ")}`,
    );
  }
  const n = Number(env.EVIL_DROP_EVERY ?? 3);
  const r = Number(env.EVIL_KT_REWRITE_INDEX ?? 0);
  return {
    attacks,
    dropEvery: Number.isInteger(n) && n >= 1 ? n : 3,
    swapWith: env.EVIL_SWAP_WITH?.trim() || null,
    ktVictim: env.EVIL_KT_VICTIM?.trim() || null,
    forkUserAgent: env.EVIL_FORK_UA?.trim() || null,
    rewriteIndex: Number.isSafeInteger(r) && r >= 0 ? r : 0,
  };
}

// ---------- Pure transforms ----------

export function flipType(msg: RelayMessage): RelayMessage {
  return { ...msg, type: "image" };
}

/**
 * Flip the v1 envelope's own contentType (authenticated as part of the
 * header). Messages without an envelope object are returned unchanged.
 */
export function flipContentType(msg: RelayMessage): RelayMessage {
  const env = msg.envelope;
  if (!env || typeof env !== "object" || Array.isArray(env)) return msg;
  const ct = (env as Record<string, unknown>).contentType;
  if (typeof ct !== "string") return msg;
  return { ...msg, envelope: { ...env, contentType: ct === "image" ? "text" : "image" } };
}

export function duplicate(msg: RelayMessage): RelayMessage[] {
  return [msg, structuredClone(msg)];
}

/** Should the `count`-th message (1-based) of a pair be dropped? */
export function shouldDrop(count: number, every: number): boolean {
  return every >= 1 && count % every === 0;
}

const PREFIX = /^([A-Za-z0-9]{1,16}:)(.*)$/s; // e.g. "GCM:<base64>"
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

interface Base64Field {
  prefix: string;
  bytes: Buffer;
  encoding: "base64" | "base64url";
}

/** Recognise a (possibly "XYZ:"-prefixed) base64 or base64url string of >= 8 bytes. */
export function parseBase64Field(value: string): Base64Field | null {
  const m = PREFIX.exec(value);
  const prefix = m ? m[1]! : "";
  const body = m ? m[2]! : value;
  if (body.length < 12) return null;

  let encoding: "base64" | "base64url";
  if (/[-_]/.test(body)) {
    if (!B64URL.test(body)) return null;
    encoding = "base64url";
  } else if (B64.test(body)) {
    // Plain alphanumerics are valid in both; padded length says base64.
    encoding = /[+/=]/.test(body) || body.length % 4 === 0 ? "base64" : "base64url";
  } else {
    return null;
  }
  const bytes = Buffer.from(body, encoding);
  if (bytes.length < 8) return null;
  return { prefix, bytes, encoding };
}

function encodeLike(field: Base64Field, bytes: Buffer): string {
  return field.prefix + bytes.toString(field.encoding);
}

const NEVER_TAMPER = new Set(["to", "from", "type"]);

/** Paths (top-level and nested) of string fields that hold base64 data. */
export function base64Paths(value: unknown, path: string[] = []): string[][] {
  if (typeof value === "string") {
    return parseBase64Field(value) ? [path] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((v, i) => base64Paths(v, [...path, String(i)]));
  }
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) =>
      path.length === 0 && NEVER_TAMPER.has(k) ? [] : base64Paths(v, [...path, k]),
    );
  }
  return [];
}

/**
 * Flip one bit in one random base64 field. Decodes, flips, re-encodes in the
 * same alphabet with the same prefix. Returns the message unchanged if it has
 * no base64 field.
 */
export function tamper(msg: RelayMessage, rng: Rng = Math.random): RelayMessage {
  const paths = base64Paths(msg);
  if (paths.length === 0) return msg;
  const path = paths[Math.floor(rng() * paths.length)]!;

  const out = structuredClone(msg);
  let parent: any = out;
  for (const key of path.slice(0, -1)) parent = parent[key];
  const leaf = path[path.length - 1]!;

  const field = parseBase64Field(parent[leaf] as string)!;
  const bytes = Buffer.from(field.bytes);
  const byte = Math.floor(rng() * bytes.length);
  const bit = Math.floor(rng() * 8);
  bytes[byte] = bytes[byte]! ^ (1 << bit);
  parent[leaf] = encodeLike(field, bytes);
  return out;
}

// ---------- Stateful relay ----------

export interface EvilRelay {
  config: EvilConfig;
  /** Turn one forwarded message into the messages actually delivered (0..n). */
  process(msg: RelayMessage): RelayMessage[];
  /** Whose keys to serve when `username`'s keys are requested. */
  keySource(username: string): string;
}

const pair = (m: RelayMessage) => `${m.from}\u0000${m.to}`;

export function createEvilRelay(config: EvilConfig, rng: Rng = Math.random): EvilRelay {
  const counts = new Map<string, number>();
  const held = new Map<string, RelayMessage>();
  const last = new Map<string, RelayMessage>();
  const on = (a: Attack) => config.attacks.has(a);

  return {
    config,
    process(msg) {
      const key = pair(msg);

      if (on("drop")) {
        const n = (counts.get(key) ?? 0) + 1;
        counts.set(key, n);
        if (shouldDrop(n, config.dropEvery)) return [];
      }

      let m = msg;
      if (on("tamper")) m = tamper(m, rng);
      if (on("flip_type")) m = flipType(m);
      if (on("flip_content_type")) m = flipContentType(m);

      let out: RelayMessage[] = on("duplicate") ? duplicate(m) : [m];

      if (on("reorder")) {
        const h = held.get(key);
        if (h) {
          held.delete(key);
          out = [...out, h];
        } else {
          held.set(key, out[0]!);
          out = out.slice(1);
        }
      }

      if (on("replay")) {
        const prev = last.get(key);
        last.set(key, m);
        if (prev) out = [...out, structuredClone(prev)];
      }

      return out;
    },
    keySource(username) {
      if (on("swap_key") && config.swapWith && username !== config.swapWith) {
        return config.swapWith;
      }
      return username;
    },
  };
}

/** Build the relay from the environment, logging a loud warning when enabled. */
export function loadEvilRelay(env: NodeJS.ProcessEnv = process.env): EvilRelay | null {
  const config = parseEvilConfig(env);
  if (!config) return null;
  const line = "!".repeat(72);
  console.warn(
    [
      line,
      "!! EVIL RELAY MODE IS ON. This server attacks its own users' messages.",
      `!! Attacks: ${[...config.attacks].join(", ") || "(none)"}`,
      config.attacks.has("drop") ? `!! Dropping every ${config.dropEvery}th message per pair` : "",
      config.attacks.has("swap_key")
        ? `!! Serving keys of: ${config.swapWith ?? "(EVIL_SWAP_WITH not set: swap disabled)"}`
        : "",
      config.attacks.has("kt_fork")
        ? `!! Forking the KT log for User-Agent ~ ${config.forkUserAgent ?? "(EVIL_FORK_UA not set)"} and ?fork=1`
        : "",
      config.attacks.has("kt_rewrite") ? `!! Rewriting KT leaf ${config.rewriteIndex} for every client` : "",
      config.attacks.has("kt_rogue_leaf") ? "!! POST /kt/evil/rogue-leaf?victim=<name> is open; KT register checks are off" : "",
      "!! For testing only. Never run this in production.",
      line,
    ]
      .filter(Boolean)
      .join("\n"),
  );
  return createEvilRelay(config);
}

// ---------- Key transparency attacks (plan 2.25) ----------

/** Request fields the KT attacks look at (a subset of express.Request). */
export interface KtRequestInfo {
  headers: Record<string, string | string[] | undefined>;
  query: Record<string, unknown>;
}

/** kt_fork: is this the client to show the forked log to? */
export function isForkTarget(req: KtRequestInfo, config: EvilConfig): boolean {
  if (req.query.fork === "1" || req.headers["x-krypt-fork"] === "1") return true;
  const ua = req.headers["user-agent"];
  return (
    !!config.forkUserAgent &&
    typeof ua === "string" &&
    ua.toLowerCase().includes(config.forkUserAgent.toLowerCase())
  );
}

/**
 * A well-formed leaf binding `victim` to `keys`, with a random "owner
 * signature" whose hash is in the leaf: it passes shape checks but no
 * signature check. Rotates from the victim's latest leaf if there is one.
 */
export async function buildRogueLeaf(
  victim: string,
  keys: { mldsaPkHash: Uint8Array; mlkemPkHash: Uint8Array },
  prev: StoredLeaf | null,
  timestampMs: number,
): Promise<{ bytes: Uint8Array; ownerSig: Uint8Array }> {
  const ownerSig = globalThis.crypto.getRandomValues(new Uint8Array(ML_DSA_87_SIG_BYTES));
  const leaf: KtLeaf = {
    op: prev ? KtOp.Rotate : KtOp.Register,
    userHash: await hashUsername(victim),
    keyVersion: prev ? prev.keyVersion + 1 : 1,
    mldsaPkHash: keys.mldsaPkHash,
    mlkemPkHash: keys.mlkemPkHash,
    timestampMs,
    ownerSigHash: await sha256(ownerSig),
  };
  return { bytes: encodeLeaf(leaf), ownerSig };
}

/** NodeStore that writes to memory and reads memory first, then `base`. */
function overlayStore(base: NodeStore): NodeStore {
  const mem = new MemoryNodeStore();
  return {
    get: async (level, index) => mem.get(level, index) ?? (await base.get(level, index)),
    put: (level, index, hash) => mem.put(level, index, hash),
  };
}

/**
 * kt_fork: the honest log at its latest head plus one extra leaf, under a
 * freshly signed head of size n + 1 that only the target client sees. It is
 * a valid extension of every honest head so far; it is exposed once the
 * honest log reaches n + 1 with a different root (witness, gossip).
 */
export async function buildForkView(
  log: KtLog,
  honest: KtView,
  extra: { bytes: Uint8Array; ownerSig: Uint8Array },
): Promise<KtView> {
  const head = await honest.latestSth();
  const n = head.treeSize;
  const nodes = overlayStore(log.storage.nodes);
  const ml = new MerkleLog(nodes, n);
  const leafHash = await hashLeaf(extra.bytes);
  await ml.append(leafHash);
  const forkHead = await log.sign(n + 1, await ml.root(), Math.max(Date.now(), head.timestampMs + 1));
  const decoded = decodeLeaf(extra.bytes);
  const row: StoredLeaf = {
    index: n,
    leaf: extra.bytes,
    leafHash,
    userHash: decoded.userHash,
    keyVersion: decoded.keyVersion,
    ownerSig: extra.ownerSig,
  };
  return {
    latestSth: async () => forkHead,
    sthAt: async (size) => (size === n + 1 ? forkHead : size <= n ? honest.sthAt(size) : null),
    log: async () => new MerkleLog(nodes, n + 1),
    leaves: async (from, to) => [
      ...(from < n ? await honest.leaves(from, Math.min(to, n)) : []),
      ...(from <= n && to > n ? [row] : []),
    ],
    latestLeafForUser: async (userHash, beforeSize) =>
      beforeSize > n && bytesEqual(userHash, row.userHash)
        ? row
        : honest.latestLeafForUser(userHash, Math.min(beforeSize, n)),
  };
}

/**
 * kt_rewrite: history up to the latest honest head with leaf `index`
 * replaced by `rewrite(leaf)`, every head re-signed (same sizes and
 * timestamps, different roots). Rebuilt in memory; the database is untouched.
 */
export async function buildRewriteView(
  log: KtLog,
  honest: KtView,
  index: number,
  rewrite: (leaf: KtLeaf) => KtLeaf,
): Promise<KtView> {
  const head = await honest.latestSth();
  const n = head.treeSize;
  if (index >= n) return honest; // nothing to rewrite yet
  const rows = await honest.leaves(0, n);
  const old = rows[index]!;
  const leaf = encodeLeaf(rewrite(decodeLeaf(old.leaf)));
  rows[index] = { ...old, leaf, leafHash: await hashLeaf(leaf) };
  const ml = new MerkleLog(new MemoryNodeStore());
  for (const r of rows) await ml.append(r.leafHash);

  const heads = new Map<number, SignedTreeHead>();
  const resign = async (th: SignedTreeHead | null) => {
    if (!th) return null;
    let h = heads.get(th.treeSize);
    if (!h) {
      h = await log.sign(th.treeSize, await ml.root(th.treeSize), th.timestampMs);
      heads.set(th.treeSize, h);
    }
    return h;
  };
  const latest = (await resign(head))!;
  return {
    latestSth: async () => latest,
    sthAt: async (size) => resign(await honest.sthAt(size)),
    log: async () => ml,
    leaves: async (from, to) => rows.slice(from, Math.min(to, n)),
    latestLeafForUser: async (userHash, beforeSize) => {
      for (let i = Math.min(beforeSize, n) - 1; i >= 0; i--) {
        if (bytesEqual(rows[i]!.userHash, userHash)) return rows[i]!;
      }
      return null;
    },
  };
}

export interface EvilKt {
  viewFor(req: KtRequestInfo): KtView;
  skipRegisterChecks: boolean;
  injectRogueLeaf?: (victim: string) => Promise<number>;
}

/**
 * Wires the KT attacks; null when none is on. `identityKeyOf` returns a
 * user's stored identityKeyPub (EVIL_SWAP_WITH's key is what gets planted).
 * Derived views are cached per honest head, so an attack costs one
 * signature per new head, not one per request.
 */
export function createEvilKt(
  config: EvilConfig,
  log: KtLog,
  identityKeyOf: (username: string) => Promise<string | null>,
): EvilKt | null {
  const on = (a: Attack) => config.attacks.has(a);
  if (!on("kt_rogue_leaf") && !on("kt_fork") && !on("kt_rewrite")) return null;

  const swapKeyHashes = async () => {
    const keys = config.swapWith ? parseIdentityKey(await identityKeyOf(config.swapWith)) : null;
    if (keys) return { mldsaPkHash: await sha256(keys.mldsaPk), mlkemPkHash: await sha256(keys.mlkemPk) };
    // No usable EVIL_SWAP_WITH key: plant random hashes (a key nobody owns).
    const r = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
    return { mldsaPkHash: r(), mlkemPkHash: r() };
  };

  // One derived view per honest head (keyed by its size and timestamp).
  const cached = (build: (honest: KtView) => Promise<KtView>) => {
    let key = "";
    let view: Promise<KtView> | null = null;
    const current = async (honest: KtView) => {
      const head = await honest.latestSth();
      const k = `${head.treeSize}:${head.timestampMs}`;
      if (k !== key || !view) {
        key = k;
        view = build(honest);
      }
      return view;
    };
    return (honest: KtView): KtView => ({
      latestSth: async () => (await current(honest)).latestSth(),
      sthAt: async (size) => (await current(honest)).sthAt(size),
      log: async (size) => (await current(honest)).log(size),
      leaves: async (from, to) => (await current(honest)).leaves(from, to),
      latestLeafForUser: async (u, b) => (await current(honest)).latestLeafForUser(u, b),
    });
  };

  const forkVictim = config.ktVictim ?? "evil-fork-victim";
  const fork = cached(async (honest) => {
    const size = (await honest.latestSth()).treeSize;
    const prev = await honest.latestLeafForUser(await hashUsername(forkVictim), size);
    const rogue = await buildRogueLeaf(forkVictim, await swapKeyHashes(), prev, Date.now());
    return buildForkView(log, honest, rogue);
  });
  const rewrite = cached(async (honest) => {
    const planted = await swapKeyHashes();
    return buildRewriteView(log, honest, config.rewriteIndex, (leaf) =>
      config.swapWith
        ? { ...leaf, ...planted }
        : { ...leaf, mldsaPkHash: leaf.mldsaPkHash.map((b, i) => (i === 0 ? b ^ 1 : b)) },
    );
  });

  const evil: EvilKt = {
    viewFor(req) {
      const honest = log.honestView();
      if (on("kt_fork") && isForkTarget(req, config)) return fork(honest);
      if (on("kt_rewrite")) return rewrite(honest);
      return honest;
    },
    skipRegisterChecks: on("kt_rogue_leaf"),
  };
  if (on("kt_rogue_leaf")) {
    evil.injectRogueLeaf = async (victim) => {
      if (!config.swapWith || !parseIdentityKey(await identityKeyOf(config.swapWith))) {
        throw new KtError(
          400,
          "kt_rogue_leaf needs EVIL_SWAP_WITH naming a user with an ML-DSA/ML-KEM identity key.",
        );
      }
      const prev = await log.latestLeafForUser(await hashUsername(victim));
      const rogue = await buildRogueLeaf(victim, await swapKeyHashes(), prev, Date.now());
      return (await log.append(rogue.bytes, rogue.ownerSig)).index;
    };
  }
  return evil;
}
