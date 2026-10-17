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
//   flip_type  set payload.type to "image"
//   swap_key   request_public_key and GET /api/bundle/:username return the keys
//              of EVIL_SWAP_WITH instead of the requested user
//
// Example: EVIL_MODE=replay,tamper EVIL_SWAP_WITH=mallory npm run dev
//
// The transforms are pure functions (randomness is injected) so they can be
// unit-tested; createEvilRelay holds the little per-pair state they need.

export const ATTACKS = [
  "replay",
  "reorder",
  "drop",
  "duplicate",
  "tamper",
  "flip_type",
  "swap_key",
] as const;
export type Attack = (typeof ATTACKS)[number];

export interface EvilConfig {
  attacks: Set<Attack>;
  dropEvery: number;
  swapWith: string | null;
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
  return {
    attacks,
    dropEvery: Number.isInteger(n) && n >= 1 ? n : 3,
    swapWith: env.EVIL_SWAP_WITH?.trim() || null,
  };
}

// ---------- Pure transforms ----------

export function flipType(msg: RelayMessage): RelayMessage {
  return { ...msg, type: "image" };
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
      "!! For testing only. Never run this in production.",
      line,
    ]
      .filter(Boolean)
      .join("\n"),
  );
  return createEvilRelay(config);
}
